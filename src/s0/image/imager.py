"""S0 Forensic Drive Imager & Bit-Stream Duplication Engine.

Adheres to NIST SP 800-86 and ISO/IEC 27037 standards for digital evidence
acquisition, preservation, and fault-tolerant disk duplication.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from s0 import certificate as cert_mod
from s0 import crypto as core_crypto
from s0 import platform as platform_mod
from s0 import resources
from s0.audit import record_audit_event
from s0.cli.devices import SafetyError, check_safety, get_block_device_size
from s0.cli.devices import Target as DevTarget
from s0.config import CONFIG


@dataclass
class BadSectorRange:
    offset_bytes: int
    length_bytes: int

    def to_dict(self) -> dict:
        return {
            "offset_bytes": self.offset_bytes,
            "length_bytes": self.length_bytes,
        }


@dataclass
class ImagingOptions:
    source: str
    destination: str
    block_size: int = 1024 * 1024  # 1 MiB default for optimal sequential I/O
    sector_size: int = 512
    error_recovery: bool = True     # Replace bad sectors with zeros (ddrescue-style)
    verify_hashes: bool = True     # Compute live SHA-256 and MD5
    operator: str = "op-forensic"
    organization: str = "Digital Forensics & Incident Response Lab"
    notes: list[str] = field(default_factory=list)
    key_path: str | Path | None = None
    no_certificate: bool = False
    out_dir: str = "."
    force: bool = False


@dataclass
class ImagingResult:
    success: bool
    source: str
    destination: str
    is_clone: bool
    source_capacity_bytes: int
    bytes_copied: int
    duration_seconds: float
    speed_mbps: float
    bad_sectors_count: int
    bad_bytes_count: int
    bad_sector_ranges: list[BadSectorRange]
    source_sha256: str
    source_md5: str
    manifest_path: str | None = None
    manifest_certificate: dict | None = None
    audit_ledger_recorded: bool = False
    audit_ledger_error: str | None = None
    error: str | None = None


def _resolve_source_target(path: str) -> tuple[str, int, str]:
    """Resolve source path, capacity, and kind ('block' or 'image')."""
    p = Path(path)
    if p.is_file():
        return str(p.resolve()), p.stat().st_size, "image"

    # Check block device
    is_blk = platform_mod.is_block_device(p)

    if is_blk:
        sz = get_block_device_size(p)
        return str(p), sz, "block"

    # Windows PhysicalDrive or letter
    if sys.platform == "win32":
        sz = 0
        try:
            from windows.cli.s0_eraser import get_windows_target_size
            sz = get_windows_target_size(path)
        except Exception:
            pass
        return path, sz, "block"

    if p.exists():
        return str(p.resolve()), p.stat().st_size, "image"

    raise FileNotFoundError(f"Source target does not exist or is inaccessible: {path}")


def acquire_image(
    options: ImagingOptions,
    progress_callback: Callable[[int, int, float, int], None] | None = None,
) -> ImagingResult:
    """Perform bit-stream forensic acquisition from source to destination."""
    start_time = time.time()
    now_iso_start = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    src_path, src_capacity, src_kind = _resolve_source_target(options.source)
    dst_p = Path(options.destination)

    # 1. Safety verification
    try:
        if dst_p.exists() and os.path.realpath(src_path) == os.path.realpath(str(dst_p)):
            raise SafetyError(f"Source and destination cannot be the same target ({src_path})!")
    except OSError:
        pass

    # Determine if destination is a physical block device (cloning mode) or image file
    is_clone = False
    try:
        if platform_mod.is_block_device(dst_p):
            is_clone = True
    except Exception:
        pass


    if is_clone:
        # Check safety of destination device
        dst_dev = DevTarget(path=str(dst_p), kind="block", capacity_bytes=get_block_device_size(dst_p))
        check_safety(dst_dev)
        if dst_dev.capacity_bytes > 0 and src_capacity > dst_dev.capacity_bytes:
            raise SafetyError(
                f"Destination drive capacity ({dst_dev.capacity_bytes} B) is smaller than "
                f"source capacity ({src_capacity} B)!"
            )
    else:
        # Destination is a regular file
        out_parent = dst_p.parent.resolve()
        out_parent.mkdir(parents=True, exist_ok=True)
        if dst_p.is_symlink():
            raise SafetyError(f"Refusing to write image to symbolic link: {dst_p}")
        if dst_p.exists() and not getattr(options, "force", False):
            raise SafetyError(f"Destination image file {dst_p} already exists. Use --force to overwrite.")
        # Check free disk space if capacity is known
        if src_capacity > 0:
            try:
                free_space = shutil.disk_usage(out_parent).free
                if free_space < src_capacity:
                    raise SafetyError(
                        f"Insufficient free space on destination filesystem. "
                        f"Required: {src_capacity / (1024**3):.2f} GB, "
                        f"Available: {free_space / (1024**3):.2f} GB."
                    )
            except OSError:
                pass

    sha256_hasher = hashlib.sha256()
    # MD5 here is a recorded acquisition fingerprint for cross-checking a copy
    # against a reference, not a security control: SHA-256 is computed alongside
    # it and is what the manifest certificate attests to. `usedforsecurity=False`
    # says so at the call site rather than leaving a reader to work out which
    # hash this is and whether it matters.
    md5_hasher = hashlib.md5(usedforsecurity=False)

    bytes_copied = 0
    bad_sectors_count = 0
    bad_bytes_count = 0
    bad_ranges: list[BadSectorRange] = []

    block_size = max(512, options.block_size)
    sector_size = max(512, options.sector_size)

    # 2. Bit-stream streaming acquisition
    src_f = None
    dst_f = None
    try:
        src_f = open(src_path, "rb")
        if not is_clone:
            flags = os.O_WRONLY | os.O_CREAT
            if sys.platform != "win32":
                flags |= getattr(os, "O_NOFOLLOW", 0)
            if not getattr(options, "force", False):
                flags |= os.O_EXCL
            else:
                flags |= os.O_TRUNC
            fd = os.open(str(dst_p), flags, 0o644)
            dst_f = open(fd, "wb")
        else:
            dst_f = open(str(dst_p), "r+b")

        while True:
            current_offset = bytes_copied
            chunk = b""
            try:
                chunk = src_f.read(block_size)
            except OSError as read_err:
                if not options.error_recovery:
                    raise OSError(f"Read error at offset {current_offset}: {read_err}") from read_err

                # Fallback: sector-by-sector read through the bad block
                sub_offset = current_offset
                sectors_to_try = block_size // sector_size
                recovered_chunk = bytearray()

                for _ in range(sectors_to_try):
                    try:
                        src_f.seek(sub_offset)
                        sec_data = src_f.read(sector_size)
                        if not sec_data:
                            break
                        recovered_chunk.extend(sec_data)
                    except OSError:
                        # Bad sector encountered: zero-fill to maintain alignment
                        bad_sectors_count += 1
                        bad_bytes_count += sector_size
                        bad_ranges.append(BadSectorRange(offset_bytes=sub_offset, length_bytes=sector_size))
                        recovered_chunk.extend(b"\x00" * sector_size)
                    sub_offset += sector_size

                chunk = bytes(recovered_chunk)
                src_f.seek(sub_offset)

            if not chunk:
                break

            # Update live cryptographic hashes
            if options.verify_hashes:
                sha256_hasher.update(chunk)
                md5_hasher.update(chunk)

            # Write to destination
            dst_f.write(chunk)
            bytes_copied += len(chunk)

            # Progress notification
            if progress_callback:
                elapsed = max(0.001, time.time() - start_time)
                speed = (bytes_copied / (1024 * 1024)) / elapsed
                progress_callback(bytes_copied, src_capacity, speed, bad_sectors_count)

        dst_f.flush()
        try:
            os.fsync(dst_f.fileno())
        except (OSError, AttributeError):
            pass

    except Exception as exc:
        duration = max(0.001, time.time() - start_time)
        speed = (bytes_copied / (1024 * 1024)) / duration
        return ImagingResult(
            success=False,
            source=src_path,
            destination=str(dst_p),
            is_clone=is_clone,
            source_capacity_bytes=src_capacity,
            bytes_copied=bytes_copied,
            duration_seconds=duration,
            speed_mbps=speed,
            bad_sectors_count=bad_sectors_count,
            bad_bytes_count=bad_bytes_count,
            bad_sector_ranges=bad_ranges,
            source_sha256=sha256_hasher.hexdigest(),
            source_md5=md5_hasher.hexdigest(),
            error=str(exc),
        )
    finally:
        if src_f:
            try:
                src_f.close()
            except Exception:
                pass
        if dst_f:
            try:
                dst_f.close()
            except Exception:
                pass

    duration = max(0.001, time.time() - start_time)
    speed = (bytes_copied / (1024 * 1024)) / duration
    source_sha256 = sha256_hasher.hexdigest()
    source_md5 = md5_hasher.hexdigest()
    now_iso_end = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # 3. Create Acquisition Manifest
    out_dir_p = Path(options.out_dir)
    out_dir_p.mkdir(parents=True, exist_ok=True)
    manifest_filename = f"acquisition_manifest_{int(start_time)}_{Path(src_path).name}.json"
    manifest_file = out_dir_p / manifest_filename

    manifest_data = {
        "operation": "FORENSIC_CLONING" if is_clone else "FORENSIC_IMAGING",
        "timestamp_start": now_iso_start,
        "timestamp_end": now_iso_end,
        "duration_seconds": round(duration, 3),
        "average_speed_mbps": round(speed, 2),
        "source": {
            "path": src_path,
            "kind": src_kind,
            "capacity_bytes": src_capacity,
        },
        "destination": {
            "path": str(dst_p.resolve() if not is_clone else dst_p),
            "kind": "block_device" if is_clone else "raw_image",
            "bytes_written": bytes_copied,
        },
        "cryptographic_hashes": {
            "sha256": source_sha256,
            "md5": source_md5,
        },
        "integrity_recovery": {
            "error_recovery_enabled": options.error_recovery,
            "bad_sectors_encountered": bad_sectors_count,
            "bad_bytes_zero_filled": bad_bytes_count,
            "bad_sector_ranges": [r.to_dict() for r in bad_ranges],
        },
        "operator": {
            "operator_id": options.operator,
            "organization": options.organization,
            "notes": options.notes,
        },
    }

    manifest_file.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")

    # 4. Optional Ed25519 Certificate Signing & Audit Hash-Chain Recording
    signed_cert = None
    audit_ledger_rec = False
    audit_ledger_err = None
    if not options.no_certificate:
        key_file = Path(options.key_path) if options.key_path else None
        if key_file and not key_file.is_file():
            # The operator named a key that is not where they said. Fall back to
            # the packaged demo key, but only if it is the same key by name --
            # silently substituting a different signer would be a custody defect.
            try:
                cand = resources.demo_private_key()
            except FileNotFoundError:
                cand = None
            if cand is not None and cand.name == key_file.name:
                key_file = cand

        method_name = "FORENSIC_CLONING" if is_clone else "FORENSIC_IMAGING"
        pattern_name = "cloning" if is_clone else "imaging"

        notes_list = [
            f"Forensic Bit-Stream Acquisition: {src_path} -> {dst_p.name}.",
            f"Bytes Acquired: {bytes_copied}.",
            f"Source SHA-256: {source_sha256}.",
            f"Source MD5: {source_md5}.",
        ]
        if bad_sectors_count > 0:
            notes_list.append(f"Fault Tolerance: {bad_sectors_count} bad sectors zero-filled.")
        notes_list.extend(options.notes)

        cert_dict = cert_mod.build_certificate(
            organization=options.organization,
            operator_id=options.operator,
            tool_name="s0-imager",
            tool_version=CONFIG.get("version", "2.4.4"),
            platform=platform_mod.current(),
            device_id=f"drive-{hashlib.sha256(src_path.encode()).hexdigest()[:16]}",
            device_type="image_file" if src_kind == "image" else "internal_disk",
            storage_type="IMAGE_FILE" if src_kind == "image" else "HDD",
            method=method_name,
            nist_category="N/A",
            pattern=pattern_name,
            start_time=now_iso_start,
            end_time=now_iso_end,
            bytes_processed=bytes_copied,
            capacity_bytes=src_capacity or bytes_copied,
            status="success" if bad_sectors_count == 0 else "partial",
            verification={
                "method": "bit_stream_simultaneous_sha256_md5",
                "samples_checked": 1,
            },
            notes=notes_list,
        )

        audit_ledger_rec = False
        audit_ledger_err = None
        if key_file and key_file.is_file():
            try:
                priv = core_crypto.load_private_pem(key_file)
                signed_cert = cert_mod.sign_certificate(cert_dict, priv)
                cert_file = out_dir_p / f"certificate_{signed_cert['cert_uuid']}.json"
                cert_file.write_text(json.dumps(signed_cert, indent=2), encoding="utf-8")
                # Record to hash-chained audit ledger
                try:
                    record_audit_event(signed_cert, operation_type=method_name, private_key=key_file)
                    audit_ledger_rec = True
                except Exception as exc:
                    audit_ledger_rec = False
                    audit_ledger_err = str(exc)
                    sys.stderr.write(f"WARNING: failed to record event into audit ledger: {exc}\n")
            except Exception:
                signed_cert = None

    return ImagingResult(
        success=True,
        source=src_path,
        destination=str(dst_p),
        is_clone=is_clone,
        source_capacity_bytes=src_capacity,
        bytes_copied=bytes_copied,
        duration_seconds=duration,
        speed_mbps=speed,
        bad_sectors_count=bad_sectors_count,
        bad_bytes_count=bad_bytes_count,
        bad_sector_ranges=bad_ranges,
        source_sha256=source_sha256,
        source_md5=source_md5,
        manifest_path=str(manifest_file),
        manifest_certificate=signed_cert,
        audit_ledger_recorded=audit_ledger_rec,
        audit_ledger_error=audit_ledger_err,
    )
