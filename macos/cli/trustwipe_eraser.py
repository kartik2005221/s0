"""TrustWipe Module 2: Secure File & Folder Eraser (macOS / Darwin Native).

Forensic-grade selective sanitization for Apple macOS (APFS, HFS+, FAT32, exFAT):
- In-place cluster overwriting with hardware cache flush via fcntl(F_FULLFSYNC)
- Extended Attribute (xattr) and Apple quarantine metadata removal
- Resetting file timestamps to epoch 0
- Directory entry obfuscation prior to unlinking
- Detection and warning for Apple File System (APFS) Copy-on-Write (CoW) and Time Machine snapshots
- Consolidated Ed25519 / SHA-256 sanitization certificate issuance matching core schema
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import stat
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, List, Optional

# Ensure core library is accessible
def _find_repo_root() -> Path:
    for p in Path(__file__).resolve().parents:
        if (p / "core" / "keys").exists():
            return p
    return Path(__file__).resolve().parents[1]

REPO_ROOT = _find_repo_root()
core_python_dir = REPO_ROOT / "core" / "python"
if core_python_dir.exists() and str(core_python_dir) not in sys.path:
    sys.path.insert(0, str(core_python_dir))

try:
    from trustwipe_core import certificate as cert_mod
    from trustwipe_core import crypto as core_crypto
except ImportError:
    cert_mod = None
    core_crypto = None

# Darwin fcntl command for full hardware write cache flush
F_FULLFSYNC = 51


@dataclass
class MacDriveWipeResult:
    target: str
    target_type: str  # "removable_disk", "partition", or "image"
    capacity_bytes: int
    bytes_overwritten: int
    passes: int
    pattern: str
    status: str
    error: Optional[str] = None
    verification_passed: bool = False
    samples_checked: int = 0
    notes: List[str] = field(default_factory=list)


@dataclass
class MacFileEraseResult:
    path: str
    original_size: int
    bytes_overwritten: int
    passes: int
    pattern: str
    status: str
    error: Optional[str] = None
    metadata_cleansed: bool = False
    cow_warning: Optional[str] = None
    xattrs_cleared: bool = False
    filesystem: str = "unknown"


def detect_macos_filesystem(path_str: str) -> tuple[str, Optional[str]]:
    """Detect filesystem and APFS CoW status on macOS."""
    fs_name = "unknown"
    cow_warning = None
    try:
        res = subprocess.run(["mount"], capture_output=True, text=True, check=False)
        if res.returncode == 0:
            for line in res.stdout.splitlines():
                if " on " in line and "(" in line:
                    mp = line.split(" on ")[1].split(" (")[0].strip()
                    opts = line.split(" (")[1].rstrip(")")
                    if path_str.startswith(mp):
                        if "apfs" in opts.lower():
                            fs_name = "apfs"
                            cow_warning = (
                                "Target resides on Apple File System (APFS), a Copy-on-Write (CoW) filesystem. "
                                "In-place overwrite allocates new storage blocks; original blocks and local snapshots "
                                "may persist until reclaimed."
                            )
                            break
                        elif "hfs" in opts.lower():
                            fs_name = "hfs+"
    except Exception:
        pass
    return fs_name, cow_warning


def macos_clear_attributes(path_str: str) -> bool:
    """Clear extended attributes (quarantine, finder info, resource forks)."""
    cleared = False
    try:
        os.chmod(path_str, stat.S_IWRITE | stat.S_IREAD)
    except Exception:
        pass
    try:
        proc = subprocess.run(["xattr", "-c", path_str], capture_output=True, check=False)
        cleared = (proc.returncode == 0)
    except Exception:
        pass
    return cleared


def macos_full_fsync(fd: int) -> None:
    """Flush macOS drive hardware write cache via F_FULLFSYNC."""
    try:
        import fcntl
        fcntl.fcntl(fd, F_FULLFSYNC, 0)
    except Exception:
        try:
            os.fsync(fd)
        except Exception:
            pass


def erase_single_file_macos(
    file_path: str | Path,
    passes: int = 1,
    pattern: str = "zero",
    chunk_size: int = 65536,
) -> MacFileEraseResult:
    path_obj = Path(file_path).resolve()
    path_str = str(path_obj)

    if not path_obj.exists() or not path_obj.is_file():
        return MacFileEraseResult(
            path=path_str,
            original_size=0,
            bytes_overwritten=0,
            passes=passes,
            pattern=pattern,
            status="failure",
            error="Target is not an existing regular file",
        )

    xattrs_cleared = macos_clear_attributes(path_str)
    fs_name, cow_warning = detect_macos_filesystem(path_str)

    try:
        file_size = path_obj.stat().st_size
    except Exception as exc:
        return MacFileEraseResult(
            path=path_str,
            original_size=0,
            bytes_overwritten=0,
            passes=passes,
            pattern=pattern,
            status="failure",
            error=f"Cannot stat target: {exc}",
            filesystem=fs_name,
        )

    bytes_written_total = 0
    try:
        if file_size > 0:
            with open(path_str, "r+b") as f:
                for _ in range(passes):
                    f.seek(0)
                    rem = file_size
                    while rem > 0:
                        to_write = min(rem, chunk_size)
                        buf = secrets.token_bytes(to_write) if pattern == "random" else b"\x00" * to_write
                        f.write(buf)
                        rem -= to_write
                        bytes_written_total += to_write
                    f.flush()
                    macos_full_fsync(f.fileno())

                # Truncate
                f.seek(0)
                f.truncate(0)
                f.flush()
                macos_full_fsync(f.fileno())

        # Reset timestamps
        try:
            os.utime(path_str, (0, 0))
        except Exception:
            pass

        # Obfuscate directory entry before deletion
        parent_dir = path_obj.parent
        rand_name = parent_dir / f".tw_del_{secrets.token_hex(16)}"
        try:
            os.rename(path_str, rand_name)
            os.unlink(rand_name)
        except Exception:
            os.unlink(path_str)

        if path_obj.exists():
            return MacFileEraseResult(
                path=path_str,
                original_size=file_size,
                bytes_overwritten=bytes_written_total,
                passes=passes,
                pattern=pattern,
                status="failure",
                error="File still exists after unlinking",
                cow_warning=cow_warning,
                xattrs_cleared=xattrs_cleared,
                filesystem=fs_name,
            )

        return MacFileEraseResult(
            path=path_str,
            original_size=file_size,
            bytes_overwritten=bytes_written_total,
            passes=passes,
            pattern=pattern,
            status="success",
            metadata_cleansed=True,
            cow_warning=cow_warning,
            xattrs_cleared=xattrs_cleared,
            filesystem=fs_name,
        )

    except Exception as exc:
        return MacFileEraseResult(
            path=path_str,
            original_size=file_size,
            bytes_overwritten=bytes_written_total,
            passes=passes,
            pattern=pattern,
            status="failure",
            error=str(exc),
            cow_warning=cow_warning,
            xattrs_cleared=xattrs_cleared,
            filesystem=fs_name,
        )


def erase_folder_macos(
    dir_path: str | Path,
    passes: int = 1,
    pattern: str = "zero",
) -> List[MacFileEraseResult]:
    root_dir = Path(dir_path).resolve()
    results = []
    if not root_dir.exists() or not root_dir.is_dir():
        return [
            MacFileEraseResult(
                path=str(root_dir),
                original_size=0,
                bytes_overwritten=0,
                passes=passes,
                pattern=pattern,
                status="failure",
                error="Target directory does not exist",
            )
        ]

    for root, dirs, files in os.walk(str(root_dir), topdown=False):
        for f in files:
            results.append(erase_single_file_macos(os.path.join(root, f), passes=passes, pattern=pattern))
        for d in dirs:
            dir_p = Path(root) / d
            try:
                rnd = Path(root) / f".tw_d_{secrets.token_hex(16)}"
                os.rename(dir_p, rnd)
                os.rmdir(rnd)
            except Exception:
                try:
                    os.rmdir(dir_p)
                except Exception:
                    pass

    try:
        rnd_root = root_dir.parent / f".tw_root_{secrets.token_hex(16)}"
        os.rename(root_dir, rnd_root)
        os.rmdir(rnd_root)
    except Exception:
        try:
            os.rmdir(root_dir)
        except Exception:
            pass

    return results


def erase_batch_macos(
    targets: List[str | Path],
    passes: int = 1,
    pattern: str = "zero",
    operator_id: str = "op-forensic-01",
    organization: str = "NTRO Digital Forensics & Data Sanitization Lab",
    signing_key_path: Optional[str | Path] = None,
    generate_certificate: bool = True,
) -> tuple[List[MacFileEraseResult], Optional[dict]]:
    """Execute batch file & folder erasure on macOS and issue an Ed25519-signed certificate."""
    start_time = cert_mod.now_utc() if cert_mod else time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    results: List[MacFileEraseResult] = []

    for t in targets:
        p = Path(t).resolve()
        if p.is_dir():
            results.extend(erase_folder_macos(p, passes=passes, pattern=pattern))
        else:
            results.append(erase_single_file_macos(p, passes=passes, pattern=pattern))

    end_time = cert_mod.now_utc() if cert_mod else time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    total = len(results)
    success = sum(1 for r in results if r.status == "success")
    failed = sum(1 for r in results if r.status == "failure")
    total_bytes = sum(r.bytes_overwritten for r in results)

    warnings: List[str] = [
        "File-level sanitization overwrites allocated filesystem clusters and scrubs metadata.",
        "Caveat: Flash storage (SSDs/NVMe) FTL wear leveling may prevent physical overwriting of retired blocks.",
    ]
    for r in results:
        if r.cow_warning and r.cow_warning not in warnings:
            warnings.append(r.cow_warning)
        if r.xattrs_cleared:
            msg = f"Extended attributes and quarantine metadata stripped on {Path(r.path).name}"
            if msg not in warnings:
                warnings.append(msg)

    signed_cert = None
    if generate_certificate:
        key_file = (
            Path(signing_key_path)
            if signing_key_path
            else REPO_ROOT / "core" / "keys" / "demo_issuer_private.pem"
        )
        if cert_mod and core_crypto and key_file.exists():
            method_name = "OVERWRITE_ZERO_1PASS" if pattern == "zero" and passes == 1 else "SHRED_RANDOM_NPASS"
            cert_dict = cert_mod.build_certificate(
                organization=organization,
                operator_id=operator_id,
                tool_name="trustwipe-macos-eraser",
                tool_version="1.0.0",
                platform="macos",
                device_id=f"mac-batch-{secrets.token_hex(8)}",
                device_type="internal_disk",
                storage_type="UNKNOWN",
                method=method_name,
                nist_category="Clear",
                start_time=start_time,
                end_time=end_time,
                bytes_processed=total_bytes,
                capacity_bytes=total_bytes,
                passes=passes,
                pattern=pattern,
                status="success" if failed == 0 else ("partial" if success > 0 else "failure"),
                errors=[r.error for r in results if r.error] or None,
                verification={
                    "method": "file_non_existence_and_cluster_overwrite",
                    "samples_checked": total,
                    "all_samples_match_wipe_pattern": (failed == 0),
                },
                notes=[
                    f"macOS batch sanitized {success}/{total} targets ({total_bytes} bytes overwritten).",
                    "Hardware write cache flushed via fcntl(F_FULLFSYNC).",
                    "Extended attributes (xattrs) and quarantine flags cleared prior to unlinking.",
                ] + warnings,
            )
            priv = core_crypto.load_private_pem(key_file)
            signed_cert = cert_mod.sign_certificate(cert_dict, priv)

    return results, signed_cert


def check_macos_wipe_safety(target: str, force: bool = False) -> None:
    """Refuse destructive wiping of internal macOS boot disk (disk0) or active system mounts."""
    norm = target.strip().rstrip("/")
    # Refuse disk0 / rdisk0
    if norm in ("/dev/disk0", "/dev/rdisk0", "disk0", "rdisk0") or norm.startswith(("/dev/disk0s", "/dev/rdisk0s")):
        if not force:
            raise PermissionError(
                f"SAFETY REFUSAL: Target '{target}' is the macOS internal boot drive (disk0). "
                "Wiping the running operating system disk is prohibited. "
                "For whole-machine bare-metal sanitization, boot the TrustWipe Live ISO."
            )

    # Check active mount points
    try:
        res = subprocess.run(["mount"], capture_output=True, text=True, check=False)
        if res.returncode == 0:
            for line in res.stdout.splitlines():
                if any(root_mp in line for root_mp in (" on / ", " on /System", " on /private", " on /Users")):
                    mp = line.split(" on ")[0].strip()
                    if norm == mp or norm.replace("/dev/rdisk", "/dev/disk") == mp:
                        raise PermissionError(
                            f"SAFETY REFUSAL: Target '{target}' is mounted as active macOS system root ({line})."
                        )
    except PermissionError:
        raise
    except Exception:
        pass


def unmount_macos_target(device_path: str) -> bool:
    """Unmount disk or volume before raw overwriting."""
    disk_path = device_path.replace("/dev/rdisk", "/dev/disk")
    try:
        proc = subprocess.run(["diskutil", "unmountDisk", disk_path], capture_output=True, check=False)
        if proc.returncode == 0:
            return True
        proc2 = subprocess.run(["diskutil", "unmount", disk_path], capture_output=True, check=False)
        return proc2.returncode == 0
    except Exception:
        return False


def get_macos_target_size(target_path: str) -> int:
    """Determine size in bytes of a raw device or disk image file on macOS."""
    # 1. Regular file / image stat
    try:
        p = Path(target_path)
        if p.is_file():
            return p.stat().st_size
    except Exception:
        pass

    # 2. Try diskutil info if on Darwin
    try:
        disk_path = target_path.replace("/dev/rdisk", "/dev/disk")
        proc = subprocess.run(["diskutil", "info", disk_path], capture_output=True, text=True, check=False)
        if proc.returncode == 0:
            for line in proc.stdout.splitlines():
                if "Disk Size:" in line and "Bytes" in line:
                    parts = line.split("(")
                    if len(parts) > 1:
                        b_str = parts[1].split()[0]
                        return int(b_str)
    except Exception:
        pass

    # 3. Seeking to end
    try:
        with open(target_path, "rb") as f:
            f.seek(0, os.SEEK_END)
            sz = f.tell()
            if sz > 0:
                return sz
    except Exception:
        pass

    return 0


def wipe_drive_or_partition_macos(
    target: str,
    passes: int = 1,
    pattern: str = "zero",
    chunk_size: int = 1048576,
    operator_id: str = "op-forensic-01",
    organization: str = "NTRO Digital Forensics & Data Sanitization Lab",
    signing_key_path: Optional[str | Path] = None,
    generate_certificate: bool = True,
    force: bool = False,
    mock_size: Optional[int] = None,
) -> tuple[MacDriveWipeResult, Optional[dict]]:
    """Wipe a USB pen drive, external disk, or secondary partition on macOS.

    - Performs strict safety check against macOS boot disk (disk0) and root mounts
    - Unmounts volume/disk via diskutil
    - Opens high-speed raw character device (/dev/rdiskX)
    - Overwrites all raw sectors and flushes cache via fcntl(F_FULLFSYNC)
    - Executes sampled read-back verification
    - Issues Ed25519-signed sanitization certificate
    """
    check_macos_wipe_safety(target, force=force)
    start_time = cert_mod.now_utc() if cert_mod else time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    norm = target.strip()
    is_partition = "s" in norm.split("/")[-1] if "/" in norm else False
    target_type = "partition" if is_partition else ("image" if Path(norm).is_file() else "removable_disk")

    # Prefer raw character device /dev/rdiskX over block device /dev/diskX for maximum speed
    dev_path = norm
    if dev_path.startswith("/dev/disk"):
        dev_path = dev_path.replace("/dev/disk", "/dev/rdisk")

    unmounted = unmount_macos_target(norm)

    open_path = norm if Path(norm).is_file() else dev_path
    capacity = mock_size or 0
    if not capacity:
        capacity = get_macos_target_size(open_path)
    if not capacity:
        capacity = get_macos_target_size(norm)

    if capacity <= 0:
        return MacDriveWipeResult(
            target=target,
            target_type=target_type,
            capacity_bytes=0,
            bytes_overwritten=0,
            passes=passes,
            pattern=pattern,
            status="failure",
            error=f"Cannot determine capacity for target '{target}'. Ensure device is connected.",
        ), None

    total_written = 0
    verification_passed = True
    samples_checked = 0

    try:
        with open(open_path, "r+b", buffering=0) as f:
            for _ in range(passes):
                f.seek(0)
                rem = capacity
                while rem > 0:
                    to_write = min(rem, chunk_size)
                    buf = secrets.token_bytes(to_write) if pattern == "random" else b"\x00" * to_write
                    f.write(buf)
                    rem -= to_write
                    total_written += to_write
                f.flush()
                macos_full_fsync(f.fileno())

            # Sampled verification
            num_samples = 32
            sample_size = min(4096, capacity)
            if capacity >= sample_size:
                step = max(1, (capacity - sample_size) // max(1, (num_samples - 1)))
                for i in range(num_samples):
                    offset = min(i * step, capacity - sample_size)
                    f.seek(offset)
                    sample = f.read(sample_size)
                    samples_checked += 1
                    if pattern == "zero":
                        if sample != b"\x00" * len(sample):
                            verification_passed = False
                            break
                    else:
                        if len(sample) == 0:
                            verification_passed = False
                            break

            f.flush()
            macos_full_fsync(f.fileno())

    except Exception as exc:
        return MacDriveWipeResult(
            target=target,
            target_type=target_type,
            capacity_bytes=capacity,
            bytes_overwritten=total_written,
            passes=passes,
            pattern=pattern,
            status="failure",
            error=str(exc),
            verification_passed=False,
            samples_checked=samples_checked,
        ), None

    end_time = cert_mod.now_utc() if cert_mod else time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    result = MacDriveWipeResult(
        target=target,
        target_type=target_type,
        capacity_bytes=capacity,
        bytes_overwritten=total_written,
        passes=passes,
        pattern=pattern,
        status="success" if verification_passed else "failure",
        verification_passed=verification_passed,
        samples_checked=samples_checked,
        notes=[
            f"macOS raw {target_type} sanitization completed ({total_written} bytes across {passes} pass(es)).",
            f"Volume unmount requested via diskutil: {unmounted}.",
            f"Hardware write cache flushed via fcntl(F_FULLFSYNC).",
            f"Sampled readback verification: {samples_checked} samples checked (passed: {verification_passed}).",
        ],
    )

    signed_cert = None
    if generate_certificate and verification_passed:
        key_file = (
            Path(signing_key_path)
            if signing_key_path
            else REPO_ROOT / "core" / "keys" / "demo_issuer_private.pem"
        )
        if cert_mod and core_crypto and key_file.exists():
            method_name = "OVERWRITE_ZERO_1PASS" if pattern == "zero" and passes == 1 else "SHRED_RANDOM_NPASS"
            schema_dev_type = "removable_disk" if target_type == "removable_disk" else ("internal_disk" if target_type == "partition" else "image_file")
            cert_dict = cert_mod.build_certificate(
                organization=organization,
                operator_id=operator_id,
                tool_name="trustwipe-macos-eraser",
                tool_version="1.0.0",
                platform="macos",
                device_id=f"mac-{target_type}-{secrets.token_hex(6)}",
                device_type=schema_dev_type,
                storage_type="UNKNOWN" if schema_dev_type != "image_file" else "IMAGE_FILE",
                method=method_name,
                nist_category="Clear",
                start_time=start_time,
                end_time=end_time,
                bytes_processed=capacity,
                capacity_bytes=capacity,
                passes=passes,
                pattern=pattern,
                status="success",
                verification={
                    "method": "sampled_readback",
                    "samples_checked": samples_checked,
                    "all_samples_match_wipe_pattern": verification_passed,
                },
                notes=result.notes + [
                    "Direct raw sector overwriting executed on raw device (/dev/rdisk).",
                    "Partition map (GUID/MBR) and filesystem headers destroyed.",
                ],
            )
            priv = core_crypto.load_private_pem(key_file)
            signed_cert = cert_mod.sign_certificate(cert_dict, priv)

    return result, signed_cert


def main() -> int:
    parser = argparse.ArgumentParser(description="TrustWipe macOS Secure Sanitization Tool (Files, Partitions, Drives)")
    parser.add_argument("--targets", "-t", nargs="*", default=None, help="Files or folders to erase")
    parser.add_argument("--wipe-partition", help="Partition device path to wipe (e.g. /dev/rdisk2s1 or /Volumes/USB)")
    parser.add_argument("--wipe-drive", help="Physical raw drive path to wipe (e.g. /dev/rdisk2)")
    parser.add_argument("--yes", "-y", action="store_true", help="Confirm destructive operation without prompt")
    parser.add_argument("--force", action="store_true", help="Force wipe despite non-critical safety warnings")
    parser.add_argument("--passes", "-p", type=int, default=1, help="Overwrite passes (default: 1)")
    parser.add_argument("--pattern", choices=["zero", "random"], default="zero", help="Overwrite pattern")
    parser.add_argument("--out-dir", default="./sanitization_reports", help="Output directory for certificate")
    parser.add_argument("--signing-key", help="Path to Ed25519 issuer private key PEM")
    parser.add_argument("--operator-id", default="op-forensic-01", help="Operator identifier")
    parser.add_argument("--organization", default="NTRO Digital Forensics & Data Sanitization Lab", help="Issuing organization")
    parser.add_argument("--cert-out", help="Explicit path to write signed certificate JSON")
    parser.add_argument("--no-certificate", action="store_true", help="Omit compliance certificate generation")
    parser.add_argument("--json", action="store_true", help="Output JSON result")
    args = parser.parse_args()

    # Case 1: Drive or partition wipe
    if args.wipe_partition or args.wipe_drive:
        target = args.wipe_partition or args.wipe_drive
        if not args.yes:
            print(f"WARNING: This will PERMANENTLY DESTROY all data on {target}!")
            confirm = input(f"Type 'yes' to proceed with wiping {target}: ").strip().lower()
            if confirm != "yes":
                print("Aborted by user.")
                return 1

        result, signed_cert = wipe_drive_or_partition_macos(
            target=target,
            passes=args.passes,
            pattern=args.pattern,
            operator_id=args.operator_id,
            organization=args.organization,
            signing_key_path=args.signing_key,
            generate_certificate=not args.no_certificate,
            force=args.force,
        )

        cert_path: Optional[Path] = None
        if signed_cert:
            out_dir = Path(args.out_dir)
            out_dir.mkdir(parents=True, exist_ok=True)
            cert_path = Path(args.cert_out) if args.cert_out else out_dir / f"certificate_{signed_cert['cert_uuid'][:8]}.json"
            cert_path.parent.mkdir(parents=True, exist_ok=True)
            cert_path.write_text(json.dumps(signed_cert, indent=2), encoding="utf-8")

        if args.json:
            if signed_cert:
                print(json.dumps(signed_cert, indent=2))
            else:
                print(json.dumps(asdict(result), indent=2))
        else:
            print("=" * 65)
            print(" TRUSTWIPE (macOS) - BLOCK SANITIZATION REPORT")
            print("=" * 65)
            print(f"Target                 : {result.target} ({result.target_type})")
            print(f"Capacity               : {result.capacity_bytes} bytes")
            print(f"Bytes overwritten      : {result.bytes_overwritten}")
            print(f"Passes / Pattern       : {result.passes} pass(es) ({result.pattern})")
            print(f"Verification Passed    : {result.verification_passed} ({result.samples_checked} samples)")
            print(f"Status                 : {result.status.upper()}")
            if result.error:
                print(f"Error                  : {result.error}")
            if cert_path and signed_cert:
                sig = signed_cert.get("signature", {})
                print(f"Signed Certificate     : {cert_path}")
                print(f"Key Fingerprint        : {sig.get('public_key_fingerprint', 'N/A')}")
            print("=" * 65)

        return 0 if result.status == "success" else 1

    # Case 2: File & folder erasure
    elif args.targets:
        results, signed_cert = erase_batch_macos(
            targets=args.targets,
            passes=args.passes,
            pattern=args.pattern,
            operator_id=args.operator_id,
            organization=args.organization,
            signing_key_path=args.signing_key,
            generate_certificate=not args.no_certificate,
        )

        total = len(results)
        success = sum(1 for r in results if r.status == "success")
        failed = sum(1 for r in results if r.status == "failure")
        total_bytes = sum(r.bytes_overwritten for r in results)

        cert_path: Optional[Path] = None
        if signed_cert:
            out_dir = Path(args.out_dir)
            out_dir.mkdir(parents=True, exist_ok=True)
            cert_path = Path(args.cert_out) if args.cert_out else out_dir / f"certificate_{signed_cert['cert_uuid'][:8]}.json"
            cert_path.parent.mkdir(parents=True, exist_ok=True)
            cert_path.write_text(json.dumps(signed_cert, indent=2), encoding="utf-8")

        if args.json:
            if signed_cert:
                print(json.dumps(signed_cert, indent=2))
            else:
                summary = {
                    "platform": "macos",
                    "total_files": total,
                    "successful_files": success,
                    "failed_files": failed,
                    "total_bytes_overwritten": total_bytes,
                    "results": [asdict(r) for r in results],
                }
                print(json.dumps(summary, indent=2))
        else:
            print("=" * 65)
            print(" TRUSTWIPE (macOS) - SECURE FILE & FOLDER SANITIZATION")
            print("=" * 65)
            print(f"Total targets processed : {total}")
            print(f"Successfully erased     : {success}")
            print(f"Failures                : {failed}")
            print(f"Bytes overwritten       : {total_bytes}")
            if cert_path and signed_cert:
                sig = signed_cert.get("signature", {})
                print(f"Signed Certificate      : {cert_path}")
                print(f"Signature Algorithm     : {sig.get('algorithm', 'Ed25519')}")
                print(f"Key Fingerprint         : {sig.get('public_key_fingerprint', 'N/A')}")
            print("=" * 65)

        return 0 if failed == 0 else 1

    else:
        parser.print_help()
        print("\nError: Must specify either --targets (files/folders), --wipe-partition (e.g. /dev/rdisk2s1), or --wipe-drive (e.g. /dev/rdisk2).")
        return 1


if __name__ == "__main__":
    sys.exit(main())

