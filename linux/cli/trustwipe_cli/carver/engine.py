"""TrustWipe Module 3: Advanced File Carving & Recovery Engine (ext4, NTFS, & Signatures)."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, List, Optional

from trustwipe_core import certificate as cert_mod
from trustwipe_core import crypto as core_crypto

from .ext4_carver import parse_ext4_superblock, scan_ext4_deleted_inodes
from .fat_carver import parse_fat32_boot_sector, scan_fat32_deleted_files
from .ntfs_carver import parse_ntfs_boot_sector, scan_ntfs_deleted_files
from .scoring import calculate_shannon_entropy, score_carved_candidate
from .signatures import SIGNATURES, FileSignature, get_signature_by_ext


@dataclass
class CarvedFile:
    file_id: str
    filename: str
    extension: str
    category: str
    offset: int
    size_bytes: int
    sha256: str
    confidence_score: int
    heuristics: List[str] = field(default_factory=list)
    recovered_path: Optional[str] = None
    recovery_method: str = "signature"  # "signature", "ntfs_mft", "ext4_inode"


@dataclass
class CarvingSessionSummary:
    target_path: str
    source_filesystem: str  # "ntfs", "ext4", "raw"
    total_bytes_scanned: int
    total_candidates_found: int
    files_recovered: int
    carved_files: List[CarvedFile] = field(default_factory=list)
    manifest_certificate: Optional[dict] = None
    warnings: List[str] = field(default_factory=list)


def _probe_fs_at_offset(f, offset: int) -> Optional[str]:
    """Probe for NTFS, ext4, or FAT32 superblock at given byte offset."""
    try:
        f.seek(offset)
        header = f.read(2048)
        if len(header) >= 512 and header[3:11] == b"NTFS    ":
            return "ntfs"
        if len(header) >= 1082:
            import struct
            magic_ext4 = struct.unpack_from("<H", header, 1024 + 56)[0]
            if magic_ext4 == 0xEF53:
                return "ext4"
        if len(header) >= 512:
            import struct
            magic_boot = struct.unpack_from("<H", header, 510)[0]
            if magic_boot == 0xAA55 and (header[82:87] == b"FAT32" or header[54:57] == b"FAT"):
                return "fat32"
    except Exception:
        pass
    return None


def detect_partitions(target_path: str | Path) -> list[tuple[str, int]]:
    """Detect partitions and underlying filesystems on media (bare FS or MBR/GPT whole-disk)."""
    results: list[tuple[str, int]] = []
    try:
        with open(target_path, "rb") as f:
            # 1. Probe at offset 0 (bare filesystem image or superfloppy)
            fs_at_0 = _probe_fs_at_offset(f, 0)
            if fs_at_0:
                return [(fs_at_0, 0)]

            # 2. Check for MBR partition table (offset 0, magic 0x55AA at 510)
            f.seek(0)
            sector0 = f.read(512)
            has_gpt = False
            if len(sector0) == 512 and sector0[510:512] == b"\x55\xaa":
                import struct
                for i in range(4):
                    entry_off = 446 + i * 16
                    ptype = sector0[entry_off + 4]
                    if ptype == 0xEE:
                        has_gpt = True
                    start_lba = struct.unpack_from("<I", sector0, entry_off + 8)[0]
                    sectors = struct.unpack_from("<I", sector0, entry_off + 12)[0]
                    if ptype != 0 and ptype != 0xEE and start_lba > 0 and sectors > 0:
                        part_byte_off = start_lba * 512
                        fs = _probe_fs_at_offset(f, part_byte_off)
                        if fs:
                            results.append((fs, part_byte_off))

            # 3. Check for GPT partition table if protective MBR detected or sector 1 has EFI PART
            if has_gpt or not results:
                f.seek(512)
                gpt_hdr = f.read(512)
                if len(gpt_hdr) >= 92 and gpt_hdr[:8] == b"EFI PART":
                    import struct
                    part_lba = struct.unpack_from("<Q", gpt_hdr, 72)[0]
                    num_parts = struct.unpack_from("<I", gpt_hdr, 80)[0]
                    part_size = struct.unpack_from("<I", gpt_hdr, 84)[0]
                    if 0 < num_parts <= 128 and 128 <= part_size <= 512:
                        f.seek(part_lba * 512)
                        for _ in range(num_parts):
                            pentry = f.read(part_size)
                            if len(pentry) < part_size:
                                break
                            if pentry[:16] == bytes(16):
                                continue  # unused entry
                            start_lba = struct.unpack_from("<Q", pentry, 32)[0]
                            if start_lba > 0:
                                part_byte_off = start_lba * 512
                                fs = _probe_fs_at_offset(f, part_byte_off)
                                if fs and (fs, part_byte_off) not in results:
                                    results.append((fs, part_byte_off))
    except Exception:
        pass

    if not results:
        return [("raw", 0)]
    return results


def detect_filesystem(target_path: str | Path) -> str:
    """Detect underlying filesystem from raw media headers or partition table."""
    parts = detect_partitions(target_path)
    for fs, _ in parts:
        if fs != "raw":
            return fs
    return "raw"


def carve_image(
    target_path: str | Path,
    output_dir: str | Path,
    *,
    extensions: Optional[List[str]] = None,
    min_confidence: int = 50,
    chunk_size: int = 2 * 1024 * 1024,  # 2 MiB read window
    overlap_size: int = 64 * 1024,      # 64 KiB window overlap
    operator_id: str = "op-forensic-01",
    organization: str = "NTRO Digital Forensics & Data Sanitization Lab",
    signing_key_path: Optional[str | Path] = None,
    progress_callback: Optional[Callable[[int, int, int], None]] = None,
    generate_certificate: bool = True,
) -> CarvingSessionSummary:
    """Scan raw disk image or block device with structure (NTFS/ext4/FAT32) and signature carving."""
    target_p = Path(target_path).resolve()
    out_p = Path(output_dir).resolve()
    out_p.mkdir(parents=True, exist_ok=True)

    if not target_p.exists():
        raise FileNotFoundError(f"Target media not found: {target_p}")

    total_size = target_p.stat().st_size if target_p.is_file() else 0
    detected_parts = detect_partitions(target_p)
    fs_types = [p[0] for p in detected_parts if p[0] != "raw"]
    fs_type = ", ".join(fs_types) if fs_types else "raw"

    carved_files: List[CarvedFile] = []
    scanned_bytes = 0
    candidate_count = 0
    recovered_hashes = set()

    warnings: List[str] = []

    # 1. Structure-based recovery across all detected partitions
    for part_fs, part_offset in detected_parts:
        if part_fs == "ntfs":
            try:
                ntfs_files = scan_ntfs_deleted_files(target_p, include_allocated=False, partition_offset=part_offset)
                for nf in ntfs_files:
                    if nf.data and len(nf.data) > 0:
                        ext = Path(nf.filename).suffix.lower().lstrip(".") or "bin"
                        if extensions and ext not in [e.lower().lstrip(".") for e in extensions]:
                            continue

                        candidate_count += 1
                        sig = get_signature_by_ext(ext)
                        if sig:
                            score, heuristics = score_carved_candidate(
                                sig, nf.data, has_valid_footer=(sig.footer is not None and sig.footer in nf.data)
                            )
                        else:
                            score = 75
                            heuristics = ["NTFS MFT record structure verified (+75%)"]

                        if score >= min_confidence:
                            f_hash = hashlib.sha256(nf.data).hexdigest()
                            if f_hash in recovered_hashes:
                                continue
                            file_id = f"carved_{len(carved_files)+1:05d}"
                            rec_filename = f"{file_id}_ntfs_rec{nf.record_num}_{score}pct_{nf.filename}"
                            rec_path = out_p / rec_filename
                            rec_path.write_bytes(nf.data)

                            carved_files.append(
                                CarvedFile(
                                    file_id=file_id,
                                    filename=rec_filename,
                                    extension=ext,
                                    category=sig.category if sig else "document",
                                    offset=part_offset + nf.record_num * 1024,
                                    size_bytes=len(nf.data),
                                    sha256=f_hash,
                                    confidence_score=score,
                                    heuristics=heuristics + [f"Recovered via NTFS MFT record #{nf.record_num} (partition @ {part_offset})"],
                                    recovered_path=str(rec_path),
                                    recovery_method="ntfs_mft",
                                )
                            )
                            recovered_hashes.add(f_hash)
            except Exception as e:
                warnings.append(f"NTFS structure carving warning (offset {part_offset}): {e}")

        elif part_fs == "ext4":
            try:
                ext4_inodes = scan_ext4_deleted_inodes(target_p, partition_offset=part_offset)
                for inode in ext4_inodes:
                    if inode.data and len(inode.data) > 0:
                        matched_sig = None
                        for sig in SIGNATURES:
                            if inode.data.startswith(sig.header):
                                matched_sig = sig
                                break
                        ext = matched_sig.extension if matched_sig else "bin"
                        if extensions and ext not in [e.lower().lstrip(".") for e in extensions]:
                            continue

                        candidate_count += 1
                        if matched_sig:
                            score, heuristics = score_carved_candidate(
                                matched_sig, inode.data, has_valid_footer=(matched_sig.footer is not None and matched_sig.footer in inode.data)
                            )
                        else:
                            score = 75
                            heuristics = ["ext4 inode structure verified (+75%)"]

                        if score >= min_confidence:
                            f_hash = hashlib.sha256(inode.data).hexdigest()
                            if f_hash in recovered_hashes:
                                continue
                            file_id = f"carved_{len(carved_files)+1:05d}"
                            rec_filename = f"{file_id}_ext4_inode{inode.inode_num}_{score}pct.{ext}"
                            rec_path = out_p / rec_filename
                            rec_path.write_bytes(inode.data)

                            carved_files.append(
                                CarvedFile(
                                    file_id=file_id,
                                    filename=rec_filename,
                                    extension=ext,
                                    category=matched_sig.category if matched_sig else "document",
                                    offset=part_offset + (inode.extent_block_ranges[0][0] * 1024 if inode.extent_block_ranges else 0),
                                    size_bytes=len(inode.data),
                                    sha256=f_hash,
                                    confidence_score=score,
                                    heuristics=heuristics + [f"Recovered via ext4 inode #{inode.inode_num} (partition @ {part_offset})"],
                                    recovered_path=str(rec_path),
                                    recovery_method="ext4_inode",
                                )
                            )
                            recovered_hashes.add(f_hash)
            except Exception as e:
                warnings.append(f"ext4 structure carving warning (offset {part_offset}): {e}")

        elif part_fs == "fat32":
            try:
                fat_files = scan_fat32_deleted_files(target_p, partition_offset=part_offset)
                for ff in fat_files:
                    if ff.data and len(ff.data) > 0:
                        ext = Path(ff.filename).suffix.lower().lstrip(".") or "bin"
                        if extensions and ext not in [e.lower().lstrip(".") for e in extensions]:
                            continue

                        candidate_count += 1
                        sig = get_signature_by_ext(ext)
                        if sig:
                            score, heuristics = score_carved_candidate(
                                sig, ff.data, has_valid_footer=(sig.footer is not None and sig.footer in ff.data)
                            )
                        else:
                            score = 75
                            heuristics = ["FAT32 directory entry structure verified (+75%)"]

                        if score >= min_confidence:
                            f_hash = hashlib.sha256(ff.data).hexdigest()
                            if f_hash in recovered_hashes:
                                continue
                            file_id = f"carved_{len(carved_files)+1:05d}"
                            rec_filename = f"{file_id}_fat32_clus{ff.first_cluster}_{score}pct_{ff.filename}"
                            rec_path = out_p / rec_filename
                            rec_path.write_bytes(ff.data)

                            carved_files.append(
                                CarvedFile(
                                    file_id=file_id,
                                    filename=rec_filename,
                                    extension=ext,
                                    category=sig.category if sig else "document",
                                    offset=part_offset + ff.first_cluster * 4096,
                                    size_bytes=len(ff.data),
                                    sha256=f_hash,
                                    confidence_score=score,
                                    heuristics=heuristics + [f"Recovered via FAT32 cluster #{ff.first_cluster} (partition @ {part_offset})"],
                                    recovered_path=str(rec_path),
                                    recovery_method="fat32_directory",
                                )
                            )
                            recovered_hashes.add(f_hash)
            except Exception as e:
                warnings.append(f"FAT32 structure carving warning (offset {part_offset}): {e}")

    # 4. Raw Stream Signature-based Carving
    active_signatures = SIGNATURES
    if extensions:
        norm_exts = [e.lower().lstrip(".") for e in extensions]
        active_signatures = [s for s in SIGNATURES if s.extension in norm_exts]

    with open(str(target_p), "rb") as f:
        buffer_offset = 0
        carry = b""

        while True:
            chunk = f.read(chunk_size)
            if not chunk and not carry:
                break

            data = carry + chunk
            current_chunk_len = len(chunk)
            scanned_bytes += current_chunk_len

            # Search for each active signature
            for sig in active_signatures:
                pos = 0
                while True:
                    idx = data.find(sig.header, pos)
                    if idx == -1:
                        break

                    global_offset = buffer_offset + idx
                    candidate_count += 1

                    # Look for matching footer within max_size
                    carved_data = None
                    has_footer = False

                    if sig.footer:
                        footer_search_len = min(len(data) - idx, sig.max_size)
                        sub_slice = data[idx : idx + footer_search_len]
                        f_idx = sub_slice.find(sig.footer, len(sig.header))

                        if f_idx != -1:
                            end_pos = f_idx + len(sig.footer)
                            candidate_bytes = sub_slice[:end_pos]
                            if len(candidate_bytes) >= sig.min_size:
                                carved_data = candidate_bytes
                                has_footer = True
                    else:
                        end_pos = min(len(data) - idx, sig.max_size)
                        candidate_bytes = data[idx : idx + end_pos]
                        if len(candidate_bytes) >= sig.min_size:
                            carved_data = candidate_bytes

                    if carved_data:
                        file_hash = hashlib.sha256(carved_data).hexdigest()
                        if file_hash not in recovered_hashes:
                            score, heuristics = score_carved_candidate(
                                sig, carved_data, has_valid_footer=has_footer
                            )

                            if score >= min_confidence:
                                file_id = f"carved_{len(carved_files)+1:05d}"
                                filename = f"{file_id}_{global_offset:08x}_{score}pct.{sig.extension}"
                                rec_path = out_p / filename

                                rec_path.write_bytes(carved_data)

                                carved_file = CarvedFile(
                                    file_id=file_id,
                                    filename=filename,
                                    extension=sig.extension,
                                    category=sig.category,
                                    offset=global_offset,
                                    size_bytes=len(carved_data),
                                    sha256=file_hash,
                                    confidence_score=score,
                                    heuristics=heuristics,
                                    recovered_path=str(rec_path),
                                    recovery_method="signature",
                                )
                                carved_files.append(carved_file)
                                recovered_hashes.add(file_hash)

                                pos = idx + max(len(sig.header), len(carved_data))
                                continue

                    pos = idx + 1

            if progress_callback and total_size > 0:
                progress_callback(scanned_bytes, total_size, len(carved_files))

            if len(data) > overlap_size:
                carry = data[-overlap_size:]
                buffer_offset += len(data) - overlap_size
            else:
                carry = b""
                buffer_offset += len(data)

    # 3. Generate Ed25519 signed recovery manifest certificate
    manifest_cert = None
    if not generate_certificate:
        warnings.append("Forensic recovery manifest certificate omitted per operator request (--no-certificate).")
    else:
        key_file = (
            Path(signing_key_path)
            if signing_key_path
            else Path(__file__).resolve().parents[4] / "core" / "keys" / "demo_issuer_private.pem"
        )

        if key_file.exists():
            try:
                total_rec_bytes = sum(c.size_bytes for c in carved_files)
                now_iso = cert_mod.now_utc()
                cert_dict = cert_mod.build_certificate(
                    organization=organization,
                    operator_id=operator_id,
                    tool_name="trustwipe-carver",
                    tool_version="1.0.0",
                    platform="linux",
                    device_id=f"media-{hashlib.sha256(str(target_p).encode()).hexdigest()[:16]}",
                    device_type="image_file",
                    storage_type="IMAGE_FILE",
                    method="FORENSIC_CARVING",
                    nist_category="N/A",
                    pattern="carving",
                    start_time=now_iso,
                    end_time=now_iso,
                    bytes_processed=scanned_bytes,
                    capacity_bytes=total_size or scanned_bytes,
                    status="success",
                    verification={
                        "method": "forensic_signature_and_structure_carving",
                        "samples_checked": len(carved_files),
                    },
                    notes=[
                        f"Forensic Carving Session: Scanned {scanned_bytes} bytes on {target_p.name}.",
                        f"Source Filesystem: {fs_type.upper()}.",
                        f"Recovered {len(carved_files)} files ({total_rec_bytes} bytes total).",
                        f"Candidate matches evaluated: {candidate_count}.",
                    ],
                )
                priv = core_crypto.load_private_pem(key_file)
                manifest_cert = cert_mod.sign_certificate(cert_dict, priv)
            except Exception as e:
                warnings.append(f"Manifest signing failed: {e}")
                manifest_cert = None
        else:
            warnings.append(
                f"WARNING: Signing key not found at '{key_file}'. "
                "No forensic recovery manifest certificate was generated."
            )

    # Write recovery_index.json for forensic logging and audit indexing
    index_data = {
        "target_path": str(target_p),
        "source_filesystem": fs_type,
        "total_bytes_scanned": scanned_bytes,
        "files_recovered": len(carved_files),
        "recovered_files": [
            {
                "file_id": c.file_id,
                "filename": c.filename,
                "extension": c.extension,
                "category": c.category,
                "offset": c.offset,
                "size_bytes": c.size_bytes,
                "sha256": c.sha256,
                "confidence_score": c.confidence_score,
                "recovery_method": c.recovery_method,
            }
            for c in carved_files
        ],
        "warnings": warnings,
    }
    try:
        (out_p / "recovery_index.json").write_text(json.dumps(index_data, indent=2))
    except Exception:
        pass

    return CarvingSessionSummary(
        target_path=str(target_p),
        source_filesystem=fs_type,
        total_bytes_scanned=scanned_bytes,
        total_candidates_found=candidate_count,
        files_recovered=len(carved_files),
        carved_files=carved_files,
        manifest_certificate=manifest_cert,
        warnings=warnings,
    )
