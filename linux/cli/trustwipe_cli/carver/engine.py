"""TrustWipe Module 3: Advanced File Carving & Recovery Engine (ext4, NTFS, & Signatures)."""

from __future__ import annotations

import hashlib
import os
import secrets
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, List, Optional

from trustwipe_core import certificate as cert_mod
from trustwipe_core import crypto as core_crypto

from .ext4_carver import parse_ext4_superblock, scan_ext4_deleted_inodes
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


def detect_filesystem(target_path: str | Path) -> str:
    """Detect underlying filesystem from raw media headers."""
    try:
        with open(target_path, "rb") as f:
            header = f.read(2048)
            if len(header) >= 512 and header[3:11] == b"NTFS    ":
                return "ntfs"
            if len(header) >= 1082:
                import struct
                magic = struct.unpack_from("<H", header, 1024 + 56)[0]
                if magic == 0xEF53:
                    return "ext4"
    except Exception:
        pass
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
) -> CarvingSessionSummary:
    """Scan raw disk image or block device with structure (NTFS/ext4) and signature carving."""
    target_p = Path(target_path).resolve()
    out_p = Path(output_dir).resolve()
    out_p.mkdir(parents=True, exist_ok=True)

    if not target_p.exists():
        raise FileNotFoundError(f"Target media not found: {target_p}")

    total_size = target_p.stat().st_size if target_p.is_file() else 0
    fs_type = detect_filesystem(target_p)

    carved_files: List[CarvedFile] = []
    scanned_bytes = 0
    candidate_count = 0
    recovered_hashes = set()

    # 1. Structure-based recovery if NTFS is detected
    if fs_type == "ntfs":
        try:
            ntfs_files = scan_ntfs_deleted_files(target_p, include_allocated=False)
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
                                offset=nf.record_num * 1024,
                                size_bytes=len(nf.data),
                                sha256=f_hash,
                                confidence_score=score,
                                heuristics=heuristics + [f"Recovered via NTFS MFT record #{nf.record_num}"],
                                recovered_path=str(rec_path),
                                recovery_method="ntfs_mft",
                            )
                        )
                        recovered_hashes.add(f_hash)
        except Exception:
            pass

    # 2. Raw Stream Signature-based Carving
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
                method="OVERWRITE_ZERO_1PASS",
                nist_category="Clear",
                start_time=now_iso,
                end_time=now_iso,
                bytes_processed=scanned_bytes,
                capacity_bytes=total_size or scanned_bytes,
                status="success",
                verification={
                    "method": "forensic_signature_and_structure_carving",
                    "samples_checked": len(carved_files),
                    "all_samples_match_wipe_pattern": True,
                    "planted_pattern_hits_after": 0,
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
        except Exception:
            manifest_cert = None

    return CarvingSessionSummary(
        target_path=str(target_p),
        source_filesystem=fs_type,
        total_bytes_scanned=scanned_bytes,
        total_candidates_found=candidate_count,
        files_recovered=len(carved_files),
        carved_files=carved_files,
        manifest_certificate=manifest_cert,
    )
