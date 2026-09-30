"""Unit tests for s0 Structure-Based NTFS Carving Engine."""

import hashlib
import struct
from pathlib import Path

import pytest
from s0_cli.carver import boundary
from s0_cli.carver import (
    carve_image,
    detect_filesystem,
    parse_ntfs_boot_sector,
    scan_ntfs_deleted_files,
)
from s0_core.certificate import verify_certificate
from s0_core.crypto import load_public_pem


def build_synthetic_mft_record(
    record_num: int,
    filename: str,
    data_payload: bytes,
    is_allocated: bool = False,
    is_resident: bool = True,
    cluster_offset: int = 10,
    cluster_size: int = 4096,
) -> bytes:
    """Construct a minimal valid NTFS MFT record with $FILE_NAME and $DATA."""
    rec = bytearray(1024)
    rec[0:4] = b"FILE"
    struct.pack_into("<H", rec, 0x0C, 1)   # sequence number
    struct.pack_into("<H", rec, 0x14, 56)  # offset to the first attribute
    flags = 1 if is_allocated else 0      # 0 = unallocated / deleted
    struct.pack_into("<H", rec, 0x16, flags)
    struct.pack_into("<I", rec, 0x2C, record_num)

    attr_offset = 56

    # 1. $FILE_NAME (0x30, Resident)
    fn_bytes = filename.encode("utf-16le")
    fn_name_len = len(filename)
    fn_val_len = 0x42 + len(fn_bytes)
    fn_attr_len = (24 + fn_val_len + 7) & ~7

    struct.pack_into("<I", rec, attr_offset, 0x30)
    struct.pack_into("<I", rec, attr_offset + 4, fn_attr_len)
    rec[attr_offset + 8] = 0  # Resident
    rec[attr_offset + 9] = 0
    struct.pack_into("<H", rec, attr_offset + 10, 0)
    struct.pack_into("<I", rec, attr_offset + 16, fn_val_len)
    struct.pack_into("<H", rec, attr_offset + 20, 24)

    fn_val_start = attr_offset + 24
    struct.pack_into("<Q", rec, fn_val_start + 0x30, len(data_payload))
    rec[fn_val_start + 0x40] = fn_name_len
    rec[fn_val_start + 0x41] = 3  # Win32+DOS
    rec[fn_val_start + 0x42 : fn_val_start + 0x42 + len(fn_bytes)] = fn_bytes
    attr_offset += fn_attr_len

    # 2. $DATA (0x80)
    if is_resident:
        data_val_len = len(data_payload)
        data_attr_len = (24 + data_val_len + 7) & ~7
        struct.pack_into("<I", rec, attr_offset, 0x80)
        struct.pack_into("<I", rec, attr_offset + 4, data_attr_len)
        rec[attr_offset + 8] = 0
        struct.pack_into("<I", rec, attr_offset + 16, data_val_len)
        struct.pack_into("<H", rec, attr_offset + 20, 24)
        rec[attr_offset + 24 : attr_offset + 24 + data_val_len] = data_payload
        attr_offset += data_attr_len
    else:
        # Non-resident single data run
        runlist = bytes([0x11, 0x01, cluster_offset, 0x00])
        nonres_hdr_len = 64
        data_attr_len = (nonres_hdr_len + len(runlist) + 7) & ~7
        struct.pack_into("<I", rec, attr_offset, 0x80)
        struct.pack_into("<I", rec, attr_offset + 4, data_attr_len)
        rec[attr_offset + 8] = 1  # Non-resident
        struct.pack_into("<Q", rec, attr_offset + 16, 0)
        struct.pack_into("<Q", rec, attr_offset + 24, 0)
        struct.pack_into("<H", rec, attr_offset + 32, nonres_hdr_len)
        struct.pack_into("<Q", rec, attr_offset + 40, cluster_size)
        struct.pack_into("<Q", rec, attr_offset + 48, len(data_payload))
        rec[attr_offset + nonres_hdr_len : attr_offset + nonres_hdr_len + len(runlist)] = runlist
        attr_offset += data_attr_len

    # End Marker
    struct.pack_into("<I", rec, attr_offset, 0xFFFFFFFF)
    struct.pack_into("<I", rec, 0x18, attr_offset + 4)
    struct.pack_into("<I", rec, 0x1C, 1024)
    # Seal a real update sequence array. Without it the last two bytes of every
    # sector hold whatever the attribute data happened to be, and a parser that
    # does not undo the fixup reads a corrupt run list or filename. Records built
    # without one only ever parsed because the fixup was being ignored.
    seq = 1
    usa_off = 48
    struct.pack_into("<H", rec, 0x04, usa_off)
    struct.pack_into("<H", rec, 0x06, 3)          # two sectors, plus the USN slot
    struct.pack_into("<H", rec, usa_off, seq)
    for i in range(1, 3):
        struct.pack_into("<H", rec, usa_off + i * 2, 0)
        struct.pack_into("<H", rec, i * 512 - 2, seq)
    # Everything the placeholders displaced was zero, so the saved slots stay 0.
    for i in range(1, 3):
        struct.pack_into("<H", rec, usa_off + i * 2, 0)
    return bytes(rec)


def create_synthetic_ntfs_image(
    image_path: Path,
    resident_files: list[tuple[str, bytes]],
    nonresident_files: list[tuple[str, bytes, int]],
    total_size_mb: int = 2,
) -> None:
    """Create a minimal synthetic NTFS disk image for testing."""
    cluster_size = 4096
    mft_cluster = 4
    mft_offset = mft_cluster * cluster_size

    data = bytearray(total_size_mb * 1024 * 1024)

    # 1. Boot Sector (Offset 0)
    data[0:3] = bytes([0xEB, 0x52, 0x90])
    data[3:11] = b"NTFS    "
    struct.pack_into("<H", data, 0x0B, 512)
    data[0x0D] = 8  # 8 sectors/cluster = 4096 B
    struct.pack_into("<Q", data, 0x28, total_size_mb * 2048)
    struct.pack_into("<q", data, 0x30, mft_cluster)
    data[0x40] = 0xF6  # -10 -> 1024 B MFT record
    data[510:512] = bytes([0x55, 0xAA])

    # 2. Plant MFT System Records 0..15
    for i in range(16):
        sys_rec = bytearray(1024)
        sys_rec[0:4] = b"FILE"
        struct.pack_into("<H", sys_rec, 0x16, 1)  # allocated
        struct.pack_into("<I", sys_rec, 0x2C, i)
        data[mft_offset + i * 1024 : mft_offset + (i + 1) * 1024] = sys_rec

    rec_num = 16

    # 3. Plant Resident Deleted Files
    for fn, payload in resident_files:
        rec_bytes = build_synthetic_mft_record(
            record_num=rec_num,
            filename=fn,
            data_payload=payload,
            is_allocated=False,
            is_resident=True,
        )
        data[mft_offset + rec_num * 1024 : mft_offset + (rec_num + 1) * 1024] = rec_bytes
        rec_num += 1

    # 4. Plant Non-Resident Deleted Files
    for fn, payload, clus_offset in nonresident_files:
        rec_bytes = build_synthetic_mft_record(
            record_num=rec_num,
            filename=fn,
            data_payload=payload,
            is_allocated=False,
            is_resident=False,
            cluster_offset=clus_offset,
        )
        data[mft_offset + rec_num * 1024 : mft_offset + (rec_num + 1) * 1024] = rec_bytes
        # Write payload at data cluster
        byte_pos = clus_offset * cluster_size
        data[byte_pos : byte_pos + len(payload)] = payload
        rec_num += 1

    image_path.write_bytes(data)


def test_ntfs_boot_sector_detection(tmp_path):
    img = tmp_path / "test_boot.ntfs"
    create_synthetic_ntfs_image(img, [], [])

    assert detect_filesystem(img) == "ntfs"
    boot = parse_ntfs_boot_sector(img)
    assert boot is not None
    assert boot.oem_id == "NTFS"
    assert boot.bytes_per_sector == 512
    assert boot.cluster_size == 4096
    assert boot.mft_start_cluster == 4
    assert boot.mft_record_size == 1024


def test_ntfs_resident_and_nonresident_carving(tmp_path):
    img = tmp_path / "ntfs_evidence.raw"
    out_dir = tmp_path / "carved_ntfs_output"

    pdf_payload = b"%PDF-1.4\n1 0 obj\n<< /Title (TOP SECRET EVIDENCE) >>\nendobj\nstream\nCONFIDENTIAL EVIDENCE\nendstream\n%%EOF"
    jpg_payload = bytes([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10]) + b"JFIF" + bytes([0x00, 0x01]) + (b"AA" * 200) + bytes([0xFF, 0xD9])

    resident_files = [("classified_intel.pdf", pdf_payload)]
    nonresident_files = [("intercept_photo.jpg", jpg_payload, 25)]

    create_synthetic_ntfs_image(img, resident_files, nonresident_files)

    # 1. Structure Carving directly via scan_ntfs_deleted_files
    recovered = scan_ntfs_deleted_files(img, include_allocated=False)
    assert len(recovered) == 2

    pdf_rec = next(r for r in recovered if r.filename == "classified_intel.pdf")
    assert pdf_rec.is_resident is True
    assert pdf_rec.data == pdf_payload
    assert pdf_rec.is_deleted is True

    jpg_rec = next(r for r in recovered if r.filename == "intercept_photo.jpg")
    assert jpg_rec.is_resident is False
    assert jpg_rec.data == jpg_payload
    assert jpg_rec.is_deleted is True

    # 2. Full Engine Carve & Manifest Certificate Verification
    summary = carve_image(
        img,
        out_dir,
        min_confidence=60,
        operator_id="op-ntfs",
        organization="Forensic Lab",
    )

    assert summary.source_filesystem == "ntfs"
    assert summary.files_recovered >= 2

    # Filesystem metadata gives the exact length, so the boundary is resolved
    # by the strongest available method and the original name comes back.
    pdf_item = next(c for c in summary.carved_files if c.extension == "pdf")
    assert pdf_item.sha256 == hashlib.sha256(pdf_payload).hexdigest()
    assert pdf_item.recovery_method == "ntfs_mft"
    assert pdf_item.boundary_method == boundary.DECLARED_SIZE
    assert pdf_item.original_name
    assert pdf_item.confidence_score >= 70

    jpg_item = next(c for c in summary.carved_files if c.extension == "jpg")
    assert jpg_item.sha256 == hashlib.sha256(jpg_payload).hexdigest()
    assert jpg_item.recovery_method == "ntfs_mft"
    assert jpg_item.original_name.endswith(".jpg")
    assert jpg_item.confidence_score >= 70

    # Verify Signed Recovery Manifest Certificate
    assert summary.manifest_certificate is not None
    demo_pub_key = Path(__file__).resolve().parents[3] / "core" / "keys" / "demo_issuer_public.pem"
    pub = load_public_pem(demo_pub_key)
    ok, reason = verify_certificate(summary.manifest_certificate, [pub])
    assert ok is True
    assert "valid Ed25519 signature" in reason
