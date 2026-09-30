"""Unit tests for s0 Structure-Based ext4 Carving Engine."""

import hashlib
import struct
from pathlib import Path

import pytest
from s0.carve import (
    carve_image,
    detect_filesystem,
    parse_ext4_superblock,
    scan_ext4_deleted_inodes,
)
from s0.certificate import verify_certificate
from s0.crypto import load_public_pem


def build_synthetic_ext4_image(image_path: Path, payload: bytes) -> None:
    """Build minimal valid ext4 image with superblock, BGD, and deleted inode."""
    block_size = 1024
    blocks_count = 128
    blocks_per_group = 128
    inodes_per_group = 32
    inode_size = 256

    img = bytearray(blocks_count * block_size)

    # 1. Superblock at offset 1024 (block 1)
    sb_off = 1024
    struct.pack_into("<I", img, sb_off + 0, 32)
    struct.pack_into("<I", img, sb_off + 4, blocks_count)
    struct.pack_into("<I", img, sb_off + 20, 1)
    struct.pack_into("<I", img, sb_off + 24, 0)  # 1024 B
    struct.pack_into("<I", img, sb_off + 32, blocks_per_group)
    struct.pack_into("<I", img, sb_off + 40, inodes_per_group)
    struct.pack_into("<H", img, sb_off + 56, 0xEF53)
    struct.pack_into("<H", img, sb_off + 88, inode_size)

    # 2. Block Group Descriptor at block 2 (offset 2048)
    bgd_off = 2 * block_size
    inode_table_block = 5
    struct.pack_into("<I", img, bgd_off + 8, inode_table_block)

    # 3. Payload at block 12 (offset 12 * 1024)
    payload_block = 12
    img[payload_block * block_size : payload_block * block_size + len(payload)] = payload

    # 4. Inode Table at block 5 (offset 5 * 1024)
    # Inode 12 (index 11)
    inode_idx = 11
    in_off = inode_table_block * block_size + inode_idx * inode_size
    struct.pack_into("<H", img, in_off + 0, 0x81A4)  # regular file
    struct.pack_into("<I", img, in_off + 4, len(payload))  # i_size_lo
    struct.pack_into("<I", img, in_off + 20, 1690000000)  # dtime > 0 (deleted)
    struct.pack_into("<I", img, in_off + 32, 0x00080000)  # EXT4_EXTENTS_FL

    # Extent tree header
    struct.pack_into("<H", img, in_off + 40 + 0, 0xF30A)
    struct.pack_into("<H", img, in_off + 40 + 2, 1)
    struct.pack_into("<H", img, in_off + 40 + 4, 4)
    struct.pack_into("<H", img, in_off + 40 + 6, 0)

    # Extent record
    struct.pack_into("<I", img, in_off + 52 + 0, 0)
    struct.pack_into("<H", img, in_off + 52 + 4, (len(payload) + block_size - 1) // block_size)
    struct.pack_into("<H", img, in_off + 52 + 6, 0)
    struct.pack_into("<I", img, in_off + 52 + 8, payload_block)

    image_path.write_bytes(img)


def test_ext4_superblock_detection(tmp_path: Path):
    img_file = tmp_path / "ext4_test.raw"
    payload = b"%PDF-1.4\n1 0 obj\n<< /Title (Test) >>\nendobj\n%%EOF"
    build_synthetic_ext4_image(img_file, payload)

    fs = detect_filesystem(img_file)
    assert fs == "ext4"

    sb = parse_ext4_superblock(img_file)
    assert sb is not None
    assert sb.magic == 0xEF53
    assert sb.block_size == 1024
    assert sb.inode_size == 256


def test_ext4_deleted_inode_carving(tmp_path: Path):
    img_file = tmp_path / "ext4_test.raw"
    payload = b"%PDF-1.4\n1 0 obj\n<< /Title (Forensic Ext4 Recovery) >>\nendobj\nstream\nExt4 Evidence Payload\nendstream\n%%EOF"
    build_synthetic_ext4_image(img_file, payload)

    inodes = scan_ext4_deleted_inodes(img_file)
    assert len(inodes) == 1
    assert inodes[0].inode_num == 12
    assert inodes[0].data == payload
    assert inodes[0].size_bytes == len(payload)

    out_dir = tmp_path / "recovered"
    summary = carve_image(img_file, out_dir, min_confidence=60)

    assert summary.source_filesystem == "ext4"
    assert summary.files_recovered >= 1

    recovered_files = list(out_dir.glob("carved_*_ext4_*"))
    assert len(recovered_files) == 1
    rec_bytes = recovered_files[0].read_bytes()
    assert rec_bytes == payload
    assert hashlib.sha256(rec_bytes).hexdigest() == hashlib.sha256(payload).hexdigest()

    # Verify manifest certificate
    assert summary.manifest_certificate is not None
    assert summary.manifest_certificate["wipe"]["method"] == "FORENSIC_CARVING"
    assert summary.manifest_certificate["wipe"]["nist_category"] == "N/A"

    repo_root = Path(__file__).resolve().parents[3]
    pub_key_path = repo_root / "src" / "s0" / "data" / "keys" / "demo_issuer_public.pem"
    if pub_key_path.exists():
        pub = load_public_pem(pub_key_path)
        ok, reason = verify_certificate(summary.manifest_certificate, [pub])
        assert ok, f"Manifest verification failed: {reason}"
