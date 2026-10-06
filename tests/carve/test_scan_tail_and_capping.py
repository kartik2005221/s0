"""Tests for scan loop tail scanning (H4), ext4/FAT32 DoS bounds (M3),
diagnostic note capping (S0-10), and manifest recovery counter accuracy (S0-12).
"""

from __future__ import annotations

import struct

import pytest

from s0.carve.allocation import build_free_space
from s0.carve.engine import carve_image
from s0.carve.ext4_carver import parse_ext4_superblock
from s0.pdfgen import qr_module_count


def test_trailing_window_scanned_when_size_is_multiple_of_chunk(tmp_path):
    """Regression test for H4: trailing carry scanned when image size % chunk == 0."""
    # Create an 8 MiB file (exact power of 2, multiple of default 4 MiB or 8 MiB chunk)
    img_size = 8 * 1024 * 1024
    img_file = tmp_path / "tail_test.raw"
    data = bytearray(img_size)

    # Place a valid minimal PDF 2048 bytes before EOF
    pdf_content = (
        b"%PDF-1.4\n"
        b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        b"3 0 obj<</Type/Page/MediaBox[0 0 612 792]>>endobj\n"
        b"xref\n0 4\n"
        b"0000000000 65535 f \n"
        b"0000000009 00000 n \n"
        b"0000000052 00000 n \n"
        b"0000000102 00000 n \n"
        b"trailer<</Size 4/Root 1 0 R>>\n"
        b"startxref\n150\n%%EOF\n"
    )
    insert_pos = img_size - 2048
    data[insert_pos : insert_pos + len(pdf_content)] = pdf_content
    img_file.write_bytes(bytes(data))

    out_dir = tmp_path / "out"
    result = carve_image(img_file, output_dir=out_dir)

    assert result.files_recovered >= 1, "Expected at least 1 recovered file from EOF carry window"
    pdf_files = list(out_dir.glob("*.pdf"))
    assert len(pdf_files) >= 1, "PDF placed near EOF in chunk-multiple image was not recovered"


def test_ext4_log_block_size_out_of_bounds_returns_none(tmp_path):
    """Regression test for M3: parse_ext4_superblock rejects log_block_size > 6."""
    img_file = tmp_path / "ext4_bad_logbs.img"
    data = bytearray(4096)
    # Magic at offset 1024 + 56
    struct.pack_into("<H", data, 1024 + 56, 0xEF53)
    # log_block_size at offset 1024 + 24 set to 7 (invalid: block_size would be 128KB, spec max is 6)
    struct.pack_into("<I", data, 1024 + 24, 7)
    img_file.write_bytes(bytes(data))

    sb = parse_ext4_superblock(img_file)
    assert sb is None, "ext4 superblock with log_block_size > 6 must return None"


def test_ext4_huge_blocks_count_caps_notes(tmp_path):
    """Regression test for S0-10: ext4 diagnostic notes capped at MAX_NOTES."""
    img_file = tmp_path / "ext4_huge_blocks.img"
    data = bytearray(8192)
    # Magic at offset 1024 + 56
    struct.pack_into("<H", data, 1024 + 56, 0xEF53)
    # blocks_count = 0xFFFFFFFF
    struct.pack_into("<I", data, 1024 + 4, 0xFFFFFFFF)
    # blocks_per_group = 8192
    struct.pack_into("<I", data, 1024 + 32, 8192)
    # log_block_size = 2 (4096 bytes)
    struct.pack_into("<I", data, 1024 + 24, 2)
    img_file.write_bytes(bytes(data))

    fsm = build_free_space(str(img_file), "ext4", 0, len(data))
    assert len(fsm.notes) <= 52, f"Diagnostic notes exceeded expected cap: {len(fsm.notes)}"


def test_qr_module_count_short_circuits_on_huge_payload():
    """Regression test for S0-10: qr_module_count raises ValueError immediately for payload > 2953 bytes."""
    huge_data = "A" * 10000
    with pytest.raises(ValueError, match="exceeds QR version 40 capacity"):
        qr_module_count(huge_data)
