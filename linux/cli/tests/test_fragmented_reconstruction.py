"""Tests for TrustWipe Fragmented File Reconstruction Engine.

Covers:
1. NTFS multi-run non-resident cluster reconstruction.
2. ext4 multi-extent inode reconstruction.
3. Bifragment / cluster-gap heuristic stream reassembly.
"""

import io
import struct
from pathlib import Path

import pytest
from trustwipe_cli.carver.ext4_carver import (
    EXT4_EXTENT_HEADER_MAGIC,
    EXT4_MAGIC,
    parse_extent_header,
    scan_ext4_deleted_inodes,
)
from trustwipe_cli.carver.fragmentation import (
    reassemble_cluster_runs,
    reconstruct_bifragment_stream,
)
from trustwipe_cli.carver.ntfs_carver import (
    ATTR_DATA,
    ATTR_END_MARKER,
    MFT_RECORD_MAGIC,
    parse_mft_record_bytes,
)


def test_ntfs_multi_fragment_runlist_reconstruction(tmp_path: Path):
    """Test reconstructing an NTFS file fragmented across 3 separate cluster runs."""
    cluster_size = 4096
    disk_data = bytearray(64 * cluster_size)

    # 3 fragments across clusters:
    # Run 1: Cluster 5, length 1 cluster (4096 B) -> part1
    # Run 2: Cluster 12 (delta +7), length 1 cluster (4096 B) -> part2
    # Run 3: Cluster 9 (delta -3), length 1 cluster (100 B used) -> part3
    part1 = b"FRAGMENT_PART_1_" * (4096 // 16)
    part2 = b"FRAGMENT_PART_2_" * (4096 // 16)
    part3 = b"FRAGMENT_PART_3_REMAINDER_DATA_100_BYTES"
    expected_full = part1 + part2 + part3

    disk_data[5 * cluster_size : 5 * cluster_size + len(part1)] = part1
    disk_data[12 * cluster_size : 12 * cluster_size + len(part2)] = part2
    disk_data[9 * cluster_size : 9 * cluster_size + len(part3)] = part3

    img_file = tmp_path / "ntfs_fragmented.raw"
    img_file.write_bytes(disk_data)

    # Build MFT record with multi-run non-resident DATA attribute
    rec = bytearray(1024)
    rec[0:4] = MFT_RECORD_MAGIC
    struct.pack_into("<H", rec, 0x14, 56)   # First attribute offset
    struct.pack_into("<H", rec, 0x16, 0x00) # Unallocated / deleted
    struct.pack_into("<I", rec, 0x2C, 101)  # Record number

    attr_off = 56
    # Non-resident DATA attribute
    struct.pack_into("<I", rec, attr_off + 0, ATTR_DATA)
    attr_len = 88
    struct.pack_into("<I", rec, attr_off + 4, attr_len)
    rec[attr_off + 8] = 1   # Non-resident
    rec[attr_off + 9] = 0   # Name length
    struct.pack_into("<H", rec, attr_off + 32, 64)  # Runlist offset
    struct.pack_into("<Q", rec, attr_off + 48, len(expected_full))  # Real size

    # Runlist encoding:
    # Run 1: len=1 (1 byte), lcn=5 (1 byte signed) -> 0x11, 0x01, 0x05
    # Run 2: len=1 (1 byte), delta=+7 (1 byte signed) -> 0x11, 0x01, 0x07
    # Run 3: len=1 (1 byte), delta=-3 (1 byte signed = 0xFD) -> 0x11, 0x01, 0xFD
    # End marker: 0x00
    runlist_bytes = bytes([
        0x11, 0x01, 0x05,
        0x11, 0x01, 0x07,
        0x11, 0x01, 0xFD,
        0x00,
    ])
    rec[attr_off + 64 : attr_off + 64 + len(runlist_bytes)] = runlist_bytes
    struct.pack_into("<I", rec, attr_off + attr_len, ATTR_END_MARKER)

    with open(img_file, "rb") as f:
        parsed = parse_mft_record_bytes(bytes(rec), disk_file=f, cluster_size=cluster_size)

    assert parsed is not None
    assert parsed.is_deleted is True
    assert parsed.fragment_count == 3
    assert len(parsed.runs) == 3
    assert parsed.data == expected_full


def test_ext4_multi_extent_reconstruction(tmp_path: Path):
    """Test reconstructing an ext4 deleted inode with multiple extent fragments."""
    block_size = 1024
    blocks_count = 128
    img = bytearray(blocks_count * block_size)

    # Superblock
    sb_off = 1024
    struct.pack_into("<I", img, sb_off + 0, 32)
    struct.pack_into("<I", img, sb_off + 4, blocks_count)
    struct.pack_into("<I", img, sb_off + 20, 1)
    struct.pack_into("<I", img, sb_off + 24, 0)
    struct.pack_into("<I", img, sb_off + 32, 128)
    struct.pack_into("<I", img, sb_off + 40, 32)
    struct.pack_into("<H", img, sb_off + 56, 0xEF53)
    struct.pack_into("<H", img, sb_off + 88, 256)

    # Inode table at block 5
    struct.pack_into("<I", img, 2 * block_size + 8, 5)
    it_start = 5 * block_size

    # Inode 15 (Deleted file fragmented across 2 separate extents):
    # Extent 1: Block 20, count 1 (1024 B)
    # Extent 2: Block 35, count 1 (256 B)
    part1 = b"A" * 1024
    part2 = b"B" * 256
    expected = part1 + part2

    img[20 * block_size : 20 * block_size + len(part1)] = part1
    img[35 * block_size : 35 * block_size + len(part2)] = part2

    ino15_off = it_start + (15 - 1) * 256
    struct.pack_into("<H", img, ino15_off + 0, 0x81A4)
    struct.pack_into("<I", img, ino15_off + 4, len(expected))
    struct.pack_into("<I", img, ino15_off + 20, 1700000000)  # dtime > 0
    struct.pack_into("<H", img, ino15_off + 26, 0)           # links == 0
    struct.pack_into("<I", img, ino15_off + 32, 0x00080000)  # EXTENTS_FL

    # Extent header in i_block (offset 40)
    i_block_off = ino15_off + 40
    struct.pack_into("<H", img, i_block_off + 0, EXT4_EXTENT_HEADER_MAGIC)
    struct.pack_into("<H", img, i_block_off + 2, 2)  # 2 entries (fragmented!)
    struct.pack_into("<H", img, i_block_off + 4, 4)  # max entries
    struct.pack_into("<H", img, i_block_off + 6, 0)  # depth = 0 (leaf)

    # Entry 1: block 0, count 1, start 20
    struct.pack_into("<I", img, i_block_off + 12 + 0, 0)
    struct.pack_into("<H", img, i_block_off + 12 + 4, 1)
    struct.pack_into("<H", img, i_block_off + 12 + 6, 0)
    struct.pack_into("<I", img, i_block_off + 12 + 8, 20)

    # Entry 2: block 1, count 1, start 35
    struct.pack_into("<I", img, i_block_off + 24 + 0, 1)
    struct.pack_into("<H", img, i_block_off + 24 + 4, 1)
    struct.pack_into("<H", img, i_block_off + 24 + 6, 0)
    struct.pack_into("<I", img, i_block_off + 24 + 8, 35)

    img_path = tmp_path / "ext4_fragmented.raw"
    img_path.write_bytes(img)

    recovered = scan_ext4_deleted_inodes(img_path)
    assert len(recovered) == 1
    ino = recovered[0]
    assert ino.inode_num == 15
    assert ino.fragment_count == 2
    assert len(ino.extent_block_ranges) == 2
    assert ino.data == expected


def test_bifragment_heuristic_reconstruction(tmp_path: Path):
    """Test heuristic bifragment reconstruction across a cluster gap."""
    head = b"%PDF-1.4\n1 0 obj\n<< /Title (Sensitive Document) >>\nstream\n" + b"A" * 1024
    footer = b"%%EOF"
    tail = b"endstream\nendobj\nxref\n0 2\ntrailer\n<<>>\nstartxref\n1234\n" + footer

    # Disk layout:
    # 0 .. len(head) : Head fragment
    # Gap: 8192 bytes of unrelated overwritten data
    # Continuation: Tail fragment containing footer
    gap = b"\x00" * 8192
    disk = bytearray(head + gap + tail + b"\x00" * 4096)

    img_path = tmp_path / "bifragment.raw"
    img_path.write_bytes(disk)

    with open(img_path, "rb") as f:
        reconstructed = reconstruct_bifragment_stream(
            head_data=head,
            disk_file=f,
            search_start_offset=len(head),
            footer_pattern=footer,
            max_search_bytes=32 * 1024,
        )

    assert reconstructed is not None
    assert reconstructed.is_fragmented is True
    assert len(reconstructed.fragments) == 2
    assert footer in reconstructed.data
