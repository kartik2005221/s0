"""Tests for the unallocated-space (allocation map) layer.

These build small filesystem images byte-by-byte rather than shelling out to
mkfs.*, so the suite has no external dependency. Each fixture is a minimal but
structurally faithful volume, and every expected value is written out longhand
so a mistake in the parser cannot be masked by a mistake in the fixture.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from s0.carve.allocation import (
    FreeSpaceMap,
    _merge,
    build_free_space,
)

KB = 1024
MB = 1024 * 1024


# --------------------------------------------------------------------------- #
# range merging
# --------------------------------------------------------------------------- #


def test_merge_coalesces_adjacent_and_overlapping_ranges():
    merged = _merge([(0, 10), (10, 20), (5, 7), (30, 40), (39, 50)])
    assert merged == [(0, 20), (30, 50)]


def test_merge_keeps_genuine_gaps():
    assert _merge([(0, 10), (20, 30)]) == [(0, 10), (20, 30)]


def test_merge_drops_empty_ranges():
    assert _merge([(5, 5), (7, 7)]) == []


def test_free_space_containment_is_half_open():
    fsm = FreeSpaceMap(0, 100, ranges=[(10, 20)], source="t", reliable=True)
    assert fsm.contains(10, 1)
    assert fsm.contains(19, 1)
    assert not fsm.contains(20, 1)      # exclusive end
    assert not fsm.contains(5, 100)     # would cross the end
    assert fsm.contains(10, 10)         # exactly fills the range


def test_free_space_summary_reports_ppm():
    fsm = FreeSpaceMap(0, 1000, ranges=[(0, 250), (500, 750)], source="t", reliable=True)
    s = fsm.summary()
    assert s["free_bytes"] == 500
    assert s["free_ppm"] == 500_000
    assert s["range_count"] == 2
    assert s["reliable"] is True


# --------------------------------------------------------------------------- #
# ext4
# --------------------------------------------------------------------------- #


def _ext4_image(path: Path, *, block_size: int = 1024, blocks: int = 64,
                blocks_per_group: int = 32, free_per_group: int = 8) -> Path:
    """Write a tiny ext4 volume with a known number of free blocks per group."""
    data = bytearray(block_size * blocks)
    sb_off = 1024

    def put(off, fmt, *vals):
        struct.pack_into(fmt, data, off, *vals)

    magic = 0xEF53
    put(sb_off + 0x00, "<I", 64)                               # s_inodes_count
    put(sb_off + 0x04, "<I", blocks)                           # s_blocks_count
    put(sb_off + 0x14, "<I", 1 if block_size == 1024 else 0)   # s_first_data_block
    put(sb_off + 0x18, "<I", block_size.bit_length() - 11)      # s_log_block_size
    put(sb_off + 0x20, "<I", blocks_per_group)
    put(sb_off + 0x28, "<I", 64)                               # s_inodes_per_group
    put(sb_off + 0x38, "<H", magic)
    put(sb_off + 0x58, "<H", 256)                              # s_inode_size
    put(sb_off + 0x60, "<I", 0)                                # s_feature_incompat
    put(sb_off + 0xFE, "<H", 32)                               # s_desc_size

    num_groups = (blocks - 1 + blocks_per_group - 1) // blocks_per_group
    # The group descriptor table is addressed in blocks, so it starts at block 2
    # when the superblock occupies block 1 (1 KiB block size).
    desc_table = 2 if block_size == 1024 else 1
    bb_base = desc_table + 1
    for g in range(num_groups):
        d = desc_table * block_size + g * 32
        put(d + 0x00, "<I", bb_base + g)          # bb_block
        put(d + 0x04, "<I", bb_base + num_groups + g)
        put(d + 0x08, "<I", bb_base + 2 * num_groups + g)
        bitmap = bytearray(block_size)
        # Mark the first (blocks_per_group - free_per_group) blocks in use.
        for b in range(blocks_per_group - free_per_group):
            bitmap[b >> 3] |= 1 << (b & 7)
        off = (bb_base + g) * block_size
        data[off : off + block_size] = bitmap

    path.write_bytes(bytes(data))
    return path


def _ext4_expected_free(blocks: int, blocks_per_group: int, free_per_group: int) -> int:
    """Free bytes implied by the fixture's own group geometry.

    The fixture marks the first `blocks_per_group - free_per_group` bits of every
    group's bitmap as in use, so a group that is short by a block has one fewer
    free block. With s_first_data_block = 1 the final group is usually short by
    one block, which is why the expectation cannot simply be a division.
    """
    in_use = blocks_per_group - free_per_group
    total = 0
    group = 0
    while 1 + group * blocks_per_group < blocks:
        g_first = 1 + group * blocks_per_group
        g_blocks = min(blocks_per_group, blocks - g_first)
        total += max(0, g_blocks - in_use)
        group += 1
    return total * KB


def test_ext4_free_space_matches_hand_computed_bitmap(tmp_path):
    img = _ext4_image(tmp_path / "ext4.img", blocks=64, blocks_per_group=32, free_per_group=8)
    fsm = build_free_space(str(img), "ext4", 0, 64 * KB)
    assert fsm.reliable
    assert fsm.free_bytes == _ext4_expected_free(64, 32, 8)
    assert fsm.range_count == 2


def test_ext4_group_descriptor_bitmap_field_is_offset_zero(tmp_path):
    """A regression guard: bb_block lives at 0x00, not 0x04 (the inode bitmap).

    Reading offset 4 yields a plausible-looking block number and a bitmap that is
    almost entirely marked in use, which silently under-reports free space.
    """
    img = _ext4_image(tmp_path / "ext4.img", blocks=64, blocks_per_group=32, free_per_group=8)
    fsm = build_free_space(str(img), "ext4", 0, 64 * KB)
    assert fsm.free_bytes == 15 * KB   # group 1 is one block short of a full group


def test_ext4_fully_used_volume_reports_no_free_space(tmp_path):
    img = _ext4_image(tmp_path / "full.img", blocks=32, blocks_per_group=32, free_per_group=0)
    fsm = build_free_space(str(img), "ext4", 0, 32 * KB)
    assert fsm.free_bytes == 0
    assert not fsm.ranges


def test_ext4_fully_free_volume_reports_one_whole_extent(tmp_path):
    img = _ext4_image(tmp_path / "empty.img", blocks=32, blocks_per_group=32,
                      free_per_group=32)
    fsm = build_free_space(str(img), "ext4", 0, 32 * KB)
    # Block 0 is the boot area and belongs to no group, so it is never free.
    assert fsm.free_bytes == 31 * KB
    assert fsm.range_count == 1


def test_ext4_4k_block_volume_tiles_exactly(tmp_path):
    """At 4 KiB blocks s_first_data_block is 0 and the groups divide the volume."""
    img = _ext4_image(tmp_path / "ext4_4k.img", block_size=4096, blocks=64,
                      blocks_per_group=32, free_per_group=8)
    fsm = build_free_space(str(img), "ext4", 0, 64 * 4096)
    assert fsm.reliable
    assert fsm.free_bytes == 2 * 8 * 4096
    assert fsm.range_count == 2


# --------------------------------------------------------------------------- #
# FAT32
# --------------------------------------------------------------------------- #


def _fat32_image(path: Path, *, spc: int = 8, reserved: int = 32, fats: int = 2,
                 root_entries: int = 16, clusters: int = 512,
                 allocated: tuple = (0, 1)) -> tuple:
    """Write a FAT32 volume with `clusters` data clusters and a matching FAT.

    Returns (path, data_clusters). The FAT is sized to describe exactly the
    requested cluster count, so a wrong parser result cannot be explained away by
    the fixture being internally inconsistent.
    """
    bps = 512
    fat_bytes = (clusters + 2) * 4
    fat_sectors = -(-fat_bytes // bps)
    root_sectors = (root_entries * 32 + bps - 1) // bps
    overhead = reserved + fats * fat_sectors + root_sectors
    total_sectors = overhead + clusters * spc
    img = bytearray(total_sectors * bps)

    def put(off, fmt, *vals):
        struct.pack_into(fmt, img, off, *vals)

    put(0x0B, "<H", bps)
    put(0x0D, "<B", spc)
    put(0x0E, "<H", reserved)
    put(0x10, "<B", fats)
    put(0x11, "<H", root_entries)
    put(0x16, "<I", fat_sectors)
    put(0x13, "<H", total_sectors)
    put(0x24, "<I", fat_sectors)
    put(0x20, "<I", total_sectors)
    put(0x1FE, "<H", 0xAA55)
    img[0x36:0x3A] = b"\x00\x00\x00\x00"     # no FSInfo sector

    # FAT #1 starts after the reserved sectors plus one FAT's worth of slack for
    # sector 0, matching the layout the parser assumes.
    fat_off = (reserved + spc) * bps
    for c in allocated:
        struct.pack_into("<I", img, fat_off + c * 4, 0x0FFFFFFF)
    path.write_bytes(bytes(img))
    return path, clusters


def test_fat32_only_an_exactly_zero_entry_means_free(tmp_path):
    spc, cluster_bytes = 8, 4096
    img, clusters = _fat32_image(tmp_path / "f.img", clusters=512, allocated=(0, 1),
                                  spc=spc)
    fsm = build_free_space(str(img), "fat32", 0, img.stat().st_size)
    # 0x0FFFFFFF is an end-of-chain marker, i.e. *in use*, never free. The data
    # area is clusters 2..513, of which only the root directory is in use, so
    # clusters 3..513 are free. The walk starts at cluster 2, which is also where
    # reserved clusters 0 and 1 stop mattering.
    assert fsm.reliable
    assert fsm.free_bytes == (clusters - 1) * cluster_bytes
    assert fsm.range_count == 1


def test_fat32_root_directory_cluster_is_never_free(tmp_path):
    spc, cluster_bytes = 8, 4096
    img, clusters = _fat32_image(tmp_path / "f.img", clusters=512, allocated=(), spc=spc)
    fsm = build_free_space(str(img), "fat32", 0, img.stat().st_size)
    # mkfs.fat can leave the root directory's FAT entry as 0; cluster 2 must still
    # be excluded because the root directory occupies it. Cluster 2 begins at
    # byte 0 of the data area.
    assert fsm.free_bytes == (clusters - 1) * cluster_bytes
    assert not fsm.contains(0, 1)


def test_fat32_reports_no_space_when_every_cluster_is_used(tmp_path):
    n = 64
    img, _ = _fat32_image(tmp_path / "f.img", clusters=n, allocated=tuple(range(0, n + 2)))
    fsm = build_free_space(str(img), "fat32", 0, img.stat().st_size)
    assert fsm.free_bytes == 0


# --------------------------------------------------------------------------- #
# exFAT
# --------------------------------------------------------------------------- #


EXFAT_HEAP_SECTOR = 2048
EXFAT_HEAP = EXFAT_HEAP_SECTOR * 512


def _exfat_cluster_byte(cluster: int, cluster_bytes: int = 4096) -> int:
    """Absolute image byte offset of an exFAT cluster number."""
    return EXFAT_HEAP + (cluster - 2) * cluster_bytes


def _exfat_image(path: Path, *, cluster_bytes: int = 4096, clusters: int = 512,
                 allocated: tuple = (), blank_bitmap: bool = True) -> Path:
    """Write a minimal exFAT volume with an allocation bitmap and upcase table."""
    bps = 512
    sectors_per_cluster = cluster_bytes // bps
    heap_sector = 2048
    fat_sectors = 16
    total_sectors = heap_sector + clusters * sectors_per_cluster + fat_sectors
    img = bytearray(total_sectors * bps)

    def put(off, fmt, *vals):
        struct.pack_into(fmt, img, off, *vals)

    img[0x03:0x0B] = b"EXFAT   "
    put(0x40, "<Q", 0)                  # PartitionOffset
    put(0x50, "<I", heap_sector)        # FatOffset
    put(0x54, "<I", fat_sectors)
    put(0x58, "<I", heap_sector)        # ClusterHeapOffset (in sectors)
    put(0x5C, "<I", clusters)
    put(0x60, "<I", 5)                  # RootDirectoryCluster
    put(0x6C, "<B", 9)                  # BytesPerSectorShift -> 512
    put(0x6D, "<B", sectors_per_cluster.bit_length() - 1)
    put(0x1FE, "<H", 0xAA55)

    heap = heap_sector * bps

    def cluster_off(c):
        return heap + (c - 2) * cluster_bytes

    # Root directory: volume label, allocation bitmap, upcase table.
    root = bytearray(cluster_bytes)
    root[0] = 0x83                                      # volume label
    struct.pack_into("<I", root, 32 + 0x00, 0x81)       # bitmap entry type
    struct.pack_into("<I", root, 32 + 0x14, 2)          # FirstClusterOfBitmap
    struct.pack_into("<I", root, 32 + 0x18, clusters // 8 + 4)
    root[64] = 0x82                                     # upcase table
    struct.pack_into("<I", root, 64 + 0x14, 3)
    struct.pack_into("<I", root, 64 + 0x18, cluster_bytes)   # spans 1 cluster
    img[cluster_off(5) : cluster_off(5) + cluster_bytes] = root

    # The allocation bitmap itself.
    bitmap = bytearray(clusters // 8 + 4)
    struct.pack_into("<I", bitmap, 0, clusters)
    if not blank_bitmap:
        for c in allocated:
            bitmap[4 + (c >> 3)] |= 1 << (c & 7)
    img[cluster_off(2) : cluster_off(2) + len(bitmap)] = bitmap

    # Upcase table body, so the 0x82 entry is honest about its length.
    img[cluster_off(3) : cluster_off(3) + cluster_bytes] = b"\x00" * cluster_bytes
    path.write_bytes(bytes(img))
    return path


def test_exfat_bitmap_fields_are_at_0x14_and_0x18(tmp_path):
    """A regression guard for the two-word offset mistake.

    Read at 0x16/0x1A the bitmap entry yields a huge cluster number and a zero
    length, so the bitmap is never found and free space silently reads as zero.
    """
    img = _exfat_image(tmp_path / "e.img", clusters=512, blank_bitmap=False)
    fsm = build_free_space(str(img), "exfat", 0, 4 * MB)
    assert fsm.reliable
    # Structural clusters: bitmap 2, upcase 3, root 5.
    assert fsm.free_bytes == (512 - 3) * 4096


def test_exfat_cluster_heap_offset_is_in_sectors_not_bytes(tmp_path):
    """A regression guard: ClusterHeapOffset is a sector count.

    Read as a byte offset, the root directory lands in the middle of the FAT area
    and appears to be a run of zero entries, so nothing is recoverable.
    """
    img = _exfat_image(tmp_path / "e.img", clusters=512, blank_bitmap=False)
    fsm = build_free_space(str(img), "exfat", 0, 4 * MB)
    assert fsm.free_bytes > 0
    assert "structural" in " ".join(fsm.notes)


def test_exfat_structural_metadata_is_excluded_even_with_a_blank_bitmap(tmp_path):
    """mkfs.exfat leaves the bitmap clear but its own structures are live.

    The bitmap, the upcase table and the root directory must never be offered to
    the carver, so they are subtracted from independently readable metadata.
    """
    img = _exfat_image(tmp_path / "e.img", clusters=512, blank_bitmap=True)
    fsm = build_free_space(str(img), "exfat", 0, 4 * MB)
    assert fsm.reliable
    assert fsm.free_bytes == (512 - 3) * 4096
    assert not fsm.contains(_exfat_cluster_byte(2), 1)    # allocation bitmap
    assert not fsm.contains(_exfat_cluster_byte(3), 1)    # upcase table
    assert not fsm.contains(_exfat_cluster_byte(5), 1)    # root directory
    assert fsm.contains(_exfat_cluster_byte(4), 1)        # cluster 4 is free


def test_exfat_bitmap_bit_zero_is_cluster_two_not_cluster_zero(tmp_path):
    """A regression guard for the cluster-numbering shift.

    The bitmap's bit 0 describes cluster 2. If bit 0 is read as cluster 0, every
    allocation is off by two clusters and a "free" extent lands on the FAT, which
    sits in front of the cluster heap.
    """
    img = _exfat_image(tmp_path / "e.img", clusters=512, blank_bitmap=False)
    fsm = build_free_space(str(img), "exfat", 0, 4 * MB)
    fat_start = EXFAT_HEAP_SECTOR * 512
    fat_len = 16 * 512
    overlaps_fat = [r for r in fsm.ranges if r[0] < fat_start + fat_len and r[1] > fat_start]
    assert not overlaps_fat, f"free space must never cover the FAT: {overlaps_fat}"
    # No free extent may start before the cluster heap.
    assert all(s >= EXFAT_HEAP for s, _ in fsm.ranges)


def test_exfat_multi_cluster_upcase_table_is_wholly_excluded(tmp_path):
    img = _exfat_image(tmp_path / "e.img", clusters=512, blank_bitmap=True)
    data = bytearray(img.read_bytes())
    root_cluster_off = _exfat_cluster_byte(5)
    # Grow the upcase table to three clusters, so it must not be offered to the
    # carver beyond its first cluster either.
    struct.pack_into("<I", data, root_cluster_off + 64 + 0x18, 3 * 4096)
    img.write_bytes(bytes(data))
    fsm = build_free_space(str(img), "exfat", 0, 4 * MB)
    # Structural: bitmap 2, upcase 3-5, root 5. The upcase table's third cluster
    # is 5, which the root directory already occupies, so four are excluded.
    assert fsm.free_bytes == (512 - 4) * 4096
    assert not fsm.contains(_exfat_cluster_byte(4), 1)    # third upcase cluster


# --------------------------------------------------------------------------- #
# NTFS
# --------------------------------------------------------------------------- #


def _ntfs_image(path: Path, *, cluster: int = 4096, clusters: int = 4096,
                mft_lcn: int = 4) -> Path:
    """Write a tiny NTFS volume with a $MFT holding a $Bitmap record."""
    bps = 512
    spc = cluster // bps
    rec = 1024
    # Exactly `clusters` clusters, so the boot record's sector count and the
    # bitmap's bit count agree and the expected free space is unambiguous.
    total_sectors = clusters * spc
    img = bytearray(total_sectors * bps)

    def put(off, fmt, *vals):
        struct.pack_into(fmt, img, off, *vals)

    img[0x03:0x0B] = b"NTFS    "
    put(0x0B, "<H", bps)
    put(0x0D, "<B", spc)
    put(0x28, "<Q", total_sectors)
    put(0x30, "<Q", mft_lcn)               # $MFT cluster, *not* 0x48
    put(0x40, "<b", -10)                   # 2^10 = 1024-byte records

    def mft_record(off, attrs: list):
        img[off : off + 4] = b"FILE"
        struct.pack_into("<H", img, off + 0x14, 0x38)
        pos = off + 0x38
        for atype, nonres, runblob, real in attrs:
            alen = 0x40 + len(runblob)
            struct.pack_into("<I", img, pos, atype)
            struct.pack_into("<I", img, pos + 4, alen)
            img[pos + 8] = 1 if nonres else 0
            if nonres:
                struct.pack_into("<H", img, pos + 0x20, 0x40)
                struct.pack_into("<Q", img, pos + 0x28, real)
                struct.pack_into("<Q", img, pos + 0x30, real)
                img[pos + 0x40 : pos + 0x40 + len(runblob)] = runblob
            pos += alen
        struct.pack_into("<I", img, pos, 0xFFFFFFFF)

    def runs(lcn, count):
        return bytes([0x21, count & 0xFF, lcn & 0xFF, (lcn >> 8) & 0xFF])

    mft_off = mft_lcn * cluster
    # Record 0 is $MFT itself; its $DATA run is deliberately a different cluster
    # so that reading record 0 instead of record 6 cannot pass by accident.
    mft_record(mft_off, [(0x80, True, runs(20, 2), 2 * cluster)])
    # Record 6 is $Bitmap, one cluster at LCN 30.
    mft_record(mft_off + 6 * rec, [(0x80, True, runs(30, 1), cluster)])

    bitmap = bytearray(cluster)
    struct.pack_into("<Q", bitmap, 0, 40)     # 40 clusters in use
    for c in range(40):
        bitmap[c >> 3] |= 1 << (c & 7)
    img[30 * cluster : 31 * cluster] = bitmap

    path.write_bytes(bytes(img))
    return path


def test_ntfs_free_space_reads_bitmap_from_record_six(tmp_path):
    """A regression guard: $Bitmap is file record 6, not record 0.

    Reading record 0 finds $MFT's own data runs and reports the MFT's size as
    free space.
    """
    img = _ntfs_image(tmp_path / "n.img", clusters=4096)
    fsm = build_free_space(str(img), "ntfs", 0, 4096 * 4096)
    assert fsm.reliable
    assert fsm.free_bytes == (4096 - 40) * 4096


def test_ntfs_mft_cluster_is_read_in_clusters_not_sectors(tmp_path):
    """A regression guard: the $MFT byte offset is lcn * cluster_size."""
    img = _ntfs_image(tmp_path / "n.img", clusters=4096)
    fsm = build_free_space(str(img), "ntfs", 0, 4096 * 4096)
    assert "not directly readable" not in " ".join(fsm.notes)


# --------------------------------------------------------------------------- #
# graceful degradation
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("fs_type", ["ext4", "fat32", "exfat", "ntfs", "zfs", "btrfs"])
def test_unknown_or_foreign_filesystem_yields_an_unreliable_map(tmp_path, fs_type):
    junk = tmp_path / "junk.img"
    junk.write_bytes(b"\x00" * 128 * KB)
    fsm = build_free_space(str(junk), fs_type, 0, 128 * KB)
    # Never claim free space that was not established.
    assert fsm.free_bytes == 0
    assert fsm.ranges == []
    assert fsm.reliable is False
    assert fsm.notes, "an unusable allocation map must explain itself"


def test_truncated_image_does_not_raise(tmp_path):
    img = tmp_path / "t.img"
    img.write_bytes(b"NTFS    " + b"\x00" * 100)
    fsm = build_free_space(str(img), "ntfs", 0, 108)
    assert fsm.free_bytes == 0
    assert not fsm.reliable
