"""Structure-Based ext4 Filesystem Recovery Engine."""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


EXT4_SUPERBLOCK_OFFSET = 1024
EXT4_MAGIC = 0xEF53
EXT4_EXTENT_HEADER_MAGIC = 0xF30A


@dataclass
class Ext4Superblock:
    inodes_count: int
    blocks_count: int
    blocks_per_group: int
    inodes_per_group: int
    inode_size: int
    block_size: int
    magic: int


@dataclass
class Ext4RecoveredInode:
    inode_num: int
    mode: int
    size_bytes: int
    deletion_time: int
    extent_block_ranges: List[tuple[int, int]] = field(default_factory=list)  # (start_block, count)
    data: Optional[bytes] = None


def parse_ext4_superblock(
    image_path: str | Path,
    partition_offset: int = 0,
) -> Optional[Ext4Superblock]:
    """Parse ext4 superblock from a disk image at partition_offset + 1024."""
    try:
        with open(image_path, "rb") as f:
            f.seek(partition_offset + EXT4_SUPERBLOCK_OFFSET)
            sb_data = f.read(1024)
            if len(sb_data) < 1024:
                return None

            magic = struct.unpack_from("<H", sb_data, 56)[0]
            if magic != EXT4_MAGIC:
                return None

            inodes_count = struct.unpack_from("<I", sb_data, 0)[0]
            blocks_count = struct.unpack_from("<I", sb_data, 4)[0]
            log_block_size = struct.unpack_from("<I", sb_data, 24)[0]
            block_size = 1024 << log_block_size
            blocks_per_group = struct.unpack_from("<I", sb_data, 32)[0]
            inodes_per_group = struct.unpack_from("<I", sb_data, 40)[0]
            inode_size = struct.unpack_from("<H", sb_data, 88)[0] or 128

            return Ext4Superblock(
                inodes_count=inodes_count,
                blocks_count=blocks_count,
                blocks_per_group=blocks_per_group,
                inodes_per_group=inodes_per_group,
                inode_size=inode_size,
                block_size=block_size,
                magic=magic,
            )
    except Exception:
        return None


def parse_extent_header(i_block_bytes: bytes) -> List[tuple[int, int]]:
    """Parse ext4 60-byte extent header and extent entries."""
    if len(i_block_bytes) < 12:
        return []
    eh_magic, eh_entries, eh_max, eh_depth, _ = struct.unpack_from("<HHHHH", i_block_bytes, 0)
    if eh_magic != EXT4_EXTENT_HEADER_MAGIC:
        return []

    extents = []
    if eh_depth == 0:
        # Leaf node
        offset = 12
        for _ in range(eh_entries):
            if offset + 12 > len(i_block_bytes):
                break
            ee_block, ee_len, ee_start_hi, ee_start_lo = struct.unpack_from("<IHHI", i_block_bytes, offset)
            start_block = (ee_start_hi << 32) | ee_start_lo
            extents.append((start_block, ee_len))
            offset += 12
    return extents


def scan_ext4_deleted_inodes(
    image_path: str | Path,
    max_inodes: int = 500,
    partition_offset: int = 0,
) -> List[Ext4RecoveredInode]:
    """Scan ext4 image structure for genuinely deleted inode structures and extent trees."""
    sb = parse_ext4_superblock(image_path, partition_offset=partition_offset)
    if not sb:
        return []

    recovered = []
    try:
        with open(image_path, "rb") as f:
            # Number of block groups
            num_groups = (sb.blocks_count + sb.blocks_per_group - 1) // sb.blocks_per_group

            # Block group descriptor table starts at block 1 (for 1KB blocks) or block 1 (for >=2KB)
            desc_table_block = 2 if sb.block_size == 1024 else 1

            desc_size = 32  # 32 bytes for standard ext4 32-bit desc
            for group_idx in range(min(num_groups, 16)):
                f.seek(partition_offset + desc_table_block * sb.block_size + group_idx * desc_size)
                desc_data = f.read(desc_size)
                if len(desc_data) < desc_size:
                    break

                inode_table_block = struct.unpack_from("<I", desc_data, 8)[0]
                inode_table_offset = partition_offset + inode_table_block * sb.block_size

                # Scan inodes in this group
                for inode_idx in range(min(sb.inodes_per_group, max_inodes)):
                    global_inode_num = group_idx * sb.inodes_per_group + inode_idx + 1

                    # Reserved ext4 inodes 1-10 are system structures (inode 8 is journal)
                    # User files are strictly allocated with inode numbers >= 11
                    if global_inode_num < 11:
                        continue

                    f.seek(inode_table_offset + inode_idx * sb.inode_size)
                    raw_inode = f.read(sb.inode_size)
                    if len(raw_inode) < 128:
                        break

                    mode = struct.unpack_from("<H", raw_inode, 0)[0]
                    size_lo = struct.unpack_from("<I", raw_inode, 4)[0]
                    dtime = struct.unpack_from("<I", raw_inode, 20)[0]
                    links_count = struct.unpack_from("<H", raw_inode, 26)[0]

                    # Regular file check ((mode & 0xF000) == 0x8000)
                    is_regular = (mode & 0xF000) == 0x8000

                    # In ext4, deleted files have dtime > 0 and links_count == 0
                    if is_regular and dtime > 0 and links_count == 0 and size_lo > 0:
                        i_block = raw_inode[40:100]
                        extents = parse_extent_header(i_block)
                        if extents:
                            data_chunks = []
                            for (start_block, count) in extents:
                                f.seek(partition_offset + start_block * sb.block_size)
                                chunk = f.read(count * sb.block_size)
                                data_chunks.append(chunk)
                            inode_data = b"".join(data_chunks)[:size_lo] if data_chunks else None
                            recovered.append(
                                Ext4RecoveredInode(
                                    inode_num=global_inode_num,
                                    mode=mode,
                                    size_bytes=size_lo,
                                    deletion_time=dtime,
                                    extent_block_ranges=extents,
                                    data=inode_data,
                                )
                            )
    except Exception:
        pass
    return recovered
