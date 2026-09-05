"""TrustWipe exFAT Structure-Based Carving Module.

Targeted at removable media, USB flash drives, and high-capacity SD cards (SDXC/SDUC).
Directly parses the exFAT Volume Boot Record (VBR), Cluster Heap geometry,
and directory entry sets (File 0x05/0x85, Stream Extension 0x40/0xC0, File Name 0x41/0xC1)
to recover deleted files with intact filenames, metadata, and data clusters without mounting.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

EXFAT_OEM_MAGIC = b"EXFAT   "
EXFAT_BOOT_SIGNATURE = 0xAA55

# Directory Entry Types
ENTRY_TYPE_END_OF_DIR = 0x00
ENTRY_TYPE_FILE_ACTIVE = 0x85
ENTRY_TYPE_FILE_DELETED = 0x05
ENTRY_TYPE_STREAM_ACTIVE = 0xC0
ENTRY_TYPE_STREAM_DELETED = 0x40
ENTRY_TYPE_NAME_ACTIVE = 0xC1
ENTRY_TYPE_NAME_DELETED = 0x41


@dataclass
class ExFatBootSector:
    bytes_per_sector: int
    sectors_per_cluster: int
    cluster_size: int
    cluster_heap_offset_bytes: int
    cluster_count: int
    root_dir_cluster: int
    volume_length_bytes: int
    fat_offset_bytes: int
    fat_length_bytes: int
    partition_offset: int = 0


@dataclass
class ExFatRecoveredFile:
    filename: str
    size_bytes: int
    first_cluster: int
    is_deleted: bool
    no_fat_chain: bool
    data: Optional[bytes] = None
    fragment_count: int = 1
    create_time: int = 0
    modify_time: int = 0


def parse_exfat_boot_sector(
    image_path: str | Path,
    partition_offset: int = 0,
) -> Optional[ExFatBootSector]:
    """Parse exFAT VBR boot sector at partition_offset."""
    try:
        with open(image_path, "rb") as f:
            f.seek(partition_offset)
            boot = f.read(512)
            if len(boot) < 512:
                return None

            # Verify OEM Name and Boot Signature
            if boot[3:11] != EXFAT_OEM_MAGIC:
                return None
            boot_sig = struct.unpack_from("<H", boot, 510)[0]
            if boot_sig != EXFAT_BOOT_SIGNATURE:
                return None

            # Read VBR fields
            volume_length_sec = struct.unpack_from("<Q", boot, 72)[0]
            fat_offset_sec = struct.unpack_from("<I", boot, 80)[0]
            fat_length_sec = struct.unpack_from("<I", boot, 84)[0]
            cluster_heap_offset_sec = struct.unpack_from("<I", boot, 88)[0]
            cluster_count = struct.unpack_from("<I", boot, 92)[0]
            root_dir_cluster = struct.unpack_from("<I", boot, 96)[0]

            bps_shift = boot[108]
            spc_shift = boot[109]

            # Shift validation (exFAT sectors: 512B-4KB, clusters: up to 32MB)
            if bps_shift < 9 or bps_shift > 12:
                return None
            if spc_shift > 25:
                return None

            bytes_per_sector = 1 << bps_shift
            sectors_per_cluster = 1 << spc_shift
            cluster_size = bytes_per_sector * sectors_per_cluster

            cluster_heap_offset_bytes = partition_offset + cluster_heap_offset_sec * bytes_per_sector
            fat_offset_bytes = partition_offset + fat_offset_sec * bytes_per_sector
            fat_length_bytes = fat_length_sec * bytes_per_sector
            volume_length_bytes = volume_length_sec * bytes_per_sector

            return ExFatBootSector(
                bytes_per_sector=bytes_per_sector,
                sectors_per_cluster=sectors_per_cluster,
                cluster_size=cluster_size,
                cluster_heap_offset_bytes=cluster_heap_offset_bytes,
                cluster_count=cluster_count,
                root_dir_cluster=root_dir_cluster,
                volume_length_bytes=volume_length_bytes,
                fat_offset_bytes=fat_offset_bytes,
                fat_length_bytes=fat_length_bytes,
                partition_offset=partition_offset,
            )
    except Exception:
        return None


def _read_fat_chain(
    f,
    boot: ExFatBootSector,
    start_cluster: int,
    max_clusters: int = 16384,
) -> List[int]:
    """Traverse exFAT File Allocation Table for a cluster chain."""
    chain = [start_cluster]
    curr = start_cluster
    visited = {curr}

    for _ in range(max_clusters):
        fat_entry_offset = boot.fat_offset_bytes + curr * 4
        f.seek(fat_entry_offset)
        raw = f.read(4)
        if len(raw) < 4:
            break
        next_cluster = struct.unpack("<I", raw)[0]
        # 0xFFFFFFFF = EOF, 0xFFFFFFF7 = Bad Cluster, 0 = Free Cluster
        if next_cluster >= 0xFFFFFFF8 or next_cluster < 2 or next_cluster in visited:
            break
        chain.append(next_cluster)
        visited.add(next_cluster)
        curr = next_cluster

    return chain


def _scan_directory_entries(
    f,
    boot: ExFatBootSector,
    dir_cluster: int,
    include_allocated: bool = False,
    max_scan_clusters: int = 64,
) -> List[ExFatRecoveredFile]:
    """Scan directory cluster chain for deleted and allocated file entry sets."""
    recovered: List[ExFatRecoveredFile] = []
    clusters_to_scan = [dir_cluster]

    # If FAT exists, follow chain for directory
    if boot.fat_length_bytes > 0:
        fat_chain = _read_fat_chain(f, boot, dir_cluster, max_clusters=max_scan_clusters)
        if len(fat_chain) > 1:
            clusters_to_scan = fat_chain

    for c in clusters_to_scan[:max_scan_clusters]:
        cluster_offset = boot.cluster_heap_offset_bytes + (c - 2) * boot.cluster_size
        f.seek(cluster_offset)
        cluster_data = f.read(boot.cluster_size)
        if len(cluster_data) < 32:
            continue

        idx = 0
        while idx + 32 <= len(cluster_data):
            entry_type = cluster_data[idx]

            if entry_type == ENTRY_TYPE_END_OF_DIR:
                break

            # Check for File Directory Entry (0x05 = deleted, 0x85 = active)
            is_file_entry = (entry_type & 0x7F) == 0x05
            if is_file_entry:
                is_deleted = (entry_type & 0x80) == 0
                if not is_deleted and not include_allocated:
                    idx += 32
                    continue

                sec_count = cluster_data[idx + 1]
                file_attr = struct.unpack_from("<H", cluster_data, idx + 4)[0]
                create_ts = struct.unpack_from("<I", cluster_data, idx + 8)[0]
                modify_ts = struct.unpack_from("<I", cluster_data, idx + 12)[0]

                # We need at least 2 secondary entries: Stream Extension + Name
                if sec_count < 2 or idx + 32 * (sec_count + 1) > len(cluster_data):
                    idx += 32
                    continue

                # Parse Secondary 1: Stream Extension (0x40 / 0xC0)
                stream_idx = idx + 32
                stream_type = cluster_data[stream_idx]
                if (stream_type & 0x7F) != 0x40:
                    idx += 32
                    continue

                flags = cluster_data[stream_idx + 1]
                no_fat_chain = bool(flags & 0x02)
                name_len = cluster_data[stream_idx + 3]
                first_cluster = struct.unpack_from("<I", cluster_data, stream_idx + 20)[0]
                data_length = struct.unpack_from("<Q", cluster_data, stream_idx + 24)[0]

                # Parse Secondary 2+: File Name Entries (0x41 / 0xC1)
                name_parts = []
                name_entries_count = sec_count - 1
                for n_i in range(name_entries_count):
                    n_idx = idx + 32 * (2 + n_i)
                    n_type = cluster_data[n_idx]
                    if (n_type & 0x7F) == 0x41:
                        # 15 UTF-16LE characters per name entry
                        raw_chars = cluster_data[n_idx + 2 : n_idx + 32]
                        try:
                            decoded = raw_chars.decode("utf-16le").rstrip("\x00")
                            name_parts.append(decoded)
                        except Exception:
                            pass

                full_filename = "".join(name_parts)[:name_len] if name_parts else f"exfat_file_c{first_cluster}.bin"

                # Check if this is a directory vs regular file
                is_dir = bool(file_attr & 0x10)
                if not is_dir and first_cluster >= 2 and data_length > 0:
                    # Read file data
                    file_bytes = None
                    fragment_count = 1
                    saved_pos = f.tell()
                    try:
                        # Max carve cap: 50 MiB
                        read_bytes_total = min(data_length, 50 * 1024 * 1024)

                        if no_fat_chain or is_deleted:
                            # Contiguous cluster allocation
                            data_offset = boot.cluster_heap_offset_bytes + (first_cluster - 2) * boot.cluster_size
                            f.seek(data_offset)
                            file_bytes = f.read(read_bytes_total)
                        else:
                            # Follow FAT chain for multi-cluster file
                            fat_chain = _read_fat_chain(f, boot, first_cluster)
                            fragment_count = len(fat_chain)
                            chunks = []
                            rem = read_bytes_total
                            for fc in fat_chain:
                                if rem <= 0:
                                    break
                                to_read = min(rem, boot.cluster_size)
                                f.seek(boot.cluster_heap_offset_bytes + (fc - 2) * boot.cluster_size)
                                chunks.append(f.read(to_read))
                                rem -= to_read
                            file_bytes = b"".join(chunks)
                    except Exception:
                        pass
                    finally:
                        f.seek(saved_pos)

                    if file_bytes is not None and len(file_bytes) > 0:
                        recovered.append(
                            ExFatRecoveredFile(
                                filename=full_filename,
                                size_bytes=len(file_bytes),
                                first_cluster=first_cluster,
                                is_deleted=is_deleted,
                                no_fat_chain=no_fat_chain,
                                data=file_bytes,
                                fragment_count=fragment_count,
                                create_time=create_ts,
                                modify_time=modify_ts,
                            )
                        )

                idx += 32 * (sec_count + 1)
                continue

            idx += 32

    return recovered


def scan_exfat_deleted_files(
    image_path: str | Path,
    partition_offset: int = 0,
    include_allocated: bool = False,
    max_clusters: int = 4096,
) -> List[ExFatRecoveredFile]:
    """Traverse exFAT directory structure and carve deleted files from Cluster Heap."""
    boot = parse_exfat_boot_sector(image_path, partition_offset=partition_offset)
    if not boot:
        return []

    try:
        with open(image_path, "rb") as f:
            return _scan_directory_entries(
                f,
                boot,
                dir_cluster=boot.root_dir_cluster,
                include_allocated=include_allocated,
                max_scan_clusters=max_clusters,
            )
    except Exception:
        return []
