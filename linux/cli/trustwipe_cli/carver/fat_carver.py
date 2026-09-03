"""Structure-Based FAT32 Filesystem Recovery Engine.

Directly parses FAT32 boot sectors (BPB) and directory entries:
  - BPB detection (OEM, sector geometry, FAT tables, root cluster)
  - Detection of deleted directory entries (marked with 0xE5 leading byte)
  - Cluster mapping and contiguous cluster data recovery
  - Extraction of deleted files from USB flash drives and SD memory cards
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


FAT32_SIGNATURE = 0xAA55


@dataclass
class Fat32BootSector:
    oem_name: str
    bytes_per_sector: int
    sectors_per_cluster: int
    cluster_size: int
    reserved_sectors: int
    fats_count: int
    sectors_per_fat: int
    root_cluster: int
    total_sectors: int
    data_start_offset: int


@dataclass
class FatRecoveredFile:
    first_cluster: int
    filename: str
    size_bytes: int
    is_deleted: bool
    data: Optional[bytes] = None


def parse_fat32_boot_sector(image_path: str | Path) -> Optional[Fat32BootSector]:
    """Parse FAT32 BPB boot sector at offset 0."""
    try:
        with open(image_path, "rb") as f:
            boot = f.read(512)
            if len(boot) < 512:
                return None

            magic = struct.unpack_from("<H", boot, 510)[0]
            if magic != FAT32_SIGNATURE:
                return None

            # Check for FAT32 marker at offset 82 or FAT string
            fs_type_str = boot[82:90].decode("ascii", "ignore").strip()
            oem_name = boot[3:11].decode("ascii", "ignore").strip()

            bytes_per_sec = struct.unpack_from("<H", boot, 11)[0]
            sec_per_clus = boot[13]
            reserved_sec = struct.unpack_from("<H", boot, 14)[0]
            fats_cnt = boot[16]
            root_ent = struct.unpack_from("<H", boot, 17)[0]

            # In FAT32 root_ent must be 0
            if root_ent != 0:
                return None

            total_sec_16 = struct.unpack_from("<H", boot, 19)[0]
            total_sec_32 = struct.unpack_from("<I", boot, 32)[0]
            total_sec = total_sec_32 if total_sec_32 != 0 else total_sec_16

            sec_per_fat_32 = struct.unpack_from("<I", boot, 36)[0]
            root_clus = struct.unpack_from("<I", boot, 44)[0]

            if bytes_per_sec not in (512, 1024, 2048, 4096) or sec_per_clus == 0 or sec_per_fat_32 == 0:
                return None

            cluster_sz = bytes_per_sec * sec_per_clus
            data_start = (reserved_sec + fats_cnt * sec_per_fat_32) * bytes_per_sec

            return Fat32BootSector(
                oem_name=oem_name,
                bytes_per_sector=bytes_per_sec,
                sectors_per_cluster=sec_per_clus,
                cluster_size=cluster_sz,
                reserved_sectors=reserved_sec,
                fats_count=fats_cnt,
                sectors_per_fat=sec_per_fat_32,
                root_cluster=root_clus,
                total_sectors=total_sec,
                data_start_offset=data_start,
            )
    except Exception:
        return None


def cluster_to_byte_offset(boot: Fat32BootSector, cluster: int) -> int:
    """Compute physical byte offset on media for given FAT32 cluster index."""
    return boot.data_start_offset + (cluster - 2) * boot.cluster_size


def scan_fat32_deleted_files(
    image_path: str | Path,
    include_allocated: bool = False,
    max_scan_clusters: int = 2048,
) -> List[FatRecoveredFile]:
    """Traverse FAT32 directory clusters and carve deleted entries (0xE5 marker)."""
    boot = parse_fat32_boot_sector(image_path)
    if not boot:
        return []

    recovered: List[FatRecoveredFile] = []

    try:
        with open(image_path, "rb") as f:
            f_size = f.seek(0, os.SEEK_END)

            # Start scanning from root directory cluster
            visited_clusters = set()
            clusters_to_check = [boot.root_cluster]

            # Also scan early data clusters in case directory blocks reside there
            for c in range(2, min(2 + max_scan_clusters, 2 + (f_size - boot.data_start_offset) // boot.cluster_size)):
                clusters_to_check.append(c)

            for clus in clusters_to_check:
                if clus in visited_clusters:
                    continue
                visited_clusters.add(clus)

                clus_offset = cluster_to_byte_offset(boot, clus)
                if clus_offset + boot.cluster_size > f_size:
                    break

                f.seek(clus_offset)
                raw_cluster = f.read(boot.cluster_size)

                # Parse 32-byte directory entries
                for entry_idx in range(0, len(raw_cluster), 32):
                    entry = raw_cluster[entry_idx : entry_idx + 32]
                    if len(entry) < 32:
                        break

                    first_byte = entry[0]
                    if first_byte == 0x00:
                        # End of directory
                        continue

                    is_deleted = (first_byte == 0xE5)
                    if not is_deleted and not include_allocated:
                        continue

                    attr = entry[11]
                    # Skip LFN entries (attr == 0x0F) and subdirectories (attr & 0x10)
                    if attr == 0x0F or (attr & 0x10) or (attr & 0x08):
                        continue

                    # Extract cluster pointers and file size
                    clus_hi = struct.unpack_from("<H", entry, 20)[0]
                    clus_lo = struct.unpack_from("<H", entry, 26)[0]
                    start_cluster = (clus_hi << 16) | clus_lo
                    file_size = struct.unpack_from("<I", entry, 28)[0]

                    if start_cluster < 2 or file_size == 0 or file_size > 100 * 1024 * 1024:
                        continue

                    # Extract 8.3 filename
                    name_bytes = bytearray(entry[0:11])
                    if is_deleted:
                        name_bytes[0] = ord("_")
                    
                    name_part = name_bytes[0:8].decode("ascii", "replace").strip()
                    ext_part = name_bytes[8:11].decode("ascii", "replace").strip().lower()
                    filename = f"{name_part}.{ext_part}" if ext_part else name_part

                    # Read file data from start_cluster
                    data_offset = cluster_to_byte_offset(boot, start_cluster)
                    if data_offset + file_size <= f_size:
                        f.seek(data_offset)
                        file_data = f.read(file_size)
                        recovered.append(
                            FatRecoveredFile(
                                first_cluster=start_cluster,
                                filename=filename,
                                size_bytes=file_size,
                                is_deleted=is_deleted,
                                data=file_data,
                            )
                        )
    except Exception:
        pass

    return recovered
