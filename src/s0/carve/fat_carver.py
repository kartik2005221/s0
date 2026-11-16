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

from . import fat_directory as fat_dir

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
    data: bytes | None = None
    # How the filename was arrived at, and how far it can be relied on. A
    # deleted entry's long name cannot be checksum-verified -- deletion overwrote
    # the byte the fragments were hashed against -- so it is corroborated
    # structurally and labelled as such rather than claimed as verified.
    name_source: str = "8.3 name only"
    name_verification: str = "none"
    # 1 for a contiguous read; the run count the FAT chain produced otherwise.
    fragment_count: int = 1


def parse_fat32_boot_sector(
    image_path: str | Path,
    partition_offset: int = 0,
) -> Fat32BootSector | None:
    """Parse FAT32 BPB boot sector at partition_offset."""
    try:
        with open(image_path, "rb") as f:
            f.seek(partition_offset)
            boot = f.read(512)
            if len(boot) < 512:
                return None

            magic = struct.unpack_from("<H", boot, 510)[0]
            if magic != FAT32_SIGNATURE:
                return None

            # Check for FAT32 marker at offset 82 or FAT string
            boot[82:90].decode("ascii", "ignore").strip()
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
            data_start = partition_offset + (reserved_sec + fats_cnt * sec_per_fat_32) * bytes_per_sec

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


def _read_cluster_chain(
    f, boot: Fat32BootSector, partition_offset: int, start_cluster: int, file_size: int, image_size: int
) -> tuple[bytes, int]:
    """Read file_size bytes by following the FAT chain from start_cluster.

    Reading contiguously from the first cluster was wrong for every fragmented
    live file: FAT32 chains hop through the FAT, so a file's second cluster
    sits wherever the allocator put it, not at the next cluster. Returns
    (data, fragment_count), where data may be a shorter prefix than requested
    if the chain ends early -- that is reported, never zero-filled.

    A chain that loops is cut rather than spun on: a prefix of honest bytes
    beats a hang.
    """
    bytes_per_sector = max(1, boot.cluster_size // boot.sectors_per_cluster)
    fat_offset = partition_offset + boot.reserved_sectors * bytes_per_sector
    chunks: list[bytes] = []
    remaining = file_size
    clus = start_cluster
    seen: set[int] = set()
    runs = 1
    last_contiguous: int | None = None
    while remaining > 0 and 2 <= clus < 0x0FFFFFF7:
        if clus in seen:
            break  # loop in the chain: better a prefix than a hang
        seen.add(clus)
        offset = cluster_to_byte_offset(boot, clus)
        if offset + boot.cluster_size > image_size:
            break
        f.seek(offset)
        chunks.append(f.read(min(boot.cluster_size, remaining)))
        remaining -= boot.cluster_size
        if remaining <= 0:
            break
        f.seek(fat_offset + clus * 4)
        raw = f.read(4)
        if len(raw) < 4:
            break
        nxt = struct.unpack_from("<I", raw, 0)[0] & 0x0FFFFFFF
        if nxt < 2 or nxt >= 0x0FFFFFF7:
            break  # end of chain before file_size was satisfied: prefix only
        if last_contiguous is not None and nxt != last_contiguous + 1:
            runs += 1
        last_contiguous = nxt
        clus = nxt
    return b"".join(chunks), runs


def cluster_to_byte_offset(boot: Fat32BootSector, cluster: int) -> int:
    """Compute physical byte offset on media for given FAT32 cluster index."""
    return boot.data_start_offset + (cluster - 2) * boot.cluster_size


def scan_fat32_deleted_files(
    image_path: str | Path,
    include_allocated: bool = False,
    max_scan_clusters: int = 2048,
    partition_offset: int = 0,
    max_file_bytes: int = 100 * 1024 * 1024,
) -> list[FatRecoveredFile]:
    """Traverse FAT32 directory clusters and carve deleted entries (0xE5 marker).

    A deleted entry keeps its 8.3 name with the first byte replaced by 0xE5, so
    the long-name fragments that precede it are reassembled to recover the name a
    user actually typed. How far that name can be trusted is carried on each
    result; see fat_directory for why a deleted entry cannot be checksummed.
    """
    boot = parse_fat32_boot_sector(image_path, partition_offset=partition_offset)
    if not boot:
        return []

    recovered: list[FatRecoveredFile] = []

    try:
        with open(image_path, "rb") as f:
            f_size = f.seek(0, os.SEEK_END)

            # Start scanning from root directory cluster
            visited_clusters = set()
            clusters_to_check = [boot.root_cluster]

            # Also scan early data clusters in case directory blocks reside there
            for c in range(
                2, min(2 + max_scan_clusters, 2 + (f_size - boot.data_start_offset) // boot.cluster_size)
            ):
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

                # Decode the whole cluster at once so the long-name fragments
                # that sit before an 8.3 entry are still available when it is
                # reached. Parsing entries in isolation -- as this did -- is what
                # made every recovered name an 8.3 stub.
                for named in fat_dir.name_entries(
                    fat_dir.read_directory_cluster(raw_cluster, boot.cluster_size), include_free=True
                ):
                    entry = named.entry
                    if entry.is_end_of_directory:
                        break
                    if not entry.is_free and not include_allocated:
                        continue

                    clus_hi = struct.unpack_from("<H", entry.raw, 20)[0]
                    clus_lo = struct.unpack_from("<H", entry.raw, 26)[0]
                    start_cluster = (clus_hi << 16) | clus_lo
                    file_size = struct.unpack_from("<I", entry.raw, 28)[0]

                    if start_cluster < 2 or file_size == 0 or file_size > max_file_bytes:
                        continue

                    data_offset = cluster_to_byte_offset(boot, start_cluster)
                    if data_offset + file_size > f_size:
                        continue
                    if entry.is_free:
                        # A deleted entry's FAT chain is normally zeroed with the
                        # rest of the entry, so the chain itself cannot be
                        # trusted: the contiguous prefix is the only honest read,
                        # and it is labelled an assumption via fragment_count.
                        f.seek(data_offset)
                        file_data = f.read(file_size)
                        fragments = 1
                    else:
                        # A live entry's chain is authoritative: follow it, so a
                        # fragmented file's bytes come from the clusters the
                        # allocator actually used, not from whatever happens to
                        # sit behind the first cluster.
                        file_data, fragments = _read_cluster_chain(
                            f, boot, partition_offset, start_cluster, file_size, f_size
                        )
                    recovered.append(
                        FatRecoveredFile(
                            first_cluster=start_cluster,
                            filename=named.name,
                            size_bytes=file_size,
                            is_deleted=entry.is_free,
                            data=file_data if file_data else None,
                            name_source=named.recovered.name_source,
                            name_verification=named.recovered.verification,
                            fragment_count=fragments,
                        )
                    )

    except Exception:
        pass

    return recovered
