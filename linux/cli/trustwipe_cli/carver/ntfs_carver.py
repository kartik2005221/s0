"""Structure-Based NTFS Filesystem Recovery Engine.

Parses Master File Table ($MFT) directly from raw images/block devices:
  - Boot sector detection (OEM ID 'NTFS    ')
  - MFT record parsing with resident and single-run non-resident $DATA streams
  - $FILE_NAME attribute UTF-16LE extraction
  - Identification and recovery of unallocated / deleted file records
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


NTFS_OEM_ID = b"NTFS    "
MFT_RECORD_MAGIC = b"FILE"
ATTR_FILE_NAME = 0x30
ATTR_DATA = 0x80
ATTR_END_MARKER = 0xFFFFFFFF


@dataclass
class NtfsBootSector:
    oem_id: str
    bytes_per_sector: int
    sectors_per_cluster: int
    cluster_size: int
    total_sectors: int
    mft_start_cluster: int
    mft_record_size: int


@dataclass
class NtfsRecoveredFile:
    record_num: int
    filename: str
    size_bytes: int
    is_resident: bool
    is_deleted: bool
    data: Optional[bytes] = None


def parse_ntfs_boot_sector(image_path: str | Path) -> Optional[NtfsBootSector]:
    """Parse NTFS boot sector at offset 0."""
    try:
        with open(image_path, "rb") as f:
            boot_data = f.read(512)
            if len(boot_data) < 512:
                return None

            oem_id = boot_data[3:11]
            if oem_id != NTFS_OEM_ID:
                return None

            bytes_per_sector = struct.unpack_from("<H", boot_data, 0x0B)[0]
            if bytes_per_sector == 0 or (bytes_per_sector & (bytes_per_sector - 1)) != 0:
                bytes_per_sector = 512

            sectors_per_cluster = boot_data[0x0D]
            if sectors_per_cluster == 0:
                sectors_per_cluster = 8

            cluster_size = bytes_per_sector * sectors_per_cluster
            total_sectors = struct.unpack_from("<Q", boot_data, 0x28)[0]
            mft_start_cluster = struct.unpack_from("<q", boot_data, 0x30)[0]

            c_mft = struct.unpack_from("<b", boot_data, 0x40)[0]
            if c_mft < 0:
                mft_record_size = 1 << abs(c_mft)
            else:
                mft_record_size = c_mft * cluster_size

            if mft_record_size <= 0 or mft_record_size > 65536:
                mft_record_size = 1024

            return NtfsBootSector(
                oem_id=oem_id.decode("ascii", errors="ignore").strip(),
                bytes_per_sector=bytes_per_sector,
                sectors_per_cluster=sectors_per_cluster,
                cluster_size=cluster_size,
                total_sectors=total_sectors,
                mft_start_cluster=mft_start_cluster,
                mft_record_size=mft_record_size,
            )
    except Exception:
        return None


def parse_mft_record_bytes(
    rec_bytes: bytes,
    disk_file=None,
    cluster_size: int = 4096,
) -> Optional[NtfsRecoveredFile]:
    """Parse single MFT record buffer (resident & single-run non-resident DATA)."""
    if len(rec_bytes) < 1024 or rec_bytes[0:4] != MFT_RECORD_MAGIC:
        return None

    flags = struct.unpack_from("<H", rec_bytes, 0x16)[0]
    is_allocated = bool(flags & 0x01)
    is_directory = bool(flags & 0x02)
    if is_directory:
        return None

    record_num = struct.unpack_from("<I", rec_bytes, 0x2C)[0]
    first_attr_offset = struct.unpack_from("<H", rec_bytes, 0x14)[0]

    filename: Optional[str] = None
    file_data: Optional[bytes] = None
    real_size: int = 0
    is_resident: bool = False

    offset = first_attr_offset
    while offset + 8 <= len(rec_bytes):
        attr_type = struct.unpack_from("<I", rec_bytes, offset)[0]
        if attr_type == ATTR_END_MARKER or attr_type == 0:
            break
        attr_len = struct.unpack_from("<I", rec_bytes, offset + 4)[0]
        if attr_len <= 0 or offset + attr_len > len(rec_bytes):
            break

        non_resident = rec_bytes[offset + 8]

        if attr_type == ATTR_FILE_NAME and non_resident == 0:
            val_len = struct.unpack_from("<I", rec_bytes, offset + 16)[0]
            val_offset = struct.unpack_from("<H", rec_bytes, offset + 20)[0]
            fn_payload = rec_bytes[offset + val_offset : offset + val_offset + val_len]
            if len(fn_payload) >= 0x42:
                name_len = fn_payload[0x40]
                name_bytes = fn_payload[0x42 : 0x42 + name_len * 2]
                try:
                    decoded_name = name_bytes.decode("utf-16le")
                    if not filename or len(decoded_name) > len(filename):
                        filename = decoded_name
                except Exception:
                    pass

        elif attr_type == ATTR_DATA:
            name_len = rec_bytes[offset + 9]
            if name_len == 0:  # Default unnamed primary $DATA stream
                if non_resident == 0:
                    val_len = struct.unpack_from("<I", rec_bytes, offset + 16)[0]
                    val_offset = struct.unpack_from("<H", rec_bytes, offset + 20)[0]
                    file_data = bytes(rec_bytes[offset + val_offset : offset + val_offset + val_len])
                    real_size = len(file_data)
                    is_resident = True
                else:
                    # Non-resident single contiguous run
                    is_resident = False
                    runlist_offset = struct.unpack_from("<H", rec_bytes, offset + 32)[0]
                    real_size = struct.unpack_from("<Q", rec_bytes, offset + 48)[0]
                    runlist_data = rec_bytes[offset + runlist_offset :]
                    if len(runlist_data) > 0 and runlist_data[0] != 0 and disk_file:
                        b = runlist_data[0]
                        len_size = b & 0x0F
                        off_size = (b >> 4) & 0x0F
                        if len(runlist_data) >= 1 + len_size + off_size:
                            run_len = int.from_bytes(
                                runlist_data[1 : 1 + len_size], byteorder="little", signed=False
                            )
                            run_offset = int.from_bytes(
                                runlist_data[1 + len_size : 1 + len_size + off_size],
                                byteorder="little",
                                signed=True,
                            )
                            disk_byte_offset = run_offset * cluster_size
                            bytes_to_read = min(real_size, run_len * cluster_size)
                            try:
                                disk_file.seek(disk_byte_offset)
                                file_data = disk_file.read(bytes_to_read)
                            except Exception:
                                pass

        offset += attr_len

    if file_data is not None or real_size > 0:
        clean_name = filename or f"ntfs_record_{record_num:05d}.bin"
        return NtfsRecoveredFile(
            record_num=record_num,
            filename=clean_name,
            size_bytes=len(file_data) if file_data is not None else real_size,
            is_resident=is_resident,
            is_deleted=(not is_allocated),
            data=file_data,
        )

    return None


def scan_ntfs_deleted_files(
    image_path: str | Path,
    max_records: int = 2000,
    include_allocated: bool = False,
) -> List[NtfsRecoveredFile]:
    """Scan NTFS $MFT on disk image and recover deleted file entries."""
    boot = parse_ntfs_boot_sector(image_path)
    if not boot:
        return []

    recovered: List[NtfsRecoveredFile] = []
    try:
        with open(image_path, "rb") as f:
            mft_offset = boot.mft_start_cluster * boot.cluster_size
            f.seek(mft_offset)

            for rec_idx in range(max_records):
                rec_bytes = f.read(boot.mft_record_size)
                if len(rec_bytes) < boot.mft_record_size:
                    break

                if rec_bytes[0:4] == MFT_RECORD_MAGIC:
                    parsed = parse_mft_record_bytes(
                        rec_bytes, disk_file=f, cluster_size=boot.cluster_size
                    )
                    if parsed:
                        if parsed.is_deleted or include_allocated:
                            recovered.append(parsed)
                elif rec_bytes[0:4] == bytes(4):
                    continue
    except Exception:
        pass
    return recovered
