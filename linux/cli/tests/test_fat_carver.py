"""Unit tests for s0 Structure-Based FAT32 Recovery Engine."""

import struct
from pathlib import Path
import pytest

from s0_cli.carver import (
    parse_fat32_boot_sector,
    scan_fat32_deleted_files,
    carve_image,
    detect_filesystem,
)


def create_synthetic_fat32_image(path: Path) -> None:
    """Build a minimal valid FAT32 filesystem image with a deleted file in root dir."""
    bytes_per_sec = 512
    sec_per_clus = 1
    reserved_sec = 32
    fats_count = 2
    sec_per_fat = 32
    root_cluster = 2

    cluster_size = bytes_per_sec * sec_per_clus
    data_start = (reserved_sec + fats_count * sec_per_fat) * bytes_per_sec

    # Allocate 1 MiB image
    img_size = 1024 * 1024
    buf = bytearray(img_size)

    # 1. BPB Boot Sector (Sector 0)
    buf[0:3] = b"\xeb\x58\x90"
    buf[3:11] = b"MSDOS5.0"
    struct.pack_into("<H", buf, 11, bytes_per_sec)
    buf[13] = sec_per_clus
    struct.pack_into("<H", buf, 14, reserved_sec)
    buf[16] = fats_count
    struct.pack_into("<H", buf, 17, 0)      # root_entries = 0 in FAT32
    struct.pack_into("<H", buf, 19, 0)
    struct.pack_into("<I", buf, 32, img_size // bytes_per_sec)  # total sectors
    struct.pack_into("<I", buf, 36, sec_per_fat)
    struct.pack_into("<I", buf, 44, root_cluster)
    buf[66] = 0x29                         # boot signature
    buf[82:90] = b"FAT32   "
    struct.pack_into("<H", buf, 510, 0xAA55)

    # 2. Root directory at cluster 2
    root_offset = data_start + (root_cluster - 2) * cluster_size

    # Entry 1: Deleted file entry (0xE5)
    # Filename: _EVIDENCE.TXT (originally EVIDENCE.TXT)
    # File size: 54 bytes
    # Target cluster: 3
    target_cluster = 3
    entry1 = bytearray(32)
    entry1[0] = 0xE5                      # Deleted file marker
    entry1[1:8] = b"EVIDENC"
    entry1[8:11] = b"TXT"
    entry1[11] = 0x20                     # Archive attribute
    struct.pack_into("<H", entry1, 20, 0) # Cluster high
    struct.pack_into("<H", entry1, 26, target_cluster) # Cluster low
    file_data = b"CONFIDENTIAL FORENSIC INTELLIGENCE FROM USB STORAGE"
    struct.pack_into("<I", entry1, 28, len(file_data))

    buf[root_offset : root_offset + 32] = entry1

    # 3. Target cluster 3 data
    clus3_offset = data_start + (target_cluster - 2) * cluster_size
    buf[clus3_offset : clus3_offset + len(file_data)] = file_data

    path.write_bytes(bytes(buf))


def test_fat32_boot_sector_detection(tmp_path):
    img_path = tmp_path / "test_usb.raw"
    create_synthetic_fat32_image(img_path)

    assert detect_filesystem(img_path) == "fat32"

    boot = parse_fat32_boot_sector(img_path)
    assert boot is not None
    assert boot.bytes_per_sector == 512
    assert boot.sectors_per_cluster == 1
    assert boot.root_cluster == 2
    assert boot.sectors_per_fat == 32


def test_fat32_deleted_file_carving(tmp_path):
    img_path = tmp_path / "test_usb.raw"
    create_synthetic_fat32_image(img_path)

    deleted_files = scan_fat32_deleted_files(img_path)
    assert len(deleted_files) == 1

    f = deleted_files[0]
    assert f.is_deleted is True
    assert "_EVIDENC.txt" in f.filename
    assert f.size_bytes == 51  # length of "CONFIDENTIAL FORENSIC INTELLIGENCE FROM USB STORAGE"
    assert b"CONFIDENTIAL FORENSIC INTELLIGENCE" in f.data

    # Test full carve_image integration
    out_dir = tmp_path / "fat_recovered"
    summary = carve_image(img_path, out_dir, min_confidence=50)
    assert summary.files_recovered >= 1
    rec_file = summary.carved_files[0]
    assert "fat32" in rec_file.recovery_method
    assert summary.manifest_certificate is not None
    assert (out_dir / "recovery_index.json").exists()
