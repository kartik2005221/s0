"""Tests for TrustWipe exFAT Structure-Based Carving Module."""

import struct
from pathlib import Path

import pytest
from trustwipe_cli.carver.engine import carve_image, detect_filesystem, detect_partitions
from trustwipe_cli.carver.exfat_carver import (
    ENTRY_TYPE_FILE_DELETED,
    ENTRY_TYPE_NAME_DELETED,
    ENTRY_TYPE_STREAM_DELETED,
    EXFAT_BOOT_SIGNATURE,
    EXFAT_OEM_MAGIC,
    parse_exfat_boot_sector,
    scan_exfat_deleted_files,
)


def create_synthetic_exfat_image(
    image_path: Path,
    filename: str = "evidence.pdf",
    payload: bytes = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF",
    total_size_kb: int = 128,
) -> None:
    """Create a minimal synthetic exFAT disk image with a deleted file entry."""
    img = bytearray(total_size_kb * 1024)

    # 1. exFAT VBR Boot Sector at sector 0
    img[0:3] = b"\xeb\x76\x90"
    img[3:11] = EXFAT_OEM_MAGIC
    struct.pack_into("<Q", img, 72, total_size_kb * 2)  # VolumeLength in sectors
    struct.pack_into("<I", img, 80, 2)                  # FatOffset
    struct.pack_into("<I", img, 84, 4)                  # FatLength
    struct.pack_into("<I", img, 88, 16)                 # ClusterHeapOffset in sectors
    struct.pack_into("<I", img, 92, 32)                 # ClusterCount
    struct.pack_into("<I", img, 96, 4)                  # FirstClusterOfRootDirectory
    img[108] = 9                                        # BytesPerSectorShift (512 B)
    img[109] = 3                                        # SectorsPerClusterShift (8 sec = 4096 B)
    struct.pack_into("<H", img, 510, EXFAT_BOOT_SIGNATURE)

    # 2. Geometry:
    # ClusterHeap starts at 16 * 512 = 8192 bytes
    # Cluster size = 512 * 8 = 4096 bytes
    # Cluster N offset = 8192 + (N - 2) * 4096
    cluster_heap_offset = 8192
    cluster_size = 4096

    # Root Directory at Cluster 4:
    root_dir_offset = cluster_heap_offset + (4 - 2) * cluster_size

    # File Data at Cluster 5:
    file_cluster = 5
    file_data_offset = cluster_heap_offset + (file_cluster - 2) * cluster_size
    img[file_data_offset : file_data_offset + len(payload)] = payload

    # 3. Directory Entry Set in Root Directory:
    fn_chunks = [filename[i : i + 15] for i in range(0, len(filename), 15)]
    sec_count = 1 + len(fn_chunks)  # 1 Stream Extension + N File Name entries

    # Entry 1: File Directory Entry (0x05 = Deleted File)
    off1 = root_dir_offset
    img[off1 + 0] = ENTRY_TYPE_FILE_DELETED
    img[off1 + 1] = sec_count
    struct.pack_into("<H", img, off1 + 4, 0x20)  # Archive attribute

    # Entry 2: Stream Extension (0x40 = Deleted Stream)
    off2 = off1 + 32
    img[off2 + 0] = ENTRY_TYPE_STREAM_DELETED
    img[off2 + 1] = 0x03  # NoFatChain = 1, AllocationPossible = 1
    img[off2 + 3] = len(filename)
    struct.pack_into("<I", img, off2 + 20, file_cluster)
    struct.pack_into("<Q", img, off2 + 24, len(payload))

    # Entry 3+: File Name Entries (0x41 = Deleted Name)
    for c_i, chunk in enumerate(fn_chunks):
        off_n = off2 + 32 * (1 + c_i)
        img[off_n + 0] = ENTRY_TYPE_NAME_DELETED
        c_bytes = chunk.encode("utf-16le")
        img[off_n + 2 : off_n + 2 + len(c_bytes)] = c_bytes

    image_path.write_bytes(img)


def test_parse_exfat_boot_sector(tmp_path: Path):
    img_path = tmp_path / "test_exfat.raw"
    create_synthetic_exfat_image(img_path)

    boot = parse_exfat_boot_sector(img_path)
    assert boot is not None
    assert boot.bytes_per_sector == 512
    assert boot.sectors_per_cluster == 8
    assert boot.cluster_size == 4096
    assert boot.cluster_heap_offset_bytes == 8192
    assert boot.root_dir_cluster == 4


def test_scan_exfat_deleted_files(tmp_path: Path):
    img_path = tmp_path / "test_exfat_deleted.raw"
    test_payload = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF"
    test_filename = "classified_report.pdf"

    create_synthetic_exfat_image(
        img_path,
        filename=test_filename,
        payload=test_payload,
    )

    recovered = scan_exfat_deleted_files(img_path)
    assert len(recovered) == 1
    rec = recovered[0]
    assert rec.filename == test_filename
    assert rec.is_deleted is True
    assert rec.size_bytes == len(test_payload)
    assert rec.data == test_payload


def test_exfat_partition_detection_and_carving(tmp_path: Path):
    img_path = tmp_path / "test_exfat_engine.raw"
    test_payload = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF"

    create_synthetic_exfat_image(
        img_path,
        filename="evidence.pdf",
        payload=test_payload,
    )

    fs = detect_filesystem(img_path)
    assert fs == "exfat"

    parts = detect_partitions(img_path)
    assert len(parts) >= 1
    assert parts[0][0] == "exfat"

    out_dir = tmp_path / "carved_exfat"
    summary = carve_image(img_path, out_dir)
    assert summary.source_filesystem == "exfat"
    assert len(summary.carved_files) >= 1

    carved = summary.carved_files[0]
    assert carved.recovery_method == "exfat_entry"
    assert carved.extension == "pdf"
    assert carved.size_bytes == len(test_payload)
