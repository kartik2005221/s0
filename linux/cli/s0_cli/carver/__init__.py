"""s0 Module 3: Advanced File Carving and Forensic Recovery."""

from .engine import CarvedFile, CarvingSessionSummary, carve_image, detect_filesystem
from .ext4_carver import parse_ext4_superblock, scan_ext4_deleted_inodes
from .fat_carver import (
    Fat32BootSector,
    FatRecoveredFile,
    parse_fat32_boot_sector,
    scan_fat32_deleted_files,
)
from .ntfs_carver import (
    NtfsBootSector,
    NtfsRecoveredFile,
    parse_mft_record_bytes,
    parse_ntfs_boot_sector,
    scan_ntfs_deleted_files,
)
from .scoring import calculate_shannon_entropy, score_carved_candidate
from .signatures import SIGNATURES, FileSignature, get_signature_by_ext, parse_hex_bytes, signature_from_dict

__all__ = [
    "CarvedFile",
    "CarvingSessionSummary",
    "carve_image",
    "detect_filesystem",
    "calculate_shannon_entropy",
    "score_carved_candidate",
    "SIGNATURES",
    "FileSignature",
    "get_signature_by_ext",
    "parse_hex_bytes",
    "signature_from_dict",
    "parse_ext4_superblock",
    "scan_ext4_deleted_inodes",
    "Fat32BootSector",
    "FatRecoveredFile",
    "parse_fat32_boot_sector",
    "scan_fat32_deleted_files",
    "NtfsBootSector",
    "NtfsRecoveredFile",
    "parse_ntfs_boot_sector",
    "parse_mft_record_bytes",
    "scan_ntfs_deleted_files",
]
