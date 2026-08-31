"""TrustWipe Module 3: Advanced File Carving and Forensic Recovery."""

from .engine import CarvedFile, CarvingSessionSummary, carve_image
from .scoring import calculate_shannon_entropy, score_carved_candidate
from .signatures import SIGNATURES, FileSignature, get_signature_by_ext
from .ext4_carver import parse_ext4_superblock, scan_ext4_deleted_inodes

__all__ = [
    "CarvedFile",
    "CarvingSessionSummary",
    "carve_image",
    "calculate_shannon_entropy",
    "score_carved_candidate",
    "SIGNATURES",
    "FileSignature",
    "get_signature_by_ext",
    "parse_ext4_superblock",
    "scan_ext4_deleted_inodes",
]
