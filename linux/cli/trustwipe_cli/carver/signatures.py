"""Forensic File Signature Definitions for File Carving."""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional


@dataclass
class FileSignature:
    name: str
    extension: str
    category: str  # "image", "document", "archive", "audio", "video", "executable"
    header: bytes
    footer: Optional[bytes] = None
    footer_offset_from_end: int = 0
    min_size: int = 64
    max_size: int = 50 * 1024 * 1024  # 50 MB default cap
    fixed_size: Optional[int] = None
    sub_headers: List[bytes] = None


SIGNATURES: List[FileSignature] = [
    FileSignature(
        name="JPEG Image",
        extension="jpg",
        category="image",
        header=b"\xff\xd8\xff",
        footer=b"\xff\xd9",
        min_size=32,
        max_size=30 * 1024 * 1024,
    ),
    FileSignature(
        name="PNG Image",
        extension="png",
        category="image",
        header=b"\x89PNG\r\n\x1a\n",
        footer=b"IEND\xaeB`\x82",
        min_size=32,
        max_size=30 * 1024 * 1024,
    ),
    FileSignature(
        name="PDF Document",
        extension="pdf",
        category="document",
        header=b"%PDF-",
        footer=b"%%EOF",
        min_size=32,
        max_size=50 * 1024 * 1024,
    ),
    FileSignature(
        name="ZIP / Office OpenXML",
        extension="zip",
        category="archive",
        header=b"PK\x03\x04",
        footer=b"PK\x05\x06",  # EOCD record
        min_size=32,
        max_size=100 * 1024 * 1024,
    ),
    FileSignature(
        name="GIF Image (87a)",
        extension="gif",
        category="image",
        header=b"GIF87a",
        footer=b"\x3b",
        min_size=32,
        max_size=20 * 1024 * 1024,
    ),
    FileSignature(
        name="GIF Image (89a)",
        extension="gif",
        category="image",
        header=b"GIF89a",
        footer=b"\x3b",
        min_size=32,
        max_size=20 * 1024 * 1024,
    ),
    FileSignature(
        name="GZIP Archive",
        extension="gz",
        category="archive",
        header=b"\x1f\x8b\x08",
        min_size=32,
        max_size=50 * 1024 * 1024,
    ),
]


def get_signature_by_ext(ext: str) -> Optional[FileSignature]:
    clean = ext.lower().lstrip(".")
    for sig in SIGNATURES:
        if sig.extension == clean:
            return sig
    return None
