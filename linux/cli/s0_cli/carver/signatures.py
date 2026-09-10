"""Forensic File Signature Definitions for File Carving."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Dict, List, Optional


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
        name="GIF Image",
        extension="gif",
        category="image",
        header=b"GIF8",
        footer=b"\x00\x3b",
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
    FileSignature(
        name="BMP Image",
        extension="bmp",
        category="image",
        header=b"BM",
        min_size=54,
        max_size=30 * 1024 * 1024,
    ),
    FileSignature(
        name="ELF Executable",
        extension="elf",
        category="executable",
        header=b"\x7fELF",
        min_size=64,
        max_size=50 * 1024 * 1024,
    ),
    FileSignature(
        name="SQLite Database",
        extension="sqlite",
        category="document",
        header=b"SQLite format 3\x00",
        min_size=512,
        max_size=100 * 1024 * 1024,
    ),
    FileSignature(
        name="MP3 Audio (ID3v2 Container)",
        extension="mp3",
        category="audio",
        header=b"ID3",
        min_size=128,
        max_size=30 * 1024 * 1024,
    ),
    FileSignature(
        name="MP3 Audio (MPEG-1 Layer 3 Sync Frame)",
        extension="mp3",
        category="audio",
        header=b"\xff\xfb",
        min_size=128,
        max_size=30 * 1024 * 1024,
    ),
    FileSignature(
        name="MP3 Audio (MPEG-2 Layer 3 Sync Frame)",
        extension="mp3",
        category="audio",
        header=b"\xff\xf3",
        min_size=128,
        max_size=30 * 1024 * 1024,
    ),
    FileSignature(
        name="MP3 Audio (MPEG-1 Layer 3 with CRC)",
        extension="mp3",
        category="audio",
        header=b"\xff\xfa",
        min_size=128,
        max_size=30 * 1024 * 1024,
    ),
    FileSignature(
        name="WAV Audio",
        extension="wav",
        category="audio",
        header=b"RIFF",
        min_size=44,
        max_size=50 * 1024 * 1024,
    ),
    FileSignature(
        name="FLAC Lossless Audio",
        extension="flac",
        category="audio",
        header=b"fLaC",
        min_size=128,
        max_size=50 * 1024 * 1024,
    ),
    FileSignature(
        name="OGG Container",
        extension="ogg",
        category="audio",
        header=b"OggS",
        min_size=64,
        max_size=50 * 1024 * 1024,
    ),
    FileSignature(
        name="7-Zip Archive",
        extension="7z",
        category="archive",
        header=b"7z\xbc\xaf'\x1c",
        min_size=32,
        max_size=100 * 1024 * 1024,
    ),
    FileSignature(
        name="PCAP Packet Capture",
        extension="pcap",
        category="document",
        header=b"\xd4\xc3\xb2\xa1",
        min_size=24,
        max_size=100 * 1024 * 1024,
    ),
    FileSignature(
        name="PCAP Next-Generation Capture",
        extension="pcapng",
        category="document",
        header=b"\n\r\r\n",
        min_size=32,
        max_size=100 * 1024 * 1024,
    ),
]


def parse_hex_bytes(val: str | bytes) -> bytes:
    """Parse hex string (with optional spaces or 0x prefixes) or raw bytes into bytes."""
    if isinstance(val, bytes):
        return val
    cleaned = re.sub(r"[^0-9a-fA-F]", "", str(val or ""))
    if not cleaned:
        return b""
    if len(cleaned) % 2 != 0:
        cleaned = "0" + cleaned
    return bytes.fromhex(cleaned)


def signature_from_dict(d: Dict[str, Any]) -> FileSignature:
    """Instantiate a FileSignature from a JSON/dict description."""
    hdr_val = d.get("header") or d.get("header_hex") or ""
    header = parse_hex_bytes(hdr_val)
    if not header:
        raise ValueError(f"Custom signature '{d.get('name', 'unnamed')}' requires valid non-empty header magic bytes")
    
    ftr_val = d.get("footer") or d.get("footer_hex")
    footer = parse_hex_bytes(ftr_val) if ftr_val else None

    return FileSignature(
        name=str(d.get("name") or "Custom Signature"),
        extension=str(d.get("extension") or "bin").lower().lstrip("."),
        category=str(d.get("category") or "custom"),
        header=header,
        footer=footer,
        footer_offset_from_end=int(d.get("footer_offset_from_end", 0)),
        min_size=int(d.get("min_size", 32)),
        max_size=int(d.get("max_size", 50 * 1024 * 1024)),
        fixed_size=int(d["fixed_size"]) if d.get("fixed_size") else None,
    )


def get_signature_by_ext(ext: str, custom_sigs: Optional[List[FileSignature]] = None) -> Optional[FileSignature]:
    clean = ext.lower().lstrip(".")
    if custom_sigs:
        for sig in custom_sigs:
            if sig.extension.lower().lstrip(".") == clean:
                return sig
    for sig in SIGNATURES:
        if sig.extension == clean:
            return sig
    return None

