"""Forensic file signature definitions for file carving.

Every signature carries the magic bytes that identify a candidate and, where the
format has one, a footer that terminates it. Critically, a signature with
``footer=None`` no longer means "carve to max_size": the carver consults
:mod:`s0.carve.boundary`, which has a registered resolver for most of the
header-only formats below (BMP, ELF, WAV, 7z, MP3, SQLite, PCAP, PCAPNG, ...) and
refuses to emit anything it cannot resolve.

``category`` drives plausibility scoring and reporting only; it is never used to
decide whether a candidate is real.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# Categories used across the signature table and the recovery report.
CATEGORIES = ("image", "document", "archive", "audio", "video", "executable", "database", "system", "custom")

_KB = 1024
_MB = 1024 * 1024
_GB = 1024 * 1024 * 1024


@dataclass
class FileSignature:
    name: str
    extension: str
    category: str
    header: bytes
    #: Where ``header`` sits relative to the *start of the file*. Zero for the
    #: usual case where the magic is the first thing in the file.
    #:
    #: Needed for ISO-BMFF, where every file opens with a 4-byte box size whose
    #: value depends on how many compatible brands the writer emitted: 0x18 for
    #: one brand, 0x20 for four, and so on. Hardcoding a size yields a table
    #: that matches the files its author happened to test with and nothing else
    #: -- which is how every ISO-BMFF signature here came to be pinned to 0x18
    #: while ffmpeg writes 0x20, and real MP4s were never even candidates.
    header_offset: int = 0
    footer: Optional[bytes] = None
    footer_offset_from_end: int = 0
    min_size: int = 64
    max_size: int = 50 * _MB
    fixed_size: Optional[int] = None
    # Optional inbuilt string: the format reliably contains this marker, which
    # is a strong additional filter for 2-byte magics (scalpel calls this
    # "inbuilt"). Checked within the first `inbuilt_search_window` bytes.
    inbuilt: Optional[bytes] = None
    inbuilt_search_window: int = 4096


SIGNATURES: List[FileSignature] = [
    # ---------------- images ----------------
    FileSignature("JPEG Image", "jpg", "image",
                  header=b"\xff\xd8\xff", footer=b"\xff\xd9",
                  min_size=64, max_size=64 * _MB),
    FileSignature("PNG Image", "png", "image",
                  header=b"\x89PNG\r\n\x1a\n", footer=b"IEND\xaeB`\x82",
                  min_size=64, max_size=64 * _MB),
    FileSignature("GIF Image", "gif", "image",
                  header=b"GIF8", footer=b"\x00\x3b",
                  min_size=32, max_size=32 * _MB),
    FileSignature("BMP Image", "bmp", "image",
                  header=b"BM", min_size=70, max_size=512 * _MB),
    FileSignature("WebP Image", "webp", "image",
                  header=b"RIFF", min_size=32, max_size=64 * _MB,
                  inbuilt=b"WEBP", inbuilt_search_window=16),
    FileSignature("TIFF Image", "tiff", "image",
                  header=b"II*\x00", min_size=32, max_size=512 * _MB),
    FileSignature("BigTIFF Image", "tiff", "image",
                  header=b"II+\x00", min_size=32, max_size=_GB),
    FileSignature("TIFF Image (Motorola)", "tiff", "image",
                  header=b"MM\x00*", min_size=32, max_size=512 * _MB),
    FileSignature("BigTIFF Image (Motorola)", "tiff", "image",
                  header=b"MM\x00+", min_size=32, max_size=_GB),
    FileSignature("HEIF / AVIF Image (heic brand)", "heic", "image",
              header=b"ftypheic", header_offset=4, min_size=64, max_size=512 * _MB),
    FileSignature("HEIF / AVIF Image (mif1 brand)", "heic", "image",
              header=b"ftypmif1", header_offset=4, min_size=64, max_size=512 * _MB),
    FileSignature("HEIF / AVIF Image (avif brand)", "avif", "image",
              header=b"ftypavif", header_offset=4, min_size=64, max_size=512 * _MB),
    FileSignature("JPEG 2000 Image", "jp2", "image",
                  header=b"\x00\x00\x00\x0cjP  \r\n\x87\n", min_size=64, max_size=512 * _MB),

    # ---------------- documents ----------------
    FileSignature("PDF Document", "pdf", "document",
                  header=b"%PDF-", footer=b"%%EOF",
                  min_size=64, max_size=256 * _MB),
    FileSignature("Microsoft Word 2007+", "docx", "archive",
                  header=b"PK\x03\x04", footer=b"PK\x05\x06",
                  min_size=128, max_size=512 * _MB,
                  inbuilt=b"word/", inbuilt_search_window=8192),
    FileSignature("Microsoft Excel 2007+", "xlsx", "archive",
                  header=b"PK\x03\x04", footer=b"PK\x05\x06",
                  min_size=128, max_size=512 * _MB,
                  inbuilt=b"xl/", inbuilt_search_window=8192),
    FileSignature("PowerPoint 2007+", "pptx", "archive",
                  header=b"PK\x03\x04", footer=b"PK\x05\x06",
                  min_size=128, max_size=512 * _MB,
                  inbuilt=b"ppt/", inbuilt_search_window=8192),
    FileSignature("ZIP / Office OpenXML / JAR / APK", "zip", "archive",
                  header=b"PK\x03\x04", footer=b"PK\x05\x06",
                  min_size=64, max_size=2 * _GB),
    FileSignature("Legacy Office (OLE2 compound file)", "doc", "document",
                  header=b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
                  min_size=512, max_size=2 * _GB),
    FileSignature("Rich Text Format", "rtf", "document",
                  header=b"{\\rtf", min_size=12, max_size=256 * _MB),
    FileSignature("Windows Registry Hive", "dat", "database",
                  header=b"regf", min_size=4096, max_size=512 * _MB),
    FileSignature("PCAP Packet Capture", "pcap", "document",
                  header=b"\xd4\xc3\xb2\xa1", min_size=24, max_size=2 * _GB),
    FileSignature("PCAP Packet Capture (nanosecond)", "pcap", "document",
                  header=b"\x4d\x3c\xb2\xa1", min_size=24, max_size=2 * _GB),
    FileSignature("PCAP (swapped byte order)", "pcap", "document",
                  header=b"\xa1\xb2\xc3\xd4", min_size=24, max_size=2 * _GB),
    FileSignature("PCAP Next-Generation Capture", "pcapng", "document",
                  header=b"\n\r\r\n", min_size=32, max_size=2 * _GB),

    # ---------------- archives & compression ----------------
    FileSignature("GZIP Archive", "gz", "archive",
                  header=b"\x1f\x8b\x08", min_size=32, max_size=2 * _GB),
    FileSignature("BZIP2 Archive", "bz2", "archive",
                  header=b"BZh", min_size=14, max_size=2 * _GB),
    FileSignature("XZ / LZMA Archive", "xz", "archive",
                  header=b"\xfd7zXZ\x00", min_size=24, max_size=2 * _GB),
    FileSignature("Zstandard Archive", "zst", "archive",
                  header=b"\x28\xb5\x2f\xfd", min_size=12, max_size=2 * _GB),
    FileSignature("7-Zip Archive", "7z", "archive",
                  header=b"7z\xbc\xaf'\x1c", min_size=64, max_size=2 * _GB),
    FileSignature("RAR Archive (v5)", "rar", "archive",
                  header=b"Rar!\x1a\x07\x01\x00", min_size=64, max_size=2 * _GB),
    FileSignature("RAR Archive (v4)", "rar", "archive",
                  header=b"Rar!\x1a\x07\x00", min_size=64, max_size=2 * _GB),
    FileSignature("tar Archive (ustar)", "tar", "archive",
                  header=b"ustar", min_size=1024, max_size=2 * _GB),
    FileSignature("LZ4 Frame", "lz4", "archive",
                  header=b"\x04\x22\x4d\x18", min_size=16, max_size=2 * _GB),

    # ---------------- databases ----------------
    FileSignature("SQLite Database", "sqlite", "database",
                  header=b"SQLite format 3\x00", min_size=512, max_size=4 * _GB),
    FileSignature("Berkeley DB Hash", "db", "database",
                  header=b"\x61\x15\x06\x00", min_size=4096, max_size=2 * _GB),
    FileSignature("Microsoft Access Database", "mdb", "database",
                  header=b"Standard Jet DB", min_size=512, max_size=2 * _GB),

    # ---------------- audio ----------------
    FileSignature("WAV Audio", "wav", "audio",
                  header=b"RIFF", min_size=64, max_size=2 * _GB,
                  inbuilt=b"WAVE", inbuilt_search_window=16),
    FileSignature("FLAC Lossless Audio", "flac", "audio",
                  header=b"fLaC", min_size=128, max_size=2 * _GB),
    FileSignature("OGG Container", "ogg", "audio",
                  header=b"OggS", min_size=64, max_size=2 * _GB),
    FileSignature("MIDI Sequence", "mid", "audio",
                  header=b"MThd", min_size=14, max_size=16 * _MB),
    FileSignature("AIFF Audio", "aiff", "audio",
                  header=b"FORM", min_size=64, max_size=2 * _GB,
                  inbuilt=b"AIFF", inbuilt_search_window=16),
    # MPEG audio: resolved by frame-sequence validation, never by a fixed size.
    FileSignature("MP3 Audio (MPEG-1 Layer III sync frame)", "mp3", "audio",
                  header=b"\xff\xfb", min_size=1024, max_size=256 * _MB),
    FileSignature("MP3 Audio (MPEG-1 Layer II sync frame)", "mp3", "audio",
                  header=b"\xff\xf5", min_size=1024, max_size=256 * _MB),
    FileSignature("MP3 Audio (MPEG-2 Layer III sync frame)", "mp3", "audio",
                  header=b"\xff\xf3", min_size=1024, max_size=256 * _MB),
    FileSignature("MP3 Audio (MPEG-2.5 Layer III sync frame)", "mp3", "audio",
                  header=b"\xe3", min_size=1024, max_size=256 * _MB),

    # ---------------- video ----------------
    FileSignature("MP4 / QuickTime / ISO-BMFF Container", "mp4", "video",
              # The ftyp box size varies with the compatible-brand list, so only
              # the box type is matched here; the boundary walker and the sample
              # table do the real work. See FileSignature.header_offset.
              header=b"ftyp", header_offset=4,
              min_size=128, max_size=16 * _GB),
    # `RIFF` alone is shared with WAV and WebP; the list type fourcc at offset 8
    # is what makes it an AVI. The inbuilt prefilter runs before the boundary
    # walk, so the shared magic costs one 16-byte compare.
    FileSignature("AVI Video (RIFF)", "avi", "video",
                  header=b"RIFF", inbuilt=b"AVI ", inbuilt_search_window=16,
                  min_size=256, max_size=16 * _GB),
    FileSignature("MPEG Transport Stream", "ts", "video",
                  header=b"G", min_size=188, max_size=64 * _GB),
    # Matroska and WebM share one 4-byte EBML magic, so one entry claims both
    # extensions and the boundary walk reads the DocType to tell them apart. A
    # 4-byte magic matters here: the DocType check does the real work, and a
    # 2-byte prefilter on `\x1a\x45` would hand every such candidate to a walk
    # that then reads 4 KiB to reject it.
    # The DocType string sits in the EBML header, so `inbuilt` disambiguates the
    # three extensions for the cost of one short compare, exactly as `AVI ` does
    # for RIFF. Without it all three signatures match every EBML file and the
    # first one in the table wins, so every WebM was being reported as `.mkv`.
    # It doubles as a filter: magic-bearing noise with no DocType is now rejected
    # in memory instead of costing a walk.
    FileSignature("Matroska Video (EBML)", "mkv", "video",
                  header=b"\x1a\x45\xdf\xa3", inbuilt=b"matroska",
                  inbuilt_search_window=64, min_size=1024, max_size=64 * _GB),
    FileSignature("WebM Video (EBML)", "webm", "video",
                  header=b"\x1a\x45\xdf\xa3", inbuilt=b"webm",
                  inbuilt_search_window=64, min_size=1024, max_size=64 * _GB),
    FileSignature("Matroska Audio (EBML)", "mka", "audio",
                  header=b"\x1a\x45\xdf\xa3", inbuilt=b"matroska",
                  inbuilt_search_window=64, min_size=512, max_size=16 * _GB),

    # ---------------- executables & system ----------------
    FileSignature("ELF Executable", "elf", "executable",
                  header=b"\x7fELF", min_size=128, max_size=2 * _GB),
    FileSignature("Windows PE Executable", "exe", "executable",
                  header=b"MZ", min_size=512, max_size=2 * _GB),
    FileSignature("Windows PE DLL", "dll", "executable",
                  header=b"MZ", min_size=512, max_size=2 * _GB),
    FileSignature("Mach-O 64-bit executable", "macho", "executable",
                  header=b"\xcf\xfa\xed\xfe", min_size=512, max_size=2 * _GB),
    FileSignature("Mach-O 64-bit executable (little endian)", "macho", "executable",
                  header=b"\xce\xfa\xed\xfe", min_size=512, max_size=2 * _GB),
    FileSignature("Java Class File", "class", "executable",
                  header=b"\xca\xfe\xba\xbe", min_size=20, max_size=64 * _MB),
    FileSignature("Windows LNK Shortcut", "lnk", "system",
                  header=b"L\x00\x00\x00\x01\x14\x02\x00", min_size=64, max_size=16 * _MB),
    FileSignature("Windows Prefetch", "pf", "system",
                  header=b"SCCA", min_size=64, max_size=4 * _MB),
    FileSignature("Windows Shortcut (DOS/Windows shell link)", "url", "system",
                  header=b"[InternetShortcut]", min_size=16, max_size=4 * _MB),
    FileSignature("Windows Desktop INI", "ini", "system",
                  header=b"[Desktop]", min_size=16, max_size=1024 * _MB),
]

# Extensions whose magic is only 2-4 bytes and therefore needs an inbuilt-string
# or structural gate to avoid shredding every image with false positives.
LOW_SPECIFICITY = {
    "exe", "dll", "ts", "lnk", "pf", "url", "ini", "class", "macho",
    "tiff", "heic", "jp2", "m4v", "ogg",
}

# Extensions the boundary resolver knows how to size exactly.
RESOLVABLE = {
    "jpg", "jpeg", "png", "gif", "bmp", "webp", "wav", "aiff", "pdf", "zip", "docx",
    "xlsx", "pptx", "7z", "mp3", "ogg", "flac", "mp4", "mov", "mkv", "webm", "m4v",
    "sqlite", "pcap", "pcapng", "gz", "tar", "elf", "exe", "dll", "rtf", "rar",
}

_SIGNATURES_BY_EXT: Dict[str, List[FileSignature]] = {}
for _sig in SIGNATURES:
    _SIGNATURES_BY_EXT.setdefault(_sig.extension, []).append(_sig)


def parse_hex_bytes(val: str | bytes) -> bytes:
    """Parse a hex string (with optional spaces or 0x prefixes) or raw bytes."""
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
        raise ValueError(
            f"Custom signature '{d.get('name', 'unnamed')}' requires valid non-empty header magic bytes"
        )
    ftr_val = d.get("footer") or d.get("footer_hex")
    footer = parse_hex_bytes(ftr_val) if ftr_val else None
    category = str(d.get("category") or "custom").lower()
    if category not in CATEGORIES:
        category = "custom"

    inbuilt_val = d.get("inbuilt") or d.get("inbuilt_hex")
    inbuilt = parse_hex_bytes(inbuilt_val) if inbuilt_val else None

    return FileSignature(
        name=str(d.get("name") or "Custom Signature"),
        extension=str(d.get("extension") or "bin").lower().lstrip("."),
        category=category,
        header=header,
        footer=footer,
        footer_offset_from_end=int(d.get("footer_offset_from_end", 0)),
        min_size=max(1, int(d.get("min_size", 64))),
        max_size=int(d.get("max_size", 256 * _MB)),
        fixed_size=int(d["fixed_size"]) if d.get("fixed_size") else None,
        inbuilt=inbuilt,
        inbuilt_search_window=int(d.get("inbuilt_search_window", 4096)),
    )


def get_signatures_by_ext(ext: str, custom_sigs: Optional[List[FileSignature]] = None) -> List[FileSignature]:
    """All signatures for an extension, custom definitions taking precedence."""
    clean = ext.lower().lstrip(".")
    if custom_sigs:
        custom = [s for s in custom_sigs if s.extension.lower().lstrip(".") == clean]
        if custom:
            return custom
    return list(_SIGNATURES_BY_EXT.get(clean, ()))


def get_signature_by_ext(ext: str, custom_sigs: Optional[List[FileSignature]] = None) -> Optional[FileSignature]:
    """The single best signature for an extension (used by structure-based recovery)."""
    found = get_signatures_by_ext(ext, custom_sigs)
    return found[0] if found else None


def supported_extensions() -> List[str]:
    """Every extension the carver can recognise, sorted."""
    return sorted({s.extension for s in SIGNATURES})


# Longest header first, so a PNG (8-byte magic) wins over a bare MZ.
# Longest magic first: the more bytes a signature pins down, the fewer
# candidates reach the (more expensive) structural validation.
_SNIFF_ORDER = sorted(SIGNATURES, key=lambda s: -len(s.header))


def sniff(data: bytes) -> Optional[FileSignature]:
    """Identify a buffer by content.

    Used for filesystem-native recoveries, where the metadata gives the exact
    length but the recovered payload is often classified as `bin` because the
    deleted directory entry no longer carries the name. Sniffing turns an
    anonymous blob into something an examiner can actually work with.
    """
    if not data:
        return None
    for sig in _SNIFF_ORDER:
        if data[sig.header_offset:sig.header_offset + len(sig.header)] == sig.header:
            if sig.inbuilt is not None:
                window = data[: max(sig.inbuilt_search_window, len(sig.inbuilt))]
                if sig.inbuilt not in window:
                    continue
            return sig
    return None
