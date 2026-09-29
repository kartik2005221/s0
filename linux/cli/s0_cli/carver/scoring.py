"""Forensic Confidence Scoring Engine for Carved Files."""

from __future__ import annotations

import math
from typing import List, Tuple
from .signatures import FileSignature


def calculate_shannon_entropy(data: bytes) -> float:
    """Calculate Shannon Entropy (0.0 to 8.0 bits per byte)."""
    if not data:
        return 0.0
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1

    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def calculate_sample_entropy(data: bytes) -> float:
    """Calculate Shannon Entropy sampled across start, middle, and end."""
    size = len(data)
    if size <= 8192:
        return calculate_shannon_entropy(data)
    s1 = data[:2048]
    mid = size // 2
    s2 = data[mid : mid + 2048]
    s3 = data[-2048:]
    return (calculate_shannon_entropy(s1) + calculate_shannon_entropy(s2) + calculate_shannon_entropy(s3)) / 3.0


def validate_jpeg_structure(data: bytes) -> tuple[bool, str]:
    if len(data) < 4 or not data.startswith(b"\xff\xd8"):
        return False, "Not a valid JPEG SOI"
    if len(data) >= 4 and data[2] == 0xFF:
        marker = data[3]
        if marker in (0x00, 0xD8, 0xD9, 0xFF) or not (0xC0 <= marker <= 0xFE):
            return False, f"Invalid JPEG marker 0xFF{marker:02X} after SOI"
    has_known_marker = any(m in data[:1024] for m in (b"\xff\xe0", b"\xff\xe1", b"\xff\xdb", b"\xff\xc0", b"\xff\xc2", b"\xff\xc4", b"JFIF", b"Exif"))
    if not has_known_marker:
        return False, "No valid JPEG APP/DQT/SOF/DHT markers found"
    return True, "Valid JPEG marker sequence detected"


def validate_bmp_structure(data: bytes) -> tuple[bool, str]:
    if len(data) < 54 or not data.startswith(b"BM"):
        return False, "Too short for valid BMP header"
    reserved = int.from_bytes(data[6:10], "little")
    if reserved != 0:
        return False, f"BMP reserved field non-zero ({reserved})"
    dib_size = int.from_bytes(data[14:18], "little")
    if dib_size not in (12, 40, 52, 56, 64, 108, 124):
        return False, f"Invalid BMP DIB header size ({dib_size})"
    return True, "Valid BMP file header and DIB structure"


def validate_mp3_structure(data: bytes) -> tuple[bool, str]:
    if len(data) < 128:
        return False, "Too short for MP3"
    if data.startswith(b"ID3"):
        if len(data) < 10:
            return False, "Truncated ID3v2 header"
        major = data[3]
        if major not in (2, 3, 4):
            return False, f"Invalid ID3v2 major version ({major})"
        if any(b & 0x80 for b in data[6:10]):
            return False, "Invalid ID3v2 synchsafe tag size (top bits set)"
        return True, "Valid ID3v2 container header"
    if len(data) >= 4 and data[0] == 0xFF and (data[1] & 0xE0 == 0xE0):
        bitrate_idx = (data[2] >> 4) & 0x0F
        if bitrate_idx in (0x00, 0x0F):
            return False, f"Invalid MPEG frame bitrate index ({bitrate_idx})"
        sr_idx = (data[2] >> 2) & 0x03
        if sr_idx == 0x03:
            return False, "Reserved MPEG frame sample rate index"
        layer = (data[1] >> 1) & 0x03
        if layer == 0x00:
            return False, "Reserved MPEG layer"
        return True, "Valid MPEG audio frame header"
    return False, "No valid ID3v2 or MPEG sync frame detected"


def score_carved_candidate(
    sig: FileSignature,
    data: bytes,
    has_valid_footer: bool = False,
) -> Tuple[int, List[str]]:
    """Compute an objective forensic confidence score (0 to 100)."""
    score = 0
    heuristics: List[str] = []

    # 1. Header Validation (30 points)
    if data.startswith(sig.header):
        score += 30
        heuristics.append("Valid magic header bytes detected (+30%)")

    # 2. Footer / Terminator Validation (30 points)
    if has_valid_footer:
        score += 30
        heuristics.append("Valid format footer / trailer delimiter found (+30%)")
    elif sig.footer is None:
        score += 15
        heuristics.append("Header-only stream format validated (+15%)")

    # 3. Size Plausibility & Sanity (20 points)
    size = len(data)
    if sig.min_size <= size <= sig.max_size:
        score += 20
        heuristics.append(f"File size {size} bytes within plausible bounds (+20%)")
    else:
        heuristics.append(f"File size {size} bytes out of normal range (-10%)")
        score = max(0, score - 10)

    # 4. Entropy & Internal Structure Check (20 points)
    entropy = calculate_sample_entropy(data)

    if sig.category in ("image", "archive"):
        # Compressed media expected to have high entropy (6.0 - 8.0)
        if entropy >= 5.5:
            score += 20
            heuristics.append(f"High Shannon entropy ({entropy:.2f}/8.0) consistent with compressed media (+20%)")
        elif entropy >= 3.5:
            score += 10
            heuristics.append(f"Moderate Shannon entropy ({entropy:.2f}/8.0) (+10%)")
        else:
            heuristics.append(f"Suspiciously low entropy ({entropy:.2f}/8.0) for compressed media (possible zero fill)")
    elif sig.category == "document":
        # PDFs / text documents typically have 3.0 - 7.8 entropy
        if 3.0 <= entropy <= 7.8:
            score += 20
            heuristics.append(f"Shannon entropy ({entropy:.2f}/8.0) consistent with document structure (+20%)")
        elif entropy >= 1.5:
            score += 10
            heuristics.append(f"Moderate document entropy ({entropy:.2f}/8.0) (+10%)")
        else:
            heuristics.append(f"Suspiciously low entropy ({entropy:.2f}/8.0) for document (possible zero fill)")
    elif sig.category in ("executable", "audio", "video"):
        if 4.0 <= entropy <= 7.9:
            score += 20
            heuristics.append(f"Shannon entropy ({entropy:.2f}/8.0) consistent with {sig.category} binary (+20%)")
        elif entropy >= 2.0:
            score += 10
            heuristics.append(f"Moderate {sig.category} entropy ({entropy:.2f}/8.0) (+10%)")
        else:
            heuristics.append(f"Suspiciously low entropy ({entropy:.2f}/8.0) for {sig.category} (possible zero fill)")

    # Structure-specific checks
    if sig.extension == "pdf":
        if any(kw in data for kw in (b"/Root", b"/Pages", b"stream", b"obj", b"xref")):
            score = min(100, score + 10)
            heuristics.append("PDF structural dictionaries (/Root, /Pages, stream, obj) verified (+10%)")
        else:
            score = max(0, score - 30)
            heuristics.append("PDF missing structural dictionaries (-30%)")
    elif sig.extension == "png":
        if b"IHDR" in data[:32]:
            score = min(100, score + 10)
            heuristics.append("PNG IHDR chunk header verified (+10%)")
        else:
            score = max(0, score - 30)
            heuristics.append("PNG missing IHDR chunk header (-30%)")
    elif sig.extension == "jpg":
        ok, reason = validate_jpeg_structure(data)
        if not ok:
            score = max(0, score - 50)
            heuristics.append(f"JPEG structural anomaly: {reason} (-50%)")
        else:
            if b"\xff\xdb" in data[:1024] or b"\xff\xc0" in data[:1024] or b"\xff\xc4" in data[:1024] or b"JFIF" in data[:32] or b"Exif" in data[:32]:
                score = min(100, score + 10)
                heuristics.append("JPEG JFIF/Exif/DQT/SOF segment markers verified (+10%)")
    elif sig.extension == "bmp":
        ok, reason = validate_bmp_structure(data)
        if not ok:
            score = max(0, score - 50)
            heuristics.append(f"BMP structural anomaly: {reason} (-50%)")
        else:
            score = min(100, score + 10)
            heuristics.append("BMP bitmap header and DIB size verified (+10%)")
    elif sig.extension == "mp3":
        ok, reason = validate_mp3_structure(data)
        if not ok:
            score = max(0, score - 50)
            heuristics.append(f"MP3 structural anomaly: {reason} (-50%)")
        else:
            if data.startswith(b"ID3"):
                score = min(100, score + 10)
                heuristics.append("MP3 ID3v2 container structure verified (+10%)")
            else:
                score = max(0, score - 20)
                heuristics.append("MP3 raw sync frame without ID3 metadata (-20%)")
    elif sig.extension == "elf":
        if len(data) >= 5 and data.startswith(b"\x7fELF") and data[4] in (1, 2):
            score = min(100, score + 10)
            heuristics.append("ELF binary architecture header (32/64-bit) verified (+10%)")
    elif sig.extension == "sqlite":
        if len(data) >= 18 and data.startswith(b"SQLite format 3\x00"):
            score = min(100, score + 10)
            heuristics.append("SQLite database header format verified (+10%)")
    elif sig.extension == "zip":
        if b"PK\x01\x02" in data or b"PK\x05\x06" in data:
            score = min(100, score + 10)
            heuristics.append("ZIP central directory / EOCD marker verified (+10%)")
        else:
            score = max(0, score - 30)
            heuristics.append("ZIP missing central directory / EOCD records (-30%)")
    elif sig.extension == "gif":
        if len(data) >= 10 and data[:6] in (b"GIF87a", b"GIF89a"):
            score = min(100, score + 10)
            heuristics.append("GIF header and screen descriptor validated (+10%)")
    elif sig.extension == "gz":
        if len(data) >= 10 and data[:3] == b"\x1f\x8b\x08":
            score = min(100, score + 10)
            heuristics.append("GZIP Deflate header flags validated (+10%)")

    final_score = min(100, max(0, score))
    return final_score, heuristics
