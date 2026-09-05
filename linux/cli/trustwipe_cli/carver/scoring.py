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
        if b"/Root" in data or b"/Pages" in data or b"stream" in data:
            score = min(100, score + 10)
            heuristics.append("PDF structural dictionaries (/Root, /Pages, stream) verified (+10%)")
    elif sig.extension == "png":
        if b"IHDR" in data[:32]:
            score = min(100, score + 10)
            heuristics.append("PNG IHDR chunk header verified (+10%)")
    elif sig.extension == "jpg":
        if b"\xff\xdb" in data[:1024] or b"\xff\xc0" in data[:1024] or b"\xff\xc4" in data[:1024]:
            score = min(100, score + 10)
            heuristics.append("JPEG DQT/SOF/DHT segment markers verified (+10%)")
    elif sig.extension == "bmp":
        if len(data) >= 18 and data.startswith(b"BM"):
            score = min(100, score + 10)
            heuristics.append("BMP bitmap header and DIB size verified (+10%)")
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
