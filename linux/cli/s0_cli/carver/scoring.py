"""s0 Module 2: forensic confidence scoring for carved candidates.

The scoring model deliberately separates three ideas that the previous model
conflated:

  1. **Identity**  -- is this byte range actually an instance of the claimed
     format?  This is a gate, not a score. :func:`boundary.validate_structure`
     answers it, and an ungated candidate is not recovered at any confidence.
  2. **Boundary confidence** -- how do we know where the file ends?  A length the
     format declares about itself is worth more than a footer that happened to
     match, which is worth more than a guess.
  3. **Plausibility** -- size sanity, entropy, and format-specific content checks.

Shannon entropy is used only as a *plausibility* signal here, never as a
false-positive filter. The old model used it the wrong way round: random noise
scores H ~= 8.0 and was rewarded with "+20 consistent with compressed media",
which is precisely how a 2 MiB block of entropy-matched garbage passed a 55%
threshold and drowned the genuine recoveries.
"""

from __future__ import annotations

import math
from typing import List, Tuple

from . import boundary
from .signatures import FileSignature

# Formats whose *correct* representation is low-entropy because they store
# uncompressed pixels, samples, text or structured tables rather than a
# compressed bitstream.
_UNCOMPRESSED = {
    "bmp", "wav", "aiff", "tar", "pcap", "pcapng", "sqlite", "rtf", "elf", "exe",
    "dll", "class", "macho", "tiff", "lnk", "pf", "url", "ini", "dat", "mid", "db",
    "mdb", "doc", "ts", "heic", "jp2",
}

# Boundary strategies, in descending order of evidentiary weight.
_BOUNDARY_WEIGHT = {
    boundary.DECLARED_SIZE: 25,
    boundary.CONTAINER_WALK: 25,
    boundary.FRAME_VALIDATED: 25,
    boundary.DECOMPRESSED: 23,
    boundary.FOOTER_ANCHORED: 18,
    boundary.MAX_SIZE_FALLBACK: 8,
    boundary.UNDETERMINED: 0,
}

_BOUNDARY_LABEL = {
    boundary.DECLARED_SIZE: "the format's own declared length",
    boundary.CONTAINER_WALK: "a clean container-structure walk",
    boundary.FRAME_VALIDATED: "a validated codec frame sequence",
    boundary.DECOMPRESSED: "the end of the decoded stream",
    boundary.FOOTER_ANCHORED: "a matching format terminator",
    boundary.MAX_SIZE_FALLBACK: "a heuristic guess (see note)",
}


def calculate_shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0.0 - 8.0)."""
    if not data:
        return 0.0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in freq:
        if count:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


def calculate_sample_entropy(data: bytes) -> float:
    """Entropy sampled at the start, middle and end of a candidate."""
    size = len(data)
    if size <= 8192:
        return calculate_shannon_entropy(data)
    s1 = data[:2048]
    mid = size // 2
    s2 = data[mid : mid + 2048]
    s3 = data[-2048:]
    return (calculate_shannon_entropy(s1) + calculate_shannon_entropy(s2) + calculate_shannon_entropy(s3)) / 3.0


def entropy_band(entropy: float) -> str:
    if entropy < 0.5:
        return "constant"
    if entropy < 3.0:
        return "low"
    if entropy < 6.0:
        return "medium"
    return "high"


# --------------------------------------------------------------------------- #
# scoring
# --------------------------------------------------------------------------- #


def score_carved_candidate(
    sig: FileSignature,
    data: bytes,
    has_valid_footer: bool = False,
    *,
    boundary_method: str = boundary.UNDETERMINED,
    boundary_notes: Tuple[str, ...] = (),
) -> Tuple[int, List[str]]:
    """Score a *structurally validated* candidate from 0 to 100.

    Callers must run :func:`boundary.validate_structure` first and discard the
    candidate if it fails; this function only ranks what already survived.

    Weights are deliberately lopsided. A candidate has already survived the two
    gates that actually matter -- it parses as the claimed format, and its end
    was independently resolved -- so 65 of the available 100 points come from
    those two facts alone. Entropy is capped at 15 and can never subtract, which
    is the fix for a class of bug this module used to have: a perfectly valid
    solid-colour PNG or a text tar was being discarded as "suspiciously low
    entropy" when it is simply a small, well-formed file. Content entropy is
    weak evidence; structural evidence is strong, and the scoring must reflect
    that.
    """
    score = 0
    heuristics: List[str] = []
    ext = sig.extension.lower().lstrip(".")

    # 1. Identity (40) -- assumed: the caller gated on structural validation.
    if data.startswith(sig.header):
        score += 40
        heuristics.append("Magic header confirmed and the payload parses as a structurally "
                          f"valid {sig.name} (+40)")

    # 2. Boundary confidence (25)
    weight = _BOUNDARY_WEIGHT.get(boundary_method, 0)
    if weight:
        score += weight
        heuristics.append(f"End of file established by {_BOUNDARY_LABEL[boundary_method]} (+{weight})")
        for note in boundary_notes:
            heuristics.append(f"  - {note}")
    elif has_valid_footer:
        score += 18
        heuristics.append("End of file established by a matching format terminator (+18)")
    else:
        heuristics.append("End of file was not independently resolvable (+0)")
        return max(0, score), heuristics

    # 3. Size plausibility (20)
    size = len(data)
    if sig.min_size <= size <= sig.max_size:
        score += 20
        heuristics.append(f"Size {size:,} B is within the expected range for this format (+20)")
    else:
        score = max(0, score - 10)
        heuristics.append(f"Size {size:,} B is outside the expected range for this format (-10)")

    # 4. Content entropy (15, never negative)
    entropy = calculate_sample_entropy(data)
    band = entropy_band(entropy)
    lo, hi = _entropy_expectation(sig.category, ext)
    if lo <= entropy <= hi:
        score += 15
        heuristics.append(f"Entropy {entropy:.2f}/8.0 ({band}) is typical for this format (+15)")
    elif entropy < 1.0:
        # Effectively constant: zero fill, repeated padding, or an unwritten
        # allocation. That is a real signal and the only one entropy may deny.
        # Random data sits near 8.0 and real content above 2.0, so a 1.0 cut is
        # unambiguous.
        score = max(0, score - 8)
        heuristics.append(f"Entropy {entropy:.2f}/8.0 is effectively constant: consistent "
                          "with padding or an unwritten allocation (-8)")
    else:
        score += 8
        heuristics.append(f"Entropy {entropy:.2f}/8.0 ({band}) is outside the typical "
                          f"{lo:.1f}-{hi:.1f} band for this format (+8)")

    return min(100, max(0, score)), heuristics


# Per (category, format) plausibility bands for Shannon entropy. Formats whose
# correct representation is uncompressed pixels, samples, text or structured
# tables sit far below the compressed-media band and must not be judged by it.
_ENTROPY_EXPECTATIONS = {
    ("image", "bmp"): (0.0, 7.2),
    ("image", "tiff"): (0.0, 8.01),
    ("audio", "wav"): (0.0, 7.4),
    ("audio", "aiff"): (0.0, 7.4),
    ("document", "rtf"): (1.0, 7.8),
    ("archive", "tar"): (0.0, 7.9),
}
_DEFAULT_EXPECTATION = {
    "image": (0.5, 8.01),
    "archive": (0.5, 8.01),
    "audio": (0.5, 8.01),
    "video": (3.5, 8.01),
    "document": (1.0, 7.9),
}


def _entropy_expectation(category: str, ext: str) -> Tuple[float, float]:
    key = (category, ext)
    if key in _ENTROPY_EXPECTATIONS:
        return _ENTROPY_EXPECTATIONS[key]
    if ext in _UNCOMPRESSED:
        return (0.0, 7.9)
    return _DEFAULT_EXPECTATION.get(category, (0.5, 8.01))


def rejection_reason(data: bytes, ext: str) -> str:
    """Return why a candidate was rejected, for the session report."""
    ok, reason = boundary.validate_structure(data, ext)
    return reason if not ok else ""
