"""Bodyfiles: byte ranges of an image, for handing to other tools.

A bodyfile is two decimal integers per line, ``start end``, zero-based and
inclusive. Most forensic tooling accepts one to say "only these byte ranges are
real data" or "only these ranges are interesting".

Two are worth producing from a carve, and they answer different questions.

**Recovered extents** -- where the recovered files actually are. Handing this to
another tool restricts it to what s0 already found, so a second opinion runs
over the same bytes rather than the whole volume again.

**Gap extents** -- the complement within the scanned range: everywhere s0 did
*not* recover a file. This is the more useful of the two for fragmented work,
because a fragmented file's damage is precisely a set of holes, and naming the
holes exactly is what lets another tool, or another pass, look only where
something is missing. For a two-fragment MP4 the gap bodyfile is the statement
"these N bytes of unrelated evidence sit between the index and the media", which
is the finding itself.

Everything is clipped to the range actually searched, and empty extents are
dropped, because a bodyfile with a zero-length or out-of-range row makes some
consumers reject the whole file.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from pathlib import Path

__all__ = ["normalise", "complement", "write_bodyfile", "read_bodyfile", "merge"]

Extent = tuple[int, int]  # inclusive start, inclusive end


def normalise(extents: Iterable[tuple[int, int]]) -> list[Extent]:
    """Sort, clip out empties, and merge overlapping or touching extents.

    Overlapping extents are normal after a fragmented recovery, and a bodyfile
    with overlaps is legal but confusing; merging keeps the file readable and the
    length accurate.
    """
    items: list[Extent] = []
    for e in extents:
        start, end = int(e[0]), int(e[1])
        if end < start:
            continue
        if end - start < 0:
            continue
        items.append((start, end))
    if not items:
        return []
    items.sort()
    merged: list[Extent] = [items[0]]
    for start, end in items[1:]:
        last_s, last_e = merged[-1]
        if start <= last_e + 1:
            if end > last_e:
                merged[-1] = (last_s, end)
        else:
            merged.append((start, end))
    return merged


def complement(extents: Sequence[tuple[int, int]], start: int, end: int) -> list[Extent]:
    """Return the parts of ``[start, end]`` not covered by ``extents``."""
    if end < start:
        return []
    covered = normalise(extents)
    out: list[Extent] = []
    cursor = start
    for s, e in covered:
        if e < start or s > end:
            continue
        s = max(s, start)
        e = min(e, end)
        if s > cursor:
            out.append((cursor, s - 1))
        if e + 1 > cursor:
            cursor = e + 1
    if cursor <= end:
        out.append((cursor, end))
    return out


def total_length(extents: Sequence[tuple[int, int]]) -> int:
    return sum(e - s + 1 for s, e in normalise(extents))


def write_bodyfile(path: Path, extents: Iterable[tuple[int, int]], comment: str = "") -> tuple[int, int]:
    """Write ``extents`` to ``path``. Returns ``(rows, bytes)``."""
    merged = normalise(extents)
    path = Path(path)
    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with open(path, "w", encoding="ascii") as fh:
        if comment:
            for line in str(comment).splitlines():
                fh.write(f"# {line}\n")
        for start, end in merged:
            fh.write(f"{start} {end}\n")
            written += 1
    return written, total_length(merged)


def read_bodyfile(path: Path) -> list[Extent]:
    """Read a bodyfile, ignoring blanks and ``#`` comments."""
    out: list[Extent] = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            raw = line.split("#", 1)[0].strip()
            if not raw:
                continue
            parts = raw.split()
            if len(parts) < 2:
                continue
            try:
                out.append((int(parts[0]), int(parts[1])))
            except ValueError:
                continue
    return normalise(out)


def merge(paths: Iterable[Path], destination: Path) -> tuple[int, int]:
    """Merge several bodyfiles into one."""
    allx: list[Extent] = []
    count = 0
    for p in paths:
        allx.extend(read_bodyfile(p))
        count += 1
    return write_bodyfile(destination, allx, comment=f"merged from {count} bodyfile(s)")
