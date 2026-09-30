"""RIFF containers, and the AVI index that makes them recoverable when split.

Why AVI is the friendliest container to carve
---------------------------------------------
A tool that only appends forward until it meets the next header scores 0 of 36 on
fragmented-out-of-order video across every format NIST tested. AVI is the
exception, and the reason is structural: the RIFF chunk chain **self-delimits**.
Every chunk is a FOURCC, a 32-bit size, and that many bytes, padded to an even
boundary, so a walker can always resynchronise -- including on the wrong order,
where the result still plays, which is why CFTT scored AVI and WMV as
"Viewable-Incomplete" rather than "Not Viewable" in its disorder test.

That self-delimiting property also makes AVI the cheapest place to prove a shared
index layer, so it goes first.

What the index adds
-------------------
``idx1`` (AVI 1.0) and the OpenDML ``indx``/``ix##`` super-index (AVI 2.0, for
files over 4 GiB or written in low-overhead mode) turn a chunk walk into a
self-describing inventory: every chunk's FOURCC, size, and keyframe flag, plus
its position. That is far stronger evidence than a container walk, and it is
what lets a physically split AVI be put back together.

Three traps, all documented in the AVI and OpenDML references, all of which
produce a plausible-looking wrong answer:

1. **The index offset base is ambiguous by design.** ``idx1`` ``dwOffset`` may
   be relative to the first byte of the ``movi`` fourcc, or absolute from the
   start of the file, and real files use both. :func:`resolve_index` does not
   guess: it tests both and keeps whichever puts the referenced FOURCCs where the
   index says they are.
2. **``ckSize`` excludes the 8-byte header and the payload is padded to a WORD
   boundary.** The next chunk is therefore at ``offset + 8 + size + (size & 1)``,
   not ``offset + size``. Getting this wrong desynchronises everything after it.
3. **``idx1`` points at chunk *headers*; OpenDML ``indx`` points at chunk
   *data*.** And OpenDML inverts the keyframe bit: ``dwSize`` bit 31 set means
   **not** a keyframe, the opposite of ``AVIIF_KEYFRAME``.

References: the Microsoft AVI RIFF File Reference, and the OpenDML 1.1
specification sections 3.1 and 3.2.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

__all__ = [
    "RiffError",
    "Chunk",
    "walk_chunks",
    "IndexEntry",
    "AviIndex",
    "find_movi",
    "parse_idx1",
    "parse_opendml_indx",
    "resolve_index",
    "AVIIF_LIST",
    "AVIIF_KEYFRAME",
]

#: The entry describes a LIST rather than a leaf chunk.
AVIIF_LIST = 0x00000001
#: The chunk is a keyframe.
AVIIF_KEYFRAME = 0x00000010
#: The chunk carries no time information (a palette change, say).
AVIIF_NO_TIME = 0x00000100

_CHUNK_HEADER = 8
#: Nesting cap for LIST/RIFF. Deeper than this in an AVI is a walk that has lost
#: the plot, not a structure.
_MAX_DEPTH = 6

#: FOURCCs an idx1 entry may legitimately point at when AVIIF_LIST is set.
_LIST_LIKE = (b"LIST", b"RIFF", b"JUNK", b"\x00\x00\x00\x00")


class RiffError(ValueError):
    """A chunk chain or index that cannot be trusted."""


@dataclass(frozen=True)
class Chunk:
    """One RIFF chunk or LIST header."""

    fourcc: bytes
    start: int          # offset of the FOURCC
    size: int           # payload size, excluding the 8-byte header
    depth: int = 0
    list_type: Optional[bytes] = None   # for LIST/RIFF, the type FOURCC at +8

    @property
    def payload_start(self) -> int:
        return self.start + _CHUNK_HEADER

    @property
    def list_type_offset(self) -> int:
        """Offset of a LIST's type FOURCC.

        This, not :attr:`start`, is what ``idx1`` offsets are relative to: the
        reference says "the position relatively to the first byte of the 'movi'
        identifier", and the identifier is the type FOURCC at ``start + 8``.
        """
        return self.start + _CHUNK_HEADER

    @property
    def children_start(self) -> int:
        return self.start + _CHUNK_HEADER + 4

    @property
    def next_offset(self) -> int:
        """Where the following sibling starts, honouring the WORD pad byte.

        Trap 2: the declared size is the payload only, and odd payloads are
        followed by a pad byte that is not counted in it.
        """
        return self.payload_start + self.size + (self.size & 1)

    @property
    def end(self) -> int:
        return self.next_offset


def walk_chunks(data: bytes, start: int, end: int, depth: int = 0) -> List[Chunk]:
    """List every chunk between ``start`` and ``end``, descending into LISTs.

    Raises :class:`RiffError` on a chunk that overruns its parent, because a
    silently-truncated walk produces a file that looks fine and is not.
    """
    if depth > _MAX_DEPTH:
        raise RiffError(f"chunk nesting deeper than {_MAX_DEPTH} levels")
    out: List[Chunk] = []
    pos = start
    while pos + _CHUNK_HEADER <= end:
        fourcc = data[pos:pos + 4]
        size = struct.unpack_from("<I", data, pos + 4)[0]
        nxt = pos + _CHUNK_HEADER + size + (size & 1)
        if nxt <= pos or nxt > end:
            # The only overrun a real file has is a final odd-sized chunk whose
            # pad byte is the last byte of its parent. Anything else means the
            # size field is not describing a chunk, and tolerating it would let
            # a walk wander to the end of the image and call the result a file.
            if pos + _CHUNK_HEADER + size != end:
                raise RiffError(
                    f"chunk {fourcc!r} at {pos} declares {size} bytes, "
                    f"overrunning its parent which ends at {end}")
        chunk = Chunk(fourcc, pos, size, depth)
        if fourcc in (b"LIST", b"RIFF"):
            chunk = Chunk(fourcc, pos, size, depth, data[pos + 8:pos + 12])
            if size >= 4 and pos + 12 <= end:
                out.extend(walk_chunks(data, pos + 12, min(pos + 8 + size, end),
                                       depth + 1))
        out.append(chunk)
        if nxt <= pos:
            break
        pos = nxt
    return out


def find_movi(chunks: List[Chunk]) -> Optional[Chunk]:
    """Return the top-level ``movi`` LIST, or ``None``."""
    for c in chunks:
        if c.fourcc == b"LIST" and c.list_type == b"movi":
            return c
    return None


# --------------------------------------------------------------------------- #
# AVI 1.0: idx1
# --------------------------------------------------------------------------- #

@dataclass
class IndexEntry:
    """One ``idx1`` row, or one OpenDML super-index row."""

    chunk_id: bytes
    flags: int
    offset: int          # as stored; relative or absolute, see resolve_index
    size: int
    base_is_absolute: bool = False

    @property
    def is_keyframe(self) -> bool:
        if self.base_is_absolute:
            # Trap 3: OpenDML inverts this. dwSize bit 31 clear means keyframe.
            return not (self.size & 0x80000000)
        return bool(self.flags & AVIIF_KEYFRAME)

    @property
    def is_list(self) -> bool:
        return bool(self.flags & AVIIF_LIST)

    @property
    def payload_size(self) -> int:
        return self.size & 0x7FFFFFFF


def parse_idx1(data: bytes, offset: int) -> List[IndexEntry]:
    """Parse an ``idx1`` box at ``offset``. Returns [] if it is not one.

    Each row is 16 bytes: ``dwChunkId``, ``dwFlags``, ``dwOffset``, ``dwSize``.
    """
    if offset + 8 > len(data) or data[offset:offset + 4] != b"idx1":
        return []
    size = struct.unpack_from("<I", data, offset + 4)[0]
    end = min(len(data), offset + 8 + size)
    entries: List[IndexEntry] = []
    pos = offset + 8
    while pos + 16 <= end:
        chunk_id = data[pos:pos + 4]
        flags, off, sz = struct.unpack_from("<III", data, pos + 4)
        entries.append(IndexEntry(chunk_id, flags, off, sz))
        pos += 16
    return entries


# --------------------------------------------------------------------------- #
# AVI 2.0: OpenDML indx / ix##
# --------------------------------------------------------------------------- #

def parse_opendml_indx(data: bytes, offset: int) -> List[IndexEntry]:
    """Parse an OpenDML ``indx`` super-index at ``offset``.

    Layout: a ``dwLongsPerEntry`` guard, ``dwIndexType``, ``dwChunkCount``, the
    reserved words, then ``dwBaseOffset`` and one 16-byte row per chunk.

    The rows carry the same four fields as ``idx1`` but with two differences
    that matter: ``dwOffset`` is relative to ``dwBaseOffset``, and bit 31 of
    ``dwSize`` means *not* a keyframe.
    """
    if offset + 8 > len(data) or data[offset:offset + 4] != b"indx":
        return []
    if offset + 40 > len(data):
        return []
    # Everything below is relative to the payload, which starts after the
    # fourcc and the size field.
    payload = offset + _CHUNK_HEADER
    longs, index_type, chunk_count = struct.unpack_from("<III", data, payload)
    if longs != 4 or index_type not in (0, 1):
        return []
    base = struct.unpack_from("<Q", data, payload + 24)[0]
    # dwLongsPerEntry(4) dwIndexType(4) dwChunkCount(4) dwReserved[3](12)
    # dwBaseOffset(8) = 32 bytes of header before the first row.
    entries: List[IndexEntry] = []
    pos = payload + 32
    end = min(len(data), payload + 32 + 16 * chunk_count)
    while pos + 16 <= end:
        chunk_id = data[pos:pos + 4]
        flags, off, sz = struct.unpack_from("<III", data, pos + 4)
        entries.append(IndexEntry(chunk_id, flags, base + off, sz, base_is_absolute=True))
        pos += 16
    return entries


# --------------------------------------------------------------------------- #
# Base resolution
# --------------------------------------------------------------------------- #

@dataclass
class AviIndex:
    """A resolved AVI chunk inventory."""

    entries: List[IndexEntry]
    base: int
    base_is_absolute: bool
    movi_start: Optional[int]
    keyframes: int = 0
    #: How the offset base was decided, and how well. This belongs in the
    #: recovery report: "which of the two documented bases did you assume, and
    #: what made you assume it" is the first question an examiner should ask of
    #: an index-driven recovery.
    resolution: str = ""
    problems: List[str] = field(default_factory=list)

    def extent(self, entry: IndexEntry) -> Tuple[int, int]:
        """Absolute ``(offset, length)`` of a referenced chunk's *header*."""
        return (entry.offset if self.base_is_absolute
                else self.base + entry.offset, entry.size)

    def media_extent(self) -> Tuple[int, int]:
        """``(first_offset, last_end)`` of all indexed chunks, or (0, 0)."""
        if not self.entries:
            return (0, 0)
        offs = []
        for e in self.entries:
            off = e.offset if self.base_is_absolute else self.base + e.offset
            offs.append((off, off + _CHUNK_HEADER + e.payload_size))
        return (min(o for o, _ in offs), max(n for _, n in offs))


def _fourcc_hits(data: bytes, entries: List[IndexEntry], base: int,
                 absolute: bool) -> int:
    """How many indexed entries land on a matching chunk header under one base.

    This is the discriminator between the two documented offset bases. It does
    not need to be right about every entry: the wrong base puts almost none of
    them on their own FOURCC, because the FOURCC is stored in the index row.
    """
    hits = 0
    for e in entries:
        off = e.offset if absolute else base + e.offset
        if off < 0 or off + 4 > len(data):
            continue
        got = data[off:off + 4]
        if got == e.chunk_id:
            hits += 1
        elif e.is_list and got in _LIST_LIKE:
            hits += 1
        elif e.is_list and data[off + 4:off + 8] == e.chunk_id:
            # The entry points at a LIST header whose type is the listed id.
            hits += 1
    return hits


def resolve_index(data: bytes, movi: Optional[Chunk],
                  entries: List[IndexEntry]) -> Optional[AviIndex]:
    """Decide whether ``entries`` are movi-relative or file-absolute.

    Trap 1: both are legal and real files use both, so this tests both and keeps
    whichever agrees with the data. Returns ``None`` when neither does, because
    an index that does not point at its own chunks is worse than no index.
    """
    if not entries:
        return None
    # Trap 1 again: the base is the offset of the "movi" identifier itself,
    # which sits 8 bytes into the LIST header.
    movi_start = movi.list_type_offset if movi is not None else None

    hits_rel = _fourcc_hits(data, entries, movi_start or 0, absolute=False)
    hits_abs = _fourcc_hits(data, entries, 0, absolute=True)
    total = len(entries)

    if hits_rel == 0 and hits_abs == 0:
        return None
    # A clear winner is required to claim a base. A tie means the index is
    # describing a layout this file does not have, and guessing would put every
    # chunk in the wrong place while looking entirely plausible.
    if hits_rel == hits_abs:
        return None

    if hits_rel > hits_abs:
        base, absolute = movi_start or 0, False
        resolution = (f"{hits_rel} of {total} index entries land on their own FOURCC "
                      f"when read relative to the movi identifier at {base}")
    else:
        base, absolute = 0, True
        resolution = (f"{hits_abs} of {total} index entries land on their own FOURCC "
                      "when read relative to the start of the file")

    keyframes = sum(1 for e in entries if e.is_keyframe)
    return AviIndex(entries=entries, base=base, base_is_absolute=absolute,
                    movi_start=movi_start, keyframes=keyframes, resolution=resolution)


def find_avi_index(data: bytes) -> Optional[AviIndex]:
    """Locate and resolve an AVI's chunk index, whichever kind it uses.

    Prefers OpenDML ``indx`` when present, because it is a stronger structure
    (a declared base offset and a declared entry count), and falls back to
    ``idx1``.
    """
    try:
        chunks = walk_chunks(data, 0, len(data))
    except (RiffError, struct.error):
        return None
    movi = find_movi(chunks)

    for c in chunks:
        if c.fourcc == b"indx":
            entries = parse_opendml_indx(data, c.start)
            idx = resolve_index(data, movi, entries)
            if idx is not None:
                return idx
    for c in chunks:
        if c.fourcc == b"idx1":
            entries = parse_idx1(data, c.start)
            idx = resolve_index(data, movi, entries)
            if idx is not None:
                return idx
    return None
