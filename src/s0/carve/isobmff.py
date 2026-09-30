"""ISO base media file format: box parsing and sample-table arithmetic.

Why this module exists
----------------------
A carver that only walks top-level boxes can recover a video only when the file
is contiguous. Cameras fragment video across a card, and NIST's CFTT video suite
measured what that costs: 36 of 36 files recovered when contiguous, 12 of 36 when
fragmented in order, and **0 of 36 when fragmented out of order** -- for every
tool tested, because they all append forward until the next recognised header.

The `moov` box changes that. `stco`/`co64` hold *absolute file offsets* and
`stsz` holds *sample sizes*, so an intact `moov` describes exactly which bytes
belong to the file and in what order. No pixel comparison, no codec heuristics,
no reference file, no machine learning. That is a deterministic answer to the
one problem the whole literature treats as research.

Scope
-----
This module handles **progressive** MP4/MOV -- files with a populated sample
table. It deliberately does not handle fragmented MP4 (`moof`/`trun`), where the
sample tables in `moov` are empty by specification and every offset is relative
to the enclosing `moof`. See :func:`is_fragmented`.

Every index produced here is validated against the checks in
:func:`SampleTable.validate`, because a wrong answer from a sample table is
worse than no answer: it produces a file that plays and is not the evidence.

Reference: ISO/IEC 14496-12. Section numbers in comments are from that
document; the arithmetic in :meth:`SampleTable.sample_extent` follows the
decompression procedure it describes for the sample-to-chunk table.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Tuple

__all__ = [
    "BoxError",
    "Box",
    "iter_boxes",
    "find_box",
    "find_box_in",
    "SampleTable",
    "Track",
    "parse_moov",
    "is_fragmented",
    "remap_chunk_offsets",
    "chunk_extents",
    "Reassembly",
    "Fragment",
    "reassemble_two_fragment",
    "CONTAINER_BOXES",
]

#: Boxes whose payload is a list of child boxes rather than data.
CONTAINER_BOXES = frozenset({
    b"moov", b"trak", b"mdia", b"minf", b"stbl", b"dinf", b"edts", b"udta",
    b"mvex", b"moof", b"traf", b"mfra", b"skip", b"meta",
})

#: Boxes that carry no children despite looking like containers.
_LEAF_CONTAINERS = frozenset({b"meta"})

#: Guard against a corrupt size field sending a walk into the gigabytes.
_MAX_BOX_SIZE = 1 << 48


class BoxError(ValueError):
    """A box header or table that cannot be trusted."""


# --------------------------------------------------------------------------- #
# Box layer
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Box:
    """One box header and the byte range of its payload.

    ``type`` is the 4-byte box type. ``header_size`` is 8, 16 (64-bit extended
    size) or 12 (a FullBox prefix, which this layer does not strip).
    """

    type: bytes
    start: int          # absolute offset of the box's first byte
    header_size: int
    size: int           # total box size including the header
    payload_start: int
    payload_end: int

    @property
    def payload_size(self) -> int:
        return self.payload_end - self.payload_start

    @property
    def is_container(self) -> bool:
        return self.type in CONTAINER_BOXES and self.type not in _LEAF_CONTAINERS


def _read_header(buf: bytes, pos: int) -> Optional[Box]:
    """Parse one box header at ``pos`` in ``buf``, or return ``None`` if short."""
    if pos + 8 > len(buf):
        return None
    size = struct.unpack_from(">I", buf, pos)[0]
    btype = buf[pos + 4:pos + 8]
    header = 8
    if size == 1:
        if pos + 16 > len(buf):
            return None
        size = struct.unpack_from(">Q", buf, pos + 8)[0]
        header = 16
    elif size == 0:
        # Extends to the end of the enclosing container.
        size = len(buf) - pos
    if size < header or size >= _MAX_BOX_SIZE:
        raise BoxError(f"box at {pos} declares an implausible size {size}")
    if pos + size > len(buf):
        raise BoxError(f"box 0x{btype.decode('latin-1')} at {pos} overruns its container")
    return Box(btype, pos, header, size, pos + header, pos + size)


def iter_boxes(buf: bytes, start: int = 0, end: Optional[int] = None,
               depth: int = 0) -> Iterator[Box]:
    """Yield every box in ``buf[start:end]``, descending into containers.

    Raises :class:`BoxError` on a malformed header rather than yielding
    something plausible, because a silently-wrong box tree produces a silently
    wrong file.
    """
    if end is None:
        end = len(buf)
    pos = start
    while pos + 8 <= end:
        box = _read_header(buf, pos)
        if box is None:
            return
        yield box
        if box.is_container:
            yield from iter_boxes(buf, box.payload_start, box.payload_end, depth + 1)
        pos += box.size


def find_box(buf: bytes, box_type: bytes) -> Optional[Box]:
    """Return the first box of ``box_type`` anywhere in the tree, or ``None``."""
    for box in iter_boxes(buf):
        if box.type == box_type:
            return box
    return None


def find_box_in(source, start: int, end: int, box_type: bytes) -> Optional["BoxHeader"]:
    """Find a box by walking a :class:`s0.carve.boundary.ByteSource`.

    The carver resolves boundaries against a file handle rather than a bytes
    object, because a disk image does not fit in memory. The box types and the
    size rules are identical, so this walks headers by seeking instead of
    slicing, and returns the little that the caller needs to read the payload.
    """
    pos = start
    while pos + 8 <= end:
        head = source.read(pos, 8)
        if len(head) < 8:
            return None
        size = struct.unpack_from(">I", head, 0)[0]
        btype = head[4:8]
        header = 8
        if size == 1:
            ext = source.read(pos + 8, 8)
            if len(ext) < 8:
                return None
            size = struct.unpack(">Q", ext)[0]
            header = 16
        elif size == 0:
            size = end - pos
        if size < header or size >= _MAX_BOX_SIZE or pos + size > end:
            return None
        if btype == box_type:
            return BoxHeader(btype, pos, header, size)
        pos += size
    return None


@dataclass(frozen=True)
class BoxHeader:
    """Just enough of a box to read its payload: type, offset, header, size."""

    type: bytes
    start: int
    header_size: int
    size: int

    @property
    def payload_start(self) -> int:
        return self.start + self.header_size


# --------------------------------------------------------------------------- #
# Sample table layer
# --------------------------------------------------------------------------- #

def _fullbox_body(buf: bytes, pos: int, nbytes: int) -> bytes:
    """Return ``nbytes`` starting after a FullBox's 4-byte version/flags."""
    start = pos + 4
    if start + nbytes > len(buf):
        raise BoxError("table truncated")
    return buf[start:start + nbytes]


def _u32s(buf: bytes) -> List[int]:
    return list(struct.unpack(f">{len(buf) // 4}I", buf[:len(buf) // 4 * 4]))


@dataclass
class Track:
    """One track's sample table, reduced to what reassembly needs."""

    track_id: int
    handler: str                    # e.g. "vide", "soun"
    timescale: int
    sample_size: int                # 0 means "per-sample, see entry_sizes"
    sample_count: int
    entry_sizes: List[int] = field(default_factory=list)
    stsc: List[Tuple[int, int, int]] = field(default_factory=list)   # (first_chunk, spc, sdi)
    chunk_offsets: List[int] = field(default_factory=list)
    offsets_are_64bit: bool = False
    stts_sample_count: Optional[int] = None
    stts_delta_sum: int = 0
    sync_samples: Optional[List[int]] = None      # 1-based, as the spec stores them
    duration: int = 0

    # -- derived, filled in by validate() ------------------------------------
    samples_before_run: List[int] = field(default_factory=list)

    # -- public API ----------------------------------------------------------

    @property
    def is_variable_size(self) -> bool:
        return self.sample_size == 0

    def size_of(self, index: int) -> int:
        """Byte length of sample ``index`` (0-based)."""
        if not self.is_variable_size:
            return self.sample_size
        return self.entry_sizes[index]

    def prepare(self) -> None:
        """Compute the per-run sample prefix sums. Idempotent.

        Every run except the last has a bounded length given by the next run's
        first_chunk. The last run is open-ended in stsc, so its length comes
        from the chunk table: it covers chunks first_chunk..len(chunk_offsets).
        Getting that wrong makes a single-entry stsc -- by far the most common
        shape -- look like it describes zero samples.
        """
        if self.samples_before_run:
            return
        n_chunks = len(self.chunk_offsets)
        self.samples_before_run = []
        total = 0
        for k, (first_chunk, spc, _sdi) in enumerate(self.stsc):
            self.samples_before_run.append(total)
            if k + 1 < len(self.stsc):
                total += (self.stsc[k + 1][0] - first_chunk) * spc
            else:
                total += max(0, n_chunks - first_chunk + 1) * spc

    @property
    def samples_described(self) -> int:
        """How many samples the stsc and chunk tables account for together."""
        if not self.stsc:
            return 0
        self.prepare()
        last_chunk, last_spc, _ = self.stsc[-1]
        return (self.samples_before_run[-1]
                + max(0, len(self.chunk_offsets) - last_chunk + 1) * last_spc)

    def chunk_of(self, sample: int) -> Tuple[int, int, int]:
        """Return ``(run_index, chunk_number_1based, first_sample_in_chunk)``."""
        self.prepare()
        j = 0
        for k in range(1, len(self.samples_before_run)):
            if sample >= self.samples_before_run[k]:
                j = k
            else:
                break
        first_chunk, spc, _sdi = self.stsc[j]
        chunk = first_chunk + (sample - self.samples_before_run[j]) // spc
        first_sample = self.samples_before_run[j] + (chunk - first_chunk) * spc
        return j, chunk, first_sample

    def run_of_chunk(self, chunk_number: int) -> int:
        """Index of the stsc run that governs 1-based ``chunk_number``."""
        self.prepare()
        run = 0
        for k, (first_chunk, _spc, _sdi) in enumerate(self.stsc):
            if first_chunk <= chunk_number:
                run = k
            else:
                break
        return run

    def sample_extent(self, sample: int) -> Tuple[int, int]:
        """Return ``(offset_within_file, length)`` for sample ``sample``.

        The offset is cumulative within its chunk, so this is
        ``chunk_offset[chunk-1] + sum(sizes of preceding samples in the chunk)``.
        """
        _j, chunk, first_sample = self.chunk_of(sample)
        if chunk < 1 or chunk > len(self.chunk_offsets):
            raise BoxError(f"sample {sample} maps to chunk {chunk}, "
                           f"but the chunk table has {len(self.chunk_offsets)} entries")
        base = self.chunk_offsets[chunk - 1]
        if base < 0:
            raise BoxError(f"sample {sample} maps to chunk {chunk}, which has no offset")
        offset = base
        for k in range(first_sample, sample):
            offset += self.size_of(k)
        return offset, self.size_of(sample)

    def chunk_extent(self, chunk_index: int) -> Tuple[int, int]:
        """Return ``(offset, total_length)`` of chunk ``chunk_index`` (0-based).

        A chunk holds ``samples_per_chunk`` samples starting at the sample whose
        index we derive from the run that owns this chunk.
        """
        chunk_number = chunk_index + 1
        run = self.run_of_chunk(chunk_number)
        first_chunk, spc, _sdi = self.stsc[run]
        first_sample = self.samples_before_run[run] + (chunk_number - first_chunk) * spc
        total = 0
        for k in range(first_sample, first_sample + spc):
            if k >= self.sample_count:
                break
            total += self.size_of(k)
        return self.chunk_offsets[chunk_index], total

    @property
    def media_start(self) -> int:
        return min(self.chunk_offsets) if self.chunk_offsets else 0

    @property
    def media_end(self) -> int:
        """Byte just past the last sample.

        This is the value that matters. A truncated recording leaves a garbage or
        zero ``mdat`` size field, because the writer never got to patch it on
        close. The sample table still knows where the last sample ends.
        """
        if not self.chunk_offsets:
            return 0
        last = self.chunk_extent(len(self.chunk_offsets) - 1)
        return last[0] + last[1]


@dataclass
class SampleTable:
    """The whole of a file's sample tables, with every track validated."""

    tracks: List[Track]
    ftyp_offset: Optional[int] = None
    moov_offset: Optional[int] = None
    fragmented: bool = False
    problems: List[str] = field(default_factory=list)

    @property
    def media_start(self) -> int:
        vals = [t.media_start for t in self.tracks if t.chunk_offsets]
        return min(vals) if vals else 0

    @property
    def media_end(self) -> int:
        vals = [t.media_end for t in self.tracks if t.chunk_offsets]
        return max(vals) if vals else 0

    def validate(self, file_size: Optional[int] = None) -> Tuple[bool, List[str]]:
        """Check every track against the format's own invariants.

        Returns ``(ok, reasons)``. ``file_size`` is the size of the *original*
        file when known; pass ``None`` to check only internal consistency, which
        is the only option when the file is already known to be fragmented.
        """
        reasons: List[str] = []
        if self.fragmented:
            return False, ["file is fragmented MP4: moov sample tables are empty by "
                           "specification, so no index can be recovered from it"]
        if not self.tracks:
            return False, ["moov contains no track with a sample table"]

        for t in self.tracks:
            label = f"track {t.track_id} ({t.handler})"

            if t.sample_count == 0:
                reasons.append(f"{label}: declares zero samples")
                continue
            if not t.stsc:
                reasons.append(f"{label}: no sample-to-chunk table")
                continue
            if not t.chunk_offsets:
                reasons.append(f"{label}: no chunk offset table")
                continue
            if t.is_variable_size and len(t.entry_sizes) != t.sample_count:
                reasons.append(f"{label}: stsz declares {t.sample_count} samples but "
                               f"lists {len(t.entry_sizes)} sizes")
                continue
            if t.stts_sample_count is not None and t.stts_sample_count != t.sample_count:
                reasons.append(f"{label}: stts accounts for {t.stts_sample_count} samples "
                               f"but stsz declares {t.sample_count} -- this moov is not "
                               "the index for this data")
                continue

            # stsc.first_chunk must be strictly ascending and start at 1.
            if t.stsc[0][0] != 1:
                reasons.append(f"{label}: stsc first_chunk starts at {t.stsc[0][0]}, not 1")
                continue
            if any(t.stsc[k + 1][0] <= t.stsc[k][0] for k in range(len(t.stsc) - 1)):
                reasons.append(f"{label}: stsc first_chunk is not strictly ascending")
                continue
            if any(spc <= 0 for _fc, spc, _sdi in t.stsc):
                reasons.append(f"{label}: stsc declares a non-positive samples_per_chunk")
                continue

            described = t.samples_described
            if described < t.sample_count:
                reasons.append(f"{label}: stsc describes {described} samples, "
                               f"fewer than the {t.sample_count} stsz declares")
                continue

            if file_size is not None:
                if t.media_start < 0 or t.media_start >= file_size:
                    reasons.append(f"{label}: first chunk offset {t.media_start} is outside "
                                   f"the {file_size}-byte file")
                    continue
                if t.media_end > file_size:
                    reasons.append(f"{label}: last sample ends at {t.media_end}, past the "
                                   f"{file_size}-byte file end")
                    continue

        return (not reasons), reasons


def is_fragmented(buf: bytes, start: int = 0, end: Optional[int] = None) -> bool:
    """True if the file uses Movie Fragments rather than a populated sample table.

    ISO/IEC 14496-12 requires an ``mvex`` box in ``moov`` and forbids non-empty
    sample tables when fragments are expected. Checking for ``mvex`` first is
    more reliable than checking whether ``stsz`` happens to be empty, because a
    writer may emit either.
    """
    if end is None:
        end = len(buf)
    try:
        for box in iter_boxes(buf, start, end):
            if box.type == b"mvex":
                return True
    except BoxError:
        return False
    return False


def _parse_stsd_handler(buf: bytes, stsd: Box) -> str:
    """Best-effort handler type from a sample-description box."""
    if stsd.payload_size < 8:
        return ""
    try:
        # version/flags(4) entry_count(4) then a sample entry whose type is a
        # codec FourCC. Map the common ones to a track handler.
        first = _ascii4(buf, stsd.payload_start + 8)
    except Exception:
        return ""
    if first.startswith(b"avc") or first.startswith(b"hvc") or first in (
            b"hev1", b"hvc1", b"vp09", b"av01", b"mp4v", b"s263"):
        return "vide"
    if first in (b"mp4a", b"ac-3", b"ec-3", b"Opus", b"fLaC", b"alac"):
        return "soun"
    return ""


def _ascii4(buf: bytes, pos: int) -> bytes:
    return buf[pos:pos + 4]


def _parse_track(buf: bytes, trak: Box) -> Optional[Track]:
    """Build a :class:`Track` from a ``trak`` box, or ``None`` if it has no table."""
    tkhd = mdhd = hdlr = stbl = stsd = None
    for box in iter_boxes(buf, trak.payload_start, trak.payload_end):
        if box.type == b"tkhd" and tkhd is None:
            tkhd = box
        elif box.type == b"mdhd" and mdhd is None:
            mdhd = box
        elif box.type == b"hdlr" and hdlr is None:
            hdlr = box
        elif box.type == b"stsd" and stsd is None:
            stsd = box
        elif box.type == b"stbl" and stbl is None:
            stbl = box
    if stbl is None:
        return None

    track_id = 0
    if tkhd is not None and tkhd.payload_size >= 16:
        # Track Header Box layout, ISO/IEC 14496-12 section 8.8.4:
        #   version 0: flags(4) creation(4) modification(4) track_ID(4)   -> +12
        #   version 1: flags(4) creation(8) modification(8) track_ID(4)   -> +20
        version = buf[tkhd.payload_start]
        track_id = struct.unpack_from(">I", buf, tkhd.payload_start + (20 if version == 1 else 12))[0]

    timescale = 0
    duration = 0
    if mdhd is not None and mdhd.payload_size >= 4:
        version = buf[mdhd.payload_start]
        if version == 1 and mdhd.payload_size >= 32:
            timescale, duration = struct.unpack_from(">IQ", buf, mdhd.payload_start + 20)
        elif mdhd.payload_size >= 20:
            timescale, duration = struct.unpack_from(">II", buf, mdhd.payload_start + 12)

    handler = ""
    if hdlr is not None and hdlr.payload_size >= 12:
        handler = _ascii4(buf, hdlr.payload_start + 8).decode("latin-1", "replace")

    if not handler and stsd is not None:
        handler = _parse_stsd_handler(buf, stsd)

    track = Track(track_id=track_id, handler=handler, timescale=timescale,
                  sample_size=0, sample_count=0, duration=duration)

    for box in iter_boxes(buf, stbl.payload_start, stbl.payload_end):
        try:
            if box.type == b"stsz":
                body = _fullbox_body(buf, box.payload_start, 8)
                track.sample_size, track.sample_count = struct.unpack(">II", body)
                if track.sample_size == 0:
                    if track.sample_count > (1 << 24):
                        raise BoxError(f"stsz declares {track.sample_count} samples, "
                                       "which is not plausible")
                    raw = _fullbox_body(buf, box.payload_start + 8, 4 * track.sample_count)
                    track.entry_sizes = _u32s(raw)
            elif box.type == b"stsc":
                body = _fullbox_body(buf, box.payload_start, 4)
                n = struct.unpack(">I", body)[0]
                if n > (1 << 20):
                    raise BoxError(f"stsc declares {n} entries")
                raw = _fullbox_body(buf, box.payload_start + 4, 12 * n)
                vals = _u32s(raw)
                track.stsc = [tuple(vals[k:k + 3]) for k in range(0, len(vals), 3)]
            elif box.type in (b"stco", b"co64"):
                body = _fullbox_body(buf, box.payload_start, 4)
                n = struct.unpack(">I", body)[0]
                if n > (1 << 22):
                    raise BoxError(f"{box.type.decode()} declares {n} entries")
                width = 8 if box.type == b"co64" else 4
                raw = _fullbox_body(buf, box.payload_start + 4, width * n)
                if width == 8:
                    track.chunk_offsets = list(struct.unpack(f">{n}Q", raw))
                    track.offsets_are_64bit = True
                else:
                    track.chunk_offsets = _u32s(raw)
            elif box.type == b"stts":
                body = _fullbox_body(buf, box.payload_start, 4)
                n = struct.unpack(">I", body)[0]
                if n > (1 << 20):
                    raise BoxError(f"stts declares {n} entries")
                raw = _fullbox_body(buf, box.payload_start + 4, 8 * n)
                vals = _u32s(raw)
                track.stts_sample_count = 0
                track.stts_delta_sum = 0
                for k in range(0, len(vals), 2):
                    track.stts_sample_count += vals[k]
                    track.stts_delta_sum += vals[k] * vals[k + 1]
            elif box.type == b"stss":
                body = _fullbox_body(buf, box.payload_start, 4)
                n = struct.unpack(">I", body)[0]
                if n > (1 << 22):
                    raise BoxError(f"stss declares {n} entries")
                raw = _fullbox_body(buf, box.payload_start + 4, 4 * n)
                track.sync_samples = _u32s(raw)
        except BoxError:
            raise
        except (struct.error, IndexError) as exc:
            raise BoxError(f"malformed {box.type.decode()} in track {track_id}: {exc}") from exc

    if not track.chunk_offsets:
        return None
    return track


def parse_moov(buf: bytes, moov_offset: Optional[int] = None) -> SampleTable:
    """Parse every track's sample table out of a file's ``moov`` box.

    ``buf`` may be the whole file or just the ``moov`` box; ``moov_offset`` is
    only used to record provenance. Raises :class:`BoxError` if the ``moov``
    cannot be parsed at all.
    """
    moov = find_box(buf, b"moov")
    if moov is None:
        raise BoxError("no moov box found")
    if moov_offset is not None:
        moov_offset = moov_offset + moov.start

    tracks: List[Track] = []
    for box in iter_boxes(buf, moov.payload_start, moov.payload_end):
        if box.type != b"trak":
            continue
        try:
            t = _parse_track(buf, box)
        except BoxError:
            continue
        if t is not None:
            tracks.append(t)

    return SampleTable(
        tracks=tracks,
        ftyp_offset=None,
        moov_offset=moov_offset,
        fragmented=any(b.type == b"mvex" for b in iter_boxes(buf, moov.payload_start,
                                                             moov.payload_end)),
    )


# --------------------------------------------------------------------------- #
# Reassembly support
# --------------------------------------------------------------------------- #

def chunk_extents(table: SampleTable) -> List[Tuple[int, int, int]]:
    """Every media extent in the file, in file order.

    Returns ``(track_index, offset, length)`` triples sorted by offset. Chunks
    are the unit of reassembly rather than samples: a sample never spans a chunk
    boundary, and a fragment boundary in practice lands on a chunk boundary too.
    """
    out: List[Tuple[int, int, int]] = []
    for ti, t in enumerate(table.tracks):
        if not t.chunk_offsets or not t.stsc:
            continue
        for ci in range(len(t.chunk_offsets)):
            try:
                off, ln = t.chunk_extent(ci)
            except BoxError:
                continue
            if ln > 0:
                out.append((ti, off, ln))
    out.sort(key=lambda r: (r[1], r[2]))
    return out


def remap_chunk_offsets(file_bytes: bytes, table: SampleTable,
                        mapping: Dict[int, int]) -> bytes:
    """Return ``file_bytes`` with every chunk offset moved through ``mapping``.

    ``mapping`` translates an offset *within the original file* to an offset
    *within the new file*. This is the second half of reassembling a fragmented
    MP4: the samples are known exactly, but ``stco``/``co64`` still describe the
    old layout, so a concatenated file will not decode until the table is
    rewritten to match.

    Rewriting the table is the lesser evil. The alternative -- padding the gaps
    so the original offsets remain valid -- means inventing bytes, and for
    evidence that is not a trade worth making. What is emitted instead is
    accompanied by a record of which bytes came from where, so the rewrite is
    auditable rather than silent.

    Only tracks whose offsets all map are rewritten; a track with an unmapped
    offset is left alone and reported by the caller, because half-rewriting a
    file is worse than not rewriting it.
    """
    moov = find_box(file_bytes, b"moov")
    if moov is None:
        raise BoxError("no moov box to rewrite")

    # Collect the stco/co64 boxes to patch, innermost first, tracking byte paths
    # so each patch is applied to the correct copy of the box.
    patches: List[Tuple[int, int, int, int, int]] = []   # (box_start, count, width, table_start, track)
    for trak in _iter_children(file_bytes, moov.payload_start, moov.payload_end, b"trak"):
        stbl = _find_child(file_bytes, trak.payload_start, trak.payload_end, b"stbl")
        if stbl is None:
            continue
        track = _parse_track(file_bytes, trak)
        if track is None:
            continue
        for bx in _iter_children(file_bytes, stbl.payload_start, stbl.payload_end, b"stco"):
            patches.append((bx.payload_start + 8, len(track.chunk_offsets), 4, bx.payload_start + 8, 0))
        for bx in _iter_children(file_bytes, stbl.payload_start, stbl.payload_end, b"co64"):
            patches.append((bx.payload_start + 8, len(track.chunk_offsets), 8, bx.payload_start + 8, 0))

    out = bytearray(file_bytes)
    for table_start, count, width, _ts, _tk in patches:
        new_vals: List[int] = []
        for k in range(count):
            old = (struct.unpack_from(">I", out, table_start + 4 * k)[0] if width == 4
                   else struct.unpack_from(">Q", out, table_start + 8 * k)[0])
            if old not in mapping:
                new_vals = []
                break
            new_vals.append(mapping[old])
        if len(new_vals) != count:
            continue
        for k, v in enumerate(new_vals):
            if width == 4:
                if v > 0xFFFFFFFF:
                    raise BoxError("remapped offset does not fit in a 32-bit stco; "
                                   "the track would need promoting to co64")
                struct.pack_into(">I", out, table_start + 4 * k, v)
            else:
                struct.pack_into(">Q", out, table_start + 8 * k, v)
    return bytes(out)


def _iter_children(buf: bytes, start: int, end: int, box_type: bytes) -> Iterator[Box]:
    for bx in iter_boxes(buf, start, end):
        if bx.type == box_type:
            yield bx


def _find_child(buf: bytes, start: int, end: int, box_type: bytes) -> Optional[Box]:
    for bx in _iter_children(buf, start, end, box_type):
        return bx
    return None


# --------------------------------------------------------------------------- #
# Two-fragment reassembly
# --------------------------------------------------------------------------- #

@dataclass
class Fragment:
    """One physically contiguous piece of a reconstructed file.

    ``file_offset`` is where these bytes belong inside the recovered file;
    ``image_offset`` is where they actually are in the evidence. Keeping both is
    what makes the reconstruction auditable: an examiner can be told exactly
    which bytes of the image produced which bytes of the file, and what was
    between them.
    """

    file_offset: int
    image_offset: int
    length: int
    label: str


@dataclass
class Reassembly:
    """A file rebuilt from fragments that were not adjacent in the image."""

    payload: bytes
    fragments: List[Fragment]
    notes: List[str]

    @property
    def gap_bytes(self) -> int:
        """Bytes of unrelated evidence *in the image* between the fragments.

        Measured in image space, not file space. In the reconstructed file the
        fragments are adjacent by construction -- that is the whole point -- so
        a file-space measurement is always zero and says nothing.
        """
        if len(self.fragments) < 2:
            return 0
        f = sorted(self.fragments, key=lambda fr: fr.image_offset)
        return max(0, f[-1].image_offset - (f[0].image_offset + f[0].length))


def reassemble_two_fragment(source, start: int, table: SampleTable,
                            image_size: int, search_limit: int) -> Optional[Reassembly]:
    """Rebuild a camera-style fragmented MP4 from its two physical fragments.

    The shape this handles is the one every camera card actually produces, and
    the one PhotoRec's own documentation describes but leaves as a manual
    ``cat file2_ftyp.mov file1_mdat.mov``:

        image:  [ftyp][moov]  ......unrelated evidence......  [mdat][payload]
        file:   [ftyp][moov][mdat][payload]

    The two fragments were once adjacent, so **concatenating them reproduces the
    original file exactly** and every ``stco``/``co64`` offset is already
    correct. Nothing has to be rewritten, and no gap has to be filled with
    invented bytes. That is what makes this preferable to the alternative of
    padding the hole to keep the original offsets.

    Not handled: fragmentation *within* the media, a split index fragment, or
    three or more pieces. Those are real and unsolved; see the module docstring.

    Returns ``None`` when the evidence does not fit this shape, so the caller
    falls back to a contiguous carve unchanged.
    """
    if table.fragmented or not table.tracks:
        return None
    t = max(table.tracks, key=lambda tr: tr.sample_count)
    if not t.chunk_offsets:
        return None
    media_len = t.media_end - t.media_start
    if media_len <= 0:
        return None

    # The index fragment runs from the file start to the end of the last
    # top-level box before the mdat. "Last box" is not necessarily the moov:
    # ffmpeg's faststart muxer emits a `free` padding box between them, and
    # skipping it would put the mdat anchor one box too early.
    ftyp = moov = None
    index_end = start
    for box in _iter_top_level(source, start, min(image_size, start + (1 << 26))):
        if box.type == b"mdat":
            break
        if box.type == b"ftyp":
            ftyp = box
        elif box.type == b"moov":
            moov = box
        index_end = box.start + box.size
    if ftyp is None or moov is None or index_end <= start:
        return None

    # The decisive consistency check: the table must say the media begins
    # immediately after the index, because that is what "two adjacent fragments
    # that were once one file" means. If the media starts somewhere else inside
    # the file, this is a different kind of damage and must not be guessed at.
    if t.media_start != (index_end - start) + 8:
        return None

    head = source.read(start, index_end - start)
    if len(head) < index_end - start:
        return None

    # Find the mdat box that belongs to this file: its declared payload length
    # must be the media length the table predicts, so the box size must be
    # exactly media_len + 8 (or +16 for a 64-bit extended size).
    limit = min(search_limit, image_size)
    probe = source.read_until(b"mdat", index_end, limit - index_end)
    anchor = None
    while probe != -1:
        box_start = probe - 4
        raw = source.read(box_start, 8)
        if len(raw) == 8:
            size = struct.unpack_from(">I", raw, 0)[0]
            header = 8
            if size == 1:
                ext = source.read(box_start + 8, 8)
                if len(ext) == 8:
                    size = struct.unpack(">Q", ext)[0]
                    header = 16
            if size >= header and size - header == media_len and box_start + size <= image_size:
                anchor = (box_start, size)
                break
        probe = source.read_until(b"mdat", probe + 4, limit - (probe + 4))
    if anchor is None:
        return None

    box_start, size = anchor
    if box_start == index_end:
        # The mdat already follows the index: the file is contiguous and needs
        # no reassembly. Saying so lets the caller skip the work entirely.
        return None
    body = source.read(box_start, size)
    if len(body) != size:
        return None

    payload = head + body
    fragments = [
        Fragment(file_offset=0, image_offset=start,
                 length=index_end - start, label="index (ftyp + moov)"),
        Fragment(file_offset=index_end - start, image_offset=box_start,
                 length=size, label="media (mdat)"),
    ]
    gap = box_start - index_end
    notes = [
        f"reassembled from 2 physically separate fragments: index at image offset "
        f"{start} ({index_end - start} B) and media at image offset {box_start} "
        f"({size} B), with {gap} B of unrelated evidence between them",
        f"the mdat payload length matches the sample table exactly ({media_len} B), "
        "so the two fragments were once adjacent and no offset rewrite is needed",
        f"recovered original: track {t.track_id}, {t.sample_count} sample(s) in "
        f"{len(t.chunk_offsets)} chunk(s)",
    ]
    return Reassembly(payload=payload, fragments=fragments, notes=notes)


def _iter_top_level(source, start: int, end: int) -> Iterator["BoxHeader"]:
    """Yield top-level boxes by walking sizes forward from ``start``."""
    pos = start
    while pos + 8 <= end:
        head = source.read(pos, 8)
        if len(head) < 8:
            return
        size = struct.unpack_from(">I", head, 0)[0]
        btype = head[4:8]
        header = 8
        if size == 1:
            ext = source.read(pos + 8, 8)
            if len(ext) < 8:
                return
            size = struct.unpack(">Q", ext)[0]
            header = 16
        elif size == 0:
            size = end - pos
        if size < header or size >= _MAX_BOX_SIZE or pos + size > end:
            return
        yield BoxHeader(btype, pos, header, size)
        pos += size
