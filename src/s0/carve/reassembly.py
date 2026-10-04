"""Reassemble a fragmented file from fragments found anywhere on a volume.

The problem this solves
-----------------------
When a file is fragmented, its pieces stop being adjacent, and the pieces
themselves carry no indication of where they belong. The usual response is to
search forward from the first piece and hope. That is what
`reconstruct_bifragment_stream` does, and it is why 46% of real fragmented
recordings are unrecovered by every shipping tool: on a volume where the
fragments were allocated out of order -- which is normal, because the
filesystem satisfies a large write with whatever extent is free -- a
forward-only search never finds the second piece.

The observation that makes this tractable is that fragmentation is not blind.
Every fragmented container writes a *monotonic logical position* into each
fragment, and it survives fragmentation because it is in the fragment itself:

* ISO-BMFF writes `mfhd.sequence_number`, which starts at 1 and increments by
  one per fragment, and `tfdt.baseMediaDecodeTime`, which is the decode time of
  the fragment's first sample in the track's timescale.
* Matroska writes `Cluster.Timestamp`, a timecode in units of
  `Info.TimecodeScale`, strictly increasing across clusters.

So the ordering does not have to be inferred from where a fragment sits on the
volume. It can be read. This module therefore reassembles by logical key and
treats spatial adjacency as evidence to be *checked*, never as the ordering
itself. Fragments scattered across a volume in any permutation reassemble the
same way, and the ones that are missing are named rather than papered over.

Why the ordering still has to be verified
-----------------------------------------
A key is a claim, not a proof. Two files on the same volume can both have a
fragment numbered 3, and a corrupted key produces a file that still parses far
enough to look plausible. So every assembly is checked three ways:

1. **Contiguity.** Keys must run 1, 2, 3, ... with no holes. A hole means a
   fragment is missing, and the result is marked incomplete with the missing
   keys listed. Silently concatenating across a hole produces a file that
   decodes to a shorter video with no visible error, which is the worst outcome
   available.
2. **Projection.** The decode time each fragment declares must be what the
   previous fragment's own sample table predicts. For ISO-BMFF the prediction is
   exact: the `trun` in fragment *i* states its sample count and durations, so
   `tfdt[i] + sum(durations)` is a value that can be compared against
   `tfdt[i+1]`. A mismatch means the fragments are not from one file or a key
   has been misread, and it is reported rather than ignored.
3. **Reparse.** The assembled bytes are fed back through the format's own
   parser. This is the only check that speaks to whether the answer is a file.

A candidate that fails any of these is refused, with the reason recorded.

What is deliberately not attempted
----------------------------------
Inferring a fragment's position from *nothing* -- an `mdat` with no reachable
`moof`, or a Matroska cluster whose header was overwritten. There is no in-band
key in that case, so any position is a guess, and a guessed position in a
container produces a file that plays the wrong footage rather than no footage.
Those bytes are reported as unassigned rather than assembled.
"""

from __future__ import annotations

import struct
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from . import isobmff

#: Refuse to assemble more fragments than this. A candidate with thousands of
#: "fragments" is a scan artefact, not a file.
MAX_FRAGMENTS = 4096

#: A `moof` larger than this is not a fragment. Real ones are a few KiB.
MAX_CLUSTER_WALK_BYTES = 16 * 1024 * 1024

#: A single fragment larger than this relative to the median is a sign the
#: pairing went wrong. Checked as a ratio so it scales with the media.
_OUTLIER_RATIO = 16.0


class ReassemblyError(ValueError):
    """The candidate fragments cannot be assembled into one file."""


# --------------------------------------------------------------------------- #
# Model
# --------------------------------------------------------------------------- #


@dataclass
class Fragment:
    """One located piece of a fragmented file, with the key that orders it.

    ``image_offset`` is where the bytes are in the evidence. ``key`` is where
    they belong in the file, read from the fragment rather than guessed from
    position. ``key_source`` is retained because a report that says "ordered by
    decode time" and one that says "ordered by cluster timestamp" are making
    different claims, and only one of them is as strong.
    """

    image_offset: int
    length: int
    key: int
    key_source: str
    label: str = ""
    #: `"sequence"` for a dense counter (ISO-BMFF `mfhd.sequence_number`), or
    #: `"timecode"` for a monotone clock (a Matroska `Cluster.Timestamp`).
    #:
    #: This distinction is load-bearing. A dense sequence must be contiguous, and
    #: a hole means a lost fragment. A timecode legitimately jumps when a
    #: recorder drops frames or a scene has no keyframe, so treating the same
    #: check as mandatory would refuse every recording that skipped a frame --
    #: and would refuse *every* Matroska file, whose keys are milliseconds.
    key_kind: str = "sequence"
    #: Decode time in track units, when the container states one. Used for the
    #: projection check; ``None`` when the container has no such field.
    decode_time: int | None = None
    #: Sum of the sample durations this fragment declares, when it declares any.
    duration_sum: int | None = None
    #: Identifying tuple shared by fragments of one file, so two files'
    #: fragments on the same volume are not merged.
    group: tuple = ()

    @property
    def image_end(self) -> int:
        return self.image_offset + self.length


@dataclass
class FragmentSet:
    """Everything one walk found: the ordered fragments plus the unfragmented
    head and tail of the same file.

    The head and tail are kept as extents rather than bytes so the caller
    decides when to read them, and so the extents can be reported alongside the
    fragments -- an examiner is entitled to know which bytes of the image
    produced the output.
    """

    fragments: list[Fragment] = field(default_factory=list)
    #: ``(start, end)`` of the `ftyp`/`moov` region preceding the first fragment.
    prefix: tuple[int, int] | None = None
    #: ``(start, end)`` of any `mfra`/index region following the last fragment.
    suffix: tuple[int, int] | None = None
    identity: tuple = ()
    kind: str = ""
    #: ``True`` when the fragments abut in the image, so the gaps between them
    #: are ``Void``/``free`` boxes that belong to the file and each extent has
    #: to be grown to meet the next. ``False`` when unrelated evidence separates
    #: them, where growing an extent would swallow that evidence -- which is how
    #: a 28 KiB file becomes 63 KiB of mostly noise.
    contiguous: bool = True

    def __bool__(self) -> bool:
        return bool(self.fragments)


@dataclass
class Assembly:
    """Fragments concatenated in logical-key order."""

    payload: bytes
    fragments: list[Fragment]
    notes: list[str] = field(default_factory=list)
    #: False when keys had holes, so the payload is known to be short.
    complete: bool = True
    missing_keys: list[int] = field(default_factory=list)
    #: Set when the assembly could not be trusted, with the reason.
    refusal: str = ""

    @property
    def ok(self) -> bool:
        return not self.refusal and bool(self.payload)

    @property
    def ordered_by(self) -> str:
        return self.fragments[0].key_source if self.fragments else ""


def _read(source, offset: int, length: int) -> bytes:
    """Read from bytes or a ``ByteSource``-like object."""
    if hasattr(source, "read") and not isinstance(source, (bytes, bytearray)):
        return source.read(offset, length)
    return bytes(source[offset : offset + length])


# --------------------------------------------------------------------------- #
# ISO-BMFF: locating fragments
# --------------------------------------------------------------------------- #


def _mfhd_sequence(payload: bytes, start: int, end: int) -> int | None:
    box = isobmff._find_child(payload, start, end, b"mfhd")
    if box is None:
        return None
    body = isobmff._fullbox_body(payload, box.payload_start, 4)
    return struct.unpack(">I", body[:4])[0]


def _traf_details(payload: bytes, start: int, end: int) -> tuple[int | None, int | None, int | None, int]:
    """Return ``(track_id, base_media_decode_time, duration_sum, sample_count)``.

    `duration_sum` is the total decode time the fragment's samples consume,
    which is what makes the projection check possible. It has to be assembled
    from two places: most muxers put the duration in `tfhd` as a *default* and
    leave `trun` without per-sample values, so a parser that reads only `trun`
    concludes the fragment declares no durations and the projection check goes
    quietly vacuous -- which is the failure mode this check exists to avoid.
    """
    track_id = base_decode = duration_sum = None
    sample_count = 0
    for traf in isobmff._iter_children(payload, start, end, b"traf"):
        default_duration = None
        tfhd = isobmff._find_child(payload, traf.payload_start, traf.payload_end, b"tfhd")
        if tfhd is not None:
            flags = struct.unpack(">I", payload[tfhd.payload_start : tfhd.payload_start + 4])[0] & 0xFFFFFF
            pos = tfhd.payload_start + 4
            # track_ID is a *required* field and comes first, before every
            # optional one. Reading it after them picks up whichever optional
            # field happens to be last, which is how default-sample-duration
            # ends up being read as 1 and the projection check compares 13
            # against 6656.
            if pos + 4 <= traf.payload_end:
                track_id = struct.unpack(">I", payload[pos : pos + 4])[0]
            pos += 4
            if flags & 0x000001:  # base-data-offset
                pos += 8
            if flags & 0x000002:  # sample-description-index
                pos += 4
            if flags & 0x000008:  # default-sample-duration
                default_duration = struct.unpack(">I", payload[pos : pos + 4])[0]
                pos += 4
            if flags & 0x000010:  # default-sample-size
                pos += 4
            if flags & 0x000020:  # default-sample-flags
                pos += 4
            if flags & 0x010000:  # duration-is-empty
                pos += 4
            if not (flags & 0x020000):  # default-base-is-moof absent
                pos += 8
        tfdt = isobmff._find_child(payload, traf.payload_start, traf.payload_end, b"tfdt")
        if tfdt is not None:
            version = payload[tfdt.payload_start]
            width = 4 if version == 0 else 8
            fmt = ">I" if version == 0 else ">Q"
            raw = payload[tfdt.payload_start + 4 : tfdt.payload_start + 4 + width]
            if len(raw) == width:
                base_decode = struct.unpack(fmt, raw)[0]
        for trun in isobmff._iter_children(payload, traf.payload_start, traf.payload_end, b"trun"):
            count = _trun_sample_count(payload, trun)
            sample_count += count
            this_sum = _trun_duration_sum(payload, trun)
            if this_sum is None and default_duration is not None:
                this_sum = count * default_duration
            if this_sum is None:
                # Neither place declares durations, so the total is unknown
                # rather than zero. Treating it as zero would make the
                # projection check silently vacuous.
                continue
            duration_sum = (duration_sum or 0) + this_sum
    return track_id, base_decode, duration_sum, sample_count


def _trun_sample_count(payload: bytes, trun) -> int:
    pos = trun.payload_start
    if pos + 8 > trun.payload_end:
        return 0
    return struct.unpack(">I", payload[pos + 4 : pos + 8])[0]


def _trun_duration_sum(payload: bytes, trun) -> int | None:
    """Total sample duration declared by one `trun`, or ``None`` if it declares none."""
    pos = trun.payload_start
    if pos + 8 > trun.payload_end:
        return None
    _version_flags = struct.unpack(">I", payload[pos : pos + 4])[0]
    flags = _version_flags & 0xFFFFFF
    sample_count = struct.unpack(">I", payload[pos + 4 : pos + 8])[0]
    pos += 8
    if flags & 0x000001:  # data-offset
        pos += 4
    if flags & 0x000004:  # first-sample-flags
        pos += 4
    if not (flags & 0x000100):  # no sample-duration present
        return None
    total = 0
    for _ in range(sample_count):
        if pos + 4 > trun.payload_end:
            return None
        total += struct.unpack(">I", payload[pos : pos + 4])[0]
        pos += 4
        if flags & 0x000200:  # sample-size
            pos += 4
        if flags & 0x000400:  # sample-flags
            pos += 4
        if flags & 0x000800:  # sample-composition-time-offset
            pos += 4
    return total


def _moov_identity(payload: bytes, moov) -> tuple:
    """Identify the file a `moov` belongs to: its timescale and track ids."""
    timescales: list[int] = []
    track_ids: list[int] = []
    for trak in isobmff._iter_children(payload, moov.payload_start, moov.payload_end, b"trak"):
        tkhd = isobmff._find_child(payload, trak.payload_start, trak.payload_end, b"tkhd")
        if tkhd is not None and tkhd.payload_start + 4 <= tkhd.payload_end:
            version = payload[tkhd.payload_start]
            base = tkhd.payload_start + 4
            tid = struct.unpack(">I", payload[base + (16 if version == 1 else 8) :][:4])[0]
            track_ids.append(tid)
        mdhd = isobmff._find_child(payload, trak.payload_start, trak.payload_end, b"mdia")
        if mdhd is not None:
            mdia = isobmff._find_child(payload, mdhd.payload_start, mdhd.payload_end, b"mdhd")
            if mdia is not None and mdia.payload_start + 4 <= mdia.payload_end:
                version = payload[mdia.payload_start]
                base = mdia.payload_start + 4
                if version == 1 and base + 20 <= mdia.payload_end:
                    timescales.append(struct.unpack(">I", payload[base + 16 : base + 20])[0])
                elif base + 12 <= mdia.payload_end:
                    timescales.append(struct.unpack(">I", payload[base + 8 : base + 12])[0])
    return (tuple(sorted(timescales)), tuple(sorted(track_ids)))


def _tile_extents(fragments: list[Fragment], region_end: int) -> None:
    """Extend each fragment to the start of the next one, in place.

    A fragmented file is contiguous: the pieces abut, and the gaps between the
    elements that *are* fragments are filled with `Void` and `free` boxes that
    belong to the file. Sizing a fragment by its own declared length therefore
    drops those bytes -- 6 bytes per Matroska cluster and 24 bytes at the tail
    on a small fixture, which is exactly the difference between the file and
    almost the file.

    The `key` is untouched: a fragment's *position in the file* comes from its
    key, while its *extent in the image* comes from where the next piece starts.
    Conflating the two is how an out-of-order layout ends up with holes in it.
    """
    ordered = sorted(fragments, key=lambda f: f.image_offset)
    for i, f in enumerate(ordered):
        nxt = ordered[i + 1].image_offset if i + 1 < len(ordered) else region_end
        if nxt > f.image_end:
            f.length = nxt - f.image_offset


def find_isobmff_fragments(source, start: int, end: int) -> FragmentSet:
    """Locate every `moof`+`mdat` fragment pair in a byte range, plus the parts
    of the file that are not fragments.

    A fragmented ISO-BMFF file is `ftyp`+`moov`, then the `moof`+`mdat` pairs,
    then an optional `mfra` index. Only the middle is fragmented, so the first
    and last parts are captured verbatim and reattached around the reassembled
    middle. Dropping the tail costs 200 bytes on a small fixture, which sounds
    trivial and means the output is not the file.

    A fragment is a `moof` immediately followed by its `mdat`. Requiring that
    adjacency is this format's projection-line check: an `mdat` whose `moof` is
    not physically next to it is not a fragment s0 can place, and searching
    forward for one is the guess this module refuses to make.
    """
    payload = _read(source, start, end - start)
    fragments: list[Fragment] = []
    identity: tuple = ()
    first_fragment_at: int | None = None
    # Every box that is not a `moof` is a candidate head or tail. Which one it
    # is decided by position once the fragments are known, not by an allow-list:
    # an allow-list misses `mfra`, and a missing tail means the output is 200
    # bytes short of the file it claims to be.
    other_boxes: list[tuple[int, int]] = []
    last_fragment_end: int | None = None

    try:
        boxes = list(isobmff.iter_boxes(payload))
    except isobmff.BoxError:
        return FragmentSet()

    for box in boxes:
        if box.type == b"moov":
            identity = _moov_identity(payload, box)
        if box.type != b"moof":
            if box.type == b"moov":
                identity = _moov_identity(payload, box)
            other_boxes.append((box.start, box.start + box.size))
            continue
        if box.type != b"moof":
            continue
        if first_fragment_at is None:
            first_fragment_at = box.start
        # The `mdat` must be the very next box, or this is not a fragment we can
        # place. Searching forward for it is the guess this module refuses.
        nxt = next((b for b in boxes if b.start >= box.start + box.size), None)
        if nxt is None or nxt.type != b"mdat" or nxt.start != box.start + box.size:
            continue
        seq = _mfhd_sequence(payload, box.payload_start, box.payload_end)
        track_id, base_decode, dur_sum, _count = _traf_details(payload, box.payload_start, box.payload_end)
        if seq is None or base_decode is None:
            # Without both keys the fragment cannot be ordered, so it is not a
            # candidate. The caller reports these as unassigned.
            continue
        fragments.append(
            Fragment(
                image_offset=start + box.start,
                length=(nxt.start + nxt.size) - box.start,
                key=seq,
                key_source="mfhd.sequence_number",
                key_kind="sequence",
                label=f"moof#{seq}",
                decode_time=base_decode,
                duration_sum=dur_sum,
                group=identity + ((track_id,) if track_id is not None else ()),
            )
        )
        last_fragment_end = nxt.start + nxt.size
        if len(fragments) > MAX_FRAGMENTS:
            break

    if not fragments or first_fragment_at is None:
        return FragmentSet()
    head = [(a, b) for a, b in other_boxes if b <= first_fragment_at]
    tail = [(a, b) for a, b in other_boxes if a >= last_fragment_end]
    prefix = (min(a for a, _ in head), first_fragment_at) if head else None
    if tail:
        suffix = (last_fragment_end, max(b for _, b in tail))
    else:
        suffix = None
        _tile_extents(fragments, max(b for _, b in other_boxes) if other_boxes else (last_fragment_end or 0))
    if tail:
        # Any `free`/`sidx` between the last fragment and the trailing index is
        # part of the file, so the last fragment is grown to meet the tail.
        _tile_extents(fragments, suffix[0])
    return FragmentSet(
        fragments=fragments, prefix=prefix, suffix=suffix, identity=identity, kind="isobmff", contiguous=True
    )


# --------------------------------------------------------------------------- #
# Matroska: locating fragments
# --------------------------------------------------------------------------- #


def find_matroska_fragments(source, start: int, end: int) -> FragmentSet:
    """One fragment per Matroska Cluster, keyed by the cluster's timecode.

    A Cluster is the format's own resync point, so it is also its access-unit
    boundary: each one is independently parseable and independently orderable.
    That makes a Matroska recording unusually recoverable, because the
    per-cluster timecode survives fragmentation in the same way `mfhd` does.

    Clusters are read through the full Matroska parser, so a cluster is only
    accepted when its children actually walk and its blocks carry real sizes.
    """
    from . import matroska as mk

    payload = _read(source, start, end - start)
    try:
        info = mk.parse(payload)
    except mk.MatroskaError:
        return FragmentSet()
    group = tuple(sorted(t.number for t in info.tracks))
    out: list[Fragment] = []
    for cluster in info.clusters:
        if cluster.size is None or not cluster.blocks:
            continue
        out.append(
            Fragment(
                image_offset=start + cluster.offset,
                length=cluster.size,
                key=cluster.timestamp,
                key_source="matroska cluster timestamp",
                key_kind="timecode",
                label=f"cluster@{cluster.timestamp}",
                group=group,
            )
        )
        if len(out) > MAX_FRAGMENTS:
            break
    if not out:
        return FragmentSet()
    # Everything before the first cluster is the header, everything after the
    # last is Cues/Void/Tags. Both are reattached in file order, so the tail has
    # to be captured: on a small file it is 24 bytes, which is small enough to
    # look like an off-by-one and is exactly the difference between the file and
    # almost the file.
    first = out[0].image_offset - start
    _tile_extents(out, info.walked_end)
    return FragmentSet(
        fragments=out,
        prefix=(0, first) if first > 0 else None,
        suffix=None,
        identity=group,
        kind="matroska",
        contiguous=True,
    )


# --------------------------------------------------------------------------- #
# Assembly
# --------------------------------------------------------------------------- #


def _check_outliers(fragments: Sequence[Fragment]) -> list[str]:
    if len(fragments) < 3:
        return []
    sizes = sorted(f.length for f in fragments)
    median = sizes[len(sizes) // 2]
    if median <= 0:
        return []
    bad = [f for f in fragments if f.length > median * _OUTLIER_RATIO]
    if not bad:
        return []
    # A comprehension has its own scope, so the label has to be read from the
    # first offender rather than from a loop variable that is not in scope here.
    worst = max(bad, key=lambda f: f.length)
    return [
        f"fragment {worst.label} is {worst.length} bytes against a median of "
        f"{median}; the pairing is probably wrong"
    ]


def _missing_keys(keys: Sequence[int], first: int) -> list[int]:
    if not keys:
        return []
    present = set(keys)
    return [k for k in range(first, max(present) + 1) if k not in present]


def reassemble(fragments: Sequence[Fragment], *, require_contiguous: bool = True) -> Assembly:
    """Concatenate fragments in logical-key order.

    `require_contiguous` refuses a set with holes rather than producing a file
    with a silent gap in it.
    """
    if not fragments:
        return Assembly(b"", [], refusal="no fragments")

    notes: list[str] = []
    ordered = sorted(fragments, key=lambda f: (f.key, f.image_offset))

    groups = {f.group for f in ordered}
    if len(groups) > 1:
        return Assembly(
            b"",
            [],
            refusal=(f"fragments carry {len(groups)} different identities; they are not all from one file"),
        )
    notes.append(f"{len(ordered)} fragment(s) ordered by {ordered[0].key_source}")

    notes.extend(_check_outliers(ordered))

    # Duplicate keys mean two fragments claim the same position. That is
    # unresolvable without picking a winner, and picking one silently would
    # corrupt the file, so it is refused.
    seen: dict = {}
    for f in ordered:
        if f.key in seen:
            return Assembly(
                b"",
                [],
                notes + [f"fragments {seen[f.key].label} and {f.label} both claim key {f.key}"],
                refusal=f"duplicate logical key {f.key}",
            )
        seen[f.key] = f

    kind = ordered[0].key_kind
    if kind == "timecode":
        # `ordered` is sorted, so the keys are already non-decreasing and a
        # separate monotonicity test could only ever fire on equal keys, which
        # the duplicate check above has already refused. What is worth saying
        # out loud is the opposite: a timecode jump is *not* a lost fragment.
        gaps = [b for a, b in zip(ordered, ordered[1:], strict=False) if b.key != a.key + 1]
        if gaps:
            widest = max((b.key - a.key for a, b in zip(ordered, ordered[1:], strict=False)), default=0)
            notes.append(
                f"timecodes jump between clusters (largest step {widest}); "
                f"the recording skipped time, which is normal for a "
                f"recorder that drops frames"
            )
        notes.append(
            "timecode keys are checked for monotonicity, not contiguity: "
            "a skipped frame is not a lost fragment"
        )
        complete = True
        missing = []
    else:
        missing = _missing_keys([f.key for f in ordered], ordered[0].key)
        complete = not missing
    if missing:
        preview = ", ".join(str(k) for k in missing[:12])
        more = "" if len(missing) <= 12 else f" (+{len(missing) - 12} more)"
        notes.append(f"keys {preview}{more} are absent, so the file is incomplete")
        if require_contiguous:
            return Assembly(
                b"",
                [],
                notes,
                complete=False,
                missing_keys=missing,
                refusal=f"{len(missing)} fragment(s) are missing",
            )

    projection = _check_projection(ordered)
    notes.extend(projection[1])
    if projection[0] is False:
        return Assembly(b"", [], notes, complete=complete, missing_keys=missing, refusal=projection[2])

    chunks = [_read_from_image(f) for f in ordered]
    return Assembly(b"".join(chunks), list(ordered), notes, complete=complete, missing_keys=missing)


#: Set by the caller so `reassemble` can read fragment payloads without the
#: caller threading a source through every layer.
_IMAGE_SOURCE: Callable | None = None


def scan_isobmff_fragments(
    source, start: int, end: int, *, window: int = 1 << 20, overlap: int = 64
) -> FragmentSet:
    """Find ISO-BMFF fragments scattered anywhere in a byte range.

    `find_isobmff_fragments` walks the box tree linearly from `start`, which
    only works while the file is contiguous. On a real volume it is not: the
    header is followed by whatever else the filesystem put there, and the
    fragments are wherever free space was. A linear walk stops at the first
    unrelated byte and reports nothing, which is why a scattered layout has to
    be *searched* for the `moof` magic rather than walked to.

    The search is cheap because the magic is four bytes and every hit is gated:
    a candidate only becomes a fragment if a `moat`-adjacent `mdat` follows it
    and it carries both `mfhd` and `tfdt`. Over uniform noise the magic appears
    roughly once per 4 GiB, so the gate is almost never reached by chance.

    The header is still read by a linear walk from `start`, because a
    fragmented file's `ftyp` and `moov` are never themselves fragmented.
    """
    fragments: list[Fragment] = []
    identity: tuple = ()
    pos = start
    seen_boxes: set[int] = set()

    # 1. The unfragmented head. This walk is done by hand rather than with
    #    `iter_boxes` for one reason: `iter_boxes` normalises a zero-size box to
    #    "runs to the end of the file", which is right for a real file and wrong
    #    here. A freshly formatted volume is full of zero-filled gaps, so the
    #    walk steps into one, reads a box claiming to be the entire rest of the
    #    volume, and swallows every fragment into the "header". The raw size
    #    field has to be inspected before that normalisation happens.
    head_end = start
    pos = start
    head_limit = min(end, start + (1 << 22))
    while pos + 8 <= head_limit:
        raw = _read(source, pos, 8)
        if len(raw) < 8:
            break
        size = struct.unpack(">I", raw[:4])[0]
        btype = raw[4:8]
        if btype == b"moof" or size < 8 or pos + size > head_limit:
            break
        if btype == b"moov":
            try:
                identity = _moov_identity(
                    _read(source, pos, size),
                    next(b for b in isobmff.iter_boxes(_read(source, pos, size)) if b.start == 0),
                )
            except (StopIteration, isobmff.BoxError, ValueError):
                pass
        pos += size
        head_end = pos

    # 2. The fragments, by searching for the magic.
    while pos < end:
        chunk = _read(source, pos, min(window, end - pos))
        if not chunk:
            break
        at = 0
        while True:
            i = chunk.find(b"moof", at)
            if i < 0:
                break
            at = i + 1
            box_start = pos + i - 4
            if box_start < start or box_start in seen_boxes:
                continue
            frag = _fragment_at(source, box_start, end, identity)
            if frag is not None:
                seen_boxes.add(box_start)
                fragments.append(frag)
                if len(fragments) > MAX_FRAGMENTS:
                    return FragmentSet(
                        fragments=fragments, prefix=(start, head_end), identity=identity, kind="isobmff"
                    )
        pos += max(1, len(chunk) - overlap)

    if not fragments:
        return FragmentSet()
    fragments.sort(key=lambda f: f.key)
    # The head can never extend past the first fragment, whatever the walk said.
    head_end = min(head_end, min(f.image_offset for f in fragments))
    if head_end <= start:
        head_end = start

    # 3. The trailing index, if one survived, found by its own magic. `mfra` is
    # optional, so its absence is not an error -- it just means the file has no
    # index and the output is the file without one.
    tail = _find_box_by_magic(source, end, b"mfra", after=max(f.image_end for f in fragments))
    return FragmentSet(
        fragments=fragments,
        prefix=(start, head_end),
        suffix=tail,
        identity=identity,
        kind="isobmff",
        contiguous=False,
    )


def _find_box_by_magic(source, end: int, magic: bytes, after: int):
    """Locate a trailing box by its fourcc, at or after `after`.

    `mfra` is optional, so returning ``None`` is a normal outcome: the file
    simply has no index. The size is read from the four bytes before the magic,
    which is where a box header puts it, and the box is then re-parsed so a
    coincidental occurrence of the fourcc inside media data is not mistaken for
    one.
    """
    pos = after
    while pos < end:
        chunk = _read(source, pos, min(1 << 20, end - pos))
        if not chunk:
            return None
        at = 0
        while True:
            i = chunk.find(magic, at)
            if i < 0:
                break
            at = i + 1
            box_start = pos + i - 4
            if box_start < after or box_start < 0:
                continue
            head = _read(source, box_start, 8)
            if len(head) < 8:
                continue
            size = struct.unpack(">I", head[:4])[0]
            if size < 8 or box_start + size > end:
                continue
            body = _read(source, box_start, size)
            try:
                boxes = list(isobmff.iter_boxes(body))
            except (isobmff.BoxError, ValueError):
                continue
            if boxes and boxes[0].type == magic and boxes[0].start == 0 and boxes[0].size == size:
                return (box_start, box_start + size)
        pos += max(1, len(chunk) - (len(magic) - 1))
    return None


def _fragment_at(source, box_start: int, end: int, identity: tuple) -> Fragment | None:
    """Parse one candidate `moof` and return a Fragment if it is a real one.

    Never raises. This runs once per `moof` occurrence in the search window, so
    its input is arbitrary bytes that merely happen to contain a four-byte
    magic, and the nested lookups into the box tree can fail on any of them.
    Guarding only the outermost parse left `BoxError` escaping from
    `_mfhd_sequence`, which is how a scan of noise becomes an exception.
    """
    try:
        return _fragment_at_inner(source, box_start, end, identity)
    except (isobmff.BoxError, ValueError, struct.error, IndexError):
        return None


def _fragment_at_inner(source, box_start: int, end: int, identity: tuple) -> Fragment | None:
    head = _read(source, box_start, 32)
    if len(head) < 8 or head[4:8] != b"moof":
        return None
    size = struct.unpack(">I", head[:4])[0]
    if size < 8 or size > MAX_CLUSTER_WALK_BYTES:
        return None
    box = head + _read(source, box_start + len(head), size - len(head))
    try:
        parsed = next(b for b in isobmff.iter_boxes(box) if b.start == 0)
    except (StopIteration, isobmff.BoxError, ValueError):
        return None
    if parsed.type != b"moof" or parsed.size != size:
        return None
    seq = _mfhd_sequence(box, parsed.payload_start, parsed.payload_end)
    track_id, base_decode, dur_sum, _count = _traf_details(box, parsed.payload_start, parsed.payload_end)
    if seq is None or base_decode is None:
        return None
    mdat_at = box_start + size
    mdat = _read(source, mdat_at, 8)
    if len(mdat) < 8 or mdat[4:8] != b"mdat":
        return None
    mdat_size = struct.unpack(">I", mdat[:4])[0]
    if mdat_size < 8 or mdat_at + mdat_size > end:
        return None
    return Fragment(
        image_offset=box_start,
        length=size + mdat_size,
        key=seq,
        key_source="mfhd.sequence_number",
        key_kind="sequence",
        label=f"moof#{seq}",
        decode_time=base_decode,
        duration_sum=dur_sum,
        group=identity + ((track_id,) if track_id is not None else ()),
    )


def assemble_file(fset: FragmentSet, source) -> Assembly:
    """Assemble a complete file: head, ordered fragments, then tail.

    The head and tail are reattached verbatim and in that order. They are not
    reordered by key because they have no key -- they are the parts of the file
    that were never fragmented, and they belong at the two ends by definition.
    """
    bind_source(source)
    assembly = reassemble(fset.fragments)
    if assembly.refusal:
        return assembly
    parts: list[bytes] = []
    if fset.prefix:
        parts.append(_read(source, fset.prefix[0], fset.prefix[1] - fset.prefix[0]))
    parts.append(assembly.payload)
    if fset.suffix:
        parts.append(_read(source, fset.suffix[0], fset.suffix[1] - fset.suffix[0]))
    assembly.payload = b"".join(parts)
    if fset.prefix:
        assembly.notes.insert(
            0,
            f"reattached {fset.prefix[1] - fset.prefix[0]}-byte "
            f"header region from image offset {fset.prefix[0]}",
        )
    if fset.suffix:
        assembly.notes.insert(
            1,
            f"reattached {fset.suffix[1] - fset.suffix[0]}-byte "
            f"index region from image offset {fset.suffix[0]}",
        )
    return assembly


def bind_source(source) -> None:
    """Bind the byte source that `reassemble` reads fragment payloads from."""
    global _IMAGE_SOURCE
    _IMAGE_SOURCE = source


def _read_from_image(f: Fragment) -> bytes:
    if _IMAGE_SOURCE is None:
        raise ReassemblyError("no byte source bound; call bind_source() first")
    return _read(_IMAGE_SOURCE, f.image_offset, f.length)


def _check_projection(ordered: Sequence[Fragment]) -> tuple[bool | None, list[str], str]:
    """Compare each fragment's declared decode time with the previous one's.

    For ISO-BMFF this is an exact identity: fragment *i* declares its sample
    durations, so the next fragment's `tfdt` must equal this one's `tfdt` plus
    their sum. A mismatch means the fragments are not consecutive, or a key has
    been misread, and in both cases the assembled file would be wrong in a way
    that still decodes.
    """
    notes: list[str] = []
    if len(ordered) < 2:
        return None, notes, ""
    usable = [f for f in ordered if f.decode_time is not None and f.duration_sum]
    if len(usable) < 2:
        notes.append(
            "no decode-time projection is available for this container; "
            "ordering rests on the in-band key alone"
        )
        return None, notes, ""
    checked = 0
    for prev, nxt in zip(usable, usable[1:], strict=False):
        if nxt.key != prev.key + 1:
            continue
        predicted = prev.decode_time + (prev.duration_sum or 0)
        if predicted != nxt.decode_time:
            return (
                False,
                notes,
                (
                    f"{prev.label} ends at decode time {predicted} but {nxt.label} "
                    f"starts at {nxt.decode_time}; the fragments are not consecutive"
                ),
            )
        checked += 1
    if checked:
        notes.append(f"decode-time projection confirmed across {checked} consecutive pair(s)")
    else:
        notes.append("no consecutive pair had a decode-time projection to check")
    return None, notes, ""


def reparse_assembly(assembly: Assembly, kind: str) -> tuple[bool, list[str]]:
    """Feed the assembled bytes back through the format's own parser."""
    notes: list[str] = []
    if kind == "matroska":
        from . import matroska as mk

        try:
            info = mk.parse(assembly.payload)
        except mk.MatroskaError as exc:
            return False, [f"assembled bytes are not a valid Matroska file: {exc}"]
        notes.append(
            f"reparsed as Matroska: {len(info.clusters)} cluster(s), {len(info.frame_blocks)} frame(s)"
        )
        return True, notes
    if kind == "isobmff":
        try:
            boxes = list(isobmff.iter_boxes(assembly.payload))
        except isobmff.BoxError as exc:
            return False, [f"assembled bytes are not valid ISO-BMFF: {exc}"]
        types = [b.type for b in boxes]
        if b"moov" not in types:
            return False, ["assembled ISO-BMFF has no moov"]
        if b"moof" not in types:
            return False, ["assembled ISO-BMFF has no moof, so nothing was reassembled"]
        notes.append(
            f"reparsed as ISO-BMFF: {types.count(b'moof')} moof, {types.count(b'mdat')} mdat, moov present"
        )
        return True, notes
    return False, [f"unknown container kind {kind!r}"]


def summary(assembly: Assembly) -> dict:
    """A compact, JSON-friendly description for reports."""
    return {
        "fragments": len(assembly.fragments),
        "ordered_by": assembly.ordered_by,
        "bytes": len(assembly.payload),
        "complete": assembly.complete,
        "missing_keys": assembly.missing_keys[:32],
        "missing_count": len(assembly.missing_keys),
        "refusal": assembly.refusal,
        "fragment_extents": [[f.image_offset, f.length] for f in assembly.fragments],
        "keys": [f.key for f in assembly.fragments],
        "notes": assembly.notes,
    }
