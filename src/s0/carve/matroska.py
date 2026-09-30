"""Matroska and WebM: exact boundaries and real frame extents.

Why this format is worth a dedicated carver
------------------------------------------
Matroska has no file-length field anywhere. MP4 can declare its length in the
box header and AVI in the RIFF size, but a Matroska file is a list of clusters
with no total, so "where does this file end" is a real question rather than a
field read. That makes it a poor signature carver and a good structural one: the
clusters carry declared sizes, so the end can be *derived* rather than guessed.

Three shapes have to work, because they are what actually exists in the wild:

* **Segment with a declared size** -- what a muxer writing to a seekable file
  produces. The end is arithmetic.
* **Unknown-size Segment** -- what a muxer writing to a pipe or a growing file
  produces, and what most in-car camera recorders emit. The end has to come
  from the clusters.
* **Unknown-size Cluster** -- a live muxer cannot know how large the cluster it
  is currently filling will be. The cluster ends where the next element ID
  appears, which is a different question and is answered structurally.

A carver that only handles the first shape recovers nothing from a fragmented
recording, which is the case an examiner most wants.

The `moov`-equivalent here is not a table: frame boundaries are *inline*. Every
`SimpleBlock` declares its own size, so the set of frame extents is recovered by
reading the blocks rather than by consulting an index. `Cues` is a seek
convenience, not a length source, and is never used to derive an end: it is
optional, it is written last, and a truncated file's cues are exactly the part
most likely to be gone.

What is deliberately not attempted
----------------------------------
Recovering frames whose cluster header was overwritten. Matroska's resync story
is genuinely good -- `Cluster`/`SimpleBlock` IDs are strong in-band anchors --
but reconstructing a cluster's contents without its header means guessing at
lacing and reference flags, and a wrong guess produces a file that decodes to
plausible garbage. That belongs to the fragmented-reassembly work, where the
allocation-unit and cluster-alignment evidence exists to constrain the guess.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

# --------------------------------------------------------------------------- #
# Element IDs
# --------------------------------------------------------------------------- #

EBML_HEADER = 0x1A45DFA3
SEGMENT = 0x18538067
SEEK_HEAD = 0x114D9B74
INFO = 0x1549A966
TRACKS = 0x1654AE6B
CLUSTER = 0x1F43B675
CUES = 0x1C53BB6B
TAGS = 0x1254C367
CHAPTERS = 0x1043A770
ATTACHMENTS = 0x1941A469
VOID = 0xEC
CRC32 = 0xBF

TRACK_ENTRY = 0xAE
TRACK_NUMBER = 0xD7
TRACK_TYPE = 0x83
CODEC_ID = 0x86
CODEC_PRIVATE = 0x63A2
VIDEO = 0xE0
PIXEL_WIDTH = 0xB0
PIXEL_HEIGHT = 0xBA
DISPLAY_WIDTH = 0x54B0
DISPLAY_HEIGHT = 0x54BA

TIMESTAMP = 0xE7
SIMPLE_BLOCK = 0xA3
BLOCK_GROUP = 0xA0
BLOCK = 0xA1
BLOCK_DURATION = 0x9B
REFERENCE_BLOCK = 0xFB

DOCTYPE = 0x4282
DOCTYPE_VERSION = 0x4287
DOCTYPE_READ_VERSION = 0x4285
TIMECODE_SCALE = 0x2AD7B1
DURATION = 0x4489
MUXING_APP = 0x4D80
WRITING_APP = 0x5741

CUE_POINT = 0xBB
CUE_TIME = 0xB3
CUE_TRACK_POSITIONS = 0xB7
CUE_CLUSTER_POSITION = 0xF1

#: Elements whose payload is a list of further elements.
MASTER_IDS = frozenset({
    EBML_HEADER, SEEK_HEAD, INFO, TRACKS, CLUSTER, CUES, TAGS, CHAPTERS,
    ATTACHMENTS, TRACK_ENTRY, BLOCK_GROUP, VIDEO, CUE_POINT,
    CUE_TRACK_POSITIONS,
})

#: Elements permitted as direct children of a Segment. This list is the main
#: defence against a false end, and it exists because of a measured failure: a
#: run of 0x5a padding parses as element 0x5A5A with a size of 6746, which fits
#: inside any carve window, so a walk that only checks "does the next element
#: fit" walks straight through the end of the file and reports 6,750 bytes of
#: padding as media.
#:
#: Requiring a known top-level ID costs nothing on real files, because a
#: conforming muxer only writes these. A future element ID would end the walk
#: early rather than over-run, which fails towards a short file and a note
#: instead of a long file that decodes to nothing.
TOP_LEVEL_IDS = frozenset({
    SEEK_HEAD, INFO, TRACKS, CLUSTER, CUES, TAGS, CHAPTERS, ATTACHMENTS,
    VOID, CRC32,
})

#: Elements permitted inside a Cluster. Unlisted IDs end the block count for
#: that cluster, which is the conservative direction: it can only reduce the
#: frame count, never invent one.
CLUSTER_CHILD_IDS = frozenset({
    TIMESTAMP, SIMPLE_BLOCK, BLOCK_GROUP, VOID, CRC32,
    0xA7,   # Position
    0xAB,   # PrevSize
    0xA7 + 0x100,  # Reserved
    0xA0 + 0x100,  # SilentTracks
    0xA1 + 0x100,  # Reserved
})

#: Track types, per the Matroska specification.
TRACK_VIDEO = 1
TRACK_AUDIO = 2
TRACK_COMPLEX = 3
TRACK_LOGO = 0x10
TRACK_SUBTITLE = 0x11
TRACK_BUTTON = 0x12
TRACK_CONTROL = 0x20

_TRACK_TYPE_NAMES = {
    TRACK_VIDEO: "video",
    TRACK_AUDIO: "audio",
    TRACK_COMPLEX: "complex",
    TRACK_LOGO: "logo",
    TRACK_SUBTITLE: "subtitle",
    TRACK_BUTTON: "button",
    TRACK_CONTROL: "control",
}

#: CodecIDs are `"<letter>_<NAME>"`, where the letter is the track type. A
#: CodecID that does not look like this means the Tracks element is not what it
#: claims to be, which is a cheap and effective structural check.
_VALID_CODEC_PREFIXES = ("V_", "A_", "S_", "B_", "T_", "L_", "D_", "C_", "M_", "F_", "I_", "H_", "P_")

#: DocTypes that mean "this is a Matroska-family file". Anything else under the
#: EBML magic is some other EBML application (`.esf`, DRM payloads) and must not
#: be carved as Matroska.
MKV_DOCTYPES = frozenset({"matroska", "webm"})

#: How a resolved end was arrived at. Returned alongside the end so the caller
#: can label the boundary honestly instead of guessing from the note text.
DERIVED_FROM_DECLARED_SIZE = "declared_size"
DERIVED_FROM_WALK = "container_walk"

#: A Cluster carrying more than this many bytes of frame data is treated as
#: implausible and rejected rather than walked. A mis-parse that produces a
#: runaway walk is worse than a refusal.
MAX_CLUSTER_WALK = 64 * 1024 * 1024

class MatroskaError(ValueError):
    """The bytes are not a Matroska file this module is willing to trust."""


# --------------------------------------------------------------------------- #
# EBML primitives
# --------------------------------------------------------------------------- #

def _vint_width(first: int) -> int:
    """Width in bytes of the variable-length integer starting with `first`."""
    if first == 0:
        raise MatroskaError("variable-length integer with a zero leading byte")
    width = 1
    mask = 0x80
    while not first & mask:
        mask >>= 1
        width += 1
    return width


def read_element_id(buf: bytes, pos: int) -> tuple[int, int]:
    """Read an EBML element ID. Returns ``(id, width)``.

    IDs keep their length marker, so they are read as a plain big-endian
    integer -- ``0x1A45DFA3`` is the literal EBML magic.
    """
    if pos >= len(buf):
        raise MatroskaError("element ID past end of buffer")
    width = _vint_width(buf[pos])
    raw = buf[pos : pos + width]
    if len(raw) < width:
        raise MatroskaError("truncated element ID")
    return int.from_bytes(raw, "big"), width


def read_vint(buf: bytes, pos: int) -> tuple[int, int, bool]:
    """Read an EBML data-size VINT. Returns ``(size, width, unknown)``.

    Matroska reserves an all-ones payload as "size not known", which is how a
    streaming muxer says the element it is writing has no end yet. Honouring
    that flag rather than computing ``2**(7*width)-1`` is the difference between
    walking a fragmented recording and believing it is a terabyte long.
    """
    if pos >= len(buf):
        raise MatroskaError("size field past end of buffer")
    width = _vint_width(buf[pos])
    raw = buf[pos : pos + width]
    if len(raw) < width:
        raise MatroskaError("truncated size field")
    mask = 0x80 >> (width - 1)
    value = raw[0] & (mask - 1)
    for byte in raw[1:]:
        value = (value << 8) | byte
    unknown = value == (1 << (7 * width)) - 1
    return value, width, unknown


def read_uint(buf: bytes, pos: int, size: int) -> int:
    """Read an unsigned integer element payload."""
    if size > 8:
        # Values wider than 64 bits carry no information this carver uses, and
        # int.from_bytes would happily produce a huge number that then fails
        # every plausibility check downstream in a confusing way.
        raise MatroskaError(f"unsigned integer of {size} bytes is implausibly wide")
    return int.from_bytes(buf[pos : pos + size], "big") if size else 0


def read_string(buf: bytes, pos: int, size: int) -> str:
    raw = buf[pos : pos + size]
    return raw.split(b"\x00", 1)[0].decode("utf-8", "replace").strip()


# --------------------------------------------------------------------------- #
# Parsed model
# --------------------------------------------------------------------------- #

@dataclass
class Track:
    number: int
    type_id: int
    codec_id: str
    width: int = 0
    height: int = 0
    codec_private: bytes = b""

    @property
    def type_name(self) -> str:
        return _TRACK_TYPE_NAMES.get(self.type_id, f"type-{self.type_id}")


@dataclass
class Block:
    """One frame's worth of data, located exactly."""
    track: int
    #: Absolute offset of the first byte of frame data.
    data_offset: int
    #: Frame data length, excluding the block header.
    data_size: int
    keyframe: bool
    #: Absolute offset of the timestamp this block is relative to.
    cluster_offset: int
    #: ``True`` when the frame payload uses lacing, so `data_size` covers
    #: several frames of differing sizes. Callers that need per-frame extents
    #: must expand the lacing rather than treat this as one frame.
    laced: bool = False
    #: Lacing mode, for the same reason.
    lacing: int = 0


@dataclass
class Cluster:
    offset: int
    body: int
    size: int | None
    timestamp: int = 0
    blocks: list[Block] = field(default_factory=list)

    @property
    def end(self) -> int | None:
        """Declared end, or ``None`` when the muxer did not know."""
        return None if self.size is None else self.body + self.size

    @property
    def frame_bytes(self) -> int:
        return sum(b.data_size for b in self.blocks)


@dataclass
class MatroskaInfo:
    """Everything recovered from a Matroska file's structure."""
    doc_type: str
    ebml_end: int
    segment_offset: int
    segment_body: int
    #: Declared segment size, or ``None`` when unknown.
    segment_size: int | None
    tracks: list[Track] = field(default_factory=list)
    clusters: list[Cluster] = field(default_factory=list)
    timecode_scale: int = 1_000_000
    duration: float = 0.0
    muxing_app: str = ""
    writing_app: str = ""
    cue_cluster_positions: list[int] = field(default_factory=list)
    #: Set when the walk stopped on something unparseable, with the reason.
    stop_reason: str = ""
    #: Elements that were present but whose size was not known.
    unknown_size_clusters: int = 0
    #: DocTypeVersion from the EBML header.
    doc_type_version: int = 1
    #: End of the last element the walk could read, used when the Segment
    #: itself declared no size.
    walked_end: int = 0

    @property
    def segment_end(self) -> int | None:
        """Declared segment end, or ``None``."""
        return None if self.segment_size is None else self.segment_body + self.segment_size

    @property
    def video_tracks(self) -> list[Track]:
        return [t for t in self.tracks if t.type_id == TRACK_VIDEO]

    @property
    def frame_blocks(self) -> list[Block]:
        return [b for c in self.clusters for b in c.blocks]

    @property
    def frame_bytes(self) -> int:
        return sum(c.frame_bytes for c in self.clusters)


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #

def parse_header(buf: bytes) -> tuple[MatroskaInfo, int]:
    """Parse the EBML header. Returns the partial info and the header's end.

    The header is the format's own statement of what it is, and it is the only
    place the DocType appears. Reading it is what distinguishes a Matroska file
    from the other EBML applications that share the magic.
    """
    if len(buf) < 4 or int.from_bytes(buf[:4], "big") != EBML_HEADER:
        raise MatroskaError("no EBML magic")
    _, id_w = read_element_id(buf, 0)
    size, size_w, unknown = read_vint(buf, id_w)
    if unknown:
        raise MatroskaError("EBML header declares an unknown size")
    body = id_w + size_w
    end = body + size
    if end > len(buf):
        raise MatroskaError("EBML header runs past the available data")

    doc_type = ""
    doc_type_version = 0
    pos = body
    while pos < end:
        try:
            eid, w = read_element_id(buf, pos)
            elsize, zw, unknown = read_vint(buf, pos + w)
        except MatroskaError:
            break
        if unknown:
            break
        el_body = pos + w + zw
        if el_body + elsize > end:
            break
        if eid == DOCTYPE:
            doc_type = read_string(buf, el_body, elsize)
        elif eid == DOCTYPE_VERSION:
            doc_type_version = read_uint(buf, el_body, elsize)
        pos = el_body + elsize

    if not doc_type:
        raise MatroskaError("EBML header carries no DocType")
    if doc_type not in MKV_DOCTYPES:
        raise MatroskaError(f"DocType {doc_type!r} is not Matroska or WebM")
    if doc_type_version == 0:
        raise MatroskaError("DocTypeVersion 0 is not valid")

    info = MatroskaInfo(doc_type=doc_type, ebml_end=end, segment_offset=-1,
                        segment_body=-1, segment_size=None,
                        doc_type_version=doc_type_version)
    return info, end


def _parse_tracks(buf: bytes, start: int, end: int) -> list[Track]:
    tracks: list[Track] = []
    pos = start
    while pos < end:
        try:
            eid, w = read_element_id(buf, pos)
            size, zw, unknown = read_vint(buf, pos + w)
        except MatroskaError:
            break
        if unknown or eid != TRACK_ENTRY:
            if unknown:
                break
            pos += w + zw + size
            continue
        body = pos + w + zw
        stop = body + size
        if stop > end:
            break
        number, type_id, codec_id = 0, 0, ""
        width = height = 0
        private = b""
        p = body
        while p < stop:
            try:
                tid, tw = read_element_id(buf, p)
                tsize, tzw, tunknown = read_vint(buf, p + tw)
            except MatroskaError:
                break
            if tunknown:
                break
            tbody = p + tw + tzw
            if tbody + tsize > stop:
                break
            if tid == TRACK_NUMBER:
                number = read_uint(buf, tbody, tsize)
            elif tid == TRACK_TYPE:
                type_id = read_uint(buf, tbody, tsize)
            elif tid == CODEC_ID:
                codec_id = read_string(buf, tbody, tsize)
            elif tid == CODEC_PRIVATE:
                private = bytes(buf[tbody : tbody + tsize])
            elif tid == VIDEO:
                vp = tbody
                vstop = tbody + tsize
                while vp < vstop:
                    try:
                        vid, vw = read_element_id(buf, vp)
                        vsize, vzw, vunknown = read_vint(buf, vp + vw)
                    except MatroskaError:
                        break
                    if vunknown:
                        break
                    vbody = vp + vw + vzw
                    if vbody + vsize > vstop:
                        break
                    if vid == PIXEL_WIDTH:
                        width = read_uint(buf, vbody, vsize)
                    elif vid == PIXEL_HEIGHT:
                        height = read_uint(buf, vbody, vsize)
                    vp = vbody + vsize
            p = tbody + tsize
        if number and codec_id:
            tracks.append(Track(number=number, type_id=type_id, codec_id=codec_id,
                                width=width, height=height, codec_private=private))
        pos = stop
    return tracks


def _parse_block(buf: bytes, pos: int, size: int, cluster_offset: int,
                 in_group: bool) -> Block | None:
    """Parse a `SimpleBlock` or a `BlockGroup`'s `Block`.

    Both share a layout: a track-number VINT, a signed 16-bit timestamp relative
    to the cluster, a flags byte, and then the frame data. The difference is
    that only a `SimpleBlock` marks a keyframe in its flags; a `Block` is a
    keyframe precisely when its group carries no `ReferenceBlock`, which the
    caller resolves.
    """
    try:
        # The track number is a VINT with the length marker stripped, unlike an
        # element ID. "Unknown" is meaningless here, so it is rejected.
        track, tw, unknown = read_vint(buf, pos)
    except MatroskaError:
        return None
    if unknown or tw == 0 or track <= 0:
        return None
    ts_pos = pos + tw
    if ts_pos + 3 > pos + size:
        return None
    flags = buf[ts_pos + 2]
    data_at = ts_pos + 3
    data_size = pos + size - data_at
    if data_size < 0:
        return None
    lacing = (flags & 0x06) >> 1
    return Block(
        track=track,
        # `pos` is already absolute, so `data_at` is absolute too. Adding the
        # cluster offset again put every frame's extent past the end of the file.
        data_offset=data_at,
        data_size=data_size,
        keyframe=bool(flags & 0x80) if not in_group else False,
        cluster_offset=cluster_offset,
        laced=lacing != 0,
        lacing=lacing,
    )


def _parse_cluster(buf: bytes, offset: int, body: int, size: int | None,
                   limit: int) -> Cluster:
    """Walk one cluster's children.

    `size` is the declared size, or ``None`` for a live muxer. In the unknown
    case the cluster ends when a child cannot be read, which for a well-formed
    file is exactly where the next top-level element begins.
    """
    if size is not None and size > MAX_CLUSTER_WALK:
        raise MatroskaError(f"cluster declares {size} bytes, above the walk limit")
    cluster = Cluster(offset=offset, body=body, size=size)
    stop = limit if size is None else min(body + size, limit)
    if stop <= body:
        return cluster
    pos = body
    while pos < stop:
        try:
            eid, w = read_element_id(buf, pos)
            elsize, zw, unknown = read_vint(buf, pos + w)
        except (MatroskaError, IndexError):
            break
        el_body = pos + w + zw
        if unknown:
            # An unknown-size child inside a cluster: the block payload runs to
            # the cluster's end. Only Void can legitimately do this, and it
            # carries no frames.
            break
        el_end = el_body + elsize
        if el_end > stop or el_end < el_body:
            break
        if eid == TIMESTAMP:
            try:
                cluster.timestamp = read_uint(buf, el_body, elsize)
            except MatroskaError:
                pass
        elif eid == SIMPLE_BLOCK:
            block = _parse_block(buf, el_body, elsize, offset, in_group=False)
            if block is not None:
                cluster.blocks.append(block)
        elif eid == BLOCK_GROUP:
            has_reference = False
            gp = el_body
            while gp < el_end:
                try:
                    gid, gw = read_element_id(buf, gp)
                    gsize, gzw, gunknown = read_vint(buf, gp + gw)
                except (MatroskaError, IndexError):
                    break
                if gunknown:
                    break
                gbody = gp + gw + gzw
                if gbody + gsize > el_end or gbody + gsize < gbody:
                    break
                if gid == BLOCK:
                    block = _parse_block(buf, gbody, gsize, offset, in_group=True)
                    if block is not None:
                        block.keyframe = not has_reference
                        cluster.blocks.append(block)
                elif gid == REFERENCE_BLOCK:
                    has_reference = True
                gp = gbody + gsize
        pos = el_end
    return cluster


def parse(buf: bytes, limit: int | None = None) -> MatroskaInfo:
    """Parse a Matroska file held in memory.

    `limit` is the furthest absolute offset that may be read, so a caller that
    only has a window can still walk a header that claims to be longer.
    """
    avail = len(buf) if limit is None else min(limit, len(buf))
    info, pos = parse_header(buf)
    stop = avail

    # SeekHead, Void and CRC-32 may precede the Segment.
    segment: tuple[int, int, int | None] | None = None
    while pos < stop:
        try:
            eid, w = read_element_id(buf, pos)
            size, zw, unknown = read_vint(buf, pos + w)
        except (MatroskaError, IndexError):
            info.stop_reason = f"unparseable element at {pos} while seeking the Segment"
            break
        body = pos + w + zw
        if eid == SEGMENT:
            segment = (pos, body, None if unknown else size)
            break
        if unknown:
            info.stop_reason = f"unknown-size element 0x{eid:X} before the Segment"
            break
        if body + size > stop:
            info.stop_reason = f"element 0x{eid:X} runs past the available data"
            break
        if eid in (SEEK_HEAD, VOID, CRC32, INFO):
            if eid == INFO:
                _parse_info(buf, body, body + size, info)
        pos = body + size

    if segment is None:
        raise MatroskaError("no Segment element")
    seg_offset, seg_body, seg_size = segment
    info.segment_offset = seg_offset
    info.segment_body = seg_body
    info.segment_size = seg_size
    if seg_size is not None:
        stop = min(seg_body + seg_size, avail)

    # Walk the Segment's children.
    p = seg_body
    furthest = seg_body
    tracks_done = False
    while p < stop:
        try:
            eid, w = read_element_id(buf, p)
            size, zw, unknown = read_vint(buf, p + w)
        except (MatroskaError, IndexError):
            info.stop_reason = f"unparseable element at {p} inside the Segment"
            break
        body = p + w + zw
        if unknown:
            if eid == CLUSTER:
                info.unknown_size_clusters += 1
                try:
                    cluster = _parse_cluster(buf, p, body, None, stop)
                except MatroskaError as exc:
                    info.stop_reason = str(exc)
                    break
                info.clusters.append(cluster)
                last = cluster.blocks[-1].data_offset + cluster.blocks[-1].data_size if cluster.blocks else body
                furthest = max(furthest, last)
                break
            info.stop_reason = f"unknown-size 0x{eid:X} inside the Segment"
            break
        el_end = body + size
        if el_end > stop or el_end < body:
            info.stop_reason = f"element 0x{eid:X} at {p} overruns the Segment"
            break
        if eid == TRACKS and not tracks_done:
            info.tracks = _parse_tracks(buf, body, el_end)
            tracks_done = True
        elif eid == INFO:
            _parse_info(buf, body, el_end, info)
        elif eid == CLUSTER:
            try:
                info.clusters.append(_parse_cluster(buf, p, body, size, stop))
            except MatroskaError as exc:
                info.stop_reason = str(exc)
                break
        elif eid == CUES:
            _parse_cues(buf, body, el_end, info, seg_body)
        furthest = max(furthest, el_end)
        p = el_end

    if not info.clusters:
        raise MatroskaError("no Cluster elements")
    if not info.tracks:
        raise MatroskaError("no usable TrackEntry elements")
    if not any(t.codec_id.startswith(_VALID_CODEC_PREFIXES) for t in info.tracks):
        raise MatroskaError("no TrackEntry carries a plausible CodecID")
    if not info.frame_blocks:
        raise MatroskaError("no frame blocks in any cluster")
    info.walked_end = furthest
    return info


def _parse_info(buf: bytes, start: int, end: int, info: MatroskaInfo) -> None:
    pos = start
    while pos < end:
        try:
            eid, w = read_element_id(buf, pos)
            size, zw, unknown = read_vint(buf, pos + w)
        except (MatroskaError, IndexError):
            return
        if unknown:
            return
        body = pos + w + zw
        if body + size > end or body + size < body:
            return
        if eid == TIMECODE_SCALE:
            try:
                info.timecode_scale = read_uint(buf, body, size) or 1_000_000
            except MatroskaError:
                pass
        elif eid == DURATION:
            try:
                if size == 4:
                    info.duration = struct.unpack(">f", buf[body : body + 4])[0]
                elif size == 8:
                    info.duration = struct.unpack(">d", buf[body : body + 8])[0]
            except (MatroskaError, struct.error):
                pass
        elif eid == MUXING_APP:
            info.muxing_app = read_string(buf, body, size)
        elif eid == WRITING_APP:
            info.writing_app = read_string(buf, body, size)
        pos = body + size


def _parse_cues(buf: bytes, start: int, end: int, info: MatroskaInfo,
                seg_body: int) -> None:
    pos = start
    while pos < end:
        try:
            eid, w = read_element_id(buf, pos)
            size, zw, unknown = read_vint(buf, pos + w)
        except (MatroskaError, IndexError):
            return
        if unknown:
            return
        body = pos + w + zw
        if body + size > end or body + size < body:
            return
        if eid == CUE_POINT:
            cp = body
            cstop = body + size
            while cp < cstop:
                try:
                    pid, pw = read_element_id(buf, cp)
                    psize, pzw, punknown = read_vint(buf, cp + pw)
                except (MatroskaError, IndexError):
                    break
                if punknown:
                    break
                pbody = cp + pw + pzw
                if pbody + psize > cstop:
                    break
                if pid == CUE_TRACK_POSITIONS:
                    q = pbody
                    qstop = pbody + psize
                    while q < qstop:
                        try:
                            qid, qw = read_element_id(buf, q)
                            qsize, qzw, qunknown = read_vint(buf, q + qw)
                        except (MatroskaError, IndexError):
                            break
                        if qunknown:
                            break
                        qbody = q + qw + qzw
                        if qbody + qsize > qstop:
                            break
                        if qid == CUE_CLUSTER_POSITION:
                            try:
                                # Relative to the Segment's data, not the file.
                                info.cue_cluster_positions.append(
                                    seg_body + read_uint(buf, qbody, qsize))
                            except MatroskaError:
                                pass
                        q = qbody + qsize
                cp = pbody + psize
        pos = body + size


# --------------------------------------------------------------------------- #
# Derived quantities
# --------------------------------------------------------------------------- #

def resolve_end(info: MatroskaInfo, available: int) -> int | None:
    """Where the file ends, or ``None`` if the structure does not say.

    Preference order, strongest evidence first:

    1. the Segment's declared size;
    2. the end of the last element the walk could read.

    The second is the interesting one. A muxer that did not know the Segment's
    size still gave every Cluster a size, so the last readable element's end is
    still a derived length rather than a guess -- and for the fragmented
    recordings that matter most it is exact.
    """
    if info.segment_size is not None:
        end = info.segment_body + info.segment_size
        return end if end <= available else None
    walked = info.walked_end
    if walked <= info.segment_body:
        return None
    return walked if walked <= available else None


def frame_extents(info: MatroskaInfo) -> list[tuple[int, int]]:
    """Byte ranges of frame data, merged.

    This is the Matroska analog of an MP4 sample table: the extents come from
    inline block headers rather than from an index, so they survive in a file
    whose `Cues` are gone. Overlapping and adjacent ranges are merged, so the
    result is "the runs of the file that hold frames" rather than one entry per
    frame.
    """
    spans = sorted((b.data_offset, b.data_offset + b.data_size - 1)
                   for b in info.frame_blocks if b.data_size > 0)
    return merge_extents(spans)


def merge_extents(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Merge inclusive ``(start, end)`` spans, dropping empty ones."""
    usable = sorted((s, e) for s, e in spans if e >= s)
    if not usable:
        return []
    out: list[list[int]] = [[usable[0][0], usable[0][1]]]
    for start, end in usable[1:]:
        if start <= out[-1][1] + 1:
            out[-1][1] = max(out[-1][1], end)
        else:
            out.append([start, end])
    return [(s, e) for s, e in out]


def summary(info: MatroskaInfo) -> dict:
    """A compact, JSON-friendly description for reports."""
    return {
        "doc_type": info.doc_type,
        "segment_size_known": info.segment_size is not None,
        "tracks": [
            {
                "number": t.number,
                "type": t.type_name,
                "codec": t.codec_id,
                "width": t.width,
                "height": t.height,
                "codec_private_bytes": len(t.codec_private),
            }
            for t in info.tracks
        ],
        "clusters": len(info.clusters),
        "unknown_size_clusters": info.unknown_size_clusters,
        "blocks": len(info.frame_blocks),
        "keyframes": sum(1 for b in info.frame_blocks if b.keyframe),
        "laced_blocks": sum(1 for b in info.frame_blocks if b.laced),
        "frame_bytes": info.frame_bytes,
        "muxing_app": info.muxing_app,
        "writing_app": info.writing_app,
        "cue_points": len(info.cue_cluster_positions),
        "stop_reason": info.stop_reason,
    }


# --------------------------------------------------------------------------- #
# Streaming boundary walk
# --------------------------------------------------------------------------- #

#: Element headers are at most 8 bytes of ID plus 8 bytes of size. A block header
#: is a VINT plus two timestamp bytes plus a flags byte.
_HEADER_WINDOW = 32

#: A declared element size above this is treated as a mis-parse. It is only a
#: backstop: known-size elements are skipped in O(1) from their header, so the
#: walk never allocates against this number.
MAX_ELEMENT_SIZE = 1 << 40


def _read_header(read, pos: int) -> tuple | None:
    """Read one element header at `pos`. Returns ``(id, body, size, unknown)``.

    `read` is a ``(offset, length) -> bytes`` callable, so this works against a
    `ByteSource` over a real volume as well as a bytes object.
    """
    head = read(pos, _HEADER_WINDOW)
    if len(head) < 2:
        return None
    try:
        eid, id_w = read_element_id(head, 0)
        size, size_w, unknown = read_vint(head, id_w)
    except MatroskaError:
        return None
    # The check has to come after `unknown` is known. An unknown-size element
    # decodes to the all-ones sentinel, which is a huge *number* while meaning
    # "no size at all" -- testing the value first rejects the unknown-size
    # Segment, which is precisely the fragmented case this module exists for.
    if not unknown and size > MAX_ELEMENT_SIZE and eid != CLUSTER:
        return None
    return eid, pos + id_w + size_w, size, unknown


def walk_end(read, start: int, limit: int) -> tuple:
    """Find where the Matroska file at `start` ends.

    Returns ``(end, notes, provenance)``. `end` is ``None`` when the structure
    does not determine it, which is the honest answer for a file whose header
    was truncated before any cluster. `provenance` is which of
    ``DERIVED_FROM_DECLARED_SIZE`` / ``DERIVED_FROM_WALK`` applies, so a report
    can say where the length came from rather than implying it was read from a
    field when it was in fact walked.

    This walks element headers and never reads a frame payload. A block can be
    tens of megabytes and the walk only needs to know its length, which the
    header already states, so a 64 GiB video costs the same memory as a 64 KiB
    one.
    """
    notes: list = []
    header = read(start, _HEADER_WINDOW)
    if len(header) < 4 or int.from_bytes(header[:4], "big") != EBML_HEADER:
        return None, ["no EBML magic"], None
    hdr = _read_header(read, start)
    if hdr is None:
        return None, ["EBML header is not readable"], None
    _, ebml_body, ebml_size, _ = hdr
    if ebml_body + ebml_size > limit:
        return None, ["EBML header runs past the carve window"], None
    # The DocType is the only thing that says this is Matroska rather than some
    # other EBML application, so it is read before anything is trusted.
    doctype = _read_doctype(read, ebml_body, ebml_body + ebml_size)
    if not doctype:
        return None, ["EBML header carries no readable DocType"], None
    if doctype not in MKV_DOCTYPES:
        return None, [f"DocType {doctype!r} is not Matroska or WebM"], None
    notes.append(f"EBML header declares DocType {doctype!r}")

    # SeekHead, Void, CRC-32 and Info may sit between the header and the Segment.
    pos = ebml_body + ebml_size
    seg = None
    while pos < limit:
        el = _read_header(read, pos)
        if el is None:
            notes.append(f"unreadable element at {pos} while seeking the Segment")
            return None, notes, None
        eid, body, size, unknown = el
        if eid == SEGMENT:
            seg = (pos, body, None if unknown else size)
            break
        if unknown:
            notes.append(f"unknown-size element 0x{eid:X} before the Segment")
            return None, notes, None
        if body + size > limit:
            notes.append(f"element 0x{eid:X} runs past the carve window")
            return None, notes, None
        pos = body + size
    if seg is None:
        return None, notes + ["no Segment element"], None

    seg_offset, seg_body, seg_size = seg
    if seg_size is not None:
        end = seg_body + seg_size
        if end > limit:
            return None, notes + [f"Segment declares {seg_size} bytes, past the carve window"], None
        notes.append(f"Segment declares {seg_size} bytes")
        return end, notes, DERIVED_FROM_DECLARED_SIZE

    notes.append("Segment size is unknown, so the end comes from its clusters")
    end, walk_notes = _walk_segment_children(read, seg_body, limit)
    notes.extend(walk_notes)
    if end is None:
        return None, notes, None
    notes.append(f"last readable element ends at {end} ({end - seg_offset} bytes after the Segment)")
    return end, notes, DERIVED_FROM_WALK


def _read_doctype(read, start: int, end: int) -> str:
    pos = start
    while pos < end:
        el = _read_header(read, pos)
        if el is None:
            return ""
        eid, body, size, unknown = el
        if unknown or body + size > end:
            return ""
        if eid == DOCTYPE:
            raw = read(body, min(size, 64))
            return read_string(raw, 0, len(raw))
        pos = body + size
    return ""


def _walk_segment_children(read, seg_body: int, limit: int) -> tuple:
    """Walk a Segment's children, returning ``(end, notes)``.

    With no declared Segment size the end is the end of the last element that
    can be read. Every Cluster a real muxer writes carries its own size, so this
    is a derived length rather than a guess -- and for the fragmented recordings
    that matter most it is exact.
    """
    notes: list = []
    pos = seg_body
    furthest = seg_body
    clusters = 0
    tracks = 0
    frames = 0
    while pos < limit:
        el = _read_header(read, pos)
        if el is None:
            notes.append(f"unreadable element at {pos}; stopping the walk")
            break
        eid, body, size, unknown = el
        if eid not in TOP_LEVEL_IDS:
            # The bytes here are not a Matroska top-level element, so the file
            # ended before this offset. Whatever the previous element ended at
            # is the file's end.
            notes.append(f"element 0x{eid:X} at {pos} is not a Matroska top-level "
                         f"element, so the file ends at {furthest}")
            break
        if unknown:
            if eid == CLUSTER:
                clusters += 1
                end, count = _walk_unknown_cluster(read, pos, body, limit)
                frames += count
                if end is not None:
                    furthest = max(furthest, end)
                notes.append("one cluster declared no size; its extent came from its blocks")
                break
            notes.append(f"unknown-size 0x{eid:X} inside the Segment; stopping the walk")
            break
        el_end = body + size
        if el_end > limit or el_end < body:
            notes.append(f"element 0x{eid:X} at {pos} overruns the carve window")
            break
        if eid == CLUSTER:
            clusters += 1
            frames += _count_cluster_blocks(read, pos, body, size)
        elif eid == TRACKS:
            tracks += 1
        furthest = max(furthest, el_end)
        pos = el_end

    if not clusters:
        notes.append("no Cluster elements were readable")
        return None, notes
    if not tracks:
        notes.append("no Tracks element was readable")
        return None, notes
    if not frames:
        notes.append("no frame blocks were readable in any cluster")
        return None, notes
    notes.append(f"walked {clusters} cluster(s), {frames} block(s), {tracks} Tracks element(s)")
    return furthest, notes


def _count_cluster_blocks(read, cluster_offset: int, body: int, size: int) -> int:
    """Count the frame blocks in a cluster of declared size, without reading payloads."""
    stop = body + size
    pos = body
    count = 0
    while pos < stop:
        el = _read_header(read, pos)
        if el is None:
            break
        eid, el_body, el_size, unknown = el
        if unknown or el_body + el_size > stop or el_body + el_size < el_body:
            break
        if eid == SIMPLE_BLOCK:
            count += 1
        elif eid == BLOCK_GROUP:
            gp = el_body
            gstop = el_body + el_size
            while gp < gstop:
                gel = _read_header(read, gp)
                if gel is None:
                    break
                gid, gbody, gsize, gunknown = gel
                if gunknown or gbody + gsize > gstop:
                    break
                if gid == BLOCK:
                    count += 1
                gp = gbody + gsize
        pos = el_body + el_size
    return count


def _walk_unknown_cluster(read, cluster_offset: int, body: int, limit: int) -> tuple:
    """Walk a cluster that declared no size.

    Such a cluster ends where its children stop making sense. Each block states
    its own length, so the last block's end is a real end; what cannot be known
    is whether the muxer would have written more, which is why the caller treats
    this as the end of the *file* only for the final cluster.
    """
    pos = body
    last_end = body
    count = 0
    while pos < limit:
        el = _read_header(read, pos)
        if el is None:
            break
        eid, el_body, el_size, unknown = el
        if unknown:
            break
        if eid == SIMPLE_BLOCK:
            count += 1
            last_end = el_body + el_size
        elif eid == TIMESTAMP:
            pass
        elif eid == BLOCK_GROUP:
            gp = el_body
            gstop = el_body + el_size
            while gp < gstop:
                gel = _read_header(read, gp)
                if gel is None:
                    break
                gid, gbody, gsize, gunknown = gel
                if gunknown or gbody + gsize > gstop:
                    break
                if gid == BLOCK:
                    count += 1
                    last_end = gbody + gsize
                gp = gbody + gsize
        elif eid == CLUSTER or eid in (CUES, VOID, TAGS, INFO, SEEK_HEAD, TRACKS):
            # A new top-level element: this cluster is over.
            return last_end, count
        el_end = el_body + el_size
        if el_end <= pos or el_end > limit:
            break
        if el_end > last_end:
            last_end = el_end
        pos = el_end
    return last_end, count
