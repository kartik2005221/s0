"""s0 Module 2: end-of-file boundary resolution and structural validation.

A file carver must decide two things about every candidate it finds:

  1. **Where does the file end?**  ("boundary resolution")
  2. **Is this candidate actually a file of that type?**  ("structural validation")

s0 previously answered (1) by carving everything to the end of the current 2 MiB
read window and (2) by awarding a flat bonus for a matching header. Together
those two shortcuts meant that any 2-byte magic -- notably the MPEG audio frame
sync ``FF FB`` and the BMP ``BM`` -- produced a full-size block of garbage that
scored above the default confidence threshold. The observable symptom was a
carver that returned the same 30-odd junk files for every target.

This module implements the boundary strategies that real recovery tools use:

  ``declared``    the format stores its own length; read it and trust it
                  (BMP ``LE32@2``, RIFF ``LE32@4``, 7z ``LE64@12+@20``, ...)
  ``container``   walk the container's own chunk/atom/frame structure until it
                  terminates (PNG chunks, MP4 atoms, Ogg pages, ZIP central
                  directory, PCAPNG blocks)
  ``footer``      search forward for the format's terminator (JPEG EOI, GIF
                  trailer, PDF %%EOF, ZIP EOCD)
  ``frames``      require N consecutive well-formed codec frames, where frame
                  k+1 must start at exactly ``offset_k + frame_len_k``. This is
                  the only thing that distinguishes a real MP3 from random data
                  that happens to contain ``FF FB``.
  ``decompress``  run the stream and take the end of the decoder output (gzip,
                  deflate, bzip2)

Anything that cannot be resolved is reported as undetermined so the caller can
apply a budget instead of guessing.

All readers take a :class:`ByteSource`, which is an absolute-offset reader over
the target. That deliberately removes the old "everything must fit inside the
read window" ceiling, which made any file larger than ``chunk_size + overlap``
impossible to carve correctly.
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

__all__ = [
    "ByteSource",
    "Boundary",
    "resolve_boundary",
    "validate_structure",
    "FRAME_VALIDATED",
    "DECLARED_SIZE",
    "CONTAINER_WALK",
    "FOOTER_ANCHORED",
    "DECOMPRESSED",
    "UNDETERMINED",
    "MAX_SIZE_FALLBACK",
    "BOUNDARY_LABELS",
]

DECLARED_SIZE = "declared_size"
CONTAINER_WALK = "container_walk"
FOOTER_ANCHORED = "footer_anchored"
FRAME_VALIDATED = "frame_sequence"
DECOMPRESSED = "decompress_to_end"
UNDETERMINED = "undetermined"
MAX_SIZE_FALLBACK = "max_size_fallback"

# Short human labels for the CLI and the recovery report.
BOUNDARY_LABELS = {
    DECLARED_SIZE: "declared size",
    CONTAINER_WALK: "container walk",
    FOOTER_ANCHORED: "footer",
    FRAME_VALIDATED: "frame sequence",
    DECOMPRESSED: "decompressed",
    MAX_SIZE_FALLBACK: "declared max_size (heuristic)",
    UNDETERMINED: "unresolved",
}

_MAX_READ = 256 * 1024 * 1024


# --------------------------------------------------------------------------- #
# Byte source
# --------------------------------------------------------------------------- #


class ByteSource:
    """Absolute-offset random access over the target, with a small read cache.

    Boundary resolution needs to look far beyond the candidate header (a PNG
    chunk walk, an MP4 atom walk, a multi-frame MPEG sequence can each run
    hundreds of megabytes past the start), so the carver must be able to read
    arbitrary ranges without being bounded by its scan window.
    """

    __slots__ = ("_fh", "_size", "_cache_off", "_cache")

    def __init__(self, fh, size: int):
        self._fh = fh
        self._size = size
        self._cache_off = -1
        self._cache = b""

    @property
    def size(self) -> int:
        return self._size

    def read(self, offset: int, length: int) -> bytes:
        """Read up to `length` bytes at absolute `offset`; short at EOF."""
        if offset < 0 or length <= 0 or offset >= self._size:
            return b""
        length = min(length, self._size - offset, _MAX_READ)
        start = offset - self._cache_off
        if start >= 0:
            cached = self._cache[start : start + length]
            if len(cached) == length:
                return cached
        self._fh.seek(offset)
        data = self._fh.read(length)
        self._cache_off = offset
        self._cache = data
        return data

    def read_until(self, needle: bytes, start: int, limit: int) -> int:
        """Return the absolute offset of `needle`, or -1 if not found in [start, start+limit)."""
        if limit <= 0:
            return -1
        window_size = 1 << 20
        overlap = len(needle) - 1
        pos = start
        end = min(start + limit, self._size)
        while pos < end:
            chunk_len = min(window_size, end - pos)
            chunk = self.read(pos, chunk_len)
            if not chunk:
                return -1
            idx = chunk.find(needle)
            if idx != -1:
                return pos + idx
            pos += chunk_len - overlap
            if chunk_len <= overlap:
                break
        return -1

    def rfind_near(self, needle: bytes, end: int, limit: int) -> int:
        """Return the absolute offset of the last `needle` in [end-limit, end), or -1."""
        lo = max(0, end - limit)
        pos = end
        while pos > lo:
            step = min(1 << 20, pos - lo)
            pos -= step
            chunk = self.read(pos, step + len(needle))
            if not chunk:
                continue
            idx = chunk.rfind(needle)
            if idx != -1:
                return pos + idx
        return -1


@dataclass
class Boundary:
    """Outcome of resolving where a candidate ends."""

    end: Optional[int]
    method: str = UNDETERMINED
    notes: List[str] = field(default_factory=list)

    @property
    def resolved(self) -> bool:
        return self.end is not None

    @property
    def authoritative(self) -> bool:
        """True when the format told us its own length, or a container walk
        terminated cleanly on a structural rule."""
        return self.method in (DECLARED_SIZE, CONTAINER_WALK, FRAME_VALIDATED, DECOMPRESSED)


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #


def _le16(b: bytes, o: int) -> int:
    return int.from_bytes(b[o : o + 2], "little")


def _le32(b: bytes, o: int) -> int:
    return int.from_bytes(b[o : o + 4], "little")


def _le64(b: bytes, o: int) -> int:
    return int.from_bytes(b[o : o + 8], "little")


def _be16(b: bytes, o: int) -> int:
    return int.from_bytes(b[o : o + 2], "big")


def _be32(b: bytes, o: int) -> int:
    return int.from_bytes(b[o : o + 4], "big")


def _ascii(b: bytes, o: int, n: int) -> bytes:
    return b[o : o + n]


def _sanity(size: Optional[int], minimum: int, maximum: int) -> Optional[int]:
    if size is None or size < minimum or size > maximum:
        return None
    return size


# --------------------------------------------------------------------------- #
# MPEG audio frame tables (ISO/IEC 11172-3 / 13818-3)
# --------------------------------------------------------------------------- #

_MPEG_BITRATES = {
    # (version_id, layer) -> [kbps indexed by bitrate_index]
    (3, 3): [0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448, 0],   # V1 L1
    (3, 2): [0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 0],   # V1 L2
    (3, 1): [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0],   # V1 L3
    (2, 3): [0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256, 0],   # V2 L1
    (2, 2): [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0],       # V2 L2/L3
}

_MPEG_SAMPLERATES = {
    3: [44100, 48000, 32000, 0],   # MPEG-1
    2: [22050, 24000, 16000, 0],   # MPEG-2
    0: [11025, 12000, 8000, 0],    # MPEG-2.5
}

# The sample rate table is keyed by the 2-bit version_id read from the header.
_MPEG_VERSION_BY_ID = {3: 3, 2: 2, 0: 0}


def parse_mpeg_frame_header(buf: bytes, off: int) -> Optional[dict]:
    """Decode a 4-byte MPEG audio frame header at `off`.

    Returns None when any reserved combination is present. Layer 3 and layer 2
    frame length is ``144 * bitrate / sample_rate + padding``; layer 1 uses
    ``(12 * bitrate / sample_rate + padding) * 4``. A CRC-16 follows the header
    when the protection bit is clear.
    """
    if off + 4 > len(buf):
        return None
    b0, b1, b2, b3 = buf[off], buf[off + 1], buf[off + 2], buf[off + 3]
    if b0 != 0xFF or (b1 & 0xE0) != 0xE0:
        return None
    version_id = (b1 >> 3) & 0x03
    layer = (b1 >> 1) & 0x03
    protection = b1 & 0x01
    bitrate_idx = (b2 >> 4) & 0x0F
    samplerate_idx = (b2 >> 2) & 0x03
    padding = (b2 >> 1) & 0x01
    channel_mode = (b3 >> 6) & 0x03
    emphasis = b3 & 0x03

    if version_id == 1:            # reserved
        return None
    if layer == 0:                 # reserved
        return None
    if bitrate_idx in (0, 15):     # "free" / invalid
        return None
    if samplerate_idx == 3:        # reserved
        return None
    if emphasis == 2:              # reserved
        return None

    ver_key = _MPEG_VERSION_BY_ID[version_id]
    layer_key = 3 - layer          # header encodes layer 1,2,3 as 1,2,3
    table = _MPEG_BITRATES.get((ver_key, layer_key))
    if not table:
        return None
    bitrate_kbps = table[bitrate_idx]
    if not bitrate_kbps:
        return None
    samplerate = _MPEG_SAMPLERATES[ver_key][samplerate_idx]
    if not samplerate:
        return None

    if layer_key == 3:  # Layer I
        frame_len = (12 * bitrate_kbps * 1000 // samplerate + padding) * 4
    else:
        frame_len = (144 * bitrate_kbps * 1000 // samplerate) + padding
    if protection == 0:
        frame_len += 2  # CRC-16

    return {
        "version_id": version_id,
        "layer": layer_key,
        "bitrate": bitrate_kbps,
        "samplerate": samplerate,
        "channel_mode": channel_mode,
        "frame_len": frame_len,
    }


def _mpeg_sequence(src: ByteSource, start: int, header_len: int, min_frames: int,
                   max_frames: int, limit: int) -> Tuple[int, int, str]:
    """Walk consecutive MPEG audio frames from `start`.

    Returns ``(frame_count, end_offset, reason)``. The decisive rule is that
    frame k+1's sync word must land at exactly ``offset_k + frame_len_k`` with a
    header consistent with frame k. Random data contains ``FF FB`` roughly once
    every 64 KiB, so demanding a chain is what makes this a real filter.
    """
    end_limit = min(src.size, start + limit)
    frames = 0
    off = start + header_len
    first = None
    # A tiny sliding window is enough; we only ever need one frame header plus
    # the next sync word.
    window_size = 64 * 1024
    buf = src.read(start, min(window_size, end_limit - start))
    if len(buf) < header_len + 4:
        return 0, start, "header truncated"

    off = header_len
    first_hdr = None
    while off + 4 <= len(buf) and frames < max_frames:
        hdr = parse_mpeg_frame_header(buf, off)
        if hdr is None:
            break
        if first_hdr is None:
            first_hdr = hdr
        elif (hdr["version_id"], hdr["layer"], hdr["samplerate"], hdr["channel_mode"]) != (
            first_hdr["version_id"], first_hdr["layer"], first_hdr["samplerate"], first_hdr["channel_mode"]
        ):
            break
        frames += 1
        off += hdr["frame_len"]
        if off + 4 <= len(buf):
            continue
        if off >= end_limit - start:
            break
        more = src.read(start + off, min(window_size, end_limit - (start + off)))
        if not more:
            break
        buf = buf[:off] + more

    if frames >= min_frames:
        return frames, start + off, f"{frames} consecutive MPEG frames, chain intact"
    return frames, start + off, f"only {frames} consecutive MPEG frame(s) (need {min_frames})"


# --------------------------------------------------------------------------- #
# ID3v2 / MP3 header-aware entry point
# --------------------------------------------------------------------------- #


def _id3v2_size(src: ByteSource, start: int) -> Optional[Tuple[int, int]]:
    """Return ``(tag_total_bytes, id3v2_major_version)`` or None."""
    head = src.read(start, 10)
    if len(head) < 10 or head[:3] != b"ID3":
        return None
    major = head[3]
    if major not in (2, 3, 4):
        return None
    flags = head[5]
    if any(head[6 + i] & 0x80 for i in range(4)):
        return None  # invalid synchsafe integer
    size = 0
    for i in range(4):
        size = (size << 7) | (head[6 + i] & 0x7F)
    total = 10 + size
    if flags & 0x10:      # footer present (ID3v2.4)
        total += 10
    return total, major


# --------------------------------------------------------------------------- #
# Per-extension boundary resolvers
# --------------------------------------------------------------------------- #

SignatureRule = Callable[[ByteSource, int, int], Boundary]

_MAX_SIGNATURE = 512 * 1024 * 1024
_MIN_SIGNATURE = 16


def _bm_end(src: ByteSource, start: int, max_size: int) -> Boundary:
    """BMP: total file size is declared at offset 2."""
    head = src.read(start, 26)
    if len(head) < 26:
        return Boundary(None, UNDETERMINED, ["BMP header truncated"])
    size = _le32(head, 2)
    dib = _le32(head, 14)
    pixel_off = _le32(head, 10)
    if _le32(head, 6) != 0:
        return Boundary(None, UNDETERMINED, ["BMP reserved field non-zero"])
    if dib not in (12, 40, 52, 56, 64, 108, 124):
        return Boundary(None, UNDETERMINED, [f"BMP DIB header size {dib} is not a known variant"])
    if size < 26 or pixel_off >= size:
        return Boundary(None, UNDETERMINED, ["BMP declared size inconsistent with pixel offset"])
    end = _sanity(start + size, start + 26, start + max_size)
    if end is None:
        return Boundary(None, UNDETERMINED, [f"BMP declared size {size} outside carve bounds"])
    return Boundary(end, DECLARED_SIZE, [f"BMP declares total size {size} at offset 2"])


def _riff_end(src: ByteSource, start: int, max_size: int) -> Boundary:
    """RIFF (WAV/WEBP/AVI): ``LE32@4`` is the size of everything after byte 8."""
    head = src.read(start, 12)
    if len(head) < 12:
        return Boundary(None, UNDETERMINED, ["RIFF header truncated"])
    declared = _le32(head, 4)
    if declared == 0xFFFFFFFF:
        # Streamed RIFF: the size field is advisory, so walk the chunk list.
        return _riff_walk(src, start, start + 12, max_size, depth=0)
    size = declared + 8
    end = _sanity(start + size, start + 12, start + max_size)
    if end is None:
        return Boundary(None, UNDETERMINED, [f"RIFF declared size {declared} outside carve bounds"])
    return Boundary(end, DECLARED_SIZE, [f"RIFF declares {declared} bytes of chunks"])


def _riff_walk(src: ByteSource, start: int, pos: int, max_size: int, depth: int) -> Boundary:
    limit = min(src.size, start + max_size)
    while pos + 8 <= limit:
        head = src.read(pos, 8)
        if len(head) < 8:
            break
        fourcc = _ascii(head, 0, 4)
        size = _le32(head, 4)
        if fourcc in (b"LIST", b"RIFF") and depth < 4:
            sub = _riff_walk(src, start, pos + 12, max_size, depth + 1)
            if sub.resolved:
                pos = sub.end - start
                continue
        nxt = pos + 8 + size + (size & 1)
        if nxt <= pos or nxt > limit + 8:
            break
        pos = nxt
    end = _sanity(start + pos, start + 12, limit)
    if end is None:
        return Boundary(None, UNDETERMINED, ["RIFF chunk walk did not terminate"])
    return Boundary(end, CONTAINER_WALK, ["RIFF chunk list terminated cleanly"])


def _riff_is_webp(head: bytes) -> bool:
    return _ascii(head, 8, 4) == b"WEBP"


def _sevenzip_end(src: ByteSource, start: int, max_size: int) -> Boundary:
    """7z: ``32 + LE64@12 + LE64@20`` is the exact archive length."""
    head = src.read(start, 32)
    if len(head) < 32:
        return Boundary(None, UNDETERMINED, ["7z header truncated"])
    next_off = _le64(head, 12)
    next_size = _le64(head, 20)
    if next_off > (1 << 40) or next_size > (1 << 40) or next_off + next_size < next_off:
        return Boundary(None, UNDETERMINED, ["7z next-header offsets implausible"])
    size = 32 + next_off + next_size
    end = _sanity(start + size, start + 32, start + max_size)
    if end is None:
        return Boundary(None, UNDETERMINED, [f"7z declared size {size} outside carve bounds"])
    return Boundary(end, DECLARED_SIZE, [f"7z declares {size} bytes (32 + nextHeaderOffset + nextHeaderSize)"])


def _png_end(src: ByteSource, start: int, max_size: int) -> Boundary:
    """PNG: walk the chunk list until IEND. Every length is self-describing."""
    limit = min(src.size, start + max_size)
    pos = start + 8
    saw_ihdr = False
    while pos + 12 <= limit:
        head = src.read(pos, 8)
        if len(head) < 8:
            break
        length = _be32(head, 0)
        ctype = _ascii(head, 4, 4)
        if length > 0x7FFFFFFF:
            break
        if not all(0x41 <= c <= 0x7A for c in ctype):
            break
        nxt = pos + 12 + length
        if nxt <= pos or nxt > limit:
            break
        if ctype == b"IHDR":
            saw_ihdr = True
        if ctype == b"IEND":
            return Boundary(nxt, CONTAINER_WALK, ["PNG chunk list terminated on IEND"])
        pos = nxt
    return Boundary(None, UNDETERMINED, ["PNG chunk list did not reach IEND" if saw_ihdr
                                          else "PNG candidate has no IHDR chunk"])


def _jpeg_end(src: ByteSource, start: int, max_size: int) -> Boundary:
    """JPEG: marker-segment walk to EOI.

    A naive forward search for ``FF D9`` is wrong: that byte pair occurs inside
    entropy-coded scan data after a stuffed ``FF 00`` escape, so the first match
    is usually not the end of the image. The walk therefore reads each segment
    header and skips exactly the number of bytes the segment declares, then scans
    the entropy-coded payload with the ``FF 00`` / ``FF D0..D7`` rules applied.
    """
    limit = min(src.size, start + max_size)
    if src.read(start, 2) != b"\xff\xd8":
        return Boundary(None, UNDETERMINED, ["JPEG candidate does not start with SOI"])

    pos = start + 2
    saw_sof = False
    saw_sos = False
    segments = 0
    sof_dims: Optional[Tuple[int, int]] = None

    while pos + 2 <= limit:
        # A real JPEG has a few dozen header segments at most. Without this cap
        # a single corrupt length field makes the walk wander through megabytes
        # of unrelated data and "find" an EOI far outside the image.
        segments += 1
        if segments > 64:
            return Boundary(None, UNDETERMINED,
                            [f"more than 64 header segments before SOS: the length fields "
                             f"are not describing a JPEG"])
        marker = src.read_until(b"\xff", pos, min(limit - pos, 1 << 24))
        if marker == -1:
            break
        # Collapse fill bytes: FF FF ... FF xx is a single marker xx.
        m_byte = src.read(marker + 1, 1)
        while m_byte == b"\xff":
            marker += 1
            m_byte = src.read(marker + 1, 1)
        if not m_byte:
            break
        m = m_byte[0]
        after = marker + 2                       # first byte past the 2-byte marker

        if m == 0xD9:                            # EOI
            if not saw_sos:
                return Boundary(None, UNDETERMINED,
                                ["JPEG reaches EOI without ever entering a scan"])
            notes = ["JPEG segment walk reached EOI after "
                     f"{segments} header segment(s)"]
            if sof_dims:
                notes.append(f"SOF declares {sof_dims[0]}x{sof_dims[1]} pixels")
            return Boundary(after, FOOTER_ANCHORED, notes)
        if m == 0x00 or m == 0xFF:
            pos = after                          # stuffed byte, not a marker
            continue
        if m == 0x01 or 0xD0 <= m <= 0xD8:
            pos = after                          # standalone marker, no length
            continue

        seg_len = src.read(after, 2)
        if len(seg_len) < 2:
            break
        length = _be16(seg_len, 0)
        if length < 2 or marker + 2 + length > limit:
            return Boundary(None, UNDETERMINED,
                            [f"JPEG segment 0xFF{m:02X} declares an implausible length {length}"])
        if m == 0xDA:                            # SOS: entropy-coded data follows
            saw_sos = True
            pos = marker + 2 + length
            nxt = _skip_entropy(src, pos, limit)
            if nxt == -1:
                return Boundary(None, UNDETERMINED,
                                ["JPEG entropy-coded scan runs past the carve window"])
            pos = nxt
            continue
        if 0xC0 <= m <= 0xCF and m not in (0xC4, 0xC8, 0xCC):
            body = src.read(after + 2, 5)
            if len(body) == 5:
                sof_dims = (_be16(body, 3), _be16(body, 1))
            saw_sof = True
        pos = marker + 2 + length

    return Boundary(None, UNDETERMINED,
                    ["JPEG segment walk never reached EOI" if saw_sof
                     else "JPEG contains no SOF frame header"])


def _skip_entropy(src: ByteSource, pos: int, limit: int) -> int:
    """Advance past entropy-coded scan data to the next real marker.

    Returns the offset of that marker's leading 0xFF, or -1 if the scan runs off
    the end of the window.
    """
    window = 1 << 20
    while pos < limit:
        chunk = src.read(pos, min(window, limit - pos))
        if not chunk:
            return -1
        i = 0
        n = len(chunk)
        while i < n:
            b = chunk[i]
            if b != 0xFF:
                i += 1
                continue
            j = i + 1
            while j < n and chunk[j] == 0xFF:
                j += 1
            if j >= n:
                break                              # marker may straddle the window
            nxt = chunk[j]
            if nxt == 0x00 or 0xD0 <= nxt <= 0xD7:
                i = j + 1                          # stuffed byte or restart marker
                continue
            return pos + i
        pos += n - 1                              # keep one byte for a straddling marker
    return -1


def _gif_end(src: ByteSource, start: int, max_size: int) -> Boundary:
    """GIF: walk the image descriptors and data sub-blocks to the 0x3B trailer."""
    limit = min(src.size, start + max_size)
    head = src.read(start, 13)
    if len(head) < 13:
        return Boundary(None, UNDETERMINED, ["GIF header truncated"])
    if _ascii(head, 0, 6) not in (b"GIF87a", b"GIF89a"):
        return Boundary(None, UNDETERMINED, ["GIF version field invalid"])
    w, h = _le16(head, 6), _le16(head, 8)
    flags = head[10]
    pos = start + 13
    if flags & 0x80:                                   # global colour table
        pos += 3 * (1 << ((flags & 0x07) + 1))
    images = 0
    while pos < limit:
        marker = src.read(pos, 1)
        if not marker:
            break
        c = marker[0]
        if c == 0x3B:                                  # trailer
            if images == 0:
                return Boundary(None, UNDETERMINED, ["GIF reaches the trailer with no image blocks"])
            return Boundary(pos + 1, FOOTER_ANCHORED,
                            [f"GIF trailer found after {images} image block(s), "
                             f"logical screen {w}x{h}"])
        if c == 0x21:                                  # extension block
            size = src.read(pos + 1, 1)
            if not size:
                break
            pos = pos + 2 + size[0]
            continue
        if c == 0x2C:                                  # image descriptor
            img = src.read(pos + 1, 10)
            if len(img) < 10:
                break
            lf = img[9]
            pos += 10
            if lf & 0x80:                              # local colour table
                pos += 3 * (1 << ((lf & 0x07) + 1))
            lzw_min = src.read(pos, 1)
            if not lzw_min:
                break
            pos += 1                                   # LZW minimum code size
            # Sub-blocks: a length byte then that many bytes, until a 0x00.
            for _ in range(1 << 20):
                size = src.read(pos, 1)
                if not size or size[0] == 0:
                    break
                pos += 1 + size[0]
                if pos > limit:
                    return Boundary(None, UNDETERMINED, ["GIF sub-blocks overrun the window"])
            images += 1
            continue
        if c == 0x00:                                  # stray NUL padding
            pos += 1
            continue
        return Boundary(None, UNDETERMINED,
                        [f"unexpected GIF block introducer 0x{c:02X} at +{pos - start}"])
    return Boundary(None, UNDETERMINED,
                    [f"GIF data-block walk did not reach the trailer ({images} image block(s) read)"])


def _pdf_end(src: ByteSource, start: int, max_size: int) -> Boundary:
    """PDF: prefer the xref/trailer, fall back to the *last* %%EOF in range."""
    limit = min(src.size, start + max_size)
    eof = src.rfind_near(b"%%EOF", limit, max_size)
    if eof == -1:
        return Boundary(None, UNDETERMINED, ["no %%EOF within the carve window"])
    end = eof + 5
    while end < src.size and src.read(end, 1) in (b"\r", b"\n"):
        end += 1
    sx = src.rfind_near(b"startxref", eof, min(eof - start, 1 << 20))
    note = "last %%EOF within the carve window"
    if sx != -1:
        note = "last %%EOF, startxref table present"
    return Boundary(end, FOOTER_ANCHORED, [note])


def _zip_end(src: ByteSource, start: int, max_size: int) -> Boundary:
    """ZIP: EOCD is authoritative; must sit within 65557 bytes of the archive end."""
    limit = min(src.size, start + max_size)
    eocd = src.rfind_near(b"PK\x05\x06", limit, 65557 + 22)
    if eocd == -1:
        eocd = src.read_until(b"PK\x05\x06", start, max_size)
        if eocd == -1:
            return Boundary(None, UNDETERMINED, ["no end-of-central-directory record in range"])
    rec = src.read(eocd, 22)
    if len(rec) < 22:
        return Boundary(None, UNDETERMINED, ["EOCD record truncated"])
    comment_len = _le16(rec, 20)
    end = eocd + 22 + comment_len
    cd_size = _le32(rec, 12)
    cd_off = _le32(rec, 16)
    notes = [f"ZIP EOCD: {cd_size} bytes of central directory at +{cd_off}"]
    if 0xFFFFFFFF not in (cd_size, cd_off) and cd_off and cd_off + cd_size == eocd - start:
        notes.append("central directory offsets are self-consistent")
    if end - start > 0xFFFFFFFF:
        notes.append("ZIP64 archive (32-bit fields saturated)")
    return Boundary(end, FOOTER_ANCHORED, notes)


def _ogg_end(src: ByteSource, start: int, max_size: int) -> Boundary:
    """Ogg: walk pages until the end-of-stream flag on a serial-consistent page."""
    limit = min(src.size, start + max_size)
    pos = start
    serial = None
    seq = None
    pages = 0
    while pos + 27 <= limit:
        head = src.read(pos, 27)
        if len(head) < 27 or _ascii(head, 0, 4) != b"OggS":
            break
        if head[4] != 0:
            break
        this_serial = _le32(head, 14)
        this_seq = _le32(head, 18)
        nsegs = head[26]
        seg_table = src.read(pos + 27, nsegs)
        if len(seg_table) < nsegs:
            break
        body = sum(seg_table)
        nxt = pos + 27 + nsegs + body
        if nxt <= pos or nxt > limit + 1:
            break
        pages += 1
        if serial is None:
            serial = this_serial
            seq = this_seq
        elif this_serial != serial or this_seq != (seq + pages - 1) % (1 << 32):
            break
        if head[5] & 0x04:                            # EOS flag
            return Boundary(nxt, CONTAINER_WALK,
                            [f"Ogg: {pages} page(s), end-of-stream page reached"])
        pos = nxt
    return Boundary(None, UNDETERMINED, [f"Ogg page walk did not terminate ({pages} page(s) read)"])


_OGG_MIME = {
    b"\x7fFLAC": "flac", b"\x01vorbis": "ogg", b"\x80theora": "ogv",
    b"Speex   ": "spx", b"\x7fFLAC": "flac",
}


def _flac_end(src: ByteSource, start: int, max_size: int) -> Boundary:
    """FLAC: metadata block walk gives the audio start; STREAMINFO gives the length."""
    limit = min(src.size, start + max_size)
    pos = start + 4
    info = None
    while pos + 4 <= limit:
        hdr = src.read(pos, 4)
        if len(hdr) < 4:
            break
        last = bool(hdr[0] & 0x80)
        btype = hdr[0] & 0x7F
        length = int.from_bytes(hdr[1:4], "big")
        body = src.read(pos + 4, min(length, 34 if btype == 0 else length))
        if btype == 0 and len(body) >= 18:
            info = body
        pos += 4 + length
        if last:
            break
    else:
        return Boundary(None, UNDETERMINED, ["FLAC metadata block list did not terminate"])

    if info is None:
        # No STREAMINFO: fall back to the next plausible audio start.
        audio = _sanity(pos, start + 8, limit)
        if audio is None:
            return Boundary(None, UNDETERMINED, ["FLAC metadata block list did not terminate"])
        return Boundary(None, UNDETERMINED,
                        [f"FLAC metadata ends at +{pos - start} but STREAMINFO is absent"])

    bits = int.from_bytes(info[10:18], "big")
    sample_rate = (bits >> 44) & 0xFFFFF
    channels = ((bits >> 41) & 0x07) + 1
    bps = ((bits >> 36) & 0x1F) + 1
    total_samples = bits & 0xFFFFFFFFF
    if not sample_rate or not total_samples:
        return Boundary(None, UNDETERMINED, ["FLAC STREAMINFO carries no usable sample count"])
    audio_bytes = (total_samples * channels * bps) // 8
    end = _sanity(pos + audio_bytes, pos, limit)
    if end is None:
        return Boundary(None, UNDETERMINED, ["FLAC STREAMINFO length exceeds the carve window"])
    return Boundary(end, DECLARED_SIZE,
                    [f"FLAC STREAMINFO: {total_samples} samples @ {sample_rate} Hz, "
                     f"{channels}ch/{bps}bit -> {audio_bytes} bytes of audio"])


def _mp4_end(src: ByteSource, start: int, max_size: int) -> Boundary:
    """MP4/MOV/QuickTime: walk the atom tree until the top-level atom ends."""
    limit = min(src.size, start + max_size)

    def atom_end(pos: int, depth: int) -> Optional[int]:
        head = src.read(pos, 8)
        if len(head) < 8:
            return None
        size = _be32(head, 0)
        ftype = _ascii(head, 4, 4)
        header = 8
        if size == 1:
            ext = src.read(pos + 8, 8)
            if len(ext) < 8:
                return None
            size = struct.unpack(">Q", ext)[0]
            header = 16
        elif size == 0:
            size = limit - pos                      # extends to end of file
        if size < header or size >= (1 << 48):
            return None
        return pos + size

    ftyp = src.read(start, 12)
    if len(ftyp) < 12 or _ascii(ftyp, 4, 4) != b"ftyp":
        return Boundary(None, UNDETERMINED, ["MP4 candidate has no ftyp box"])
    pos = atom_end(start, 0)
    if pos is None:
        return Boundary(None, UNDETERMINED, ["ftyp box size is implausible"])
    pos = _sanity(pos, start + 12, limit)
    if pos is None:
        return Boundary(None, UNDETERMINED, ["ftyp box overruns the carve window"])

    container_atoms = {b"moov", b"trak", b"mdia", b"minf", b"stbl", b"udta", b"edts", b"moof", b"traf"}
    end = pos
    while pos < limit:
        nxt = atom_end(pos, 0)
        if nxt is None or nxt <= pos or nxt > limit:
            break
        name = _ascii(src.read(pos + 4, 4), 0, 4)
        if name in container_atoms:
            inner = src.read(pos + 8, 8)
            if len(inner) == 8:
                child = pos + 8
                last = None
                while child < nxt - 8:
                    ce = atom_end(child, 1)
                    if ce is None or ce <= child or ce > nxt:
                        break
                    last = ce
                    child = ce
                if last is not None:
                    end = max(end, last)
        end = max(end, nxt)
        pos = nxt

    end = _sanity(end, start + 12, limit)
    if end is None:
        return Boundary(None, UNDETERMINED, ["MP4 atom walk did not terminate"])
    return Boundary(end, CONTAINER_WALK, ["MP4 atom tree walked to its last top-level box"])


def _sqlite_end(src: ByteSource, start: int, max_size: int) -> Boundary:
    """SQLite: page count x page size, valid only when the change counters agree."""
    head = src.read(start, 100)
    if len(head) < 100 or _ascii(head, 0, 16) != b"SQLite format 3\x00":
        return Boundary(None, UNDETERMINED, ["SQLite magic string invalid"])
    page_size = _be16(head, 16)
    if page_size == 1:
        page_size = 65536
    if page_size < 512 or page_size & (page_size - 1):
        return Boundary(None, UNDETERMINED, [f"SQLite page size {page_size} is not a power of two in 512..65536"])
    db_pages = _be32(head, 28)
    change_counter = _be32(head, 24)
    version_valid_for = _be32(head, 92)
    if change_counter != version_valid_for:
        return Boundary(None, UNDETERMINED,
                        ["SQLite change counter != version-valid-for: database header is stale, "
                         "the on-disk page count cannot be trusted"])
    if db_pages == 0:
        return Boundary(None, UNDETERMINED, ["SQLite in-header page count is zero"])
    size = db_pages * page_size
    end = _sanity(start + size, start + 512, start + max_size)
    if end is None:
        return Boundary(None, UNDETERMINED, [f"SQLite declared size {size} exceeds the carve window"])
    return Boundary(end, DECLARED_SIZE,
                    [f"SQLite header: {db_pages} pages x {page_size} B = {size} bytes"])


def _pcap_end(src: ByteSource, start: int, max_size: int) -> Boundary:
    head = src.read(start, 24)
    if len(head) < 24:
        return Boundary(None, UNDETERMINED, ["PCAP header truncated"])
    endian = "<" if _le32(head, 0) in (0xA1B2C3D4, 0xA1B23C4D) else ">"
    if endian == "<":
        incl = _le32(head, 16)
    else:
        incl = int.from_bytes(head[16:20], "big")
    if incl < 16 or incl > (1 << 24):
        return Boundary(None, UNDETERMINED, [f"PCAP captured length {incl} is implausible"])
    size = 24 + incl
    end = _sanity(start + size, start + 24, start + max_size)
    if end is None:
        return Boundary(None, UNDETERMINED, ["PCAP record overruns the carve window"])
    return Boundary(end, DECLARED_SIZE, [f"PCAP record declares {incl} captured bytes"])


def _pcapng_end(src: ByteSource, start: int, max_size: int) -> Boundary:
    """PCAPNG: every block declares its own total length twice; walk and cross-check."""
    limit = min(src.size, start + max_size)
    pos = start
    blocks = 0
    while pos + 12 <= limit:
        head = src.read(pos, 8)
        if len(head) < 8:
            break
        total = _le32(head, 4)
        btype = _le32(head, 0)
        if total < 12 or total % 4 or pos + total > limit:
            break
        trailer = _le32(src.read(pos + total - 4, 4), 0)
        if trailer != total:
            break
        blocks += 1
        if btype == 0x00000006:                       # Enhanced Packet Block: records follow
            pass
        pos += total
    end = _sanity(start + pos, start + 12, limit)
    if end is None:
        return Boundary(None, UNDETERMINED, [f"PCAPNG block walk did not terminate ({blocks} block(s))"])
    return Boundary(end, CONTAINER_WALK,
                    [f"PCAPNG: {blocks} block(s), every length field cross-checked"])


def _gzip_end(src: ByteSource, start: int, max_size: int) -> Boundary:
    """gzip: the only reliable end is where the inflate stream stops.

    The deflate payload has no length field, so the end of the container is
    determined by running the decoder and taking the first byte it did not
    consume. CRC32 and ISIZE are then cross-checked, which turns a candidate into
    a positively-identified file rather than a guess.
    """
    limit = min(src.size, start + max_size)
    head = src.read(start, 10)
    if len(head) < 10 or _ascii(head, 0, 3) != b"\x1f\x8b\x08":
        return Boundary(None, UNDETERMINED, ["gzip magic or compression method byte invalid"])
    flags = head[3]
    pos = 10
    if flags & 0xE0:                                    # reserved bits must be zero
        return Boundary(None, UNDETERMINED, ["gzip FLG has reserved bits set"])
    if flags & 0x04:                                    # FEXTRA
        xlen_b = src.read(start + pos, 2)
        if len(xlen_b) < 2:
            return Boundary(None, UNDETERMINED, ["gzip FEXTRA length truncated"])
        pos += 2 + _le16(xlen_b, 0)
    for flag in (0x08, 0x10):                           # FNAME, FCOMMENT
        if flags & flag:
            z = src.read_until(b"\x00", start + pos, min(65536, limit - start - pos))
            if z == -1:
                return Boundary(None, UNDETERMINED, ["gzip header string is not NUL-terminated"])
            pos = z - start + 1
    if flags & 0x02:                                    # FHCRC
        pos += 2
    if pos >= max_size:
        return Boundary(None, UNDETERMINED, ["gzip header overruns the carve window"])

    window = 1 << 20
    dec = zlib.decompressobj(16 + zlib.MAX_WBITS)
    fed = 0
    produced = 0
    try:
        while start + fed < limit:
            take = min(window, limit - (start + fed))
            chunk = src.read(start + fed, take)
            if not chunk:
                break
            out = dec.decompress(chunk, 64 * 1024 * 1024)
            produced += len(out)
            fed += len(chunk)
            if dec.eof:
                # unused_data counts from the start of the data handed to the
                # decompressor, i.e. from `start`, not from offset 0.
                consumed = fed - len(dec.unused_data)
                end = start + consumed
                trailer = src.read(end - 8, 8) if end >= start + 8 else b""
                notes = [f"gzip inflate stream terminates after {produced:,} bytes of output"]
                if len(trailer) == 8:
                    if _le32(trailer, 4) == (produced & 0xFFFFFFFF):
                        notes.append("ISIZE trailer matches the decoded length")
                    else:
                        notes.append("ISIZE trailer does NOT match the decoded length")
                    if _le32(trailer, 0) == (zlib.crc32(out) & 0xFFFFFFFF):
                        notes.append("CRC32 trailer verified")
                    else:
                        notes.append("CRC32 trailer does NOT match the decoded data")
                return Boundary(end, DECOMPRESSED, notes)
            if dec.unconsumed_tail:
                # zlib stopped early because of max_length; skip what it buffered.
                step = len(dec.unconsumed_tail)
                fed -= step
                pos += step
                if fed <= 0:
                    break
    except zlib.error as exc:
        return Boundary(None, UNDETERMINED, [f"gzip inflate failed: {exc}"])
    return Boundary(None, UNDETERMINED, ["gzip inflate stream did not terminate in the carve window"])


def _tar_end(src: ByteSource, start: int, max_size: int) -> Boundary:
    """tar: 512-byte headers, size as octal at +124.

    The ``ustar`` magic lives at offset 257 *inside* the header, so a candidate
    offset points 257 bytes into the record. Both layouts are accepted: some
    producers and some carvers register the signature at offset 0 instead.
    """
    hdr_base = None
    for base in ((start - 257, start) if start >= 257 else (start,)):
        if base < 0:
            continue
        head = src.read(base, 512)
        if len(head) < 512 or head[257:263] != b"ustar\x00" and head[257:262] != b"ustar":
            continue
        # Both ustar\0 (POSIX) and ustar  (GNU, space padded) are valid.
        if head[257:262] != b"ustar":
            continue
        hdr_base = base
        break
    if hdr_base is None:
        return Boundary(None, UNDETERMINED, ["no ustar header at offset 257 relative to the candidate"])

    hdr = src.read(hdr_base, 512)
    name = hdr[0:100].split(b"\x00")[0]
    raw = hdr[124:136]
    try:
        if raw[0] & 0x80:                              # GNU base-256 encoding
            size = int.from_bytes(raw, "big") & ((1 << 88) - 1)
        else:
            size = int(raw.split(b"\x00")[0].strip() or b"0", 8)
    except ValueError:
        return Boundary(None, UNDETERMINED, ["tar size field is not valid octal"])
    if size < 0 or size > (1 << 40):
        return Boundary(None, UNDETERMINED, ["tar declared size is implausible"])
    blocks = (size + 511) // 512
    trailer = hdr_base + 512 * (1 + blocks)
    if src.read(trailer, 1024) != b"\x00" * 1024:
        return Boundary(None, UNDETERMINED,
                        [f"tar member {name.decode('utf-8', 'replace')!r} has no 1024-byte "
                         f"end-of-archive marker at +{trailer - hdr_base}"])
    absolute_end = trailer + 1024
    if absolute_end > hdr_base + max_size:
        return Boundary(None, UNDETERMINED, ["tar member overruns the carve window"])
    # Archives are conventionally padded with zero blocks to a 10240-byte record
    # boundary. Absorb that padding so the recovered archive is byte-identical
    # to the one written, but stop at the first non-zero block so a tar carved
    # out of a larger disk image does not swallow unrelated data.
    padded = absolute_end
    while padded + 512 <= hdr_base + max_size:
        if src.read(padded, 512) != b"\x00" * 512:
            break
        padded += 512
    end = padded + (start - hdr_base)
    note = f"tar member {name.decode('utf-8', 'replace')!r}, {size} bytes of data, " \
           f"end-of-archive marker at +{absolute_end - hdr_base}"
    if padded > absolute_end:
        note += f", {padded - absolute_end} bytes of conventional zero padding absorbed"
    return Boundary(end, DECLARED_SIZE, [note])


def _elf_end(src: ByteSource, start: int, max_size: int) -> Boundary:
    head = src.read(start, 64)
    if len(head) < 64 or head[:4] != b"\x7fELF":
        return Boundary(None, UNDETERMINED, ["ELF magic invalid"])
    is64 = head[4] == 2
    le = head[5] == 1
    e = "<" if le else ">"
    if is64:
        e_phoff = struct.unpack_from(e + "Q", head, 0x20)[0]
        e_shoff = struct.unpack_from(e + "Q", head, 0x28)[0]
        e_phentsize = struct.unpack_from(e + "H", head, 0x36)[0]
        e_phnum = struct.unpack_from(e + "H", head, 0x38)[0]
        e_shentsize = struct.unpack_from(e + "H", head, 0x3A)[0]
        e_shnum = struct.unpack_from(e + "H", head, 0x3C)[0]
    else:
        e_phoff = struct.unpack_from(e + "I", head, 0x1C)[0]
        e_shoff = struct.unpack_from(e + "I", head, 0x20)[0]
        e_phentsize = struct.unpack_from(e + "H", head, 0x2A)[0]
        e_phnum = struct.unpack_from(e + "H", head, 0x2C)[0]
        e_shentsize = struct.unpack_from(e + "H", head, 0x2E)[0]
        e_shnum = struct.unpack_from(e + "H", head, 0x30)[0]
    if e_version_ok := (struct.unpack_from(e + "I", head, 0x14)[0] != 1):
        return Boundary(None, UNDETERMINED, ["ELF e_version is not EV_CURRENT"])
    if e_phnum > 4096 or e_shnum > 65535:
        return Boundary(None, UNDETERMINED, ["ELF table counts are implausible"])
    ends = []
    if e_phnum and e_phentsize:
        ends.append(e_phoff + e_phnum * e_phentsize)
    if e_shnum and e_shentsize:
        ends.append(e_shoff + e_shnum * e_shentsize)
    if not ends:
        return Boundary(None, UNDETERMINED, ["ELF has neither a program nor a section header table"])
    size = max(ends)
    end = _sanity(start + size, start + 64, start + max_size)
    if end is None:
        return Boundary(None, UNDETERMINED, [f"ELF header tables declare {size} bytes, beyond the window"])
    return Boundary(end, DECLARED_SIZE,
                    [f"ELF {'64' if is64 else '32'}-bit, {'LE' if le else 'BE'}: "
                     f"{e_phnum} program + {e_shnum} section headers -> {size} bytes"])


def _pe_end(src: ByteSource, start: int, max_size: int) -> Boundary:
    head = src.read(start, 64)
    if len(head) < 64 or head[:2] != b"MZ":
        return Boundary(None, UNDETERMINED, ["PE candidate has no MZ header"])
    e_lfanew = _le32(head, 0x3C)
    nt = src.read(start + e_lfanew, 24)
    if len(nt) < 24 or nt[:4] != b"PE\x00\x00":
        return Boundary(None, UNDETERMINED, ["PE header offset does not point at a PE signature"])
    n_sections = _le16(nt, 6)
    opt_size = _le16(nt, 20)
    if n_sections == 0 or n_sections > 4096:
        return Boundary(None, UNDETERMINED, ["PE section count is implausible"])
    sec_off = start + e_lfanew + 24 + opt_size
    ends = []
    for i in range(n_sections):
        sh = src.read(sec_off + i * 40, 40)
        if len(sh) < 40:
            break
        raw_size = _le32(sh, 16)
        raw_ptr = _le32(sh, 20)
        if raw_size:
            ends.append(raw_ptr + raw_size)
    if not ends:
        return Boundary(None, UNDETERMINED, ["PE has no sections with raw data"])
    size = max(ends)
    end = _sanity(start + size, start + 512, start + max_size)
    if end is None:
        return Boundary(None, UNDETERMINED, ["PE sections overrun the carve window"])
    return Boundary(end, DECLARED_SIZE, [f"PE: {n_sections} section(s), last raw data ends at +{size}"])


def _wav_specific_end(src: ByteSource, start: int, max_size: int) -> Boundary:
    head = src.read(start, 12)
    if len(head) < 12 or _ascii(head, 0, 4) != b"RIFF" or _ascii(head, 8, 4) != b"WAVE":
        return Boundary(None, UNDETERMINED, ["RIFF form is not WAVE"])
    if _le32(head, 4) == 0xFFFFFFFF:
        return _riff_walk(src, start, start + 12, max_size, depth=0)
    return _riff_end(src, start, max_size)


# --------------------------------------------------------------------------- #
# MPEG audio entry point
# --------------------------------------------------------------------------- #


def _mpeg_audio_end(src: ByteSource, start: int, max_size: int, id3_version: Optional[int]) -> Boundary:
    limit = min(src.size, start + max_size)
    pos = start
    header_len = 0
    if id3_version is not None:
        info = _id3v2_size(src, start)
        if info is None:
            return Boundary(None, UNDETERMINED, ["ID3v2 header is malformed (bad synchsafe size)"])
        tag_len, _ = info
        pos = start + tag_len
        if pos >= limit:
            return Boundary(None, UNDETERMINED, ["ID3v2 tag overruns the carve window"])
        header_len = 0
    frames, end, reason = _mpeg_sequence(src, pos, header_len, min_frames=3, max_frames=4096,
                                         limit=limit - pos)
    if frames < 3:
        return Boundary(None, UNDETERMINED, [reason])
    if end > limit:
        return Boundary(None, UNDETERMINED, ["MPEG frame sequence extends past the carve window"])
    notes = [reason]
    if id3_version is not None:
        notes.insert(0, f"ID3v2.{id3_version} tag parsed, audio starts after it")
    return Boundary(end, FRAME_VALIDATED, notes)


def _mpegts_end(src: ByteSource, start: int, max_size: int) -> Boundary:
    """MPEG-TS: fixed 188-byte packets, each starting with the 0x47 sync byte."""
    limit = min(src.size, start + max_size)
    packets = 0
    pid = None
    pos = start
    while pos + 188 <= limit:
        if src.read(pos, 1) != b"\x47":
            break
        head = src.read(pos + 1, 3)
        if len(head) < 3:
            break
        this_pid = ((head[0] & 0x1F) << 8) | head[1]
        pusi = bool(head[2] & 0x40)
        afc = (head[3] >> 4) & 0x03 if len(head) > 3 else 0
        step = 188
        if afc in (1, 3):                      # payload present -> adapt next
            af_len = src.read(pos + 4, 1)
            if af_len:
                step += 1 + af_len[0]
        if pid is None:
            pid = this_pid
        elif this_pid == pid and pusi:
            pass
        packets += 1
        pos += step
        if packets > 200_000:
            break
    if packets < 4:
        return Boundary(None, UNDETERMINED, [f"only {packets} consecutive 188-byte TS packet(s)"])
    return Boundary(pos, FRAME_VALIDATED,
                    [f"MPEG-TS: {packets} consecutive 188-byte packet(s) on PID 0x{(pid or 0):04x}"])


def _macho_end(src: ByteSource, start: int, max_size: int) -> Boundary:
    """Mach-O: walk the load commands to the end of the last segment."""
    head = src.read(start, 32)
    if len(head) < 32:
        return Boundary(None, UNDETERMINED, ["Mach-O header truncated"])
    magic = int.from_bytes(head[:4], "little")
    ncmds = int.from_bytes(head[16:20], "little")
    sizeofcmds = int.from_bytes(head[20:24], "little")
    if ncmds == 0 or ncmds > 4096:
        return Boundary(None, UNDETERMINED, ["Mach-O load command count is implausible"])
    pos = start + 32 if magic in (0xFEEDFACF, 0xFEEDFACE) else start + 28
    limit = min(src.size, start + max_size)
    end = pos + sizeofcmds
    for _ in range(ncmds):
        cmd = src.read(pos, 8)
        if len(cmd) < 8:
            return Boundary(None, UNDETERMINED, ["Mach-O load command truncated"])
        cmdsize = int.from_bytes(cmd[4:8], "little")
        if cmdsize < 8 or pos + cmdsize > limit:
            return Boundary(None, UNDETERMINED, ["Mach-O load command size is implausible"])
        if int.from_bytes(cmd[:4], "little") in (0x01, 0x19):      # LC_SEGMENT / LC_SEGMENT_64
            if cmdsize < 72:
                return Boundary(None, UNDETERMINED, ["Mach-O segment command is too short"])
            seg = src.read(pos, cmdsize)
            fileoff = int.from_bytes(seg[40:48], "little")
            filesize = int.from_bytes(seg[48:56], "little")
            if filesize:
                end = max(end, pos + fileoff + filesize)
        pos += cmdsize
    e = _sanity(start + (end - start), pos, limit)
    if e is None:
        return Boundary(None, UNDETERMINED, ["Mach-O segments overrun the carve window"])
    return Boundary(e, DECLARED_SIZE, [f"Mach-O: {ncmds} load command(s), last segment ends at +{end - start}"])


# --------------------------------------------------------------------------- #
# registry
# --------------------------------------------------------------------------- #

_BOUNDARY_RULES: Dict[str, SignatureRule] = {
    "bmp": _bm_end,
    "ico": _pe_end,
    "wav": _wav_specific_end,
    "webp": _riff_end,
    "avi": _riff_end,
    "7z": _sevenzip_end,
    "png": _png_end,
    "jpg": _jpeg_end,
    "jpeg": _jpeg_end,
    "gif": _gif_end,
    "pdf": _pdf_end,
    "zip": _zip_end,
    "ogg": _ogg_end,
    "flac": _flac_end,
    "mp4": _mp4_end,
    "mov": _mp4_end,
    "mkv": _mp4_end,
    "webm": _mp4_end,
    "sqlite": _sqlite_end,
    "pcap": _pcap_end,
    "pcapng": _pcapng_end,
    "gz": _gzip_end,
    "tar": _tar_end,
    "elf": _elf_end,
    "exe": _pe_end,
    "dll": _pe_end,
    "ts": _mpegts_end,
    "macho": _macho_end,
}


def has_boundary_rule(ext: str) -> bool:
    return ext.lower().lstrip(".") in _BOUNDARY_RULES


def resolve_boundary(src: ByteSource, offset: int, sig, max_size: int,
                     *, allow_max_size_fallback: bool = False) -> Boundary:
    """Resolve where the candidate at `offset` ends.

    `sig` is a :class:`~s0.carve.signatures.FileSignature`. `src` is an
    absolute-offset reader, so resolution is not limited to any read window.

    `allow_max_size_fallback` is set only for operator-supplied custom
    signatures. Those describe formats the engine has never heard of, so there
    is nothing to walk and nothing to validate; carving to the declared
    `max_size` is the only thing available, and it is reported as a heuristic
    rather than dressed up as a resolved boundary. Built-in formats always
    refuse: guessing where a file ends is what produced megabytes of noise.
    """
    ext = sig.extension.lower().lstrip(".")
    max_size = min(max_size, _MAX_SIGNATURE)
    if max_size < _MIN_SIGNATURE:
        return Boundary(None, UNDETERMINED, ["carve window smaller than the minimum file size"])

    if ext == "mp3":
        id3 = _id3v2_size(src, offset)
        return _mpeg_audio_end(src, offset, max_size, id3[1] if id3 else None)
    if ext in ("m4a", "aac"):
        b = _mp4_end(src, offset, max_size)
        if b.resolved:
            return b
        return Boundary(None, UNDETERMINED, b.notes)

    rule = _BOUNDARY_RULES.get(ext)
    if rule is None:
        if allow_max_size_fallback:
            # A custom signature that declares its own terminator can still be
            # sized exactly, which is what scalpel-style signature databases do.
            if sig.footer is not None:
                found = src.read_until(sig.footer, offset + len(sig.header),
                                       max(0, max_size - len(sig.header)))
                if found != -1:
                    return Boundary(
                        found + len(sig.footer), FOOTER_ANCHORED,
                        [f"terminator {sig.footer!r} declared by the signature found "
                         f"{found + len(sig.footer) - offset} bytes in"])
            return Boundary(offset + max_size, MAX_SIZE_FALLBACK,
                            [f"no boundary rule exists for .{ext} and the signature declares no "
                             f"terminator; carved to the declared max_size of {max_size} bytes"])
        return Boundary(None, UNDETERMINED, [f"no boundary rule is registered for .{ext}"])

    try:
        boundary = rule(src, offset, max_size)
    except (struct.error, IndexError, ValueError, OverflowError, MemoryError) as exc:
        return Boundary(None, UNDETERMINED, [f"boundary rule for .{ext} failed: {exc}"])

    if boundary.resolved and (sig.min_size > (boundary.end - offset) or
                              (boundary.end - offset) > sig.max_size):
        return Boundary(None, UNDETERMINED,
                        [f"resolved size {boundary.end - offset} outside the signature's "
                         f"[{sig.min_size}, {sig.max_size}] bounds"])
    return boundary


# --------------------------------------------------------------------------- #
# structural validation (the gate)
# --------------------------------------------------------------------------- #


def validate_structure(data: bytes, ext: str) -> Tuple[bool, str]:
    """Decide whether `data` is a coherent instance of `.ext`.

    This is a *gate*, not a score component. s0's scoring model used to award a
    flat bonus for "the header matched and there is no footer", which is exactly
    what let 2-byte magics through. A candidate that cannot be structurally
    validated is not recovered at any confidence.
    """
    ext = ext.lower().lstrip(".")
    n = len(data)
    if n < 16:
        return False, "too short to contain any complete structure"

    if ext == "jpg" or ext == "jpeg":
        return _validate_jpeg(data)
    if ext == "png":
        return _validate_png(data)
    if ext == "gif":
        return _validate_gif(data)
    if ext == "pdf":
        return _validate_pdf(data)
    if ext == "zip":
        return _validate_zip(data)
    if ext == "bmp":
        return _validate_bmp(data)
    if ext == "wav":
        return _validate_wav(data)
    if ext == "mp3":
        return _validate_mp3(data)
    if ext == "gz":
        return _validate_gzip(data)
    if ext == "sqlite":
        return _validate_sqlite(data)
    if ext == "elf":
        return _validate_elf(data)
    if ext == "7z":
        return _validate_7z(data)
    if ext == "ogg":
        return _validate_ogg(data)
    if ext in ("mp4", "mov", "mkv", "webm", "m4v"):
        return _validate_mp4(data)
    if ext == "flac":
        return _validate_flac(data)
    if ext == "pcap":
        return _validate_pcap(data)
    if ext == "pcapng":
        return _validate_pcapng(data)
    if ext == "tar":
        return _validate_tar(data)
    if ext == "ts":
        return _validate_mpegts(data)
    if ext == "macho":
        return _validate_macho(data)
    return True, "no structural rule for this format; accepted on boundary resolution alone"


def _validate_jpeg(data: bytes) -> Tuple[bool, str]:
    if data[:2] != b"\xff\xd8":
        return False, "missing SOI"
    marker = data[3] if len(data) > 3 else 0
    if marker in (0x00, 0xD8, 0xD9, 0xFF):
        return False, f"byte following SOI (0xFF{marker:02X}) is not a valid segment marker"
    if not any(m in data[:4096] for m in (b"\xff\xe0", b"\xff\xe1", b"\xff\xdb", b"\xff\xc0",
                                          b"\xff\xc2", b"\xff\xc4", b"JFIF", b"Exif")):
        return False, "no APP/DQT/SOF/DHT marker in the first 4 KiB"
    if not data.rstrip(b"\x00").endswith(b"\xff\xd9"):
        return False, "does not terminate on EOI"
    return True, "SOI ... SOS ... EOI marker sequence intact"


def _validate_png(data: bytes) -> Tuple[bool, str]:
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return False, "invalid PNG signature"
    if _be32(data, 8) != 13 or _ascii(data, 12, 4) != b"IHDR":
        return False, "first chunk is not a 13-byte IHDR"
    pos = 8
    crc_bad = 0
    while pos + 12 <= len(data):
        length = _be32(data, pos)
        ctype = _ascii(data, pos + 4, 4)
        if length > 0x7FFFFFFF or pos + 12 + length > len(data):
            break
        payload = data[pos + 8 : pos + 8 + length]
        want = _be32(data, pos + 8 + length)
        if length <= 0xFFFF and zlib.crc32(_ascii(data, pos + 4, 4) + payload) & 0xFFFFFFFF != want:
            crc_bad += 1
        pos += 12 + length
        if ctype == b"IEND":
            return (True, f"PNG chunk list complete ({pos - 8} bytes, {crc_bad} CRC mismatch)")
    return False, "PNG chunk list does not terminate on IEND"


def _validate_gif(data: bytes) -> Tuple[bool, str]:
    if _ascii(data, 0, 6) not in (b"GIF87a", b"GIF89a"):
        return False, "GIF version field invalid"
    if _le16(data, 6) == 0 or _le16(data, 8) == 0:
        return False, "GIF logical screen has a zero dimension"
    return True, f"GIF {_ascii(data, 0, 6).decode()} logical screen {_le16(data, 6)}x{_le16(data, 8)}"


def _validate_pdf(data: bytes) -> Tuple[bool, str]:
    if not data.startswith(b"%PDF-"):
        return False, "missing %PDF- header"
    ver = _ascii(data, 5, 3)
    if not (ver[:1].isdigit() and ver[1:2] == b"."):
        return False, f"malformed PDF version {ver!r}"
    if b"/Root" not in data:
        return False, "no /Root entry in the trailer or catalogue"
    if not data.rstrip(b"\r\n \t").endswith(b"%%EOF"):
        return False, "does not terminate on %%EOF"
    return True, f"PDF {ver.decode()} with /Root and %%EOF terminator"


def _validate_zip(data: bytes) -> Tuple[bool, str]:
    eocd = data.rfind(b"PK\x05\x06")
    if eocd == -1:
        return False, "no end-of-central-directory record"
    if len(data) - eocd < 22:
        return False, "end-of-central-directory record is truncated"
    entries = _le16(data, eocd + 10)
    cd_size = _le32(data, eocd + 12)
    cd_off = _le32(data, eocd + 16)
    if 0xFFFFFFFF not in (cd_size, cd_off):
        if cd_off + cd_size != eocd:
            return False, (f"central directory is inconsistent with the EOCD offset "
                           f"({cd_off} + {cd_size} != {eocd})")
        first = data[cd_off : cd_off + 4]
        if first != b"PK\x01\x02":
            return False, "central directory offset does not point at a central directory header"
        if data[:4] != b"PK\x03\x04":
            return False, "archive does not start with a local file header"
        return True, f"ZIP with {entries} central directory entries, offsets self-consistent"
    return True, f"ZIP64 archive with {entries} entries"


def _validate_bmp(data: bytes) -> Tuple[bool, str]:
    if _le32(data, 6) != 0:
        return False, "reserved field is non-zero"
    dib = _le32(data, 14)
    if dib not in (12, 40, 52, 56, 64, 108, 124):
        return False, f"DIB header size {dib} is not a known variant"
    size = _le32(data, 2)
    pixel_off = _le32(data, 10)
    if size != len(data):
        return False, f"declared size {size} != actual {len(data)}"
    if pixel_off >= size:
        return False, "pixel data offset is beyond the declared size"
    return True, f"BMP {size} bytes, DIB variant {dib}, pixel data at +{pixel_off}"


def _validate_wav(data: bytes) -> Tuple[bool, str]:
    if _ascii(data, 8, 4) != b"WAVE":
        return False, "RIFF form is not WAVE"
    pos = 12
    seen_fmt = False
    seen_data = False
    while pos + 8 <= len(data):
        fourcc = _ascii(data, pos, 4)
        size = _le32(data, pos + 4)
        body = pos + 8
        if body + size > len(data):
            break
        if fourcc == b"fmt " and size >= 16:
            tag, channels, rate = _le16(data, body), _le16(data, body + 2), _le32(data, body + 4)
            bits = _le16(data, body + 14)
            if tag not in (1, 0xFFFE) or channels == 0 or channels > 64 or rate == 0 or bits == 0:
                return False, (f"fmt chunk is implausible: tag={tag} channels={channels} "
                               f"rate={rate} bits={bits}")
            seen_fmt = True
        if fourcc == b"data":
            seen_data = True
        pos = body + size + (size & 1)
    if not seen_fmt:
        return False, "no valid fmt chunk"
    if not seen_data:
        return False, "no data chunk"
    return True, "WAVE with a valid fmt chunk and a data chunk"


def _validate_mp3(data: bytes) -> Tuple[bool, str]:
    """Frame-chain validation. This is the whole point for MP3."""
    pos = 0
    id3_note = ""
    if data[:3] == b"ID3":
        info = _id3v2_size(_BytesView(data), 0)
        if info is None:
            return False, "ID3v2 header is malformed (bad synchsafe size)"
        pos, id3_note = info[0], f"valid ID3v2.{info[1]} tag of {info[0]} bytes, "
    frames, end, reason = _mpeg_sequence(_BytesView(data), pos, 0, min_frames=3, max_frames=8192,
                                         limit=len(data))
    if frames < 3:
        return False, reason
    return True, f"{id3_note}{frames} consecutive MPEG frames with an intact sync chain ({reason})"


def _validate_gzip(data: bytes) -> Tuple[bool, str]:
    if _ascii(data, 0, 3) != b"\x1f\x8b\x08":
        return False, "gzip magic or CM byte invalid"
    flg = data[3]
    pos = 10
    if flg & 0x04:                                       # FEXTRA
        if pos + 2 > len(data):
            return False, "FEXTRA length field truncated"
        xlen = _le16(data, pos)
        pos += 2 + xlen
    if flg & 0x08:                                       # FNAME
        z = data.find(b"\x00", pos)
        if z == -1:
            return False, "FNAME is not NUL-terminated"
        pos = z + 1
    if flg & 0x10:                                       # FCOMMENT
        z = data.find(b"\x00", pos)
        if z == -1:
            return False, "FCOMMENT is not NUL-terminated"
        pos = z + 1
    if flg & 0x02:
        pos += 2
    if pos >= len(data):
        return False, "no deflate payload"
    try:
        # The gzip wrapper was stripped above, so the payload is a raw deflate
        # stream: wbits = -MAX_WBITS. Using the gzip wrapper here would try to
        # parse the deflate payload as a second header.
        obj = zlib.decompressobj(-zlib.MAX_WBITS)
        out = obj.decompress(data[pos:])
        out += obj.flush()
    except zlib.error as exc:
        return False, f"deflate stream is not valid: {exc}"
    if not obj.eof:
        return False, "deflate stream does not terminate"
    if len(data) >= 8:
        want = _le32(data, len(data) - 4)
        got = (len(out) & 0xFFFFFFFF)
        if want != got:
            return False, f"ISIZE trailer says {want}, decoded {got} bytes"
        crc = zlib.crc32(out) & 0xFFFFFFFF
        if crc != _le32(data, len(data) - 8):
            return False, "CRC32 trailer does not match the decoded data"
        return True, f"gzip decodes cleanly to {len(out)} bytes; CRC32 and ISIZE both verified"
    return True, "gzip decodes cleanly (no trailer present in the carved window)"


def _validate_sqlite(data: bytes) -> Tuple[bool, str]:
    if _ascii(data, 0, 16) != b"SQLite format 3\x00":
        return False, "SQLite magic string invalid"
    page_size = _be16(data, 16) or 65536
    if page_size < 512 or page_size & (page_size - 1):
        return False, f"page size {page_size} is not a power of two in 512..65536"
    if len(data) % page_size:
        return False, f"length {len(data)} is not a multiple of the {page_size}-byte page size"
    pages = len(data) // page_size
    # 0x02 index interior / 0x05 table interior -> 12-byte header
    # 0x0A index leaf     / 0x0D table leaf     ->  8-byte header
    interior = {0x02, 0x05}
    leaf = {0x0A, 0x0D}
    btree = 0
    for i in range(min(pages, 512)):
        base = i * page_size
        # Page 1 of a SQLite file begins with the 100-byte database header; its
        # b-tree page header starts at offset 100.
        header_offset = 100 if i == 0 else 0
        t = data[base + header_offset]
        if t == 0x00:
            continue
        if t in interior:
            hdr = 12
        elif t in leaf:
            hdr = 8
        else:
            continue
        ncell = _be16(data, base + header_offset + 3)
        if t in interior:
            right = _be32(data, base + header_offset + 8)
            if right != 0 and right >= pages:
                continue
        ptr = base + header_offset + hdr
        if ptr + ncell * 2 > len(data):
            continue
        last = -1
        ok = True
        for c in range(ncell):
            off = _be16(data, ptr + c * 2)
            if off <= last or off >= page_size:
                ok = False
                break
            last = off
        if ok:
            btree += 1
    if btree == 0:
        return False, "no page carries a self-consistent b-tree header and cell pointer array"
    return True, f"{pages} page(s); {btree} page(s) have valid b-tree headers and ordered cell pointers"


def _validate_elf(data: bytes) -> Tuple[bool, str]:
    if data[:4] != b"\x7fELF":
        return False, "ELF magic invalid"
    if data[4] not in (1, 2):
        return False, f"EI_CLASS {data[4]} is not ELFCLASS32/64"
    if data[5] not in (1, 2):
        return False, "EI_DATA is neither little nor big endian"
    if struct.unpack_from("<I", data, 0x14)[0] != 1:
        return False, "e_version is not EV_CURRENT"
    e_type = struct.unpack_from("<H", data, 0x10)[0]
    if e_type not in (1, 2, 3, 4):
        return False, f"e_type {e_type} is not ET_REL/ET_EXEC/ET_DYN/ET_CORE"
    return True, f"ELF e_type={e_type}, {'64' if data[4] == 2 else '32'}-bit, consistent header"


def _validate_7z(data: bytes) -> Tuple[bool, str]:
    if _ascii(data, 0, 6) != b"7z\xbc\xaf\x27\x1c":
        return False, "7z signature invalid"
    ver_major, ver_minor = data[6], data[7]
    if ver_major != 0:
        return False, f"unsupported 7z major version {ver_major}"
    start_hdr = _le64(data, 12)
    next_off = _le64(data, 20)
    if start_hdr < 32 or next_off == 0:
        return False, "start header CRC offset or next-header offset is implausible"
    return True, f"7z v{ver_major}.{ver_minor}, next header at +{32 + start_hdr + next_off}"


def _validate_ogg(data: bytes) -> Tuple[bool, str]:
    if _ascii(data, 0, 4) != b"OggS":
        return False, "Ogg capture pattern invalid"
    if data[4] != 0:
        return False, f"Ogg stream structure version {data[4]} is not 0"
    nsegs = data[26]
    if 27 + nsegs > len(data):
        return False, "Ogg segment table is truncated"
    return True, f"Ogg page, {nsegs} segment(s), body {sum(data[27:27 + nsegs])} bytes"


def _validate_mp4(data: bytes) -> Tuple[bool, str]:
    if _ascii(data, 4, 4) != b"ftyp":
        return False, "no ftyp box at offset 4"
    major = _ascii(data, 8, 4).decode("latin-1")
    compat = []
    for o in range(16, min(len(data), 16 + _be32(data, 0) - 8), 4):
        compat.append(_ascii(data, o, 4).decode("latin-1"))
    return True, f"ISO-BMFF ftyp major brand {major!r}, compatible with {', '.join(compat[:4]) or 'n/a'}"


def _validate_flac(data: bytes) -> Tuple[bool, str]:
    if _ascii(data, 0, 4) != b"fLaC":
        return False, "fLaC signature invalid"
    pos = 4
    last = False
    blocks = []
    while pos + 4 <= len(data) and not last:
        hdr = data[pos]
        last = bool(hdr & 0x80)
        btype = hdr & 0x7F
        if btype == 127:
            return False, "invalid metadata block type 127"
        length = int.from_bytes(data[pos + 1 : pos + 4], "big")
        if pos + 4 + length > len(data):
            return False, "metadata block overruns the file"
        blocks.append(btype)
        pos += 4 + length
    if not last:
        return False, "metadata block list has no last-block flag"
    if 0 not in blocks:
        return False, "no STREAMINFO block"
    return True, f"FLAC with {len(blocks)} metadata block(s), last-block flag set"


def _validate_pcap(data: bytes) -> Tuple[bool, str]:
    magic = _le32(data, 0)
    if magic == 0xA1B2C3D4:
        endian, nano = "little", False
    elif magic == 0xD4C3B2A1:
        endian, nano = "big", False
    elif magic == 0xA1B23C4D:
        endian, nano = "little", True
    elif magic == 0x4D3CB2A1:
        endian, nano = "big", True
    else:
        return False, f"pcap magic 0x{magic:08X} is not a known variant"
    incl = int.from_bytes(data[16:20], endian)
    if incl < 16 or 24 + incl > len(data):
        return False, f"captured length {incl} is implausible for a {len(data)}-byte candidate"
    return True, f"pcap, {endian}-endian{', nanosecond' if nano else ''}, first record {incl} bytes"


def _validate_pcapng(data: bytes) -> Tuple[bool, str]:
    if _ascii(data, 0, 4) != b"\x0a\x0d\x0d\x0a":
        return False, "PCAPNG section header block magic invalid"
    total = _le32(data, 4)
    if total < 12 or total % 4 or total > len(data):
        return False, f"block total length {total} is invalid"
    if _le32(data, total - 4) != total:
        return False, "block trailer length does not match the header length"
    if _le32(data, 8) != 0x1A2B3C4D:
        return False, "byte-order magic is not 0x1A2B3C4D"
    return True, f"PCAPNG section header block, {total} bytes, length cross-checked"


def _validate_tar(data: bytes) -> Tuple[bool, str]:
    if not data[:1].isalnum() and data[:1] not in (b".", b"/"):
        return False, "tar name field has an implausible first byte"
    try:
        raw = data[124:136]
        size = int(raw.split(b"\x00")[0].strip() or b"0", 8)
    except ValueError:
        return False, "tar size field is not valid octal"
    if size > len(data):
        return False, f"tar member declares {size} bytes, more than the {len(data)}-byte candidate"
    return True, f"tar header, member size {size} bytes"


def _validate_mpegts(data: bytes) -> Tuple[bool, str]:
    if len(data) < 188 * 4:
        return False, "fewer than four 188-byte MPEG-TS packets"
    if len(data) % 188:
        return False, f"length {len(data)} is not a multiple of 188"
    if data[0] != 0x47 or data[188] != 0x47:
        return False, "188-byte packet boundaries do not align to the 0x47 sync byte"
    pids = set()
    for off in range(0, min(len(data), 188 * 4096), 188):
        pids.add(((data[off + 1] & 0x1F) << 8) | data[off + 2])
    return True, f"{len(data) // 188} aligned 188-byte packet(s) across {len(pids)} PID(s)"


def _validate_macho(data: bytes) -> Tuple[bool, str]:
    magic = int.from_bytes(data[:4], "little")
    if magic not in (0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE):
        return False, f"Mach-O magic 0x{magic:08X} is not a known variant"
    ncmds = int.from_bytes(data[16:20], "little")
    if ncmds == 0 or ncmds > 4096:
        return False, "Mach-O load command count is implausible"
    return True, f"Mach-O with {ncmds} load command(s)"


class _BytesView:
    """Adapts a bytes object to the ByteSource interface for in-memory validation."""

    __slots__ = ("_data",)

    def __init__(self, data: bytes):
        self._data = data

    @property
    def size(self) -> int:
        return len(self._data)

    def read(self, offset: int, length: int) -> bytes:
        if offset < 0 or length <= 0 or offset >= len(self._data):
            return b""
        return self._data[offset : offset + length]

    def read_until(self, needle: bytes, start: int, limit: int) -> int:
        idx = self._data.find(needle, start, start + limit)
        return idx

    def rfind_near(self, needle: bytes, end: int, limit: int) -> int:
        lo = max(0, end - limit)
        idx = self._data.rfind(needle, lo, end)
        return idx
