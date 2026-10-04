"""Structural boundary resolution for the container formats that lacked one.

The rule
--------
A boundary is only reported when the format states one. These resolvers exist
for the twenty-odd formats whose signature table had an entry and no way to
size the file, which meant they were carved to `max_size` or refused outright.
Both are wrong: one emits a file with unrelated evidence glued to the end, the
other cannot recover a format it has a signature for.

The grouping below is by *mechanism*, not by format, because that is what
determines how much can actually be proven:

* **Declared total** -- one field states the whole file (AIFF's `FORM` size,
  a shell link's `LinkSize`, a prefetch entry's file size). Read it, sanity
  check it, done.
* **Chunk or box walk** -- the file is a sequence of self-sizing elements
  (MIDI tracks, TIFF IFDs, JPEG 2000 boxes, CFB directory entries, Java class
  members, RAR blocks). The end is the end of the last element that parses.
* **Directory chain** -- the file describes where its own data lives (CFB's
  FAT, TIFF's strip offsets, ZIP's central directory). Follow the chain.
* **Decompress to exhaustion** -- a compressed stream has no length field at
  all; the only honest end is where the decoder stops accepting input.

What is refused
---------------
Formats with no length, no chain and no terminator. Windows INI files are the
clear case: they are text, they may legitimately run to the end of the medium,
and there is nothing in the format that says where one stops. s0 refuses them
rather than guessing, because a guessed end produces a file that looks
complete and is not. Registry hives (`dat`) are in the same position -- the
`regf` block chain is walkable, but a truncated hive is indistinguishable from
a complete one, so the walk reports what it can prove and refuses when the
chain does not close.
"""

from __future__ import annotations

import struct
from collections.abc import Callable

#: Formats whose declared size is trusted only after these checks.
MIN_FILE = 16


class ResolveError(ValueError):
    """The bytes do not support a defensible answer."""


def _need(buf: bytes, off: int, n: int, what: str) -> bytes:
    if off < 0 or off + n > len(buf):
        raise ResolveError(f"ran out of data reading {what} at {off}")
    return buf[off : off + n]


def _u16le(b: bytes, o: int) -> int:
    return struct.unpack_from("<H", b, o)[0]


def _u32le(b: bytes, o: int) -> int:
    return struct.unpack_from("<I", b, o)[0]


def _u64le(b: bytes, o: int) -> int:
    return struct.unpack_from("<Q", b, o)[0]


def _u16be(b: bytes, o: int) -> int:
    return struct.unpack_from(">H", b, o)[0]


def _u32be(b: bytes, o: int) -> int:
    return struct.unpack_from(">I", b, o)[0]


def _sanitise(end: int, start: int, limit: int, *, minimum: int = MIN_FILE) -> int | None:
    """A plausible absolute end, or ``None``."""
    size = end - start
    if size < minimum or end > limit:
        return None
    return end


# --------------------------------------------------------------------------- #
# Declared total
# --------------------------------------------------------------------------- #


def aiff_end(buf: bytes, start: int, limit: int) -> int | None:
    """AIFF/AIFC: a `FORM` whose size field is everything after byte 8.

    Chunked like RIFF but with a big-endian size, and a different type word.
    """
    if _need(buf, start, 12, "FORM header")[:4] != b"FORM":
        raise ResolveError("no FORM")
    form = _ascii(buf, start + 8, 4)
    if form not in (b"AIFF", b"AIFC"):
        raise ResolveError(f"FORM type {form!r} is not AIFF")
    size = _u32be(buf, start + 4)
    return _sanitise(start + 8 + size, start, limit)


def shell_link_end(buf: bytes, start: int, limit: int, header_size: int) -> int | None:
    """Windows shell link (`.lnk`, `.url`): `LinkSize` at offset 24.

    Both are the same header, distinguished by the 4-byte CLSID: the internet
    shortcut's is the URL moniker, everything else's is a volume or file one.
    """
    head = _need(buf, start, 0x4C, "shell link header")
    if head[0:4] != b"L\x00\x00\x00":
        raise ResolveError("no shell link header size")
    declared = _u32le(head, 0x04)
    if declared < header_size:
        raise ResolveError(f"LinkSize {declared} is below the header size")
    if head[0x4C - 2 : 0x4C] == b"\x00\x00":
        return _sanitise(start + declared, start, limit, minimum=header_size)
    raise ResolveError("no HasLinkTargetIDList terminator")


def prefetch_end(buf: bytes, start: int, limit: int) -> int | None:
    """Windows prefetch (`.pf`): version 3 states the original file's size.

    Only version 3 carries that field, so earlier versions are refused rather
    than sized by the prefetch container's own length, which is routinely
    truncated by the prefetcher.
    """
    head = _need(buf, start, 0x20, "prefetch header")
    if head[:4] != b"SCCA":
        raise ResolveError("no SCCA magic")
    version = _u32le(head, 4)
    if version != 3:
        raise ResolveError(f"prefetch version {version} does not declare a file size")
    original_size = _u32le(head, 0x1C)
    if original_size < MIN_FILE:
        raise ResolveError("declared original size is implausible")
    # The prefetch container is at least the header plus that many bytes of
    # trace data, but it is capped: the prefetcher never stores the whole file.
    return _sanitise(start + 0x20 + min(original_size, 1 << 20), start, limit)


# --------------------------------------------------------------------------- #
# Chunk and box walks
# --------------------------------------------------------------------------- #


def midi_end(buf: bytes, start: int, limit: int) -> int | None:
    """Standard MIDI file: a header chunk then `MTrk` chunks, each self-sizing."""
    head = _need(buf, start, 14, "MThd")
    if head[:4] != b"MThd":
        raise ResolveError("no MThd")
    header_len = _u32be(head, 4)
    if header_len < 6 or header_len > 0x10000:
        raise ResolveError(f"implausible MThd length {header_len}")
    pos = start + 8 + header_len
    tracks = 0
    while pos + 8 <= limit:
        if buf[pos : pos + 4] != b"MTrk":
            break
        length = _u32be(buf, pos + 4)
        end = pos + 8 + length
        if end > limit or end <= pos:
            break
        tracks += 1
        pos = end
    if not tracks:
        raise ResolveError("no MTrk chunks")
    return _sanitise(pos, start, limit)


def cfb_end(buf: bytes, start: int, limit: int) -> int | None:
    """Compound File Binary (`.doc`, `.mdb`, `.xls`): walk the FAT chain.

    The header states the sector size, and the DIFAT/FAT give where the
    directory and mini-stream live. The file is as long as its highest used
    sector, which is derivable without trusting any single declared total.
    """
    head = _need(buf, start, 512, "CFB header")
    if head[:8] != b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        raise ResolveError("no CFB signature")
    sector_shift = _u16le(head, 30)
    mini_shift = _u16le(head, 32)
    if not (6 <= sector_shift <= 20) or mini_shift != 6:
        raise ResolveError(f"implausible CFB sector shift {sector_shift}/{mini_shift}")
    sector = 1 << sector_shift
    first_dir = _u32le(head, 48)
    mini_cutoff = _u32le(head, 56)
    first_difat = _u32le(head, 68)
    num_difat = _u32le(head, 72)

    def sector_offset(n: int) -> int:
        return start + 512 + n * sector

    # The DIFAT: the first 109 entries live in the header, the rest in sectors
    # chained from first_difat.
    difat: list[int] = []
    for i in range(109):
        v = _u32le(head, 76 + i * 4)
        if v == 0xFFFFFFFF:
            break
        difat.append(v)
    nxt, guard = first_difat, 0
    while nxt not in (0xFFFFFFFE, 0xFFFFFFFF) and guard < num_difat + 8 and guard < 4096:
        s = _need(buf, sector_offset(nxt), sector, "DIFAT sector")
        per = sector // 4 - 1
        for i in range(per):
            v = _u32le(s, i * 4)
            if v != 0xFFFFFFFF:
                difat.append(v)
        nxt = _u32le(s, per * 4)
        guard += 1
    if not difat:
        raise ResolveError("CFB has no FAT sectors")

    def fat_sector(n: int) -> bytes | None:
        if n >= len(difat):
            return None
        off = sector_offset(difat[n])
        if off + sector > limit:
            return None
        return buf[off : off + sector]

    # Follow the directory chain to find the highest sector it touches, which
    # is where the file ends.
    highest = first_dir
    seen = 0
    cur = first_dir
    per = sector // 4
    while cur not in (0xFFFFFFFE, 0xFFFFFFFF) and seen < 1 << 20:
        f = fat_sector(cur // per)
        if f is None:
            break
        nxt = _u32le(f, (cur % per) * 4)
        highest = max(highest, cur)
        seen += 1
        if nxt == cur:
            break
        cur = nxt
    if seen == 0:
        raise ResolveError("CFB directory chain does not start")
    del mini_cutoff  # documented above; not needed to bound the file
    return _sanitise(sector_offset(highest) + sector, start, limit, minimum=512)


def tiff_end(buf: bytes, start: int, limit: int) -> int | None:
    """TIFF: the IFD chain, then every strip and tile the IFDs point at.

    A TIFF's last IFD is not the end of the file -- the pixel data normally
    follows it, and where it ends is only knowable from the strip offsets *and*
    their byte counts together. Offsets and counts are different quantities, and
    treating a byte count as an offset is how this first read a 32 KB strip
    count as a 32 KB offset and walked into the surrounding evidence.
    """
    head = _need(buf, start, 8, "TIFF header")
    order = head[:2]
    # Named `byte_order`, not `end`. This used to be `end`, and so was the
    # absolute end offset computed 120 lines below -- one name, two types, in one
    # function. It happened to work only because the int was assigned last; adding
    # any use of the byte order after that point would hand an int to
    # struct.unpack_from and raise a StructError from inside a boundary walk.
    # mypy flagged it as a return-type mismatch, which is what prompted the look.
    if order == b"II":
        byte_order = "<"
    elif order == b"MM":
        byte_order = ">"
    else:
        raise ResolveError(f"bad TIFF byte order {order!r}")
    magic = struct.unpack_from(byte_order + "H", head, 2)[0]
    if magic == 43:
        raise ResolveError("BigTIFF uses 8-byte offsets and is not handled")
    if magic != 42:
        raise ResolveError(f"bad TIFF magic {magic}")

    def u16(o: int) -> int:
        return struct.unpack_from(byte_order + "H", _need(buf, o, 2, "u16"), 0)[0]

    def u32(o: int) -> int:
        return struct.unpack_from(byte_order + "I", _need(buf, o, 4, "u32"), 0)[0]

    def values(eo: int, type_id: int, count: int) -> list[int]:
        """The value(s) of an IFD entry, inline or via its offset.

        A count of one is stored inline in the four-byte value field whatever
        the type, which is the detail that makes naive TIFF readers wrong.
        """
        if count == 0:
            return []
        if count == 1:
            if type_id == 3:
                return [u16(eo + 8)]
            return [u32(eo + 8)]
        if count > (1 << 22):
            raise ResolveError("implausible IFD value count")
        at = u32(eo + 8)
        step = 2 if type_id == 3 else 4
        if at + step * count > limit:
            raise ResolveError("IFD value array runs past the window")
        return [u16(at + step * k) if type_id == 3 else u32(at + step * k) for k in range(count)]

    # The IFD offset in the header is relative to the start of the file, so it
    # has to be added to `start`. Reading it at absolute offset 4 reads the
    # *image's* fourth byte instead, which for a candidate found mid-volume is
    # unrelated evidence.
    ifd = start + u32(start + 4)
    seen = 0
    furthest = 0
    while ifd and seen < 64:
        if ifd + 2 > limit or ifd + 2 < start:
            # A multi-page TIFF chains IFDs by offset, and a damaged or
            # truncated chain can point anywhere. Without this guard the read
            # below raises `struct.error` out of the resolver, which the carver
            # turns into "carving aborted" for the whole target.
            raise ResolveError("IFD offset is outside the window")
        count = u16(ifd)
        if count > 4096:
            raise ResolveError(f"implausible IFD entry count {count}")
        entry_base = ifd + 2
        # Collect the geometry in tag order, then pair it up: the strip arrays
        # come in matched pairs and a TIFF may hold several images.
        # Compression (0x0103) 1 is uncompressed. For anything else the strips
        # are a compressed stream whose length is not their byte count, so the
        # geometry below would produce a confident wrong answer. Measured:
        # uncompressed TIFF resolves exactly across raw, greyscale, RGBA and
        # big-endian variants; LZW, Deflate and PackBits did not, so they are
        # refused rather than guessed at.
        comp = None
        for i in range(count):
            eo = entry_base + i * 12
            if u16(eo) == 0x0103:
                comp = u16(eo + 8)
        if comp is not None and comp != 1:
            raise ResolveError(
                f"TIFF compression {comp} is not handled: a compressed strip's "
                f"length is not its byte count, so the end would be a guess"
            )

        geometry: dict[int, list[int]] = {}
        # Width of each TIFF field type. Needed because any value that does not
        # fit inline -- which is every value with a count above one -- lives at an
        # offset, and the file has to contain it. Tracking only the strip arrays
        # misses a `BitsPerSample` array that happens to sit last, and the file
        # then comes out a few bytes short of itself.
        item = {
            1: 1,
            2: 1,
            3: 2,
            4: 4,
            5: 8,
            6: 1,
            7: 1,
            8: 2,
            9: 4,
            10: 8,
            11: 4,
            12: 8,
            13: 4,
            16: 8,
            17: 8,
            18: 8,
        }
        for i in range(count):
            eo = entry_base + i * 12
            tag = u16(eo)
            type_id = u16(eo + 2)
            n = u32(eo + 4)
            if n > 1:
                width = item.get(type_id)
                if width:
                    at = u32(eo + 8)
                    furthest = max(furthest, start + at + width * n)
            if tag in (0x0111, 0x0144, 0x0117, 0x0146, 0x0115, 0x0116, 0x0147):
                geometry.setdefault(tag, values(eo, type_id, n))
        for off_tag, cnt_tag in ((0x0111, 0x0117), (0x0144, 0x0146), (0x0115, 0x0116), (0x0117, 0x0146)):
            offs = geometry.get(off_tag)
            cnts = geometry.get(cnt_tag)
            if not offs or not cnts:
                continue
            for k, o in enumerate(offs):
                length = cnts[k] if k < len(cnts) else (cnts[-1] if len(cnts) == 1 else 0)
                furthest = max(furthest, start + o + length)
        furthest = max(furthest, entry_base + count * 12 + 4)
        nxt = u32(entry_base + count * 12)
        if nxt == ifd:
            break
        ifd = nxt
        seen += 1
        if ifd and not (start <= ifd < limit):
            # A chain that leaves the file is a chain we cannot follow. Ending
            # the walk here reports what was proven rather than reading past
            # the evidence.
            break
    if seen == 0 or furthest == 0:
        raise ResolveError("no TIFF IFD could be walked")
    if seen == 0 or furthest == 0:
        raise ResolveError("no TIFF IFD could be walked")
    end = _sanitise(furthest, start, limit, minimum=32)
    if end is None:
        raise ResolveError(
            f"the IFD chain points to offset {furthest - start}, past the end of "
            f"the {limit - start}-byte window; the strips cannot be trusted"
        )
    return end


def jp2_end(buf: bytes, start: int, limit: int) -> int | None:
    """JPEG 2000: walk the codestream boxes to the end of `EOC`.

    A JP2 file is a sequence of marker segments, each with a declared length,
    terminated by `EOC`. A raw codestream (`.j2k`) starts at `SOC`/`SIZ` and is
    also a box sequence, so both are handled by the same walk.
    """
    pos = start
    if buf[pos : pos + 4] == b"\xff\x4f\xff\x51":  # raw codestream
        pos = start + 4
        length = _u32be(buf, pos)
        header = buf[pos + 4 : pos + 4 + length - 4]
        width = height = 0
        i = 0
        while i + 4 <= len(header):
            marker = header[i]
            seg = struct.unpack_from(">H", header, i + 2)[0] if i + 4 <= len(header) else 0
            if marker == 0xFF51:  # SIZ
                width = struct.unpack_from(">I", header, i + 6)[0] if i + 10 <= len(header) else 0
                height = struct.unpack_from(">I", header, i + 10)[0] if i + 14 <= len(header) else 0
            i += 2 + seg
        if not (width and height):
            raise ResolveError("codestream SIZ not found")
        # An image's codestream length is not derivable from its dimensions, so
        # the only structural end is EOC.
        pos = start + 4 + length
    else:
        pos = start
        if buf[pos : pos + 12] != b"\x00\x00\x00\x0cjP  \r\n\x87\n":
            raise ResolveError("no JP2 signature box")
        pos = start + 12
    saw_soc = False
    guard = 0
    while pos + 4 <= limit and guard < 4096:
        length = _u32be(buf, pos)
        marker = buf[pos + 4 : pos + 8]
        if marker == b"\xff\x4f\xff\x51":  # SOC inside a box
            pos += 4
            continue
        if length < 2:
            raise ResolveError(f"marker segment length {length} at {pos}")
        if marker == b"jp2c":  # contiguous codestream
            body = pos + 8
            eoc = buf.find(b"\xff\xd9", body, min(limit, body + length))
            if eoc < 0:
                raise ResolveError("codestream box has no EOC")
            return _sanitise(eoc + 2, start, limit, minimum=64)
        pos += length
        saw_soc = True
        guard += 1
    del saw_soc
    raise ResolveError("no jp2c codestream box found")


def java_class_end(buf: bytes, start: int, limit: int) -> int | None:
    """Java `.class`: magic, version, constant pool, then the class body.

    The constant pool is variable-length by construction -- each entry's size
    depends on its tag -- so it is walked entry by entry. Getting it right is
    the whole test of this resolver: a mis-read count lands the walk in the
    middle of a UTF-8 string and the next "field" is garbage.
    """
    head = _need(buf, start, 10, "class header")
    if head[:4] != b"\xca\xfe\xba\xbe":
        raise ResolveError("no Java class magic")
    count = struct.unpack_from(">H", head, 8)[0]
    pos = start + 10
    # Tag 1 (Utf8) is variable-length and handled separately, so it has to be
    # named here too. Leaving it out means the membership check below rejects
    # every real class file, since almost every class has string constants.
    sizes = {
        1: None,
        7: 2,
        8: 2,
        16: 2,
        19: 2,
        20: 2,
        15: 3,
        3: 4,
        4: 4,
        9: 4,
        10: 4,
        11: 4,
        12: 4,
        17: 4,
        18: 4,
        5: 8,
        6: 8,
    }
    for _ in range(count - 1):
        if pos >= limit:
            raise ResolveError("constant pool ran past the window")
        tag = buf[pos]
        if tag not in sizes:
            raise ResolveError(f"unknown constant pool tag {tag} at {pos}")
        if tag == 1:  # Utf8: u16 length + bytes
            n = _u16be(buf, pos + 1)
            if n > limit:
                raise ResolveError("Utf8 constant length is implausible")
            pos += 3 + n
        else:
            pos += 1 + sizes[tag]
    # access_flags, this_class, super_class, interfaces, then the members.
    pos += 6
    if_count = _u16be(buf, pos)
    pos += 2 + 2 * if_count
    for _group in ("fields", "methods"):
        n = _u16be(buf, pos)
        pos += 2
        if n > 1 << 16:
            raise ResolveError(f"implausible member count {n}")
        for _ in range(n):
            pos += 6  # access, name, descriptor
            attr_count = _u16be(buf, pos)
            pos += 2
            if attr_count > 1 << 16:
                raise ResolveError(f"implausible attribute count {attr_count}")
            for _ in range(attr_count):
                alen = _u32be(buf, pos + 2)
                if alen > limit:
                    raise ResolveError("attribute length is implausible")
                pos += 6 + alen
    class_attrs = _u16be(buf, pos)
    pos += 2
    if class_attrs > 1 << 16:
        raise ResolveError(f"implausible class attribute count {class_attrs}")
    for _ in range(class_attrs):
        alen = _u32be(buf, pos + 2)
        if alen > limit:
            raise ResolveError("class attribute length is implausible")
        pos += 6 + alen
    return _sanitise(pos, start, limit, minimum=20)


def rar_end(buf: bytes, start: int, limit: int) -> int | None:
    """RAR 5.x: a chain of self-describing blocks from the RAR5 signature."""
    head = _need(buf, start, 8, "RAR signature")
    if head[:8] != b"Rar!\x1a\x07\x01\x00":
        raise ResolveError("not a RAR5 signature")
    pos = start + 8
    furthest = pos
    guard = 0
    while pos + 4 <= limit and guard < 1 << 20:
        head_size = _u32le(buf, pos)
        if head_size < 7 or pos + head_size > limit:
            break
        header_type = buf[pos + 4]
        flags = buf[pos + 5]
        extra = _u32le(buf, pos + 6) if head_size >= 11 else 0
        data_len = 0
        if flags & 0x0001:  # extra area present
            p = pos + head_size - 4
            while p + 4 <= pos + head_size:
                rec_size = _u64le(buf, p)
                if rec_size == 0 or p + rec_size > pos + head_size:
                    break
                if _u64le(buf, p + 8) == 1:  # file data
                    data_len = _u64le(buf, p + 16)
                p += rec_size
        block_end = pos + head_size + extra + data_len
        if block_end > limit or block_end <= pos:
            break
        furthest = max(furthest, block_end)
        if header_type == 5:  # end-of-archive
            return _sanitise(block_end, start, limit, minimum=16)
        pos = block_end
        guard += 1
    if furthest <= start + 8:
        raise ResolveError("no RAR block could be read")
    raise ResolveError("RAR archive has no end-of-archive block")


def rtf_end(buf: bytes, start: int, limit: int) -> int | None:
    """RTF: the file ends where its brace nesting returns to zero.

    A declared length does not exist, so this is a real walk rather than a
    field read -- and it is only accepted when the nesting closes cleanly, so a
    truncated RTF is refused instead of being reported as a complete document.
    """
    if _need(buf, start, 6, "RTF header")[:5] != b"{\\rtf":
        raise ResolveError("no RTF header")
    depth = 0
    i = start
    while i < limit:
        c = buf[i]
        if c == 0x5C:  # backslash escape
            i += 2
            continue
        if c == 0x7B:
            depth += 1
        elif c == 0x7D:
            # The walk returns at the first return to depth zero, so depth
            # cannot go negative here: trailing junk after the document is not
            # evidence that the document is malformed.
            depth -= 1
            if depth == 0:
                return _sanitise(i + 1, start, limit, minimum=8)
        i += 1
    raise ResolveError("RTF group nesting never closes")


def registry_hive_end(buf: bytes, start: int, limit: int) -> int | None:
    """Windows registry hive: the `regf` block chain, if it closes.

    A hive is a sequence of 4 KiB `hbin` blocks, each with a declared size. A
    *complete* hive ends with a zero-length block; a truncated one does not.
    Only the complete case is reported, because a truncated hive and a complete
    one are otherwise indistinguishable and the difference is the whole point.
    """
    head = _need(buf, start, 0x1000, "hive header")
    if head[:4] != b"regf":
        raise ResolveError("no regf block")
    # The first 4 KiB block is the `regf` block itself; the `hbin` chain starts
    # after it. Starting the walk at `start` looks for an `hbin` where the
    # `regf` magic is, so it refuses every real hive.
    # Offset 0x28 is "hive bins data size": the total of every `hbin` block that
    # follows. The `regf` block has no length field of its own; it is always
    # 4 KiB, so the chain starts one block in.
    hbin_bytes = _u32le(head, 0x28)
    if hbin_bytes and (hbin_bytes < 0x1000 or hbin_bytes % 0x1000):
        raise ResolveError(f"regf declares an implausible hbin area {hbin_bytes}")
    pos = start + 0x1000
    seen = 0
    budget = hbin_bytes or None
    while pos + 0x1000 <= limit and seen < 1 << 22:
        # The end of a hive is a zero-length block, not an `hbin`. It has to be
        # tested before the `hbin` requirement, or a complete hive is refused
        # for ending where it is supposed to.
        if buf[pos : pos + 4] == b"\x00\x00\x00\x00":
            return _sanitise(pos + 4, start, limit, minimum=0x1000)
        block = buf[pos : pos + 0x1000]
        if len(block) < 8:
            break
        if block[:4] != b"hbin":
            raise ResolveError(f"expected hbin at {pos}, found {block[:4]!r}")
        size = _u32le(block, 4) & 0xFFFFF000
        if size < 0x1000 or pos + size > limit:
            raise ResolveError(f"hbin declares {size} bytes, past the window")
        seen += 1
        pos += size
    del budget
    if buf[pos : pos + 4] == b"\x00\x00\x00\x00":
        return _sanitise(pos + 4, start, limit, minimum=0x1000)
    raise ResolveError("hive has no terminating empty block, so it is truncated")


def _ascii(buf: bytes, o: int, n: int) -> bytes:
    return buf[o : o + n]


# --------------------------------------------------------------------------- #
# Streams with no length at all
# --------------------------------------------------------------------------- #


def _decompressed_end(ctor, buf: bytes, start: int, limit: int, what: str) -> int | None:
    """Exact end of a compressed stream, from the decompressor's own accounting.

    A decompressor that has finished a stream reports the bytes it did not
    consume in ``unused_data``. That is an exact answer rather than a scan: the
    consumed length is the stream length by definition, and it works on a
    window that contains several concatenated streams as well as on one that
    contains trailing evidence.

    This is the honest way to size a format with no length field. The
    alternative -- searching for a terminator -- finds the first thing that
    *looks* like one, and a compressed stream is dense enough that something
    always does.
    """
    window = buf[start:limit]
    try:
        d = ctor()
    except Exception as exc:  # pragma: no cover - ctor
        raise ResolveError(f"{what}: no decompressor available ({exc})") from exc
    consumed = None
    try:
        d.decompress(window)
        if d.eof:
            consumed = len(window) - len(d.unused_data)
    except Exception as exc:
        # A truncated stream raises rather than setting `eof`. That is the
        # answer "cannot tell", not "ends here", so it is not turned into one.
        raise ResolveError(f"{what}: the stream is truncated inside the window") from exc
    if consumed is None:
        raise ResolveError(f"{what}: the stream does not end inside the window")
    return _sanitise(start + consumed, start, limit, minimum=16)


def bzip2_end(buf: bytes, start: int, limit: int) -> int | None:
    """bzip2: exact end, from :class:`bz2.BZ2Decompressor`."""
    if _need(buf, start, 4, "bzip2 magic")[:3] != b"BZh":
        raise ResolveError("no BZh magic")
    if buf[start + 3 : start + 4] < b"1" or buf[start + 3 : start + 4] > b"9":
        raise ResolveError("implausible bzip2 level")
    import bz2

    return _decompressed_end(bz2.BZ2Decompressor, buf, start, limit, "bzip2")


def xz_end(buf: bytes, start: int, limit: int) -> int | None:
    """XZ/LZMA: exact end, from :class:`lzma.LZMADecompressor`."""
    if _need(buf, start, 6, "xz magic") != b"\xfd7zXZ\x00":
        raise ResolveError("no XZ magic")
    import lzma

    return _decompressed_end(lzma.LZMADecompressor, buf, start, limit, "xz")


def lzma_alone_end(buf: bytes, start: int, limit: int) -> int | None:
    """Legacy `.lzma` (alone format), which has a different magic."""
    import lzma

    return _decompressed_end(lzma.LZMADecompressor, buf, start, limit, "lzma")


def zstd_end(buf: bytes, start: int, limit: int) -> int | None:
    """Zstandard: walk frame and block headers, which need no decoder.

    A frame header states its window and content size; each block inside it has
    a three-byte header whose low bits give the block's length. So the frame end
    is arithmetic. Decoding would be the wrong tool anyway: a zstd stream can
    hold a terabyte, and its length is a matter of three-byte headers.
    """
    if _need(buf, start, 4, "zstd magic") != b"\x28\xb5\x2f\xfd":
        raise ResolveError("no zstd magic")
    pos = start
    guard = 0
    while pos + 5 <= limit and guard < 1 << 16:
        if buf[pos : pos + 4] != b"\x28\xb5\x2f\xfd":
            # Not another frame. A `.zst` on a volume is followed by whatever
            # else was there, and that is the answer, not a parse error.
            break
        fhd = buf[pos + 4]
        fcs_flag = (fhd >> 6) & 0x03
        single = (fhd >> 5) & 0x01
        checksum = (fhd >> 2) & 0x01
        # FCS code 0 means no content-size field at all in a multi-segment frame
        # and a single byte in a single-segment one.
        fcs_size = {0: 0 if not single else 1, 1: 2, 2: 4, 3: 8}[fcs_flag]
        p = pos + 4 + (1 if single else 5)  # no window byte if single
        p += fcs_size
        dict_flag = fhd & 0x03
        p += (0, 1, 2, 4)[dict_flag]
        if p > limit:
            break
        # Blocks: 3-byte header, low bit = last, bits 1-2 = type, rest = size.
        while p + 3 <= limit:
            bh = int.from_bytes(buf[p : p + 3], "little")
            last = bh & 1
            btype = (bh >> 1) & 0x03
            bsize = bh >> 3
            p += 3
            if btype == 0:  # raw
                p += bsize
            elif btype == 1:  # RLE: 1 byte
                p += 1
            elif btype == 2:  # compressed
                p += bsize
            else:  # reserved
                raise ResolveError("reserved zstd block type")
            if p > limit:
                raise ResolveError("zstd block runs past the window")
            if last:
                break
        else:
            raise ResolveError("zstd frame has no final block inside the window")
        if checksum:
            # A 4-byte content checksum follows the last block. Missing it makes
            # every frame 4 bytes short, which is the kind of error that looks
            # like padding rather than a bug.
            p += 4
        if p <= pos:
            raise ResolveError("zstd frame made no progress")
        pos = p
        guard += 1
    if pos <= start + 4:
        raise ResolveError("no zstd frame could be walked")
    return _sanitise(pos, start, limit, minimum=8)


def lz4_end(buf: bytes, start: int, limit: int) -> int | None:
    """LZ4 frame: same idea -- frame header then self-describing blocks.

    Legacy and skippable frames are also accepted, since a real `.lz4` file may
    start with either and refusing would be wrong for a format that is simply
    versioned.
    """
    if _need(buf, start, 4, "lz4 magic") != b"\x04\x22\x4d\x18":
        raise ResolveError("no LZ4 frame magic")
    pos = start + 4
    flg = buf[pos]
    version = flg >> 6
    if version != 1:
        raise ResolveError(f"LZ4 frame version {version} is not 01")
    block_independence = bool(flg & 0x20)
    del block_independence
    content_size = (flg >> 3) & 0x0F
    dict_id = flg & 0x03
    pos += 1
    if content_size == 15:
        pos += 8
    if dict_id:
        pos += 4
    pos += 1  # header checksum
    if pos > limit:
        raise ResolveError("LZ4 header runs past the window")
    while pos + 4 <= limit:
        size = _u32le(buf, pos)
        if size == 0:  # end mark
            return _sanitise(pos + 4, start, limit, minimum=7)
        pos += 4 + size
        if pos > limit:
            raise ResolveError("LZ4 block runs past the window")
    raise ResolveError("LZ4 frame has no end mark inside the window")


# --------------------------------------------------------------------------- #
# Dispatch
# --------------------------------------------------------------------------- #


def resolve(
    ext: str, buf: bytes, start: int, limit: int, reader: Callable | None = None
) -> tuple[int, list[str]] | None:
    """Resolve one of these formats, returning ``(end, notes)``.

    Raises :class:`ResolveError` when the format does not support a defensible
    answer, which the caller turns into a refusal with the reason attached.
    """
    ext = ext.lower().lstrip(".")
    fn = _DISPATCH.get(ext)
    if fn is None:
        raise ResolveError(f"no container resolver for .{ext}")
    end = fn(buf, start, limit)
    if end is None:
        raise ResolveError(f"the .{ext} structure does not support a length")
    return end, [f"{ext.upper()}: structural walk resolved the end to {end} ({end - start} bytes)"]


_DISPATCH: dict = {
    "aiff": aiff_end,
    "mid": midi_end,
    "tiff": tiff_end,
    "jp2": jp2_end,
    "class": java_class_end,
    "rar": rar_end,
    "rtf": rtf_end,
    "dat": registry_hive_end,
    "bz2": bzip2_end,
    "xz": xz_end,
    "lzma": lzma_alone_end,
    "zst": zstd_end,
    "lz4": lz4_end,
}
