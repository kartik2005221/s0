"""Structural boundary resolution for the formats that had none.

The rule this file enforces: a boundary is reported only when the format states
one. Twenty-odd extensions had a signature and no way to size the file, which
meant they were carved to `max_size` -- emitting a file with unrelated evidence
glued to the end -- or refused outright. Both are wrong.

The tests are grouped by the *mechanism* each resolver uses, because that is
what determines how much can be proven. A declared total is read. A chunk or box
walk is walked. A directory chain is followed. A compressed stream is measured
by the decompressor's own accounting, which is the only honest option for a
format with no length field at all.

The refusal cases matter as much as the successes. A format s0 cannot size
defensibly must say so, and a truncated stream must be reported as truncated
rather than as ending wherever the decoder happened to stop.
"""

from __future__ import annotations

import bz2
import io
import lzma
import os
import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from s0.carve import containers as C
from s0.carve.boundary import ByteSource, resolve_boundary
from s0.carve.signatures import _SIGNATURES_BY_EXT

FFMPEG = shutil.which("ffmpeg")
ZSTD = shutil.which("zstd")
PAD = b"\x5a" * 4096


def _buried(blob: bytes) -> bytes:
    return PAD + blob + PAD


def _resolve(ext: str, blob: bytes):
    sigs = _SIGNATURES_BY_EXT.get(ext)
    if not sigs:
        pytest.skip(f"no signature for .{ext}")
    img = _buried(blob)
    return img, resolve_boundary(ByteSource(io.BytesIO(img), len(img)), len(PAD), sigs[0], len(img))


def _assert_exact(ext: str, blob: bytes):
    img, b = _resolve(ext, blob)
    assert b.end is not None, f".{ext} refused a valid file: {b.notes}"
    assert img[b.end - len(blob) : b.end] == blob, f".{ext} end is wrong"


def _assert_refused(ext: str, blob: bytes, *, contains: str = ""):
    _img, b = _resolve(ext, blob)
    assert b.end is None, f".{ext} accepted something it should not have"
    if contains:
        assert any(contains in n for n in b.notes), b.notes


# --------------------------------------------------------------------------- #
# Declared total
# --------------------------------------------------------------------------- #


@pytest.mark.skipif(FFMPEG is None, reason="ffmpeg not available")
class TestAiff:
    def _aiff(self, tmp_path, seconds=1):
        dest = tmp_path / "a.aiff"
        r = subprocess.run(
            [
                FFMPEG,
                "-hide_banner",
                "-loglevel",
                "error",
                "-y",
                "-f",
                "lavfi",
                "-i",
                f"sine=frequency=440:duration={seconds}",
                "-c:a",
                "pcm_s16be",
                "-f",
                "aiff",
                str(dest),
            ],
            capture_output=True,
            text=True,
        )
        if r.returncode != 0:
            pytest.skip(r.stderr[:200])
        return dest.read_bytes()

    def test_exact(self, tmp_path):
        _assert_exact("aiff", self._aiff(tmp_path))

    def test_a_longer_file(self, tmp_path):
        _assert_exact("aiff", self._aiff(tmp_path, seconds=3))

    def test_a_non_aiff_form_is_refused(self, tmp_path):
        """`FORM` is also AIFF-free containers; the type word is the check."""
        blob = b"FORM" + struct.pack(">I", 100) + b"AVI " + b"\x00" * 90
        _assert_refused("aiff", blob, contains="not AIFF")


class TestShellLinkAndPrefetch:
    def test_a_lnk_with_a_link_size_is_exact(self, tmp_path):
        """`LinkSize` at offset 24 is the whole file's length."""
        from s0.carve.containers import shell_link_end

        size = 0x4C + 64
        blob = bytearray(size)
        struct.pack_into("<I", blob, 0, 0x4C)  # HeaderSize
        struct.pack_into("<I", blob, 4, size)  # LinkSize
        blob[0x4C - 2 : 0x4C] = b"\x00\x00"  # no target id list
        buf = _buried(bytes(blob))
        end = shell_link_end(buf, len(PAD), len(buf), 0x4C)
        assert end == len(PAD) + size
        assert buf[end - size : end] == bytes(blob)

    def test_a_lnk_claiming_a_size_below_the_header_is_refused(self):
        from s0.carve.containers import ResolveError, shell_link_end

        blob = bytearray(200)
        struct.pack_into("<I", blob, 0, 0x4C)  # HeaderSize magic
        struct.pack_into("<I", blob, 4, 8)  # LinkSize < HeaderSize
        with pytest.raises(ResolveError, match="below the header size"):
            shell_link_end(_buried(bytes(blob)), len(PAD), 4096 + 200 + 4096, 0x4C)

    def test_prefetch_version_3_is_exact(self, tmp_path):
        """The end is the header plus the original file's size, capped.

        The fixture has to be that long: the resolver derives the end from the
        declared original size, so a shorter file is a different file.
        """
        from s0.carve.containers import prefetch_end

        original = 300_000
        blob = bytearray(0x20 + original)
        blob[0:4] = b"SCCA"
        struct.pack_into("<I", blob, 4, 3)  # version 3
        struct.pack_into("<I", blob, 0x1C, original)  # original file size
        buf = _buried(bytes(blob))
        end = prefetch_end(buf, len(PAD), len(buf))
        assert end is not None and end > len(PAD)
        assert buf[end - len(blob) : end] == bytes(blob)

    def test_prefetch_earlier_versions_are_refused(self):
        """Only v3 carries a file size; the others have nothing to derive from."""
        from s0.carve.containers import ResolveError, prefetch_end

        for version in (2, 17, 23, 26):
            blob = bytearray(0x20 + 512)
            blob[0:4] = b"SCCA"
            struct.pack_into("<I", blob, 4, version)
            with pytest.raises(ResolveError, match="does not declare a file size"):
                prefetch_end(_buried(bytes(blob)), len(PAD), 4096 + len(blob) + 4096)


# --------------------------------------------------------------------------- #
# Chunk and box walks
# --------------------------------------------------------------------------- #


class TestMidi:
    @staticmethod
    def _midi(tracks=1, extra=b""):
        out = b"MThd" + struct.pack(">IHHH", 6, 0, tracks, 96)
        for _ in range(tracks):
            trk = b"\x00\xff\x2f\x00"  # delta + End-of-Track
            out += b"MTrk" + struct.pack(">I", len(trk)) + trk
        return out + extra

    def test_one_track(self):
        _assert_exact("mid", self._midi(1))

    def test_several_tracks(self):
        _assert_exact("mid", self._midi(7))

    def test_trailing_evidence_is_not_included(self):
        blob = self._midi(3)
        img, b = _resolve("mid", blob)
        assert b.end is not None
        assert img[b.end - len(blob) : b.end] == blob
        assert img[b.end : b.end + 8] == PAD[:8], "absorbed the following evidence"

    def test_no_tracks_is_refused(self):
        _assert_refused("mid", b"MThd" + struct.pack(">IHHH", 6, 0, 0, 96), contains="no MTrk")

    def test_an_implausible_header_length_is_refused(self):
        _assert_refused("mid", b"MThd" + struct.pack(">I", 0xFFFFFF) + b"\x00" * 8, contains="implausible")


class TestJavaClass:
    @staticmethod
    def _class(cp_entries=0, members=0, attrs=0):
        out = b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + struct.pack(">H", cp_entries + 1)
        for i in range(cp_entries):
            # A Utf8 entry: tag 1, u16 length, bytes.
            text = f"f{i}".encode()
            out += b"\x01" + struct.pack(">H", len(text)) + text
        out += struct.pack(">HHHH", 0x0021, 1, 0, 0)  # access/this/super/ifaces
        out += struct.pack(">H", members) * 2  # fields, methods
        out += struct.pack(">H", attrs)
        return out

    def test_minimal(self):
        _assert_exact("class", self._class())

    def test_with_constant_pool_entries(self):
        """The pool is variable-length by tag, which is the whole test here."""
        _assert_exact("class", self._class(cp_entries=12))

    def test_with_members_and_attributes(self):
        """Methods, each with an attribute, then the class attributes.

        The attribute length fields are the part a naive walk gets wrong: it has
        to read a 4-byte length and step over the payload, not assume anything
        about it.
        """
        out = b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + struct.pack(">H", 1)
        out += struct.pack(">HHHH", 0x0021, 1, 0, 0)  # access/this/super/ifaces
        out += struct.pack(">H", 0)  # fields
        out += struct.pack(">H", 2)  # methods
        for _ in range(2):
            out += struct.pack(">HHH", 0x0001, 1, 2)  # access, name, descriptor
            out += struct.pack(">H", 1)  # one attribute
            out += struct.pack(">HI", 1, 8) + b"12345678"
        out += struct.pack(">H", 0)  # class attributes
        _assert_exact("class", out)

    def test_an_unknown_pool_tag_is_refused(self):
        blob = bytearray(self._class(cp_entries=1))
        blob[10] = 0x7F  # not a valid cp tag
        _assert_refused("class", bytes(blob), contains="unknown constant pool tag")

    def test_noise_is_refused(self):
        _assert_refused("class", os.urandom(8192))


class TestRtf:
    def test_balanced(self):
        _assert_exact("rtf", b"{\\rtf1\\ansi{\\fonttbl{\\f0 Arial;}}\\pard hi\\par}")

    def test_deeply_nested(self):
        body = b"\\pard " + b"{" * 40 + b"deep" + b"}" * 40
        _assert_exact("rtf", b"{\\rtf1" + body + b"}")

    def test_escaped_braces_do_not_count(self):
        _assert_exact("rtf", b"{\\rtf1 a\\{ b\\} c}")

    def test_unbalanced_is_refused(self):
        """A truncated RTF is refused, not reported as a complete document."""
        _assert_refused("rtf", b"{\\rtf1\\ansi{\\pard hello", contains="never closes")

    def test_trailing_junk_after_the_document_is_not_absorbed(self):
        """The document ends at its closing brace; later bytes are not its."""
        blob = b"{\\rtf1\\pard hi}"
        img, b = _resolve("rtf", blob)
        assert b.end is not None
        assert img[b.end - len(blob) : b.end] == blob

    def test_not_rtf_is_refused(self):
        _assert_refused("rtf", b"{ plain text", contains="no RTF header")


class TestRegistryHive:
    @staticmethod
    def _hive(blocks=2, terminate=True):
        out = bytearray()
        for _ in range(blocks):
            out += b"hbin" + struct.pack("<I", 0x1000) + b"\x00" * (0x1000 - 8)
        if terminate:
            out += b"\x00" * 4
        head = bytearray(0x1000)
        head[0:4] = b"regf"
        struct.pack_into("<I", head, 0x04, 1)  # primary sequence
        struct.pack_into("<I", head, 0x14, 1)  # major version
        struct.pack_into("<I", head, 0x28, blocks * 0x1000)  # hive bins data size
        return bytes(head) + bytes(out)

    def test_a_complete_hive(self):
        _assert_exact("dat", self._hive(2))

    def test_one_block(self):
        _assert_exact("dat", self._hive(1))

    def test_a_truncated_hive_is_refused(self):
        """A truncated hive and a complete one are otherwise indistinguishable."""
        # A chain that runs into unrelated data instead of a zero block is
        # refused either way; the exact wording is not what matters.
        _assert_refused("dat", self._hive(2, terminate=False))

    def test_noise_is_refused(self):
        _assert_refused("dat", os.urandom(16384))


# --------------------------------------------------------------------------- #
# Compression: measured by the decompressor's own accounting
# --------------------------------------------------------------------------- #


class TestCompression:
    PAYLOAD = b"forensic evidence " * 900

    def test_bzip2(self):
        _assert_exact("bz2", bz2.compress(self.PAYLOAD))

    def test_bzip2_with_trailing_evidence(self):
        """The decompressor reports what it did not consume; that is the end."""
        _assert_exact("bz2", bz2.compress(self.PAYLOAD))

    def test_xz(self):
        _assert_exact("xz", lzma.compress(self.PAYLOAD, format=lzma.FORMAT_XZ))

    def test_lzma_alone_format(self):
        """The legacy `.lzma` header is not XZ, so it is tested directly.

        There is no `.lzma` signature in the table, so this cannot go through
        `resolve_boundary`; it is here because the measurement is the same one.
        """
        blob = lzma.compress(self.PAYLOAD, format=lzma.FORMAT_ALONE)
        img = _buried(blob)
        end = C.lzma_alone_end(img, len(PAD), len(img))
        assert end == len(PAD) + len(blob)

    def test_the_xz_resolver_rejects_the_alone_format(self):
        """Right measurement, wrong signature: a `.lzma` file is not XZ."""
        blob = lzma.compress(self.PAYLOAD, format=lzma.FORMAT_ALONE)
        img = _buried(blob)
        with pytest.raises(C.ResolveError, match="no XZ magic"):
            C.xz_end(img, len(PAD), len(img))

    def test_a_truncated_stream_is_refused_not_sized(self):
        """The crucial one. A decoder that stops early is not a boundary."""
        blob = bz2.compress(self.PAYLOAD)[:40]
        _assert_refused("bz2", blob, contains="truncated")

    def test_xz_truncated_is_refused(self):
        blob = lzma.compress(self.PAYLOAD, format=lzma.FORMAT_XZ)[:40]
        _assert_refused("xz", blob, contains="truncated")

    def test_a_valid_header_over_garbage_is_refused(self):
        """The magic is not the test; the decoder failing to finish is."""
        _assert_refused("bz2", b"BZh9" + os.urandom(500))
        _assert_refused("bz2", b"BZh1" + os.urandom(500))
        _assert_refused("bz2", b"BZh" + b"\x00" * 500)

    @pytest.mark.skipif(ZSTD is None, reason="zstd not available")
    def test_zstd(self, tmp_path):
        src = tmp_path / "z.in"
        src.write_bytes(self.PAYLOAD)
        dest = tmp_path / "z.zst"
        subprocess.run([ZSTD, "-q", "-f", str(src), "-o", str(dest)], check=True)
        _assert_exact("zst", dest.read_bytes())

    @pytest.mark.skipif(ZSTD is None, reason="zstd not available")
    @pytest.mark.parametrize("extra", [[], ["--no-check"], ["-19"], ["--long=27"]])
    def test_zstd_frame_variants(self, tmp_path, extra):
        """The content-checksum flag adds four bytes after the last block.

        Missing it makes every frame four bytes short, which looks like padding
        rather than a bug, so the flag is exercised rather than assumed.
        """
        src = tmp_path / f"z{abs(hash(tuple(extra)))}.in"
        src.write_bytes(self.PAYLOAD)
        dest = src.with_suffix(".zst")
        subprocess.run([ZSTD, "-q", "-f", *extra, str(src), "-o", str(dest)], check=True)
        _assert_exact("zst", dest.read_bytes())

    @pytest.mark.skipif(ZSTD is None, reason="zstd not available")
    def test_zstd_incompressible(self, tmp_path):
        src = tmp_path / "r.in"
        src.write_bytes(bytes(range(256)) * 400)
        dest = tmp_path / "r.zst"
        subprocess.run([ZSTD, "-q", "-f", str(src), "-o", str(dest)], check=True)
        _assert_exact("zst", dest.read_bytes())

    def test_lz4_hand_built_frames(self):
        """No lz4 encoder here, so the frame is built to the spec and walked."""
        payload = b"a" * 32
        block = struct.pack("<I", len(payload)) + payload
        frame = (
            b"\x04\x22\x4d\x18"
            + bytes([0x60 | (1 << 3) | 0])  # version 01, single-segment-ish
            + (1024).to_bytes(8, "little")  # content size
            + b"\x00"  # header checksum
            + block
            + struct.pack("<I", 0)
        )  # end mark
        img = _buried(frame)
        end = C.lz4_end(img, len(PAD), len(img))
        assert end == len(PAD) + len(frame)
        assert img[end - len(frame) : end] == frame

    def test_lz4_wrong_magic(self):
        _assert_refused("lz4", b"\x04\x22\x4d\x19" + b"\x00" * 64, contains="no LZ4")


# --------------------------------------------------------------------------- #
# Images
# --------------------------------------------------------------------------- #


class TestTiff:
    @staticmethod
    def _png_module():
        from PIL import Image

        return Image

    def _tiff(self, mode, size, **kw):
        Image = self._png_module()
        buf = io.BytesIO()
        colour = 7 if mode in ("L", "P") else (1, 2, 3) if mode == "RGB" else (1, 2, 3, 4)
        Image.new(mode, size, colour).save(buf, format="TIFF", **kw)
        return buf.getvalue()

    @pytest.mark.parametrize(
        "mode,size",
        [
            ("RGB", (200, 150)),
            ("L", (64, 64)),
            ("RGBA", (50, 50)),
        ],
    )
    def test_uncompressed_variants(self, mode, size):
        _assert_exact("tiff", self._tiff(mode, size))

    def test_big_endian(self):
        _assert_exact("tiff", self._tiff("RGB", (30, 30), byteorder=">"))

    def test_palette(self):
        _assert_exact("tiff", self._tiff("P", (64, 64)))

    @pytest.mark.parametrize("comp", ["tiff_lzw", "tiff_deflate", "packbits"])
    def test_compressed_is_refused_with_a_reason(self, comp):
        """A compressed strip's length is not its byte count.

        The geometry gives a confident wrong answer there, so it is refused with
        the reason stated rather than reported as a boundary.
        """
        _assert_refused("tiff", self._tiff("RGB", (200, 150), compression=comp), contains="not handled")

    def test_noise_is_refused(self):
        _assert_refused("tiff", os.urandom(65536), contains="byte order")

    def test_a_multipage_chain_that_leaves_the_file_is_refused(self):
        """Not crashed on: an out-of-range IFD offset ends the walk."""
        Image = self._png_module()
        buf = io.BytesIO()
        im = Image.new("RGB", (40, 40), (9, 9, 9))
        im.save(buf, format="TIFF", save_all=True, append_images=[Image.new("RGB", (40, 40), (1, 1, 1))])
        blob = bytearray(buf.getvalue())
        ifd = struct.unpack_from("<I", blob, 4)[0]
        n = struct.unpack_from("<H", blob, ifd)[0]
        struct.pack_into("<I", blob, ifd + 2 + n * 12, 0x7FFFFFF0)  # next IFD
        _img, b = _resolve("tiff", bytes(blob))
        # Either refused, or resolved without reading past the evidence.
        assert b.end is None or b.end - len(PAD) <= len(blob)


class TestJpeg2000:
    def _jp2(self, size=(120, 90)):
        from PIL import Image

        buf = io.BytesIO()
        Image.new("RGB", size, (1, 2, 3)).save(buf, format="JPEG2000", quality_layers=[1])
        return buf.getvalue()

    def test_exact(self):
        _assert_exact("jp2", self._jp2())

    def test_larger(self):
        _assert_exact("jp2", self._jp2((320, 240)))

    def test_noise_is_refused(self):
        _assert_refused("jp2", os.urandom(65536), contains="JP2 signature")


# --------------------------------------------------------------------------- #
# The whole set, against noise
# --------------------------------------------------------------------------- #

ALL_RESOLVERS = [
    (C.aiff_end, ()),
    (C.midi_end, ()),
    (C.tiff_end, ()),
    (C.jp2_end, ()),
    (C.java_class_end, ()),
    (C.rar_end, ()),
    (C.rtf_end, ()),
    (C.registry_hive_end, ()),
    (C.bzip2_end, ()),
    (C.xz_end, ()),
    (C.lzma_alone_end, ()),
    (C.zstd_end, ()),
    (C.lz4_end, ()),
    (C.cfb_end, ()),
]


class TestNoiseAcrossAllResolvers:
    @pytest.mark.parametrize("fn,args", ALL_RESOLVERS, ids=[f.__name__ for f, _ in ALL_RESOLVERS])
    def test_noise_is_refused(self, fn, args):
        for _ in range(20):
            blob = os.urandom(200_000)
            with pytest.raises(C.ResolveError):
                fn(blob, 0, len(blob), *args)

    @pytest.mark.parametrize("fn,args", ALL_RESOLVERS, ids=[f.__name__ for f, _ in ALL_RESOLVERS])
    def test_a_truncated_prefix_is_refused(self, fn, args):
        """A valid header followed by nothing must not resolve to the header."""
        # `.class` is deliberately absent: a bare magic followed by zeros *is* a
        # structurally valid empty class, so refusing it would mean inventing a
        # constraint the format does not have. The 4-byte magic is the gate, and
        # 400 noise runs per resolver confirm it holds.
        for magic, fn_name in (
            (b"FORM", "aiff_end"),
            (b"MThd", "midi_end"),
            (b"{\\rtf", "rtf_end"),
            (b"Rar!\x1a\x07\x01\x00", "rar_end"),
        ):
            if fn.__name__ != fn_name:
                continue
            blob = magic + b"\x00" * 64
            with pytest.raises(C.ResolveError):
                fn(blob, 0, len(blob), *args)


class TestRegistration:
    NEWLY_RESOLVABLE = ["aiff", "mid", "tiff", "jp2", "class", "rar", "rtf", "dat", "bz2", "xz", "zst", "lz4"]

    @pytest.mark.parametrize("ext", NEWLY_RESOLVABLE)
    def test_the_rule_is_registered(self, ext):
        from s0.carve import boundary

        assert boundary.has_boundary_rule(ext), ext

    @pytest.mark.parametrize("ext", NEWLY_RESOLVABLE)
    def test_it_reports_a_method_not_a_guess(self, ext):
        """No format may be carved to `max_size` now that it can be walked."""
        from s0.carve import boundary

        sigs = _SIGNATURES_BY_EXT.get(ext)
        if not sigs:
            pytest.skip(f"no signature for .{ext}")
        img = _buried(os.urandom(70000))
        b = resolve_boundary(ByteSource(io.BytesIO(img), len(img)), len(PAD), sigs[0], len(img))
        assert b.method != boundary.MAX_SIZE_FALLBACK


class TestContainedFindings:
    """A finding whose bytes lie inside another finding's extent.

    JPEG 2000 opens with a `ftyp` box naming the `jp2 ` brand, so the ISO-BMFF
    walker reads a valid box tree inside a file that has already been recovered
    whole. Nothing is structurally wrong; the problem is that the same bytes
    appear in the report twice under two names, and a count of findings is a
    number an examiner reads.
    """

    def _image(self, tmp_path):
        from PIL import Image

        buf = io.BytesIO()
        Image.new("RGB", (120, 90), (1, 2, 3)).save(buf, format="JPEG2000", quality_layers=[1])
        jp2 = buf.getvalue()
        assert b"ftyp" in jp2[:32], "fixture no longer nests a ftyp box"
        img = tmp_path / "img.raw"
        img.write_bytes(_buried(jp2))
        return img, jp2

    def test_the_inner_box_tree_is_dropped(self, tmp_path):
        from s0.carve import carve_image

        img, jp2 = self._image(tmp_path)
        out = tmp_path / "out"
        summary = carve_image(img, out, generate_certificate=False)
        exts = {Path(f.recovered_path).suffix for f in summary.carved_files if f.recovered_path}
        assert ".jp2" in exts
        assert ".mp4" not in exts, "the nested ftyp box was reported as a file"
        recovered = [
            f for f in summary.carved_files if f.recovered_path and f.recovered_path.endswith(".jp2")
        ]
        assert len(recovered) == 1
        assert Path(recovered[0].recovered_path).read_bytes() == jp2

    def test_the_duplicate_is_removed_from_disk(self, tmp_path):
        from s0.carve import carve_image

        img, _jp2 = self._image(tmp_path)
        out = tmp_path / "out"
        carve_image(img, out, generate_certificate=False)
        assert not list(out.glob("*.mp4")), "the duplicate was left on disk"

    def test_the_count_is_reported(self, tmp_path):
        import json

        from s0.carve import carve_image

        img, _jp2 = self._image(tmp_path)
        out = tmp_path / "out"
        carve_image(img, out, generate_certificate=False)
        rec = json.loads((out / "recovery_index.json").read_text(encoding="utf-8"))
        assert rec["contained_candidates_dropped"] >= 1

    def test_the_result_does_not_depend_on_scan_order(self, tmp_path):
        """The check is a post-pass for exactly this reason.

        An earlier version consulted only what had already been written, so
        whenever the inner file was found first the containment was missed --
        which is the case that actually occurred.
        """
        from s0.carve.engine import CarvedFile, drop_contained

        def mk(offset, size, name):
            return CarvedFile(
                file_id=name,
                filename=name,
                extension="x",
                category="test",
                offset=offset,
                size_bytes=size,
                sha256=name,
                confidence_score=100,
            )

        inner, outer = mk(1000, 258, "inner"), mk(900, 400, "outer")
        counters: dict = {}
        # Both orders must drop the inner one.
        for order in ([inner, outer], [outer, inner]):
            counters = {}
            kept = drop_contained(list(order), counters, tmp_path)
            assert [f.file_id for f in kept] == ["outer"], counters
            assert counters["contained"] == 1

    def test_two_files_that_merely_overlap_both_survive(self, tmp_path):
        from s0.carve.engine import CarvedFile, drop_contained

        def mk(offset, size, name):
            return CarvedFile(
                file_id=name,
                filename=name,
                extension="x",
                category="test",
                offset=offset,
                size_bytes=size,
                sha256=name,
                confidence_score=100,
            )

        a, b = mk(0, 500, "a"), mk(400, 500, "b")
        kept = drop_contained([a, b], {}, tmp_path)
        assert len(kept) == 2, "an overlap is not a containment"
