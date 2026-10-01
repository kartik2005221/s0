"""RIFF chunk walking and the AVI chunk index.

The three traps this file exists to pin, all of which produce a
plausible-looking wrong answer rather than an obvious failure:

1. The ``idx1`` offset base is ambiguous *by design* -- movi-relative or
   file-absolute, and real files use both. Getting it wrong shifts every chunk.
2. ``ckSize`` is the payload only, and odd payloads carry a pad byte that is not
   counted in it, so the next sibling is at ``offset + 8 + size + (size & 1)``.
3. ``idx1`` points at chunk *headers*; OpenDML ``indx`` points at chunk *data*,
   and OpenDML inverts the keyframe bit.

Real ffmpeg output is the primary fixture: a hand-written RIFF would encode the
same assumptions the parser has and so could not catch a wrong one.
"""

from __future__ import annotations

import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from s0.carve import riff

FFMPEG = shutil.which("ffmpeg")


def _encode_avi(tmp_path: Path, name: str = "clip.avi", *extra: str) -> Path:
    out = tmp_path / name
    cmd = [FFMPEG, "-hide_banner", "-loglevel", "error", "-y",
           "-f", "lavfi", "-i", "testsrc=size=160x120:rate=15:duration=2",
           "-c:v", "mpeg4", *extra, "-f", "avi", str(out)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0 or not out.is_file() or out.stat().st_size < 512:
        pytest.skip(f"ffmpeg could not produce {name}: {proc.stderr[:200]}")
    return out


# --------------------------------------------------------------------------- #
# Synthetic chunk builders, for the traps
# --------------------------------------------------------------------------- #

def chunk(fourcc: bytes, payload: bytes) -> bytes:
    """A RIFF chunk, with the WORD pad byte the format requires."""
    return fourcc + struct.pack("<I", len(payload)) + payload + (b"\x00" if len(payload) & 1 else b"")


def lst(list_type: bytes, *chunks: bytes) -> bytes:
    body = list_type + b"".join(chunks)
    return b"LIST" + struct.pack("<I", len(body)) + body


def build_avi(chunk_payloads, *, base_is_absolute=False, movi_pad=0):
    """A minimal but structurally real AVI with an ``idx1``.

    ``chunk_payloads`` is a list of (fourcc, payload) pairs. Index offsets are
    written either relative to the ``movi`` identifier or absolute, so both
    documented conventions can be produced and told apart by the parser.
    """
    movi_chunks = b"".join(chunk(f, p) for f, p in chunk_payloads)
    # Note: movi_chunks is one bytes object, not a sequence of chunks. Passing it
    # with * would unpack it into ints.
    movi = lst(b"movi", b"\x00" * movi_pad, movi_chunks)
    hdrl = lst(b"hdrl", chunk(b"avih", b"\x00" * 56))

    # The 'movi' identifier sits 8 bytes into its own LIST header, and that LIST
    # follows RIFF (4cc + size = 8) + the 'AVI ' list type (4) + hdrl.
    movi_id = 12 + len(hdrl) + 8

    rows = b""
    rel = 4 + movi_pad          # the identifier itself is 4 bytes
    for fourcc, payload in chunk_payloads:
        off = (movi_id + rel) if base_is_absolute else rel
        rows += fourcc + struct.pack("<III", riff.AVIIF_KEYFRAME, off, len(payload))
        rel += len(chunk(fourcc, payload))
    idx1 = chunk(b"idx1", rows)

    body = b"AVI " + hdrl + movi + idx1
    return b"RIFF" + struct.pack("<I", len(body)) + body


class TestChunkWalk:
    def test_lists_are_descended_into(self):
        body = b"AVI " + lst(b"movi", chunk(b"00dc", b"x" * 4))
        data = b"RIFF" + struct.pack("<I", len(body)) + body
        chunks = riff.walk_chunks(data, 0, len(data))
        fourccs = {c.fourcc for c in chunks}
        list_types = {c.list_type for c in chunks if c.list_type}
        assert b"LIST" in fourccs
        assert b"movi" in list_types
        assert b"00dc" in fourccs, "the movi children must be reached"

    def test_odd_payloads_get_a_pad_byte(self):
        """Trap 2: the next sibling is not at offset + size."""
        data = chunk(b"AAAA", b"12345") + chunk(b"BBBB", b"ok")
        c0, c1 = riff.walk_chunks(data, 0, len(data))
        assert c0.size == 5
        assert c0.next_offset == 8 + 5 + 1
        assert c1.start == c0.next_offset

    def test_even_payloads_have_no_pad(self):
        data = chunk(b"AAAA", b"1234") + chunk(b"BBBB", b"ok")
        c0, c1 = riff.walk_chunks(data, 0, len(data))
        assert c0.next_offset == 8 + 4
        assert c1.start == c0.next_offset

    def test_a_chunk_overrunning_its_parent_is_rejected(self):
        data = b"AAAA" + struct.pack("<I", 9999) + b"short"
        with pytest.raises(riff.RiffError):
            riff.walk_chunks(data, 0, len(data))

    def test_list_type_offset_is_where_movi_sits(self):
        body = b"AVI " + lst(b"movi", chunk(b"00dc", b"x"))
        data = b"RIFF" + struct.pack("<I", len(body)) + body
        movi = riff.find_movi(riff.walk_chunks(data, 0, len(data)))
        assert data[movi.list_type_offset:movi.list_type_offset + 4] == b"movi"
        assert data[movi.children_start:movi.children_start + 4] == b"00dc"


class TestIndexBaseResolution:
    """Trap 1: the offset base is ambiguous and must be decided by the data."""

    PAYLOADS = [(b"00dc", b"a" * 100), (b"00dc", b"b" * 120), (b"01wb", b"c" * 90)]

    def test_movi_relative_base_is_detected(self):
        data = build_avi(self.PAYLOADS, base_is_absolute=False)
        idx = riff.find_avi_index(data)
        assert idx is not None
        assert not idx.base_is_absolute
        assert data[idx.base:idx.base + 4] == b"movi"
        for e in idx.entries:
            off = idx.extent(e)[0]
            assert data[off:off + 4] == e.chunk_id

    def test_file_absolute_base_is_detected(self):
        data = build_avi(self.PAYLOADS, base_is_absolute=True)
        idx = riff.find_avi_index(data)
        assert idx is not None
        assert idx.base_is_absolute
        for e in idx.entries:
            off = idx.extent(e)[0]
            assert data[off:off + 4] == e.chunk_id

    def test_an_index_that_points_at_nothing_is_rejected(self):
        data = bytearray(build_avi(self.PAYLOADS))
        at = data.find(b"idx1")
        # Corrupt every offset so neither base resolves.
        for row in range(3):
            struct.pack_into("<I", data, at + 4 + 8 + row * 16 + 4, 0x7FFFFFFF)
        assert riff.find_avi_index(bytes(data)) is None

    def test_an_ambiguous_index_is_refused_not_guessed(self):
        """A tie between the two readings means we do not know which it is."""
        data = build_avi(self.PAYLOADS)
        # Make the movi identifier sit at file offset 0's twin is impossible;
        # instead check the tie path directly.
        idx = riff.resolve_index(data, None, [])
        assert idx is None
        entries = riff.parse_idx1(data, data.find(b"idx1"))
        # With no movi to anchor to, the relative base is 0 == the absolute base.
        assert riff.resolve_index(data, None, entries) is None

    def test_keyframes_are_counted_from_the_flags(self):
        data = build_avi(self.PAYLOADS)
        idx = riff.find_avi_index(data)
        assert idx is not None
        assert idx.keyframes == len(self.PAYLOADS)
        assert all(e.is_keyframe for e in idx.entries)


class TestOpendml:
    """Trap 3: OpenDML points at data and inverts the keyframe bit."""

    def _indx(self, rows, base=0):
        payload = struct.pack("<III", 4, 1, len(rows))
        payload += b"\x00" * 12
        payload += struct.pack("<Q", base)
        for fourcc, flags, off, size in rows:
            payload += fourcc + struct.pack("<III", flags, off, size)
        return b"indx" + struct.pack("<I", len(payload)) + payload

    def test_rows_are_read_with_a_64_bit_base(self):
        rows = [(b"00dc", 0x10, 100, 200), (b"00dc", 0x10, 300, 210)]
        idx = riff.parse_opendml_indx(self._indx(rows, base=4096), 0)
        assert len(idx) == 2
        assert all(e.base_is_absolute for e in idx)
        assert idx[0].offset == 4196
        assert idx[1].offset == 4396

    def test_keyframe_bit_is_inverted_against_aviif(self):
        """Bit 31 of dwSize clear means keyframe; AVIIF_KEYFRAME would say the
        opposite, so reading it the obvious way inverts every frame."""
        keyed = riff.IndexEntry(b"00dc", 0, 0, 0x00001234, base_is_absolute=True)
        unkeyed = riff.IndexEntry(b"00dc", 0, 0, 0x80001234, base_is_absolute=True)
        assert keyed.is_keyframe is True
        assert unkeyed.is_keyframe is False
        assert keyed.payload_size == 0x1234
        assert unkeyed.payload_size == 0x1234

    def test_a_guard_word_mismatch_is_refused(self):
        rows = [(b"00dc", 0x10, 0, 16)]
        assert riff.parse_opendml_indx(self._indx(rows), 0), "the well-formed table parses"
        broken = bytearray(self._indx(rows))
        struct.pack_into("<I", broken, 8, 7)      # dwLongsPerEntry != 4
        assert riff.parse_opendml_indx(bytes(broken), 0) == []

    def test_a_zero_length_row_still_parses(self):
        """A super-index may legitimately carry a zero-length placeholder row."""
        rows = [(b"00dc", 0, 0, 0)]
        parsed = riff.parse_opendml_indx(self._indx(rows), 0)
        assert len(parsed) == 1
        assert parsed[0].payload_size == 0


class TestAgainstRealEncoder:
    @pytest.mark.skipif(FFMPEG is None, reason="ffmpeg not available")
    @pytest.mark.parametrize("codec", ["mpeg4", "ffv1", "rawvideo", "h264"])
    def test_index_resolves_and_every_chunk_lands_on_its_fourcc(self, tmp_path, codec):
        data = _encode_avi(tmp_path, f"{codec}.avi", "-c:v", codec).read_bytes()
        idx = riff.find_avi_index(data)
        assert idx is not None, "a real AVI must have a resolvable index"
        assert len(idx.entries) > 0
        hits = sum(1 for e in idx.entries
                   if data[idx.extent(e)[0]:idx.extent(e)[0] + 4] == e.chunk_id)
        assert hits == len(idx.entries), f"only {hits}/{len(idx.entries)} chunks resolved"
        first, last = idx.media_extent()
        assert 0 < first < last <= len(data)

    @pytest.mark.skipif(FFMPEG is None, reason="ffmpeg not available")
    def test_at_least_one_keyframe_is_indexed(self, tmp_path):
        data = _encode_avi(tmp_path).read_bytes()
        idx = riff.find_avi_index(data)
        assert idx.keyframes >= 1, "a real AVI has keyframes"

    @pytest.mark.skipif(FFMPEG is None, reason="ffmpeg not available")
    def test_every_indexed_chunk_size_is_consistent_with_the_data(self, tmp_path):
        data = _encode_avi(tmp_path).read_bytes()
        idx = riff.find_avi_index(data)
        for e in idx.entries:
            off = idx.extent(e)[0]
            declared = struct.unpack_from("<I", data, off + 4)[0]
            assert declared == e.payload_size, (
                f"index says {e.payload_size} bytes for {e.chunk_id!r} at {off} "
                f"but the chunk header says {declared}")


class TestCarverIntegration:
    @pytest.mark.skipif(FFMPEG is None, reason="ffmpeg not available")
    @pytest.mark.parametrize("codec", ["mpeg4", "ffv1"])
    def test_avi_is_recovered_byte_exact(self, tmp_path, codec):
        from s0.carve import carve_image
        src = _encode_avi(tmp_path, f"{codec}.avi", "-c:v", codec)
        original = src.read_bytes()
        image = tmp_path / "img.raw"
        image.write_bytes(b"\x5a" * 8192 + original + b"\x5a" * 8192)
        out = tmp_path / "out"
        carve_image(image, out, generate_certificate=False)
        avis = [f for f in out.iterdir() if f.suffix == ".avi"]
        assert len(avis) == 1, sorted(f.name for f in out.iterdir())
        assert avis[0].read_bytes() == original

    @pytest.mark.skipif(FFMPEG is None, reason="ffmpeg not available")
    def test_the_report_shows_the_resolved_index(self, tmp_path):
        import json

        from s0.carve import carve_image
        src = _encode_avi(tmp_path)
        image = tmp_path / "img.raw"
        image.write_bytes(b"\x5a" * 4096 + src.read_bytes() + b"\x5a" * 4096)
        out = tmp_path / "out"
        carve_image(image, out, generate_certificate=False)
        rec = json.loads((out / "recovery_index.json").read_text())
        assert rec["recovered_files"]
        joined = " ".join(rec["recovered_files"][0]["heuristics"])
        assert "AVI index resolved" in joined
        assert "keyframe(s)" in joined

    def test_a_riff_that_is_not_avi_is_not_claimed(self):
        from s0.carve.boundary import _validate_avi
        wav = b"RIFF" + struct.pack("<I", 36) + b"WAVEfmt " + b"\x00" * 32
        ok, why = _validate_avi(wav)
        assert not ok and "AVI" in why

    def test_an_avi_without_a_usable_index_is_rejected(self):
        from s0.carve.boundary import _validate_avi
        body = b"AVI " + lst(b"hdrl", chunk(b"avih", b"\x00" * 56)) + lst(b"movi", chunk(b"00dc", b"x" * 40))
        data = b"RIFF" + struct.pack("<I", len(body)) + body
        ok, why = _validate_avi(data)
        assert not ok and "index" in why

    def test_an_avi_whose_index_points_nowhere_is_rejected(self):
        from s0.carve.boundary import _validate_avi
        data = bytearray(build_avi(TestIndexBaseResolution.PAYLOADS))
        at = data.find(b"idx1")
        for row in range(3):
            struct.pack_into("<I", data, at + 8 + row * 16 + 8, 0x7FFFFFF0)
        ok, why = _validate_avi(bytes(data))
        assert not ok and ("resolves" in why or "index" in why)
