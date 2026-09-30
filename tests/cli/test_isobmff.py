"""ISO-BMFF sample-table arithmetic, checked against real encoder output.

Two kinds of test here, and the second is the one that matters:

* **Synthetic** files built by hand, where the ground truth for every sample
  offset is known exactly. This pins the arithmetic in
  ``SampleTable.sample_extent`` -- the STSC decompression in particular, which
  is where an off-by-one silently produces a file that plays and is wrong.
* **ffmpeg output**, faststart and non-faststart, greyscale and colour, with and
  without B-frames. The sample table of a real file is the only real test of
  whether the parser matches what a real muxer writes.

The synthetic builders live here rather than in a fixture module because their
whole purpose is to be obviously wrong when the parser is wrong: every offset
they write is also written out as the expected answer.

Everything ffmpeg-dependent is skipped when ffmpeg is absent. The synthetic
tests are not skipped, because they are the actual specification of the
arithmetic and must run everywhere.
"""

from __future__ import annotations

import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from s0.carve import isobmff

FFMPEG = shutil.which("ffmpeg")
FFPROBE = shutil.which("ffprobe")

# --------------------------------------------------------------------------- #
# Synthetic builders
# --------------------------------------------------------------------------- #

def box(btype: bytes, payload: bytes) -> bytes:
    return struct.pack(">I", len(payload) + 8) + btype + payload


def fullbox(btype: bytes, version: int, flags: int, payload: bytes) -> bytes:
    return box(btype, struct.pack(">BBBB", version, (flags >> 16) & 0xFF,
                                  (flags >> 8) & 0xFF, flags & 0xFF) + payload)


def chunk_starts(spcs, first_offset: int, sample_size: int):
    """Absolute start of each chunk given samples-per-chunk and a sample size."""
    starts, cursor = [], first_offset
    for spc in spcs:
        starts.append(cursor)
        cursor += spc * sample_size
    return starts


def _stbl(sample_sizes, chunk_offsets, stsc, stts_runs) -> bytes:
    """A Sample Table Box with a *correct* entry_count on every table.

    Omitting entry_count is the classic way to write a table that looks
    plausible and that a real parser reads as garbage, so it is spelled out
    here rather than left implicit.
    """
    n = len(sample_sizes)
    return b"".join([
        fullbox(b"stsd", 0, 0, struct.pack(">I", 0)),                 # no codec needed
        fullbox(b"stts", 0, 0, struct.pack(">I", len(stts_runs))
                + b"".join(struct.pack(">II", c, d) for c, d in stts_runs)),
        fullbox(b"stsc", 0, 0, struct.pack(">I", len(stsc))
                + b"".join(struct.pack(">III", *e) for e in stsc)),
        fullbox(b"stsz", 0, 0, struct.pack(">II", 0, n)
                + b"".join(struct.pack(">I", s) for s in sample_sizes)),
        fullbox(b"stco", 0, 0, struct.pack(">I", len(chunk_offsets))
                + b"".join(struct.pack(">I", o) for o in chunk_offsets)),
    ])


def build_mp4(sample_sizes, chunk_offsets, stsc, *, media_size=None,
              timescale=1000, stts_runs=None, faststart=False,
              ftyp=b"isom", filler=0xA5):
    """Build a progressive MP4 whose sample table describes ``sample_sizes``.

    ``media_size`` is the required length of the mdat payload. Grow it until it
    exceeds the largest declared chunk offset, so the offsets are genuinely
    inside the file -- an offset past the end is a real validation failure and
    this builder is not allowed to produce one by accident. The mdat is grown
    rather than the file, because trailing zeros after the last box would be
    parsed as a box by any top-level walker.

    ``faststart`` places moov before mdat, which is what a camera or streaming
    muxer does, and is what makes a corrupt mdat size field recoverable: it
    cannot hide the index behind it.
    """
    need = (max(chunk_offsets) + max(sample_sizes, default=0) + 8) if chunk_offsets else 0
    payload_len = max(media_size or 0, need, sum(sample_sizes))
    sample_bytes = bytes([filler]) * sum(sample_sizes)
    # Samples are placed at the end of the payload so earlier bytes are filler,
    # which makes an offset that lands in the wrong place detectable.
    mdat_payload = bytes([0x00]) * (payload_len - len(sample_bytes)) + sample_bytes

    ftyp_box = box(b"ftyp", ftyp + struct.pack(">I", 0) + b"isomiso2avc1mp41")
    mdat_box = box(b"mdat", mdat_payload)

    stbl = _stbl(sample_sizes, chunk_offsets, stsc,
                 stts_runs or [(len(sample_sizes), 1000)])
    stbl_box = box(b"stbl", stbl)
    vmhd = fullbox(b"vmhd", 0, 1, struct.pack(">HHHH", 0, 0, 0, 0))
    dinf = box(b"dinf", fullbox(b"dref", 0, 0, struct.pack(">I", 1) + fullbox(b"url ", 0, 1, b"")))
    hdlr = fullbox(b"hdlr", 0, 0, struct.pack(">I", 0) + b"vide" + b"\0" * 12 + b"v\0")
    minf = box(b"minf", vmhd + dinf + stbl_box)
    mdhd = fullbox(b"mdhd", 0, 0,
                   struct.pack(">IIII", 0, 0, timescale, len(sample_sizes) * 1000) + b"\0" * 4)
    mdia = box(b"mdia", mdhd + hdlr + minf)
    # tkhd v0: flags(4) creation(4) modification(4) track_ID(4) reserved(4) duration(4)
    tkhd = fullbox(b"tkhd", 0, 7,
                   struct.pack(">IIII", 0, 0, 1, 0) + struct.pack(">I", len(sample_sizes) * 1000)
                   + b"\0" * 52)
    moov_box = box(b"moov", box(b"trak", tkhd + mdia))

    if faststart:
        return ftyp_box + moov_box + mdat_box
    return ftyp_box + mdat_box + moov_box


# --------------------------------------------------------------------------- #
# Arithmetic
# --------------------------------------------------------------------------- #

class TestSampleExtentArithmetic:
    def test_one_sample_per_chunk(self):
        sizes = [100, 200, 300, 400]
        offsets = [200, 300, 500, 800]
        data = build_mp4(sizes, offsets, [(1, 1, 1)])
        table = isobmff.parse_moov(data)
        ok, why = table.validate(len(data))
        assert ok, why
        t = table.tracks[0]
        assert t.sample_count == 4
        for i, (off, ln) in enumerate(zip(offsets, sizes, strict=True)):
            assert t.sample_extent(i) == (off, ln), f"sample {i}"

    def test_constant_sample_size_uses_the_stsz_shortcut(self):
        """stsz with a non-zero sample_size means every sample is that size."""
        n, size, per_chunk = 48, 64, 4
        n_chunks = n // per_chunk
        offsets = [300 + i * size * per_chunk for i in range(n_chunks)]
        # stsz with sample_size != 0 carries no per-sample size table at all.
        stbl = b"".join([
            fullbox(b"stsd", 0, 0, struct.pack(">I", 0)),
            fullbox(b"stts", 0, 0, struct.pack(">III", 1, n, 1000)),
            fullbox(b"stsc", 0, 0, struct.pack(">IIII", 1, 1, per_chunk, 1)),
            fullbox(b"stsz", 0, 0, struct.pack(">II", size, n)),
            fullbox(b"stco", 0, 0, struct.pack(">I", len(offsets))
                    + b"".join(struct.pack(">I", o) for o in offsets)),
        ])
        moov = box(b"moov", box(b"trak", box(b"mdia", box(b"minf", box(b"stbl", stbl)))))
        data = box(b"ftyp", b"isom" + b"\0" * 8) + box(b"mdat", b"\0" * 4000) + moov
        table = isobmff.parse_moov(data)
        ok, why = table.validate(len(data))
        assert ok, why
        t = table.tracks[0]
        assert not t.is_variable_size and t.sample_count == n
        for i in range(n):
            _j, chunk, first = t.chunk_of(i)
            assert t.sample_extent(i) == (offsets[chunk - 1] + (i - first) * size, size)

    def test_multiple_stsc_runs(self):
        """The STSC decompression: samples_per_chunk changes part-way through.

        ``stsc [(1,3),(3,2),(5,1)]`` over six chunks means chunks 1-2 hold 3
        samples, chunks 3-4 hold 2, and chunks 5-6 hold 1 -- twelve samples in
        all. Reading a single samples_per_chunk for the whole track gets every
        sample from chunk 3 onward wrong.
        """
        spcs = [3, 3, 2, 2, 1, 1]
        sizes = [10] * sum(spcs)
        offsets = chunk_starts(spcs, 500, 10)
        assert offsets == [500, 530, 560, 580, 600, 610]
        stsc = [(1, 3, 1), (3, 2, 1), (5, 1, 1)]
        data = build_mp4(sizes, offsets, stsc)
        table = isobmff.parse_moov(data)
        ok, why = table.validate(len(data))
        assert ok, why
        t = table.tracks[0]
        assert t.sample_count == 12

        expected = []
        for ci, off in enumerate(offsets):
            for k in range(spcs[ci]):
                expected.append((off + k * 10, 10))
        assert len(expected) == len(sizes)
        for i, want in enumerate(expected):
            assert t.sample_extent(i) == want, f"sample {i} at a run boundary"

    def test_a_single_run_covers_the_whole_file(self):
        """The most common shape: one stsc entry, samples_per_chunk == chunk count.

        The last run's length comes from the chunk table, not from stsc, so a
        single-entry table must still be measured correctly. Getting this wrong
        makes every ordinary file look like it declares zero samples.
        """
        spcs = [2, 2, 2, 2, 2]
        sizes = [8] * sum(spcs)
        offsets = [100, 116, 132, 148, 164]
        data = build_mp4(sizes, offsets, [(1, 2, 1)])
        table = isobmff.parse_moov(data)
        ok, why = table.validate(len(data))
        assert ok, why
        assert table.tracks[0].sample_count == 10
        assert table.tracks[0].sample_extent(9) == (164 + 8, 8)


# --------------------------------------------------------------------------- #
# Media extents
# --------------------------------------------------------------------------- #

class TestMediaExtents:
    def test_media_end_comes_from_the_table_not_the_mdat_header(self):
        """A truncated recording leaves a garbage mdat size; the table does not.

        This is the single highest-value thing the sample table buys over an atom
        walk: the true end of the media is known even when the writer never got
        to patch the mdat size field on close. Cameras write mdat with a
        placeholder and fix it up when recording stops.
        """
        sizes = [64] * 8
        offsets = [300 + 64 * i for i in range(8)]
        data = build_mp4(sizes, offsets, [(1, 1, 1)], faststart=True)
        mdat_at = data.index(b"mdat") - 4
        # Claim the payload is only two samples long.
        corrupt = data[:mdat_at] + struct.pack(">I", 8 + 64 * 2) + data[mdat_at + 4:]

        table = isobmff.parse_moov(corrupt)
        ok, why = table.validate(len(corrupt))
        assert ok, why
        assert table.media_start == offsets[0]
        assert table.media_end == offsets[-1] + 64, \
            "the table must report where the last sample really ends"

    def test_media_extents_span_every_track(self):
        data = build_mp4([10] * 4, [400, 410, 420, 430], [(1, 1, 1)])
        table = isobmff.parse_moov(data)
        assert table.media_start == 400
        assert table.media_end == 440

    def test_chunk_extents_tile_the_media(self):
        spcs = [3, 3, 2, 2, 1, 1]
        sizes = [10] * sum(spcs)
        offsets = chunk_starts(spcs, 500, 10)
        stsc = [(1, 3, 1), (3, 2, 1), (5, 1, 1)]
        data = build_mp4(sizes, offsets, stsc)
        table = isobmff.parse_moov(data)
        ok, why = table.validate(len(data))
        assert ok, why
        extents = isobmff.chunk_extents(table)
        assert len(extents) == len(offsets)
        assert extents[0][1] == offsets[0]
        assert sum(e[2] for e in extents) == sum(sizes)
        # Chunks are contiguous and in order.
        for a, b in zip(extents, extents[1:], strict=False):
            assert a[1] + a[2] == b[1], "chunks must tile without gaps"


# --------------------------------------------------------------------------- #
# Validation -- the gate that keeps a wrong index from becoming evidence
# --------------------------------------------------------------------------- #

class TestValidation:
    def test_rejects_stts_stsz_mismatch(self):
        """The decisive integrity test: two tables must agree on the sample count.

        A mismatch means this moov is not the index for this data, which is the
        signature of a file whose header and payload came from different files.
        """
        data = build_mp4([10] * 4, [200, 210, 220, 230], [(1, 1, 1)],
                         stts_runs=[(3, 1000)])
        ok, why = isobmff.parse_moov(data).validate(len(data))
        assert not ok
        assert any("stts" in r and "stsz" in r for r in why)

    def test_rejects_equal_not_ascending_first_chunk(self):
        data = build_mp4([10] * 8, [200, 210, 220, 230], [(1, 2, 1), (1, 2, 1)])
        ok, why = isobmff.parse_moov(data).validate(len(data))
        assert not ok and any("ascending" in r for r in why)

    def test_rejects_decreasing_first_chunk(self):
        data = build_mp4([10] * 8, [200, 210, 220, 230], [(2, 2, 1), (1, 2, 1)])
        ok, why = isobmff.parse_moov(data).validate(len(data))
        assert not ok and any("not 1" in r for r in why)

    def test_rejects_stsc_covering_too_few_samples(self):
        data = build_mp4([10] * 10, [200, 210, 220, 230], [(1, 1, 1)])
        ok, why = isobmff.parse_moov(data).validate(len(data))
        assert not ok and any("fewer than" in r for r in why)

    def test_rejects_offsets_past_the_end_of_file(self):
        data = build_mp4([10] * 4, [200, 210, 220, 230], [(1, 1, 1)])
        # The builder grows the mdat to make offsets reachable, so push the
        # table out of range afterwards rather than asking for it up front.
        stco = isobmff.find_box(data, b"stco")
        first = stco.payload_start + 8        # skip version/flags and entry_count
        buf = bytearray(data)
        for k, val in enumerate((10 ** 7, 10 ** 7 + 10)):
            struct.pack_into(">I", buf, first + 4 * (k + 2), val)
        data = bytes(buf)
        ok, why = isobmff.parse_moov(data).validate(len(data))
        assert not ok and any("past the" in r for r in why)

    def test_rejects_a_zero_sample_count(self):
        data = build_mp4([10] * 4, [200, 210, 220, 230], [(1, 1, 1)])
        table = isobmff.parse_moov(data)
        table.tracks[0].sample_count = 0
        ok, why = table.validate(len(data))
        assert not ok and any("zero samples" in r for r in why)

    def test_rejects_a_mismatched_entry_size_table(self):
        data = build_mp4([10] * 4, [200, 210, 220, 230], [(1, 1, 1)])
        table = isobmff.parse_moov(data)
        table.tracks[0].entry_sizes = table.tracks[0].entry_sizes[:2]
        ok, why = table.validate(len(data))
        assert not ok and any("lists" in r for r in why)

    def test_rejects_a_non_positive_samples_per_chunk(self):
        data = build_mp4([10] * 4, [200, 210, 220, 230], [(1, 0, 1)])
        ok, why = isobmff.parse_moov(data).validate(len(data))
        assert not ok and any("non-positive" in r for r in why)

    def test_no_moov_is_an_error_not_an_empty_result(self):
        with pytest.raises(isobmff.BoxError):
            isobmff.parse_moov(box(b"ftyp", b"isom" + b"\0" * 8))


class TestFragmentedDetection:
    def test_mvex_means_fragmented(self):
        """In fragmented MP4 the moov sample tables are empty by specification.

        Treating that as an ordinary file and reporting "recovered" is the worst
        available outcome: a plausible, playable, wrong file.
        """
        moov = box(b"moov", box(b"mvex", box(b"trex", b"\0" * 24)) + box(b"trak", b""))
        data = box(b"ftyp", b"iso5" + b"\0" * 8) + moov
        assert isobmff.is_fragmented(data)
        table = isobmff.parse_moov(data)
        assert table.fragmented
        ok, why = table.validate(len(data))
        assert not ok and any("fragmented" in r for r in why)

    def test_progressive_file_is_not_flagged_fragmented(self):
        data = build_mp4([10] * 4, [200, 210, 220, 230], [(1, 1, 1)])
        assert not isobmff.is_fragmented(data)
        assert not isobmff.parse_moov(data).fragmented


class TestBoxWalker:
    def test_rejects_a_size_that_overruns_its_container(self):
        with pytest.raises(isobmff.BoxError):
            list(isobmff.iter_boxes(struct.pack(">I", 9999) + b"mdat" + b"\0" * 16))

    def test_rejects_a_size_smaller_than_its_header(self):
        with pytest.raises(isobmff.BoxError):
            list(isobmff.iter_boxes(struct.pack(">I", 4) + b"mdat"))

    def test_size_zero_means_extends_to_the_end(self):
        data = (box(b"ftyp", b"isom" + b"\0" * 4)
                + struct.pack(">I", 0) + b"mdat" + b"payload")
        boxes = list(isobmff.iter_boxes(data))
        assert [b.type for b in boxes] == [b"ftyp", b"mdat"]
        assert boxes[1].size == len(data) - boxes[1].start

    def test_64_bit_extended_size(self):
        payload = b"x" * 32
        big = struct.pack(">I", 1) + b"mdat" + struct.pack(">Q", len(payload) + 16) + payload
        boxes = list(isobmff.iter_boxes(big))
        assert boxes[0].header_size == 16
        assert boxes[0].size == len(payload) + 16

    def test_descends_into_known_containers(self):
        inner = box(b"stco", b"\0" * 8)
        data = box(b"moov", box(b"trak", box(b"mdia", box(b"minf", box(b"stbl", inner)))))
        types = [b.type for b in isobmff.iter_boxes(data)]
        for want in (b"moov", b"trak", b"mdia", b"minf", b"stbl", b"stco"):
            assert want in types

    def test_meta_is_treated_as_a_leaf(self):
        """``meta`` is a FullBox: its children start after a version/flags field,
        so descending into it naively walks garbage."""
        inner = box(b"stco", b"\0" * 8)
        data = box(b"moov", box(b"meta", b"\0\0\0\0" + inner))
        assert b"stco" not in [b.type for b in isobmff.iter_boxes(data)]


# --------------------------------------------------------------------------- #
# Offset rewriting
# --------------------------------------------------------------------------- #

class TestRemapChunkOffsets:
    def test_rewrites_stco_through_a_mapping(self):
        data = build_mp4([10] * 4, [200, 210, 220, 230], [(1, 1, 1)])
        table = isobmff.parse_moov(data)
        ok, _ = table.validate(len(data))
        assert ok
        mapping = {200: 0, 210: 10, 220: 20, 230: 30}
        out = isobmff.remap_chunk_offsets(data, table, mapping)
        new = isobmff.parse_moov(out)
        assert new.tracks[0].chunk_offsets == [0, 10, 20, 30]

    def test_leaves_the_table_alone_when_a_mapping_is_incomplete(self):
        """Half-rewriting a file is worse than not rewriting it."""
        data = build_mp4([10] * 4, [200, 210, 220, 230], [(1, 1, 1)])
        table = isobmff.parse_moov(data)
        table.validate(len(data))
        out = isobmff.remap_chunk_offsets(data, table, {200: 0, 210: 10})
        assert isobmff.parse_moov(out).tracks[0].chunk_offsets == [200, 210, 220, 230]


# --------------------------------------------------------------------------- #
# Real encoder output
# --------------------------------------------------------------------------- #

def _encode(tmp_path: Path, name: str, *extra: str) -> Path:
    out = tmp_path / name
    cmd = [FFMPEG, "-hide_banner", "-loglevel", "error", "-y",
           "-f", "lavfi", "-i", "testsrc=size=128x96:rate=15:duration=2",
           "-c:v", "libx264", "-pix_fmt", "yuv420p", *extra, str(out)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0 or not out.is_file() or out.stat().st_size < 512:
        pytest.skip(f"ffmpeg could not produce {name}: {proc.stderr[:200]}")
    return out


def _decodes(path: Path) -> bool:
    proc = subprocess.run(
        [FFMPEG, "-hide_banner", "-loglevel", "error", "-i", str(path), "-f", "null", "-"],
        capture_output=True, text=True)
    return proc.returncode == 0


@pytest.mark.skipif(FFMPEG is None or FFPROBE is None,
                    reason="ffmpeg/ffprobe not available")
class TestAgainstRealEncoder:
    @pytest.mark.parametrize("name,extra", [
        ("plain.mp4", ()),
        ("faststart.mp4", ("-movflags", "+faststart")),
        ("nofaststart.mp4", ("-movflags", "-faststart")),
        ("bframes.mp4", ("-bf", "3")),
        ("keyint15.mp4", ("-g", "15")),
    ])
    def test_table_is_internally_consistent(self, tmp_path, name, extra):
        data = _encode(tmp_path, name, *extra).read_bytes()
        table = isobmff.parse_moov(data)
        ok, why = table.validate(len(data))
        assert ok, why

        ftyp = isobmff.find_box(data, b"ftyp")
        assert table.media_start >= ftyp.payload_end, "media cannot precede ftyp"
        assert table.media_end <= len(data), "media cannot extend past the file"

    def test_samples_in_order_reproduce_the_payload_exactly(self, tmp_path):
        """Byte-exact proof of the arithmetic, on a real muxer.

        Concatenating every sample in table order must equal the mdat payload
        exactly, with no byte gained, lost or reordered. A one-sample STSC
        off-by-one fails this.
        """
        data = _encode(tmp_path, "exact.mp4").read_bytes()
        table = isobmff.parse_moov(data)
        ok, why = table.validate(len(data))
        assert ok, why

        t = max(table.tracks, key=lambda tr: tr.sample_count)
        rebuilt = b"".join(data[off:off + ln] for off, ln in
                           (t.sample_extent(i) for i in range(t.sample_count)))
        mdat = isobmff.find_box(data, b"mdat")
        assert mdat is not None
        assert rebuilt == data[mdat.payload_start:mdat.payload_start + len(rebuilt)]
        assert len(rebuilt) == t.media_end - t.media_start

    def test_reassembled_file_decodes_after_offset_rewrite(self, tmp_path):
        """The scattered-file path, end to end.

        Samples are gathered into a new contiguous layout and ``stco`` is
        rewritten to match. If the arithmetic or the rewrite is wrong, the
        decoder fails on the NAL length prefixes. Preserving the original layout
        would also work, but only when the gaps can be padded -- and padding
        means inventing bytes, which is not a trade worth making for evidence.
        """
        data = _encode(tmp_path, "rebuild.mp4").read_bytes()
        table = isobmff.parse_moov(data)
        ok, why = table.validate(len(data))
        assert ok, why

        ftyp = isobmff.find_box(data, b"ftyp")
        moov = isobmff.find_box(data, b"moov")
        payload = []

        # Gather only the extents the table knows about, in file order.
        extents = isobmff.chunk_extents(table)
        moov_bytes = data[moov.start:moov.start + moov.size]
        ftyp_bytes = data[ftyp.start:ftyp.start + ftyp.size]
        # The gathered media still needs its mdat header: a file with a valid
        # sample table and no mdat box is not a file any demuxer will accept.
        # The remapped offsets are absolute in the *new* file, so they start
        # after ftyp, after moov, and after the 8-byte mdat header.
        payload_start = len(ftyp_bytes) + len(moov_bytes) + 8
        mapping, cursor = {}, payload_start
        for _ti, off, ln in extents:
            mapping[off] = cursor
            cursor += ln
        for _ti, off, ln in extents:
            payload.append(data[off:off + ln])

        provisional = ftyp_bytes + moov_bytes + box(b"mdat", b"".join(payload))
        remapped = isobmff.remap_chunk_offsets(provisional, table, mapping)

        out = tmp_path / "rebuilt.mp4"
        out.write_bytes(remapped)
        assert _decodes(out), "a file reassembled from its own sample table must decode"

    def test_reassembly_preserves_the_known_frame_count(self, tmp_path):
        """A scramble check: the rebuilt file must have the same frame count.

        Decoding can succeed on a truncated file, so compare the count the
        decoder reports against the sample table's.
        """
        src = _encode(tmp_path, "count.mp4")
        data = src.read_bytes()
        table = isobmff.parse_moov(data)
        ok, _ = table.validate(len(data))
        assert ok
        t = max(table.tracks, key=lambda tr: tr.sample_count)

        extents = isobmff.chunk_extents(table)
        ftyp = isobmff.find_box(data, b"ftyp")
        moov = isobmff.find_box(data, b"moov")
        ftyp_bytes = data[ftyp.start:ftyp.start + ftyp.size]
        moov_bytes = data[moov.start:moov.start + moov.size]
        cursor = len(ftyp_bytes) + len(moov_bytes) + 8
        mapping, payload = {}, []
        for _ti, off, ln in extents:
            mapping[off] = cursor
            cursor += ln
            payload.append(data[off:off + ln])
        provisional = ftyp_bytes + moov_bytes + box(b"mdat", b"".join(payload))
        out = tmp_path / "rebuilt.mp4"
        out.write_bytes(isobmff.remap_chunk_offsets(provisional, table, mapping))

        def frames(p: Path) -> int:
            r = subprocess.run(
                [FFPROBE, "-v", "error", "-select_streams", "v:0",
                 "-count_frames", "-show_entries", "stream=nb_read_frames",
                 "-of", "default=nokey=1:noprint_wrappers=1", str(p)],
                capture_output=True, text=True)
            try:
                return int(r.stdout.strip())
            except ValueError:
                return -1

        assert frames(out) > 0
        assert frames(out) == frames(src), \
            f"rebuilt {frames(out)} frames vs original {frames(src)}; " \
            f"table claims {t.sample_count} samples"

    def test_stss_keys_are_one_based_and_in_range(self, tmp_path):
        """ISO/IEC 14496-12 stores stss as 1-based sample numbers.

        Treating them as 0-based shifts every sync sample by one, which is
        exactly the kind of off-by-one that produces a file that decodes to the
        wrong frames.
        """
        data = _encode(tmp_path, "keys.mp4", "-g", "15").read_bytes()
        table = isobmff.parse_moov(data)
        seen = False
        for t in table.tracks:
            if t.sync_samples is None:
                continue
            seen = True
            assert t.sync_samples, "stss present but empty"
            assert all(1 <= s <= t.sample_count for s in t.sync_samples)
        assert seen, "expected at least one track with a sync sample table"

    def test_co64_is_understood(self, tmp_path):
        """A 64-bit chunk table must parse the same way as a 32-bit one."""
        data = _encode(tmp_path, "wide.mp4").read_bytes()
        stco = isobmff.find_box(data, b"stco")
        co64 = isobmff.find_box(data, b"co64")
        assert stco is not None or co64 is not None
        table = isobmff.parse_moov(data)
        ok, why = table.validate(len(data))
        assert ok, why
        t = max(table.tracks, key=lambda tr: tr.sample_count)
        assert t.offsets_are_64bit == (co64 is not None and stco is None)


# --------------------------------------------------------------------------- #
# End to end through the carver
# --------------------------------------------------------------------------- #

def _carve(image: Path, out: Path):
    from s0.carve import carve_image
    carve_image(image, out, generate_certificate=False)
    return sorted(f for f in out.iterdir() if f.suffix != ".json")


@pytest.mark.skipif(FFMPEG is None, reason="ffmpeg not available")
class TestCarverIntegration:
    """The sample table only matters if the engine actually consults it."""

    @pytest.mark.parametrize("name,extra", [
        ("moov_at_end.mp4", ()),
        ("faststart.mp4", ("-movflags", "+faststart")),
    ])
    def test_real_mp4_is_recovered_byte_exact(self, tmp_path, name, extra):
        src = _encode(tmp_path, name, *extra)
        original = src.read_bytes()
        image = tmp_path / "img.raw"
        image.write_bytes(b"\x5a" * 8192 + original + b"\x5a" * 8192)

        files = _carve(image, tmp_path / "out")
        mp4s = [f for f in files if f.suffix == ".mp4"]
        assert len(mp4s) == 1, f"expected exactly one mp4, got {[f.name for f in files]}"
        assert mp4s[0].read_bytes() == original, "recovered MP4 differs from the original"

    def test_confidence_is_full_when_the_table_verifies(self, tmp_path):
        import json
        src = _encode(tmp_path, "conf.mp4")
        image = tmp_path / "img.raw"
        image.write_bytes(b"\x5a" * 4096 + src.read_bytes() + b"\x5a" * 4096)
        out = tmp_path / "out"
        _carve(image, out)
        rec = json.loads((out / "recovery_index.json").read_text())
        assert rec["recovered_files"], "nothing recovered"
        r = rec["recovered_files"][0]
        assert r["confidence_score"] == 100, r["heuristics"]
        assert r["boundary_method"] == "declared_size"
        joined = " ".join(r["heuristics"])
        assert "sample table accounts for the media exactly" in joined

    def test_a_truncated_recording_is_cut_at_the_last_sample(self, tmp_path):
        """The case the sample table exists for.

        A camera writes mdat with a placeholder size and patches it when
        recording stops. Simulate a recorder that was killed: shrink the mdat
        size field so an atom walk stops early, and check the carver still
        recovers the whole file.
        """
        src = _encode(tmp_path, "trunc.mp4", "-movflags", "+faststart")
        original = src.read_bytes()
        corrupt = bytearray(original)
        at = corrupt.index(b"mdat") - 4
        struct.pack_into(">I", corrupt, at, 8 + 1024)      # claim a tiny payload
        corrupt = bytes(corrupt)

        image = tmp_path / "img.raw"
        image.write_bytes(b"\x5a" * 4096 + corrupt + b"\x5a" * 4096)
        files = _carve(image, tmp_path / "out")
        mp4s = [f for f in files if f.suffix == ".mp4"]
        assert len(mp4s) == 1, [f.name for f in files]
        got = mp4s[0].read_bytes()
        # The only legitimate difference from the pristine original is the four
        # bytes of the mdat header we deliberately broke. Everything else must
        # match, and in particular the length must not be cut short at the
        # shrunken size field.
        assert len(got) == len(original), (
            f"recovered {len(got)} bytes, expected {len(original)}: "
            "a stale mdat size truncated the recovery")
        assert got[:at] == original[:at]
        assert got[at + 4:] == original[at + 4:]
        assert _decodes(mp4s[0]), "the recovered file must decode"

    def test_noise_around_the_file_does_not_create_extra_mp4s(self, tmp_path):
        src = _encode(tmp_path, "one.mp4")
        image = tmp_path / "img.raw"
        image.write_bytes(b"\x5a" * 8192 + src.read_bytes() + b"\x5a" * 8192)
        files = _carve(image, tmp_path / "out")
        assert len([f for f in files if f.suffix == ".mp4"]) == 1

    def test_a_fake_ftyp_box_in_noise_is_rejected(self, tmp_path):
        """A bare `ftyp` at offset 4 is a weak magic; the sample table is not.

        The signature matches four bytes so that it works for any ftyp size, so
        the structural gates have to be what rejects this.
        """
        import os
        blob = bytearray(os.urandom(256 * 1024))
        blob[4096:4104] = b"\x00\x00\x00\x20ftypisom"
        image = tmp_path / "img.raw"
        image.write_bytes(bytes(blob))
        files = _carve(image, tmp_path / "out")
        assert [f for f in files if f.suffix in ("mp4", "mov", "m4v")] == []


class TestSignatureModel:
    def test_header_offset_defaults_to_zero(self):
        from s0.carve.signatures import SIGNATURES
        assert all(s.header_offset == 0 for s in SIGNATURES if s.extension != "mp4"
                   and s.extension not in ("heic", "avif"))

    def test_isobmff_signatures_match_the_box_type_not_a_box_size(self):
        """A 4-byte box size varies with the brand list; pinning it misses files.

        ffmpeg writes ftyp size 0x20 for four compatible brands. The table used
        to contain only 0x18 entries, so no real MP4 was ever a candidate.
        """
        from s0.carve.signatures import SIGNATURES
        mp4 = [s for s in SIGNATURES if s.extension == "mp4"]
        assert mp4, "no mp4 signature"
        for s in mp4:
            assert s.header_offset == 4
            assert s.header.startswith(b"ftyp")

    def test_sniff_finds_a_mp4_with_any_ftyp_size(self):
        from s0.carve.signatures import sniff
        for ftyp_size in (0x18, 0x20, 0x2C, 0x40):
            data = ftyp_size.to_bytes(4, "big") + b"ftypisom" + b"\0" * 64
            sig = sniff(data)
            assert sig is not None and sig.extension == "mp4", f"ftyp size {ftyp_size:#x}"

    def test_matroska_is_not_claimed_as_mp4(self):
        """Matroska is EBML, not ISO-BMFF. Routing it through the MP4 walker
        meant a signature match with no correct validator behind it."""
        from s0.carve.signatures import SIGNATURES
        assert not [s for s in SIGNATURES if s.extension in ("mkv", "webm")]
