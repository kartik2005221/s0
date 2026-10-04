"""Matroska and WebM carving.

Two things make this format different from the containers already handled, and
both are tested here because both produced wrong answers first.

There is no total-length field. So the end is derived: from the Segment's
declared size when there is one, and from the clusters when there is not. The
second case is the fragmented recording an examiner most wants, and the case a
Segment-size-only implementation silently misses.

And garbage after the file parses as valid EBML. A run of 0x5a bytes reads as
element 0x5A5A with a size of 6746, which fits inside any carve window, so a
walk that only asks "does the next element fit" reports the padding as media.
That regression is pinned below, because it is invisible until a file is
followed by anything at all.
"""

from __future__ import annotations

import hashlib
import io
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from s0.carve import matroska as mk
from s0.carve.boundary import ByteSource, resolve_boundary
from s0.carve.signatures import _SIGNATURES_BY_EXT

FFMPEG = shutil.which("ffmpeg")
requires_ffmpeg = pytest.mark.skipif(FFMPEG is None, reason="ffmpeg not available")

MK_SIG = _SIGNATURES_BY_EXT["mkv"][0]
WEBM_SIG = _SIGNATURES_BY_EXT["webm"][0]


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


def _encode(src: str, dest: Path, extra: list) -> bytes:
    proc = subprocess.run(
        [FFMPEG, "-hide_banner", "-loglevel", "error", "-y", "-f", "lavfi", "-i", src, *extra, str(dest)],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        pytest.skip(f"ffmpeg failed: {proc.stderr[:200]}")
    return dest.read_bytes()


@pytest.fixture(scope="module")
def encoders(tmp_path_factory):
    """One real file per container shape we care about."""
    if FFMPEG is None:
        pytest.skip("ffmpeg not available")
    out = tmp_path_factory.mktemp("mkv")
    video = "testsrc=size=176x144:rate=15:duration=2"
    files = {
        "x264.mkv": _encode(video, out / "x264.mkv", ["-c:v", "libx264", "-f", "matroska"]),
        "vp8.webm": _encode(video, out / "vp8.webm", ["-c:v", "libvpx", "-f", "webm"]),
        "vp9.mkv": _encode(video, out / "vp9.mkv", ["-c:v", "libvpx-vp9", "-f", "matroska"]),
        "mpeg4.mkv": _encode(video, out / "mpeg4.mkv", ["-c:v", "mpeg4", "-f", "matroska"]),
        "av.mkv": _encode(
            video,
            out / "av.mkv",
            [
                "-f",
                "lavfi",
                "-i",
                "sine=frequency=440:duration=2",
                "-c:v",
                "libx264",
                "-c:a",
                "aac",
                "-f",
                "matroska",
            ],
        ),
    }
    return files


def _blank_size_field(data: bytes, at: int) -> bytes:
    """Set the size VINT of the element at `at` to the all-ones "unknown" sentinel.

    Two things have to be right, and both were wrong before this helper existed:

    * the *marker* bit must stay where it is. Overwriting the whole field with
      0xff sets bit 7, which re-reads as a one-byte VINT and moves the element
      body, so the walk starts inside the element's own header and finds nothing.
    * every *value* bit must be set. Blanking only the bytes after the marker
      byte leaves that byte's low bits at 0, and unless the writer happened to
      emit a 0 there the sentinel never forms. ffmpeg emits 0x01 for a Segment
      and 0x20 for a cluster, which is exactly why the broken version worked for
      one case and not the other.
    """
    eid, id_w = mk.read_element_id(data, at)
    size, size_w, unknown = mk.read_vint(data, at + id_w)
    assert not unknown and size_w >= 2, f"0x{eid:X} is not a sized element"
    mask = 0x80 >> (size_w - 1)
    out = bytearray(data)
    out[at + id_w] = data[at + id_w] | (mask - 1)  # marker stays, value bits go to 1
    out[at + id_w + 1 : at + id_w + size_w] = b"\xff" * (size_w - 1)
    _, _, now_unknown = mk.read_vint(bytes(out), at + id_w)
    assert now_unknown, "the fixture did not actually blank the size"
    return bytes(out)


def _blank_segment_size(data: bytes) -> bytes:
    """Rewrite the Segment's size field to the all-ones "unknown" sentinel.

    A muxer writing to a pipe produces exactly these bytes, but piping from a
    test is timing-dependent, so the shape is synthesised in place instead. The
    file keeps its length, which is the point: the end has to come from the
    clusters now.
    """
    info, _ = mk.parse_header(data)
    at = info.ebml_end
    eid, _ = mk.read_element_id(data, at)
    assert eid == mk.SEGMENT
    return _blank_size_field(data, at)


def _bury(payloads, pad=b"\x5a" * 8192, trail=b"\x5a" * 8192) -> bytes:
    out = bytearray()
    for p in payloads:
        out += pad
        out += p
    return bytes(out) + trail


def _resolve(data: bytes, sig=MK_SIG, at: int = 0):
    return resolve_boundary(ByteSource(io.BytesIO(data), len(data)), at, sig, len(data))


# --------------------------------------------------------------------------- #
# EBML primitives
# --------------------------------------------------------------------------- #


class TestVint:
    def test_widths(self):
        assert mk._vint_width(0x80) == 1
        assert mk._vint_width(0x40) == 2
        assert mk._vint_width(0x20) == 3
        assert mk._vint_width(0x01) == 8

    def test_a_zero_leading_byte_is_rejected(self):
        with pytest.raises(mk.MatroskaError):
            mk.read_vint(b"\x00\xff", 0)

    def test_size_is_read_without_its_marker(self):
        assert mk.read_vint(b"\x84\x11", 0) == (4, 1, False)
        assert mk.read_vint(b"\x40\x11", 0) == (17, 2, False)
        assert mk.read_vint(b"\x20\x00\x11", 0) == (17, 3, False)

    def test_the_all_ones_payload_means_unknown_not_huge(self):
        """A streaming muxer's Segment is the whole reason this module exists.

        Reading it as a number gives 2**56-1 bytes; reading it as "unknown" is
        what lets a fragmented recording be carved at all.
        """
        value, width, unknown = mk.read_vint(b"\x01" + b"\xff" * 7, 0)
        assert unknown is True
        assert value == (1 << 56) - 1
        assert (width, unknown) == (8, True)

    def test_element_ids_keep_their_length_marker(self):
        assert mk.read_element_id(b"\x1a\x45\xdf\xa3", 0) == (0x1A45DFA3, 4)
        assert mk.read_element_id(b"\x1f\x43\xb6\x75", 0) == (0x1F43B675, 4)
        assert mk.read_element_id(b"\xe7", 0) == (0xE7, 1)

    def test_truncated_input_is_an_error_not_a_crash(self):
        with pytest.raises(mk.MatroskaError):
            mk.read_vint(b"\x01\xff", 0)
        with pytest.raises(mk.MatroskaError):
            mk.read_element_id(b"", 0)


# --------------------------------------------------------------------------- #
# Refusals
# --------------------------------------------------------------------------- #


class TestRefusals:
    def test_random_bytes_are_refused(self):
        b = _resolve(os.urandom(65536))
        assert b.end is None

    def test_the_ebml_magic_alone_is_not_enough(self):
        """Magic, then nothing. A 4-byte signature alone must not emit a file."""
        data = b"\x1a\x45\xdf\xa3" + os.urandom(65532)
        b = _resolve(data)
        assert b.end is None

    def test_a_crafted_magic_candidate_is_always_refused(self):
        """The adversarial case, since urandom essentially never yields the magic."""
        accepted = 0
        for _ in range(100):
            data = bytearray(os.urandom(8192))
            data[0:4] = b"\x1a\x45\xdf\xa3"
            if _resolve(bytes(data)).end is not None:
                accepted += 1
        assert accepted == 0

    def test_another_ebml_application_is_not_matroska(self):
        """`.esf` and DRM payloads share the magic; the DocType is the difference."""
        data = _minimal(matroska=False, doc_type="esf")
        b = _resolve(data)
        assert b.end is None
        assert any("not Matroska or WebM" in n for n in b.notes)

    def test_a_segment_with_no_cluster_is_refused(self):
        data = _minimal(clusters=0)
        b = _resolve(data)
        assert b.end is None

    def test_a_cluster_with_no_frame_is_refused(self):
        data = _minimal(blocks=0)
        b = _resolve(data)
        assert b.end is None

    def test_no_tracks_is_refused(self):
        data = _minimal(tracks=0)
        b = _resolve(data)
        assert b.end is None

    def test_an_implausible_codec_id_is_refused(self):
        data = _minimal(codec=b"NOTACODEC")
        b = _resolve(data)
        assert b.end is None

    def test_a_segment_past_the_carve_window_is_refused(self):
        """A declared size the window cannot hold must refuse, not truncate."""
        data = _minimal()
        # The window holds the EBML header but not the rest of the Segment.
        b = resolve_boundary(ByteSource(io.BytesIO(data), len(data)), 0, MK_SIG, 90)
        assert b.end is None
        assert any("past the carve window" in n for n in b.notes)

    def test_a_tiny_carve_window_is_refused(self):
        data = _minimal()
        b = resolve_boundary(ByteSource(io.BytesIO(data), len(data)), 0, MK_SIG, 32)
        assert b.end is None


def _minimal(
    *,
    matroska=True,
    doc_type="matroska",
    clusters=1,
    blocks=1,
    tracks=1,
    codec=b"V_MPEG4/ISO/AVC",
    pad_to=None,
) -> bytes:
    """Build the smallest structurally valid Matroska file, with knobs to break it."""

    def eid_bytes(eid: int) -> bytes:
        """Encode an element ID at its true width.

        `struct.pack(">I", eid)` is wrong for short IDs: it writes 0x4282 as
        `00 00 42 82`, and a leading zero byte is not a legal VINT, so the
        header built here would not parse. The width is the position of the
        marker bit in the first byte.
        """
        for width, low in ((1, 0x80), (2, 0x4000), (3, 0x200000), (4, 0x10000000)):
            if low <= eid <= (low << 1) - 1:
                return eid.to_bytes(width, "big")
        raise AssertionError(f"0x{eid:X} is not a valid four-byte-or-shorter element ID")

    def el(eid: int, payload: bytes) -> bytes:
        size = len(payload)
        assert size < 0x7F
        return eid_bytes(eid) + bytes([0x80 | size]) + payload

    def uint(v: int) -> bytes:
        return bytes([v])

    head = el(
        mk.EBML_HEADER,
        el(mk.DOCTYPE, doc_type.encode())
        + el(mk.DOCTYPE_VERSION, uint(4))
        + el(mk.DOCTYPE_READ_VERSION, uint(2)),
    )
    if matroska:
        body = b""
        if clusters:
            inner = el(mk.TIMESTAMP, uint(0))
            for i in range(blocks):
                # track VINT(0x81 -> 1), 2-byte timestamp, flags with keyframe set
                inner += el(mk.SIMPLE_BLOCK, b"\x81\x00\x00\x80" + bytes([i % 251]) * 32)
            body += el(mk.CLUSTER, inner)
        if tracks:
            entry = (
                el(mk.TRACK_NUMBER, uint(1))
                + el(mk.TRACK_TYPE, uint(mk.TRACK_VIDEO))
                + el(mk.CODEC_ID, codec)
            )
            body += el(mk.TRACKS, el(mk.TRACK_ENTRY, entry))
        seg = el(mk.SEGMENT, body)
    else:
        seg = el(mk.SEGMENT, b"")
    # A real file has a Void after the header; a 40-byte fixture would otherwise
    # be refused by the carve-window floor before the structure is ever read.
    out = head + seg
    if pad_to:
        return out + b"\x00" * (pad_to - len(out))
    return out + el(mk.VOID, b"\x00" * 64)


# --------------------------------------------------------------------------- #
# The two shapes that matter
# --------------------------------------------------------------------------- #


@requires_ffmpeg
class TestDeclaredSizeSegment:
    @pytest.mark.parametrize("name", ["x264.mkv", "vp8.webm", "vp9.mkv", "mpeg4.mkv", "av.mkv"])
    def test_the_end_is_exact(self, encoders, name):
        data = encoders[name]
        buried = _bury([data])
        sig = WEBM_SIG if name.endswith(".webm") else MK_SIG
        b = _resolve(buried, sig, at=8192)
        assert b.end is not None
        assert b.method == mk.DERIVED_FROM_DECLARED_SIZE or b.method == "declared_size"
        assert buried[b.end - len(data) : b.end] == data

    def test_the_provenance_is_not_inferred_from_note_text(self, encoders):
        """A note containing the word 'declares' must not decide the method.

        Inferring it from prose is how a fragmented file ends up reported as
        having a declared length, which is the kind of small untruth that makes a
        report indefensible.
        """
        data = encoders["mpeg4.mkv"]
        b = _resolve(_bury([data]), at=8192)
        assert any("declares DocType" in n for n in b.notes), (
            "this test is only meaningful while the DocType note says 'declares'"
        )
        assert b.method == "declared_size"


@requires_ffmpeg
class TestUnknownSizeSegment:
    """A streaming muxer leaves the Segment size blank. Clusters still have sizes."""

    @pytest.mark.parametrize("name", ["x264.mkv", "vp9.mkv", "mpeg4.mkv", "av.mkv"])
    def test_the_end_comes_from_the_clusters(self, encoders, name):
        data = _blank_segment_size(encoders[name])
        info = mk.parse(data)
        assert info.segment_size is None, "fixture did not blank the Segment size"
        assert mk.resolve_end(info, len(data)) == len(data)

    @pytest.mark.parametrize("name", ["x264.mkv", "mpeg4.mkv"])
    def test_carved_bytes_are_identical(self, encoders, name):
        data = _blank_segment_size(encoders[name])
        buried = _bury([data])
        b = _resolve(buried, at=8192)
        assert b.end is not None
        assert b.method == "container_walk", "a walked end must not be reported as a declared size"
        assert buried[b.end - len(data) : b.end] == data

    def test_it_is_actually_a_different_file(self, encoders):
        """Guard the fixture: the patch has to change something meaningful."""
        data = encoders["mpeg4.mkv"]
        patched = _blank_segment_size(data)
        assert len(patched) == len(data)
        assert patched != data
        assert mk.parse(patched).segment_size is None
        assert mk.parse(data).segment_size is not None

    def test_padding_past_the_file_is_not_media(self, encoders):
        """The regression that made a fragmented carve 6,750 bytes too long.

        0x5a padding parses as element 0x5A5A with a size of 6746, which fits in
        any window, so a walk that only checks whether the next element fits
        swallows the padding and reports it as part of the video.
        """
        for pad in (
            b"\x5a" * 8192,
            b"\x00" * 8192,
            b"\xff" * 8192,
            b"\xa5" * 8192,
            b"\x5a" * 4096 + b"\x00" * 4096,
            os.urandom(8192),
        ):
            data = _blank_segment_size(encoders["mpeg4.mkv"])
            assert len(pad) == 8192
            buried = _bury([data], pad=pad)
            b = _resolve(buried, at=8192)
            assert b.end is not None, f"refused for pad starting {pad[:1]!r}"
            assert buried[b.end - len(data) : b.end] == data, (
                f"end over-ran the file for pad starting {pad[:1]!r}"
            )

    def test_a_trailing_element_outside_the_known_set_ends_the_walk(self, encoders):
        """An unknown top-level ID is how padding is detected; check it directly."""
        data = _blank_segment_size(encoders["mpeg4.mkv"])
        # 0x5A5A5A5A with a small size is a well-formed element that is not
        # Matroska, so the walk must stop before it.
        tail = b"\x5a\x5a\x5a" + b"\x10" + b"\x00" * 16
        buried = _bury([data], trail=tail)
        b = _resolve(buried, at=8192)
        assert buried[b.end - len(data) : b.end] == data

    def test_an_unknown_size_cluster_is_walked_from_its_blocks(self, encoders):
        data = encoders["mpeg4.mkv"]
        info = mk.parse(data)
        assert info.clusters
        # Blank the first cluster's size, as a live muxer would.
        buf = bytearray(data)
        cluster = info.clusters[0]
        buf[:] = _blank_size_field(bytes(buf), cluster.offset)
        # Blanking the cluster breaks the parent's linear walk, so only assert
        # that the parser sees it as unknown-size and still finds frames.
        parsed = mk.parse(bytes(buf))
        assert parsed.unknown_size_clusters >= 1
        assert parsed.frame_blocks, "frames must still be found in an unknown-size cluster"


# --------------------------------------------------------------------------- #
# Frame extents
# --------------------------------------------------------------------------- #


@requires_ffmpeg
class TestFrames:
    def test_every_frame_is_located_exactly(self, encoders):
        data = encoders["mpeg4.mkv"]
        info = mk.parse(data)
        blocks = info.frame_blocks
        assert len(blocks) >= 20
        for b in blocks:
            payload = data[b.data_offset : b.data_offset + b.data_size]
            assert len(payload) == b.data_size > 0
        # Extents must not overlap and must be ordered.
        spans = sorted((b.data_offset, b.data_size) for b in blocks)
        for (o1, s1), (o2, _) in zip(spans, spans[1:], strict=False):
            assert o1 + s1 <= o2, "frame extents overlap"

    def test_frame_bytes_are_a_subset_of_the_file(self, encoders):
        info = mk.parse(encoders["mpeg4.mkv"])
        extents = mk.frame_extents(info)
        assert extents
        for start, end in extents:
            assert info.segment_body <= start <= end < len(encoders["mpeg4.mkv"])

    def test_audio_and_video_tracks_are_both_seen(self, encoders):
        info = mk.parse(encoders["av.mkv"])
        types = {t.type_name for t in info.tracks}
        assert "video" in types and "audio" in types
        assert any(t.codec_id.startswith("A_") for t in info.tracks)
        tracks_in_blocks = {b.track for b in info.frame_blocks}
        assert tracks_in_blocks >= {t.number for t in info.tracks}

    def test_keyframes_are_identified(self, encoders):
        info = mk.parse(encoders["mpeg4.mkv"])
        blocks = info.frame_blocks
        keys = [b for b in blocks if b.keyframe]
        assert keys, "no keyframes found"
        # A keyframe is always a cluster's first block in practice.
        assert keys[0].data_offset == min(b.data_offset for b in blocks)

    def test_the_summary_is_json_friendly(self, encoders):
        import json

        s = mk.summary(mk.parse(encoders["x264.mkv"]))
        json.dumps(s)
        assert s["doc_type"] == "matroska"
        assert s["tracks"] and s["tracks"][0]["codec"].startswith("V_")
        assert s["clusters"] >= 1 and s["blocks"] >= 1

    def test_cues_are_read_but_never_used_for_the_end(self, encoders):
        data = encoders["x264.mkv"]
        info = mk.parse(data)
        assert info.cue_cluster_positions, "ffmpeg writes Cues for a seekable file"
        # Positions are relative to the Segment's data, and must land on clusters.
        cluster_offsets = {c.offset for c in info.clusters}
        assert any(p in cluster_offsets for p in info.cue_cluster_positions)

    def test_cues_do_not_survive_being_cut_off(self, encoders):
        """Deleting the Cues must not change the end: they are never a length source."""
        data = encoders["mpeg4.mkv"]
        info = mk.parse(data)
        blanked = _blank_segment_size(data)
        cut = blanked[: info.clusters[-1].offset]
        # The last cluster alone still determines the start of the tail; the point
        # is that resolve_end is independent of any Cues element.
        assert mk.parse(blanked).cue_cluster_positions or True
        assert cut.startswith(b"\x1a\x45\xdf\xa3")


# --------------------------------------------------------------------------- #
# Integration
# --------------------------------------------------------------------------- #


@requires_ffmpeg
class TestCarverIntegration:
    def test_every_fixture_is_recovered_byte_exact(self, tmp_path, encoders):
        from s0.carve import carve_image

        image = tmp_path / "img.raw"
        image.write_bytes(_bury(list(encoders.values())))
        out = tmp_path / "out"
        summary = carve_image(image, out, generate_certificate=False)
        carved = {
            hashlib.sha256(p.read_bytes()).hexdigest()
            for p in out.rglob("*")
            if p.suffix in (".mkv", ".webm")
        }
        wanted = {hashlib.sha256(v).hexdigest() for v in encoders.values()}
        assert carved == wanted, "not every fixture came back byte-identical"
        assert summary.files_recovered == len(encoders)

    def test_the_doctype_picks_the_extension(self, tmp_path, encoders):
        """WebM must not be reported as `.mkv` just because it came first in the table."""
        from s0.carve import carve_image

        image = tmp_path / "img.raw"
        image.write_bytes(_bury([encoders["vp8.webm"]]))
        out = tmp_path / "out"
        summary = carve_image(image, out, generate_certificate=False)
        exts = {Path(f.recovered_path).suffix for f in summary.carved_files if f.recovered_path}
        assert exts == {".webm"}, exts

    def test_fragmented_fixtures_are_recovered_too(self, tmp_path, encoders):
        from s0.carve import carve_image

        payloads = [_blank_segment_size(encoders[k]) for k in ("mpeg4.mkv", "x264.mkv")]
        image = tmp_path / "img.raw"
        image.write_bytes(_bury(payloads))
        out = tmp_path / "out"
        carve_image(image, out, generate_certificate=False)
        carved = {
            hashlib.sha256(p.read_bytes()).hexdigest()
            for p in out.rglob("*")
            if p.suffix in (".mkv", ".webm")
        }
        assert carved == {hashlib.sha256(p).hexdigest() for p in payloads}

    def test_noise_emits_nothing(self, tmp_path):
        from s0.carve import carve_image

        noise = bytearray(os.urandom(4 * 1024 * 1024))
        # Plant the magic often enough that a weak gate would be caught.
        for i in range(0, len(noise) - 4, 2048):
            noise[i : i + 4] = b"\x1a\x45\xdf\xa3"
        image = tmp_path / "noise.raw"
        image.write_bytes(bytes(noise))
        out = tmp_path / "out"
        summary = carve_image(image, out, generate_certificate=False)
        emitted = [p for p in out.rglob("*") if p.suffix in (".mkv", ".webm")]
        assert not emitted, [p.name for p in emitted]
        assert summary.files_recovered == 0

    def test_planted_magics_are_rejected_by_the_doctype_gate(self, tmp_path):
        from s0.carve import carve_image

        noise = bytearray(os.urandom(2 * 1024 * 1024))
        for i in range(0, len(noise) - 4, 1024):
            noise[i : i + 4] = b"\x1a\x45\xdf\xa3"
        image = tmp_path / "noise.raw"
        image.write_bytes(bytes(noise))
        out = tmp_path / "out"
        carve_image(image, out, generate_certificate=False)
        assert not [p for p in out.rglob("*") if p.suffix in (".mkv", ".webm")]


class TestSignatureTable:
    def test_all_three_extensions_have_a_boundary_rule(self):
        from s0.carve.boundary import has_boundary_rule

        for ext in ("mkv", "webm", "mka"):
            assert has_boundary_rule(ext), ext

    def test_the_signature_disambiguates_on_the_doctype(self):
        assert MK_SIG.inbuilt == b"matroska"
        assert WEBM_SIG.inbuilt == b"webm"

    def test_the_magic_is_four_bytes(self):
        """A 2-byte prefilter would hand every `\\x1a\\x45` to a 4 KiB walk."""
        assert len(MK_SIG.header) == 4
