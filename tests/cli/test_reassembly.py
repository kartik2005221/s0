"""Reassembly of fragmented files from fragments found out of order.

The claim under test is narrow and specific: a fragmented file whose pieces sit
in *any* spatial arrangement on the volume can be rebuilt, because the ordering
is read out of each fragment rather than inferred from where it happens to lie.

That is the whole point. 46% of real fragmented recordings are laid out out of
order, which is what defeats the forward-scan approach every shipping tool
uses, and no shipping tool recovers them. The reason this module can is that
fragmentation is not blind -- `mfhd.sequence_number` and `Cluster.Timestamp`
survive it.

The other half of the file is the refusals. An assembler that concatenates
whatever it is given will happily produce a plausible file with a hole in the
middle, and a plausible file is worse than no file, because it looks like
evidence. Every case below where the input is wrong must produce a refusal with
a stated reason.
"""

from __future__ import annotations

import os
import random
import shutil
import subprocess
from dataclasses import replace

import pytest

from s0.carve import reassembly as ra

FFMPEG = shutil.which("ffmpeg")
requires_ffmpeg = pytest.mark.skipif(FFMPEG is None, reason="ffmpeg not available")

_SEEDS = (1, 2, 3, 7, 20260930)


@pytest.fixture(scope="module")
def fragmented_mp4(tmp_path_factory):
    """A genuinely fragmented MP4: `empty_moov` plus real `moof`/`mdat` pairs."""
    if FFMPEG is None:
        pytest.skip("ffmpeg not available")
    out = tmp_path_factory.mktemp("fragmp4")
    dest = out / "frag.mp4"
    proc = subprocess.run(
        [FFMPEG, "-hide_banner", "-loglevel", "error", "-y", "-f", "lavfi",
         "-i", "testsrc=size=176x144:rate=25:duration=4", "-c:v", "libx264",
         "-g", "25", "-movflags", "frag_keyframe+empty_moov+default_base_moof",
         "-frag_duration", "500000", "-f", "mp4", str(dest)],
        capture_output=True, text=True)
    if proc.returncode != 0:
        pytest.skip(proc.stderr[:200])
    return dest.read_bytes()


@pytest.fixture(scope="module")
def fragmented_mkv(tmp_path_factory):
    """A live-muxed Matroska: one Cluster per keyframe, unknown-size Segment."""
    if FFMPEG is None:
        pytest.skip("ffmpeg not available")
    out = tmp_path_factory.mktemp("fragmkv")
    dest = out / "frag.mkv"
    proc = subprocess.run(
        [FFMPEG, "-hide_banner", "-loglevel", "error", "-y", "-f", "lavfi",
         "-i", "testsrc=size=176x144:rate=25:duration=4", "-c:v", "libx264",
         "-f", "matroska", "-live", "1", "-cluster_size_limit", "20000",
         str(dest)],
        capture_output=True, text=True)
    if proc.returncode != 0:
        pytest.skip(proc.stderr[:200])
    return dest.read_bytes()


def _pieces(fset, blob):
    """Split a `FragmentSet` into head, keyed pieces, and tail."""
    head = blob[fset.prefix[0]:fset.prefix[1]] if fset.prefix else b""
    tail = blob[fset.suffix[0]:fset.suffix[1]] if fset.suffix else b""
    return head, {f.key: blob[f.image_offset:f.image_end] for f in fset.fragments}, tail


def _permute(fset, blob, seed):
    head, pieces, tail = _pieces(fset, blob)
    order = list(pieces)
    random.Random(seed).shuffle(order)
    return head + b"".join(pieces[k] for k in order) + tail, order


# --------------------------------------------------------------------------- #
# The fixtures must be what the tests assume
# --------------------------------------------------------------------------- #

@requires_ffmpeg
class TestFixtures:
    def test_the_mp4_is_really_fragmented(self, fragmented_mp4):
        fset = ra.find_isobmff_fragments(fragmented_mp4, 0, len(fragmented_mp4))
        assert len(fset.fragments) >= 4, "fixture has too few fragments to be a test"
        assert [f.key for f in fset.fragments] == list(range(1, len(fset.fragments) + 1))

    def test_the_mp4_fragments_carry_both_ordering_keys(self, fragmented_mp4):
        fset = ra.find_isobmff_fragments(fragmented_mp4, 0, len(fragmented_mp4))
        for f in fset.fragments:
            assert f.key_source == "mfhd.sequence_number"
            assert f.decode_time is not None, f"{f.label} has no tfdt"
            assert f.duration_sum, f"{f.label} declares no sample durations"

    def test_the_matroska_has_multiple_clusters(self, fragmented_mkv):
        fset = ra.find_matroska_fragments(fragmented_mkv, 0, len(fragmented_mkv))
        assert len(fset.fragments) >= 3
        keys = [f.key for f in fset.fragments]
        assert keys == sorted(keys), "cluster timecodes must be increasing"
        assert len(set(keys)) == len(keys)

    def test_the_matroska_segment_size_is_unknown(self, fragmented_mkv):
        """If the Segment declared its size this would not be a fragmented case."""
        from s0.carve import matroska as mk
        assert mk.parse(fragmented_mkv).segment_size is None


# --------------------------------------------------------------------------- #
# The claim: order comes from the data, not from position
# --------------------------------------------------------------------------- #

@requires_ffmpeg
class TestOutOfOrderMP4:
    def test_in_order_reassembles_byte_exact(self, fragmented_mp4):
        fset = ra.find_isobmff_fragments(fragmented_mp4, 0, len(fragmented_mp4))
        assembly = ra.assemble_file(fset, fragmented_mp4)
        assert assembly.ok, assembly.refusal
        assert assembly.payload == fragmented_mp4

    @pytest.mark.parametrize("seed", _SEEDS)
    def test_a_full_permutation_reassembles_byte_exact(self, fragmented_mp4, seed):
        image, order = _permute(
            ra.find_isobmff_fragments(fragmented_mp4, 0, len(fragmented_mp4)),
            fragmented_mp4, seed)
        fset = ra.find_isobmff_fragments(image, 0, len(image))
        # Guard the fixture: the permutation has to actually be out of order.
        assert [f.key for f in fset.fragments] == order
        assert order != sorted(order) or len(order) < 3
        assembly = ra.assemble_file(fset, image)
        assert assembly.ok, assembly.refusal
        assert [f.key for f in assembly.fragments] == sorted(order)
        assert assembly.payload == fragmented_mp4

    def test_the_reversed_layout_still_reassembles(self, fragmented_mp4):
        """The worst realistic case: fragments in exactly reverse order."""
        fset = ra.find_isobmff_fragments(fragmented_mp4, 0, len(fragmented_mp4))
        head, pieces, tail = _pieces(fset, fragmented_mp4)
        keys = sorted(pieces, reverse=True)
        image = head + b"".join(pieces[k] for k in keys) + tail
        f2 = ra.find_isobmff_fragments(image, 0, len(image))
        assert [f.key for f in f2.fragments] == keys
        assert ra.assemble_file(f2, image).payload == fragmented_mp4

    def test_the_decode_time_projection_is_checked(self, fragmented_mp4):
        fset = ra.find_isobmff_fragments(fragmented_mp4, 0, len(fragmented_mp4))
        assembly = ra.assemble_file(fset, fragmented_mp4)
        assert any("projection confirmed" in n for n in assembly.notes), assembly.notes

    def test_reparse_accepts_the_result(self, fragmented_mp4):
        fset = ra.find_isobmff_fragments(fragmented_mp4, 0, len(fragmented_mp4))
        ok, notes = ra.reparse_assembly(ra.assemble_file(fset, fragmented_mp4), "isobmff")
        assert ok, notes

    def test_the_tail_region_is_reattached(self, fragmented_mp4):
        """`mfra` is not a fragment, and dropping it means the output is not the file."""
        fset = ra.find_isobmff_fragments(fragmented_mp4, 0, len(fragmented_mp4))
        assert fset.suffix, "the trailing index region was not captured"
        assembly = ra.assemble_file(fset, fragmented_mp4)
        assert assembly.payload == fragmented_mp4
        assert any("index region" in n for n in assembly.notes)


@requires_ffmpeg
class TestOutOfOrderMatroska:
    def test_in_order_reassembles_byte_exact(self, fragmented_mkv):
        fset = ra.find_matroska_fragments(fragmented_mkv, 0, len(fragmented_mkv))
        assembly = ra.assemble_file(fset, fragmented_mkv)
        assert assembly.ok, assembly.refusal
        assert assembly.payload == fragmented_mkv

    @pytest.mark.parametrize("seed", _SEEDS)
    def test_a_full_permutation_reassembles_byte_exact(self, fragmented_mkv, seed):
        image, order = _permute(
            ra.find_matroska_fragments(fragmented_mkv, 0, len(fragmented_mkv)),
            fragmented_mkv, seed)
        fset = ra.find_matroska_fragments(image, 0, len(image))
        assert [f.key for f in fset.fragments] == order
        assembly = ra.assemble_file(fset, image)
        assert assembly.ok, assembly.refusal
        assert assembly.payload == fragmented_mkv

    def test_the_reversed_layout_still_reassembles(self, fragmented_mkv):
        fset = ra.find_matroska_fragments(fragmented_mkv, 0, len(fragmented_mkv))
        head, pieces, tail = _pieces(fset, fragmented_mkv)
        keys = sorted(pieces, reverse=True)
        image = head + b"".join(pieces[k] for k in keys) + tail
        f2 = ra.find_matroska_fragments(image, 0, len(image))
        assert ra.assemble_file(f2, image).payload == fragmented_mkv

    def test_interstitial_void_bytes_are_not_lost(self, fragmented_mkv):
        """Matroska pads between clusters with `Void`; those bytes are the file's."""
        fset = ra.find_matroska_fragments(fragmented_mkv, 0, len(fragmented_mkv))
        total = sum(f.length for f in fset.fragments)
        header = fset.prefix[1] - fset.prefix[0] if fset.prefix else 0
        # Extents must tile the file exactly, with no unaccounted bytes.
        assert header + total == len(fragmented_mkv), (
            f"{len(fragmented_mkv) - header - total} bytes are unaccounted for")


# --------------------------------------------------------------------------- #
# Refusals: a plausible wrong file is worse than no file
# --------------------------------------------------------------------------- #

@requires_ffmpeg
class TestRefusals:
    def test_a_missing_fragment_is_named_not_gapped(self, fragmented_mp4):
        fset = ra.find_isobmff_fragments(fragmented_mp4, 0, len(fragmented_mp4))
        ra.bind_source(fragmented_mp4)
        without = [f for f in fset.fragments if f.key != 4]
        assembly = ra.reassemble(without)
        assert not assembly.ok
        assert "1 fragment(s) are missing" in assembly.refusal
        assert "4" in " ".join(assembly.notes)
        assert not assembly.payload, "a refused assembly must not emit bytes"

    def test_duplicate_keys_are_refused(self, fragmented_mp4):
        fset = ra.find_isobmff_fragments(fragmented_mp4, 0, len(fragmented_mp4))
        ra.bind_source(fragmented_mp4)
        clashing = list(fset.fragments) + [replace(fset.fragments[0], image_offset=0)]
        assembly = ra.reassemble(clashing)
        assert not assembly.ok
        assert "duplicate logical key" in assembly.refusal

    def test_two_files_fragments_are_never_merged(self, fragmented_mp4):
        fset = ra.find_isobmff_fragments(fragmented_mp4, 0, len(fragmented_mp4))
        ra.bind_source(fragmented_mp4)
        intruder = replace(fset.fragments[0], group=("some other file",))
        assembly = ra.reassemble(list(fset.fragments) + [intruder])
        assert not assembly.ok
        assert "different identities" in assembly.refusal

    def test_a_wrong_decode_time_is_caught_by_the_projection(self, fragmented_mp4):
        fset = ra.find_isobmff_fragments(fragmented_mp4, 0, len(fragmented_mp4))
        ra.bind_source(fragmented_mp4)
        tampered = [replace(f, decode_time=f.decode_time + 7) if f.key == 3 else f
                    for f in fset.fragments]
        assembly = ra.reassemble(tampered)
        assert not assembly.ok
        assert "not consecutive" in assembly.refusal

    def test_no_fragments_is_a_refusal_not_an_empty_file(self):
        assembly = ra.reassemble([])
        assert not assembly.ok and assembly.refusal

    def test_timecode_keys_are_not_held_to_contiguity(self, fragmented_mkv):
        """A recorder that drops frames leaves a timecode jump. That is not a
        lost fragment, and refusing it would refuse most real recordings."""
        fset = ra.find_matroska_fragments(fragmented_mkv, 0, len(fragmented_mkv))
        ra.bind_source(fragmented_mkv)
        if len(fset.fragments) < 3:
            pytest.skip("need at least three clusters")
        gapped = fset.fragments[:1] + fset.fragments[2:]
        assembly = ra.reassemble(gapped)
        assert "missing" not in assembly.refusal
        assert any("monotonicity" in n for n in assembly.notes)

    def test_duplicate_timecodes_are_refused(self, fragmented_mkv):
        """Two clusters claiming the same timecode is unresolvable, not a tie to break."""
        fset = ra.find_matroska_fragments(fragmented_mkv, 0, len(fragmented_mkv))
        ra.bind_source(fragmented_mkv)
        if len(fset.fragments) < 2:
            pytest.skip("need at least two clusters")
        clashing = [fset.fragments[0], replace(fset.fragments[1], key=fset.fragments[0].key)]
        assembly = ra.reassemble(clashing)
        assert not assembly.ok
        assert "duplicate logical key" in assembly.refusal

    def test_an_mdat_without_an_adjacent_moof_is_not_a_fragment(self, fragmented_mp4):
        """Splicing a `free` box between a `moof` and its `mdat` must cost the
        fragment.

        Searching forward for the `mdat` would silently pick up a *different*
        file's media and produce a file that plays the wrong footage, which is
        the failure this adjacency requirement exists to prevent.
        """
        from s0.carve import isobmff
        image = _permute(ra.find_isobmff_fragments(fragmented_mp4, 0, len(fragmented_mp4)),
                         fragmented_mp4, 3)[0]
        fset = ra.find_isobmff_fragments(image, 0, len(image))
        assert fset.fragments, "sanity: the intact image has fragments"
        f0 = fset.fragments[0]
        # Find this fragment's `moof` and splice the box in *after* the whole
        # moof, not inside its payload, so the box tree still parses.
        boxes = {b.start: b for b in isobmff.iter_boxes(image)}
        moof = boxes[f0.image_offset]
        assert moof.type == b"moof"
        at = moof.start + moof.size
        broken = image[:at] + b"\x00\x00\x00\x08free" + image[at:]
        after = ra.find_isobmff_fragments(broken, 0, len(broken))
        assert len(after.fragments) == len(fset.fragments) - 1, (
            "a displaced mdat must not still count as a fragment")
        assert f0.key not in {f.key for f in after.fragments}


class TestNoByteSource:
    def test_reading_a_fragment_without_a_source_is_an_error(self, monkeypatch):
        monkeypatch.setattr(ra, "_IMAGE_SOURCE", None)
        frag = ra.Fragment(image_offset=0, length=4, key=1,
                           key_source="test", key_kind="sequence")
        with pytest.raises(ra.ReassemblyError):
            ra._read_from_image(frag)


class TestNoise:
    def test_noise_yields_no_fragments(self):
        blob = os.urandom(1 << 20)
        assert not ra.find_isobmff_fragments(blob, 0, len(blob)).fragments
        assert not ra.find_matroska_fragments(blob, 0, len(blob)).fragments

    def test_a_magic_prefixed_junk_file_yields_no_ordered_fragments(self):
        """A `ftyp` box over random bytes must not become an assemblable file.

        This is the shape a signature-only carver would emit, so it is the case
        where a fragment walker is most likely to invent structure.
        """
        blob = bytearray(os.urandom(65536))
        blob[0:8] = b"\x00\x00\x00\x18ftyp"
        blob[8:12] = b"isom"
        fset = ra.find_isobmff_fragments(bytes(blob), 0, len(blob))
        assert not fset.fragments, "junk behind an ftyp box produced fragments"

    def test_a_truncated_box_tree_is_not_walked(self):
        """A box whose size runs past the end must not yield fragments."""
        blob = b"\x00\x00\x00\x18ftypisom" + b"\xff\xff\xff\xffmoof" + os.urandom(64)
        assert not ra.find_isobmff_fragments(blob, 0, len(blob)).fragments


# --------------------------------------------------------------------------- #
# The scattered case, which is the one that matters
# --------------------------------------------------------------------------- #

def _scatter(fset, blob, seed=3, filler=b"\x9c", pad=5000):
    """Lay the fragments out in random order with unrelated data between them."""
    head, pieces, tail = _pieces(fset, blob)
    order = list(pieces)
    random.Random(seed).shuffle(order)
    out = bytearray(head)
    for k in order:
        out += filler * pad
        out += pieces[k]
    out += filler * pad
    out += tail
    return bytes(out), order


@requires_ffmpeg
class TestScatteredVolume:
    def test_the_linear_walk_cannot_see_them(self, fragmented_mp4):
        """Why the scan exists, pinned so the reason is not lost.

        A linear box walk from the header stops at the first unrelated byte, so
        on a scattered volume it finds nothing at all. Without this test the
        scan looks redundant.
        """
        fset = ra.find_isobmff_fragments(fragmented_mp4, 0, len(fragmented_mp4))
        image, _ = _scatter(fset, fragmented_mp4)
        assert not ra.find_isobmff_fragments(image, 0, len(image)).fragments, \
            "fixture is contiguous, so it does not test the scattered case"

    def test_a_scattered_volume_reassembles_byte_exact(self, fragmented_mp4):
        fset = ra.find_isobmff_fragments(fragmented_mp4, 0, len(fragmented_mp4))
        image, order = _scatter(fset, fragmented_mp4)
        found = ra.scan_isobmff_fragments(image, 0, len(image))
        assert found.contiguous is False
        assert len(found.fragments) == len(fset.fragments)
        assembly = ra.assemble_file(found, image)
        assert assembly.ok, assembly.refusal
        assert assembly.payload == fragmented_mp4

    def test_the_extents_do_not_swallow_the_filler(self, fragmented_mp4):
        """A scattered extent must stop at the fragment's own end.

        Growing each fragment to meet the next -- correct when they abut, wrong
        when 5,000 bytes of unrelated evidence sits between them -- turns a
        28 KiB file into 63 KiB that is mostly filler.
        """
        fset = ra.find_isobmff_fragments(fragmented_mp4, 0, len(fragmented_mp4))
        image, _ = _scatter(fset, fragmented_mp4)
        found = ra.scan_isobmff_fragments(image, 0, len(image))
        total = sum(f.length for f in found.fragments)
        original_total = sum(f.length for f in fset.fragments)
        assert total == original_total, (
            f"fragment extents grew by {total - original_total} bytes")

    def test_the_trailing_index_is_found_by_its_magic(self, fragmented_mp4):
        fset = ra.find_isobmff_fragments(fragmented_mp4, 0, len(fragmented_mp4))
        image, _ = _scatter(fset, fragmented_mp4)
        found = ra.scan_isobmff_fragments(image, 0, len(image))
        assert found.suffix, "the mfra region was not found in the scattered layout"

    def test_it_works_without_the_trailing_index(self, fragmented_mp4):
        """`mfra` is optional; its absence must not stop the reassembly."""
        fset = ra.find_isobmff_fragments(fragmented_mp4, 0, len(fragmented_mp4))
        head, pieces, _tail = _pieces(fset, fragmented_mp4)
        order = list(pieces)
        random.Random(9).shuffle(order)
        image = head + b"".join(pieces[k] for k in order)
        found = ra.scan_isobmff_fragments(image, 0, len(image))
        assert found.suffix is None
        assembly = ra.assemble_file(found, image)
        assert assembly.ok, assembly.refusal
        # Without the index the file is the header plus the fragments, which is
        # every byte of the original except the trailing 200.
        assert assembly.payload == fragmented_mp4[: fset.suffix[0]]

    @pytest.mark.parametrize("filler", [b"\x9c", b"\x00", b"RIFF", b"\xff\xd8\xff\xe0"])
    def test_several_filler_kinds(self, fragmented_mp4, filler):
        fset = ra.find_isobmff_fragments(fragmented_mp4, 0, len(fragmented_mp4))
        image, _ = _scatter(fset, fragmented_mp4, filler=filler, pad=2000)
        assembly = ra.assemble_file(ra.scan_isobmff_fragments(image, 0, len(image)), image)
        assert assembly.ok, assembly.refusal
        assert assembly.payload == fragmented_mp4


class TestScanCost:
    def test_noise_produces_no_fragments(self):
        """The four-byte magic appears about once per 4 GiB, so noise is cheap."""
        blob = os.urandom(4 << 20)
        assert not ra.scan_isobmff_fragments(blob, 0, len(blob)).fragments

    def test_planted_moof_magic_still_yields_nothing(self):
        """Magic without a valid box tree behind it must not become a fragment."""
        blob = bytearray(os.urandom(2 << 20))
        for i in range(0, len(blob) - 64, 4096):
            blob[i + 4:i + 8] = b"moof"
            blob[i:i + 4] = (200).to_bytes(4, "big")
        assert not ra.scan_isobmff_fragments(bytes(blob), 0, len(blob)).fragments
