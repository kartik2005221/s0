"""Known-hash suppression and bodyfiles.

Two features with a shared theme: both exist so a report can be *smaller and
honest* about what it contains.

Suppression withholds files the examiner already has. The design constraint is
that a match must never be invisible: withholding a finding silently is how a
report stops being trustworthy, so suppressions are counted, attributed to a
specific algorithm, and listed in the rejection summary.

A bodyfile names byte ranges for another tool. The gaps bodyfile is the more
useful of the two here, because for fragmented work the holes *are* the finding.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess

import pytest

from s0.carve import bodyfile as bf
from s0.carve import suppression

FFMPEG = shutil.which("ffmpeg")


# --------------------------------------------------------------------------- #
# Hash sets
# --------------------------------------------------------------------------- #

class TestParsingHashLists:
    def test_bare_digest_of_each_algorithm(self, tmp_path):
        data = b"evidence"
        p = tmp_path / "known.txt"
        p.write_text("\n".join([
            hashlib.md5(data).hexdigest(),
            hashlib.sha1(data).hexdigest(),
            hashlib.sha256(data).hexdigest(),
            hashlib.sha512(data).hexdigest(),
        ]) + "\n")
        s = suppression.load_hash_set(p)
        assert len(s) == 4
        assert set(s.algorithms) == {"md5", "sha1", "sha256", "sha512"}
        assert s.match(data) is not None

    def test_sha256sum_output_is_understood(self, tmp_path):
        data = b"payload"
        p = tmp_path / "known.txt"
        p.write_text(f"{hashlib.sha256(data).hexdigest()}  notes.txt\n")
        s = suppression.load_hash_set(p)
        assert s.match(data) == "sha256"

    def test_nsrl_style_rows_are_understood(self, tmp_path):
        data = b"nsrl row"
        digest = hashlib.sha256(data).hexdigest()
        p = tmp_path / "known.txt"
        p.write_text(f'SHA-256,"some/file.bin",{len(data)},2019-01-01T00:00:00\n')
        p2 = tmp_path / "known2.txt"
        p2.write_text(f'SHA-256,"{digest}",{len(data)},2019-01-01T00:00:00\n')
        assert suppression.load_hash_set(p2).match(data) == "sha256"
        assert len(suppression.load_hash_set(p2)) == 1

    def test_comments_and_blanks_are_skipped_silently(self, tmp_path):
        data = b"x"
        p = tmp_path / "known.txt"
        p.write_text(f"# a comment\n\n; another\n{hashlib.sha256(data).hexdigest()}\n\n")
        s = suppression.load_hash_set(p)
        assert len(s) == 1
        assert s.lines_skipped == 0, "comments are not malformed lines"

    def test_malformed_lines_are_counted_not_ignored(self, tmp_path):
        """A hash list that silently loads 40% of its rows is worse than one
        that refuses, so skipped lines are reported with a reason."""
        data = b"y"
        p = tmp_path / "known.txt"
        p.write_text("\n".join([
            hashlib.sha256(data).hexdigest(),
            "not a digest at all",
            "ZZZZZZZZ",                       # right length for md5, not hex
            "ab" * 20,                        # 40 hex chars: a valid sha1
        ]) + "\n")
        s = suppression.load_hash_set(p)
        # The 40-hex-char line is a legitimate sha1 and is kept; the two garbage
        # lines are counted.
        assert set(s.algorithms) == {"sha1", "sha256"}
        assert s.lines_skipped == 2
        assert any("unrecognised length" in r or "unparseable" in r
                   for r in s.skip_reasons)

    def test_algorithms_can_be_restricted(self, tmp_path):
        data = b"z"
        p = tmp_path / "known.txt"
        p.write_text(hashlib.md5(data).hexdigest() + "\n"
                     + hashlib.sha256(data).hexdigest() + "\n")
        s = suppression.load_hash_set(p, algorithms=["sha256"])
        assert s.algorithms == ["sha256"]

    def test_a_list_with_nothing_usable_is_refused(self, tmp_path):
        p = tmp_path / "known.txt"
        p.write_text("nope\nstill nope\n")
        with pytest.raises(suppression.SuppressionError) as exc:
            suppression.load_hash_set(p)
        assert "no usable digests" in str(exc.value)

    def test_a_missing_path_is_refused(self, tmp_path):
        with pytest.raises(suppression.SuppressionError):
            suppression.load_hash_set(tmp_path / "absent.txt")

    def test_only_present_algorithms_are_computed(self, tmp_path):
        """Hashing a 4 GiB candidate with SHA-512 to check a SHA-256 list is waste."""
        data = b"big" * 1000
        p = tmp_path / "known.txt"
        p.write_text(hashlib.sha256(data).hexdigest() + "\n")
        s = suppression.load_hash_set(p)
        called = []
        real_new = suppression.hashlib.new

        def spy(algo, *a, **kw):
            called.append(algo)
            return real_new(algo, *a, **kw)

        suppression.hashlib.new = spy
        try:
            assert s.match(data) == "sha256"
        finally:
            suppression.hashlib.new = real_new
        assert called == ["sha256"], called

    def test_a_non_match_returns_none(self, tmp_path):
        p = tmp_path / "known.txt"
        p.write_text(hashlib.sha256(b"other").hexdigest() + "\n")
        assert suppression.load_hash_set(p).match(b"something else") is None


class TestDirectoryHashing:
    def test_a_directory_is_hashed_in_place(self, tmp_path):
        d = tmp_path / "reference"
        d.mkdir()
        (d / "a.bin").write_bytes(b"first")
        (d / "sub").mkdir()
        (d / "sub" / "b.bin").write_bytes(b"second")
        s = suppression.load_hash_set(d)
        assert len(s) == 2
        assert s.match(b"first") == "sha256"
        assert s.match(b"second") == "sha256"

    def test_an_empty_directory_is_refused(self, tmp_path):
        d = tmp_path / "empty"
        d.mkdir()
        with pytest.raises(suppression.SuppressionError):
            suppression.load_hash_set(d)

    def test_algorithm_names_are_normalised(self, tmp_path):
        d = tmp_path / "reference"
        d.mkdir()
        (d / "a.bin").write_bytes(b"streamed")
        s = suppression.load_hash_set(d, algorithms=["SHA-256", "sha256", "Sha_1"])
        assert set(s.algorithms) == {"sha256", "sha1"}
        assert s.match(b"streamed") == "sha256"

    def test_the_filter_reaches_a_directory(self, tmp_path):
        """A directory passed through load_hash_set must honour --hash-algorithms."""
        d = tmp_path / "reference"
        d.mkdir()
        (d / "a.bin").write_bytes(b"filtered")
        s = suppression.load_hash_set(d, algorithms=["SHA-1"])
        assert s.algorithms == ["sha1"]
        assert s.match(b"filtered") == "sha1"

    def test_files_are_streamed_not_read_whole(self, tmp_path, monkeypatch):
        """A multi-gigabyte reference must not be pulled into memory at once."""
        import builtins
        d = tmp_path / "reference"
        d.mkdir()
        payload = b"x" * (3 * 1024 * 1024 + 7)
        (d / "big.bin").write_bytes(payload)
        biggest = [0]
        real_open = builtins.open

        def counting_open(file, mode="r", *a, **kw):
            fh = real_open(file, mode, *a, **kw)
            if "b" in mode and "r" in mode:
                real_read = fh.read

                def read(size=-1):
                    got = real_read(size)
                    biggest[0] = max(biggest[0], len(got))
                    return got
                fh.read = read
            return fh

        monkeypatch.setattr(builtins, "open", counting_open)
        try:
            s = suppression.load_file_hashes(d, chunk_size=1 << 16)
        finally:
            monkeypatch.undo()
        assert len(s) == 1
        assert biggest[0] <= (1 << 16), f"a single read pulled {biggest[0]} bytes"
        assert s.match(payload) == "sha256"

    def test_multi_algorithm_directory_hash_in_one_pass(self, tmp_path):
        d = tmp_path / "reference"
        d.mkdir()
        (d / "a.bin").write_bytes(b"one pass")
        s = suppression.load_file_hashes(d, algorithms=["md5", "sha256"])
        assert set(s.algorithms) == {"md5", "sha256"}
        assert s.match(b"one pass") in ("md5", "sha256")


# --------------------------------------------------------------------------- #
# Bodyfiles
# --------------------------------------------------------------------------- #

class TestBodyfile:
    def test_write_and_read_round_trip(self, tmp_path):
        p = tmp_path / "b.body"
        rows, nbytes = bf.write_bodyfile(p, [(0, 99), (200, 299)])
        assert rows == 2
        assert nbytes == 200
        assert bf.read_bodyfile(p) == [(0, 99), (200, 299)]

    def test_overlapping_extents_are_merged(self, tmp_path):
        merged = bf.normalise([(0, 100), (50, 150), (300, 320)])
        assert merged == [(0, 150), (300, 320)]

    def test_touching_extents_are_merged(self, tmp_path):
        assert bf.normalise([(0, 99), (100, 199)]) == [(0, 199)]

    def test_empty_and_inverted_extents_are_dropped(self, tmp_path):
        assert bf.normalise([(100, 99), (5, 4)]) == []
        p = tmp_path / "b.body"
        rows, nbytes = bf.write_bodyfile(p, [(100, 99), (5, 4), (0, 9)])
        assert rows == 1 and nbytes == 10

    def test_complement_is_the_gaps(self):
        assert bf.complement([(0, 99), (200, 299)], 0, 399) == [(100, 199), (300, 399)]

    def test_complement_of_a_full_cover_is_empty(self):
        assert bf.complement([(0, 999)], 0, 999) == []

    def test_complement_of_nothing_is_everything(self):
        assert bf.complement([], 0, 99) == [(0, 99)]

    def test_complement_clips_to_the_range(self):
        assert bf.complement([(0, 999)], 100, 199) == []

    def test_complement_handles_an_inverted_range(self):
        assert bf.complement([(0, 10)], 100, 50) == []

    def test_total_length_counts_each_byte_once(self):
        assert bf.total_length([(0, 99), (50, 149)]) == 150

    def test_comments_and_blank_lines_are_ignored_on_read(self, tmp_path):
        p = tmp_path / "b.body"
        p.write_text("# header\n\n0 99\n  200 299  \n# trailing\n")
        assert bf.read_bodyfile(p) == [(0, 99), (200, 299)]

    def test_merge_combines_bodyfiles(self, tmp_path):
        a, b = tmp_path / "a.body", tmp_path / "b.body"
        bf.write_bodyfile(a, [(0, 99)])
        bf.write_bodyfile(b, [(50, 199)])
        rows, nbytes = bf.merge([a, b], tmp_path / "m.body")
        assert rows == 1 and nbytes == 200

    def test_merge_accepts_a_generator(self, tmp_path):
        """A generator of paths must not be exhausted by the count in the comment."""
        a, b = tmp_path / "a.body", tmp_path / "b.body"
        bf.write_bodyfile(a, [(0, 99)])
        bf.write_bodyfile(b, [(300, 399)])
        dest = tmp_path / "m.body"
        rows, nbytes = bf.merge((p for p in (a, b)), dest)
        assert rows == 2 and nbytes == 200
        assert "merged from 2 bodyfile(s)" in dest.read_text()

    def test_write_creates_missing_parent_directories(self, tmp_path):
        p = tmp_path / "deep" / "er" / "b.body"
        rows, _ = bf.write_bodyfile(p, [(0, 9)])
        assert rows == 1 and p.is_file()


# --------------------------------------------------------------------------- #
# End to end through the carver
# --------------------------------------------------------------------------- #

def _png(w=64, h=64):
    import io

    from PIL import Image
    buf = io.BytesIO()
    Image.new("RGB", (w, h), (10, 120, 200)).save(buf, format="PNG")
    return buf.getvalue()


class TestCarverIntegration:
    def test_a_known_file_is_withheld_and_counted(self, tmp_path):
        from s0.carve import carve_image
        known_payload = _png(64, 64)
        wanted = _png(48, 48)
        img = tmp_path / "img.raw"
        img.write_bytes(b"\x5a" * 4096 + known_payload + b"\x5a" * 4096
                        + wanted + b"\x5a" * 4096)
        hashes = tmp_path / "known.txt"
        hashes.write_text(hashlib.sha256(known_payload).hexdigest() + "\n")

        out = tmp_path / "out"
        summary = carve_image(img, out, generate_certificate=False,
                              known_hashes=suppression.load_hash_set(hashes))
        assert summary.suppressed_known == 1
        assert "sha256" in summary.suppression_note
        assert str(hashes) in summary.suppression_note
        written = {f.read_bytes() for f in out.iterdir() if f.suffix != ".json"}
        assert known_payload not in written
        assert wanted in written

    def test_suppression_is_recorded_in_the_index(self, tmp_path):
        import json

        from s0.carve import carve_image
        payload = _png(32, 32)
        img = tmp_path / "img.raw"
        img.write_bytes(b"\x5a" * 4096 + payload + b"\x5a" * 4096)
        hashes = tmp_path / "known.txt"
        hashes.write_text(hashlib.sha256(payload).hexdigest() + "\n")
        out = tmp_path / "out"
        carve_image(img, out, generate_certificate=False,
                    known_hashes=suppression.load_hash_set(hashes))
        rec = json.loads((out / "recovery_index.json").read_text())
        assert rec["suppressed_known_files"] == 1
        assert rec["suppressed_known_bytes"] == len(payload)
        assert any("known sha256 digest" in r["reason"] for r in rec["rejection_summary"])

    def test_without_a_hash_set_nothing_is_suppressed(self, tmp_path):
        from s0.carve import carve_image
        payload = _png(32, 32)
        img = tmp_path / "img.raw"
        img.write_bytes(b"\x5a" * 4096 + payload + b"\x5a" * 4096)
        out = tmp_path / "out"
        summary = carve_image(img, out, generate_certificate=False)
        assert summary.suppressed_known == 0
        assert summary.suppression_note == ""

    def test_suppression_covers_filesystem_native_recovery(self, tmp_path):
        """A hash set that only works on the signature path is not a hash set.

        Structure recovery is the path an examiner trusts most, so if a known
        file survived there the suppression would look effective while the bulk
        of the volume's findings stayed put.
        """
        from test_carver import _ext4_with_two_jpegs

        from s0.carve import carve_image
        from s0.carve.policy import CarvePolicy

        img, _live, deleted, _blk = _ext4_with_two_jpegs(tmp_path, allocated=False)
        policy = CarvePolicy.for_target(img.stat().st_size)
        policy.structure_recovery_enabled = True
        policy.use_free_space_only = False

        # Control: the deleted file is recoverable at all.
        baseline = carve_image(str(img), tmp_path / "base", extensions=[".jpg"],
                               policy=policy, generate_certificate=False)
        assert any(f.size_bytes == len(deleted) for f in baseline.carved_files), \
            "fixture did not recover the deleted file; the test proves nothing"

        hashes = tmp_path / "known.txt"
        hashes.write_text(hashlib.sha256(deleted).hexdigest() + "\n")
        out = tmp_path / "out"
        summary = carve_image(str(img), out, extensions=[".jpg"], policy=policy,
                              generate_certificate=False,
                              known_hashes=suppression.load_hash_set(hashes))
        assert summary.suppressed_known == 1
        written = {f.read_bytes() for f in out.rglob("*") if f.is_file()
                   and f.suffix.lower() in (".jpg", ".jpeg")}
        assert deleted not in written, "a suppressed file was still written"
        rec = json.loads((out / "recovery_index.json").read_text())
        assert any("known sha256 digest" in r["reason"]
                   for r in rec["rejection_summary"]), rec["rejection_summary"]

    def test_extents_and_gaps_agree(self, tmp_path):
        from s0.carve import carve_image
        payload = _png(40, 40)
        img = tmp_path / "img.raw"
        img.write_bytes(b"\x5a" * 4096 + payload + b"\x5a" * 4096)
        out = tmp_path / "out"
        summary = carve_image(img, out, generate_certificate=False)
        assert summary.recovered_extents, "a recovered file must contribute an extent"
        gaps = bf.complement(summary.recovered_extents, 0,
                             summary.total_bytes_scanned - 1)
        assert gaps
        assert bf.total_length(summary.recovered_extents) + bf.total_length(gaps) \
            == summary.total_bytes_scanned

    @pytest.mark.skipif(FFMPEG is None, reason="ffmpeg not available")
    def test_cli_writes_both_bodyfiles(self, tmp_path):
        import json
        import sys
        src = tmp_path / "a.avi"
        proc = subprocess.run(
            [FFMPEG, "-hide_banner", "-loglevel", "error", "-y", "-f", "lavfi",
             "-i", "testsrc=size=160x120:rate=15:duration=1", "-c:v", "mpeg4",
             "-f", "avi", str(src)], capture_output=True, text=True)
        if proc.returncode != 0:
            pytest.skip(proc.stderr[:200])
        original = src.read_bytes()
        img = tmp_path / "img.raw"
        img.write_bytes(b"\x5a" * 4096 + original + b"\x5a" * 4096)
        found = tmp_path / "found.body"
        gaps = tmp_path / "gaps.body"
        out = tmp_path / "out"
        rc = subprocess.run(
            [sys.executable, "-m", "s0.cli.main", "carve",
             "--target", str(img), "--out-dir", str(out),
             "--bodyfile", str(found), "--gaps-bodyfile", str(gaps),
             "--format", "json", "--quiet"],
            capture_output=True, text=True)
        assert rc.returncode == 0, (rc.stdout[-300:], rc.stderr[-500:])
        assert found.is_file(), f"no bodyfile written; stdout={rc.stdout[-300:]}"
        assert gaps.is_file()
        found_extents = bf.read_bodyfile(found)
        assert found_extents, "a recovered file must appear in the bodyfile"
        # Every extent must really contain the recovered file's bytes.
        data = img.read_bytes()
        rec = json.loads((out / "recovery_index.json").read_text())
        offsets = {f["offset"] for f in rec["recovered_files"]}
        for off in offsets:
            assert any(s <= off <= e for s, e in found_extents), \
                f"offset {off} is not inside any bodyfile range"
        assert data[found_extents[0][0]:found_extents[0][0] + 4] == b"RIFF"
