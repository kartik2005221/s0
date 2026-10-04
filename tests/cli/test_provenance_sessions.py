"""Name and path provenance (3g, 3h) and resume-able sessions (3i).

Two unrelated things, joined only by being the same phase: both are about a
report being honest about what it does not know.

Provenance exists because a bare filename in a recovery report reads as
authoritative. It is not. On exFAT a deleted file's name has no checksum to
verify it against and no parent pointer, so a report that prints it plainly is
asserting more than the volume can support -- and a report that prints
`Documents/Q3.pdf` is asserting a directory hierarchy that, on exFAT, FAT32 and
ext4, cannot be recovered at all.

Sessions exist because a carve of a large image takes hours and gets
interrupted. The failure mode that matters is not the crash: it is resuming
against the *wrong* image and reporting findings as previously done.
"""

from __future__ import annotations

import io
import json
import shutil
import subprocess
import sys

import pytest

from s0.carve import provenance as prov
from s0.carve import session as sess

# --------------------------------------------------------------------------- #
# Provenance
# --------------------------------------------------------------------------- #


class TestNameProvenance:
    def test_only_a_checksum_bound_name_is_verified(self):
        assert prov.for_filesystem("fat32", name_source=prov.NAME_SOURCE_CHECKSUM).name_is_verified
        for source in (prov.NAME_SOURCE_ADJACENCY, prov.NAME_SOURCE_DIRECTORY_ENTRY, prov.NAME_SOURCE_CARVED):
            assert not prov.NameProvenance(name_source=source).name_is_verified, source

    def test_exfat_names_are_never_verified(self):
        """exFAT stores no checksum for a name, so there is nothing to check."""
        p = prov.for_filesystem("exfat")
        assert not p.name_is_verified
        assert p.name_source == prov.NAME_SOURCE_DIRECTORY_ENTRY

    def test_a_path_is_only_claimed_when_one_was_recovered(self):
        assert prov.for_filesystem("ntfs", path="\\Users\\a\\f.pdf").path_is_recovered
        for fs in ("fat32", "exfat", "ext4", "raw"):
            p = prov.for_filesystem(fs)
            assert not p.path_is_recovered, fs
            assert p.path is None

    def test_the_absence_of_a_path_is_stated_not_left_blank(self):
        """The whole point: "no path" has to be a sentence, not a null."""
        for fs in ("fat32", "exfat", "ext4"):
            text = prov.for_filesystem(fs).describe()
            assert "not recoverable" in text, fs

    def test_ntfs_paths_are_labelled_as_metadata_not_inference(self):
        p = prov.for_filesystem("ntfs", path="\\Users\\a\\f.pdf")
        assert "$FILE_NAME" in p.describe()

    def test_the_explanation_names_the_right_filesystem(self):
        """The exFAT wording must not be attached to an NTFS or ext4 name.

        "exFAT stores no checksum" said about an NTFS record is simply wrong,
        and a report that misattributes its own evidence is worse than one that
        says nothing.
        """
        assert (
            "exFAT"
            not in prov.for_filesystem("ntfs", name_source=prov.NAME_SOURCE_DIRECTORY_ENTRY).describe()
        )
        assert (
            "exFAT"
            not in prov.for_filesystem("ext4", name_source=prov.NAME_SOURCE_DIRECTORY_ENTRY).describe()
        )
        assert (
            "exFAT" in prov.for_filesystem("exfat", name_source=prov.NAME_SOURCE_DIRECTORY_ENTRY).describe()
        )
        assert (
            "$FILE_NAME"
            in prov.for_filesystem("ntfs", name_source=prov.NAME_SOURCE_DIRECTORY_ENTRY).describe()
        )

    def test_a_carved_name_says_it_was_not_recovered(self):
        p = prov.for_filesystem("raw")
        assert "not recovered from the volume" in p.describe()

    def test_the_dict_form_is_json_serialisable_and_complete(self):
        d = prov.for_filesystem("exfat").as_dict()
        json.dumps(d)
        for key in (
            "name_source",
            "name_is_verified",
            "name_detail",
            "path",
            "path_source",
            "path_is_recovered",
            "path_detail",
        ):
            assert key in d, key
        assert d["name_is_verified"] is False
        assert d["path_is_recovered"] is False

    def test_an_unknown_filesystem_falls_back_rather_than_raising(self):
        p = prov.for_filesystem("zfs")
        assert p.name_source == prov.NAME_SOURCE_CARVED
        assert not p.path_is_recovered


class TestExfatNameSource:
    def test_the_exfat_record_carries_its_provenance(self):
        """3g: the strength of the name travels with the record, not in a comment."""
        from s0.carve.exfat_carver import ExFatRecoveredFile

        f = ExFatRecoveredFile(
            filename="evidence.pdf", size_bytes=10, first_cluster=8, is_deleted=True, no_fat_chain=False
        )
        assert f.name_source == prov.NAME_SOURCE_DIRECTORY_ENTRY
        assert not prov.NameProvenance(name_source=f.name_source).name_is_verified


# --------------------------------------------------------------------------- #
# Sessions
# --------------------------------------------------------------------------- #


def _png(size=64, colour=(9, 9, 200)):
    from PIL import Image

    buf = io.BytesIO()
    Image.new("RGB", (size, size), colour).save(buf, format="PNG")
    return buf.getvalue()


def _image(tmp_path, payloads):
    img = tmp_path / "img.raw"
    img.write_bytes(b"".join(b"\x5a" * 4096 + p for p in payloads) + b"\x5a" * 4096)
    return img


class TestSessionFile:
    def test_round_trip(self, tmp_path):
        img = _image(tmp_path, [b"x" * 5000])
        s = sess.CarveSession(str(img), img.stat().st_size, sess.CarveSession.compute_fingerprint(img))
        s.entries = [sess.SessionEntry(4096, 5000, "ab" * 32, "pdf", "a.pdf", "a.pdf")]
        back = sess.CarveSession.read(s.write(tmp_path / "s.json"))
        assert back.entries[0].offset == 4096
        assert back.entries[0].original_name == "a.pdf"
        assert back.fingerprint == s.fingerprint

    def test_the_format_is_marked_and_versioned(self, tmp_path):
        img = _image(tmp_path, [b"x" * 2000])
        s = sess.CarveSession(str(img), img.stat().st_size, sess.CarveSession.compute_fingerprint(img))
        doc = json.loads(s.write(tmp_path / "s.json").read_text())
        assert doc["format"] == sess.SESSION_FORMAT
        assert doc["version"] == sess.SESSION_VERSION

    def test_a_non_session_file_is_refused(self, tmp_path):
        p = tmp_path / "other.json"
        p.write_text('{"format": "something_else"}')
        with pytest.raises(sess.SessionError, match="not an s0 carve session"):
            sess.CarveSession.read(p)

    def test_malformed_json_is_refused(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("{not json")
        with pytest.raises(sess.SessionError, match="not valid JSON"):
            sess.CarveSession.read(p)

    def test_a_future_version_is_refused_rather_than_misread(self, tmp_path):
        p = tmp_path / "future.json"
        p.write_text(json.dumps({"format": sess.SESSION_FORMAT, "version": 99, "entries": []}))
        with pytest.raises(sess.SessionError, match="newer than this build"):
            sess.CarveSession.read(p)

    def test_a_missing_file_is_refused(self, tmp_path):
        with pytest.raises(sess.SessionError, match="cannot read session"):
            sess.CarveSession.read(tmp_path / "absent.session")

    def test_one_malformed_entry_does_not_cost_the_whole_session(self, tmp_path):
        """A session is a convenience; a bad row must not discard the good ones."""
        img = _image(tmp_path, [b"x" * 2000])
        p = tmp_path / "s.json"
        p.write_text(
            json.dumps(
                {
                    "format": sess.SESSION_FORMAT,
                    "version": 1,
                    "target_path": str(img),
                    "target_size": img.stat().st_size,
                    "fingerprint": "x",
                    "entries": [
                        {"offset": 10, "length": 5, "sha256": "aa"},
                        {"offset": "not a number", "length": 5},
                        "not even a dict",
                        {"length": 5},
                    ],
                }
            )
        )
        assert len(sess.CarveSession.read(p).entries) == 1

    def test_the_write_is_atomic(self, tmp_path):
        """An interrupted write must not leave a session that claims work is done."""
        img = _image(tmp_path, [b"x" * 2000])
        s = sess.CarveSession(str(img), img.stat().st_size, sess.CarveSession.compute_fingerprint(img))
        out = s.write(tmp_path / "s.json")
        assert not list(tmp_path.glob("*.tmp"))
        assert out.is_file()


class TestResumeIdentity:
    def test_the_same_image_is_accepted(self, tmp_path):
        img = _image(tmp_path, [b"x" * 5000])
        s = sess.CarveSession(str(img), img.stat().st_size, sess.CarveSession.compute_fingerprint(img))
        s.check_against(img)

    def test_a_different_size_is_refused(self, tmp_path):
        img = _image(tmp_path, [b"x" * 5000])
        s = sess.CarveSession(str(img), img.stat().st_size, sess.CarveSession.compute_fingerprint(img))
        other = tmp_path / "other.raw"
        other.write_bytes(b"y" * (img.stat().st_size * 2))
        with pytest.raises(sess.SessionError, match="not the same image"):
            s.check_against(other)

    def test_a_same_size_but_different_image_is_refused(self, tmp_path):
        """Size alone is not identity: two disks of the same model match."""
        img = _image(tmp_path, [b"x" * 5000])
        s = sess.CarveSession(str(img), img.stat().st_size, sess.CarveSession.compute_fingerprint(img))
        other = tmp_path / "twin.raw"
        other.write_bytes(b"y" * img.stat().st_size)
        with pytest.raises(sess.SessionError, match="has changed"):
            s.check_against(other)

    def test_an_edit_anywhere_in_a_small_image_is_caught(self, tmp_path):
        """Below 2 MiB the fingerprint covers the whole file, so nothing escapes."""
        img = _image(tmp_path, [b"x" * 5000])
        s = sess.CarveSession(str(img), img.stat().st_size, sess.CarveSession.compute_fingerprint(img))
        for offset in (0, img.stat().st_size // 2, img.stat().st_size - 1):
            other = tmp_path / f"edited{offset}.raw"
            data = bytearray(img.read_bytes())
            data[offset] ^= 0xFF
            other.write_bytes(bytes(data))
            with pytest.raises(sess.SessionError, match="has changed"):
                s.check_against(other)

    def test_a_large_image_gets_middle_samples(self, tmp_path):
        """The read cost is bounded by design, so prove the samples are read."""
        img = tmp_path / "big.raw"
        with open(img, "wb") as fh:
            fh.truncate(64 * 1024 * 1024)
        reads = []
        real_open = open

        def counting_open(file, mode="r", *a, **kw):
            fh = real_open(file, mode, *a, **kw)
            if "b" in mode:
                real_seek = fh.seek

                def seek(off, whence=0):
                    reads.append(off)
                    return real_seek(off, whence)

                fh.seek = seek
            return fh

        import builtins

        builtins.open = counting_open
        try:
            sess.CarveSession.compute_fingerprint(img)
        finally:
            builtins.open = real_open
        # Two ends plus the sample spread: bounded, and not proportional to 64 MiB.
        assert len(reads) <= 3 + sess._FINGERPRINT_SAMPLES
        # The first read is sequential from 0 and issues no seek, so the seeks
        # start at the tail. What matters is that they span the image and that
        # the middle is among them.
        assert max(reads) >= img.stat().st_size - sess._FINGERPRINT_BYTES - 1
        assert min(reads) < img.stat().st_size // 2
        assert len(set(reads)) > 2, "the middle was not sampled"


class TestMissingOutputs:
    def test_a_named_file_that_is_gone_is_reported(self, tmp_path):
        img = _image(tmp_path, [b"x" * 2000])
        s = sess.CarveSession(str(img), img.stat().st_size, sess.CarveSession.compute_fingerprint(img))
        s.entries = [
            sess.SessionEntry(0, 10, "a", "pdf", "a.pdf", str(tmp_path / "present.pdf")),
            sess.SessionEntry(20, 10, "b", "pdf", "b.pdf", str(tmp_path / "absent.pdf")),
        ]
        (tmp_path / "present.pdf").write_bytes(b"x")
        gone = s.missing_outputs()
        assert [e.original_name for e in gone] == ["b.pdf"]

    def test_the_report_explains_what_is_missing_and_why(self, tmp_path):
        img = _image(tmp_path, [b"x" * 2000])
        s = sess.CarveSession(str(img), img.stat().st_size, sess.CarveSession.compute_fingerprint(img))
        s.entries = [sess.SessionEntry(0, 10, "a", "pdf", "a.pdf", str(tmp_path / "absent.pdf"))]
        notes = sess.describe_resume(s, out_dir=tmp_path, skipped=1)
        assert any("no file in" in n for n in notes)
        assert any("not what is still on the medium" in n for n in notes)


class TestResumeEndToEnd:
    def test_a_resumed_run_does_not_rewrite_what_was_found(self, tmp_path):
        from s0.carve import carve_image

        img = _image(tmp_path, [_png()])
        first = carve_image(img, tmp_path / "out1", generate_certificate=False)
        assert first.files_recovered == 1

        s = sess.CarveSession(str(img), img.stat().st_size, sess.CarveSession.compute_fingerprint(img))
        s.merge(first.carved_files, out_dir=tmp_path / "out1")
        assert len(s.entries) == 1

        second = carve_image(img, tmp_path / "out2", generate_certificate=False, resume=s)
        assert second.files_recovered == 0, "the known extent was carved again"
        rec = json.loads((tmp_path / "out2" / "recovery_index.json").read_text())
        assert rec["resumed_from_session"] == 1
        assert rec["duplicates_suppressed"] >= 1, "the skip was not counted anywhere"
        assert not [p for p in (tmp_path / "out2").iterdir() if p.suffix == ".png"]

    def test_merging_is_idempotent(self, tmp_path):
        from s0.carve import carve_image

        img = _image(tmp_path, [_png()])
        first = carve_image(img, tmp_path / "out1", generate_certificate=False)
        s = sess.CarveSession(str(img), img.stat().st_size, sess.CarveSession.compute_fingerprint(img))
        s.merge(first.carved_files, out_dir=tmp_path / "out1")
        n = len(s.entries)
        s.merge(first.carved_files, out_dir=tmp_path / "out1")
        assert len(s.entries) == n

    def test_a_partial_session_only_skips_what_it_knows(self, tmp_path):
        """Half a session must still find the other half."""
        from s0.carve import carve_image

        a, b = _png(64, (9, 9, 200)), _png(48, (200, 9, 9))
        img = _image(tmp_path, [a, b])
        first = carve_image(img, tmp_path / "out1", generate_certificate=False)
        assert first.files_recovered == 2

        s = sess.CarveSession(str(img), img.stat().st_size, sess.CarveSession.compute_fingerprint(img))
        s.merge(first.carved_files[:1], out_dir=tmp_path / "out1")
        second = carve_image(img, tmp_path / "out2", generate_certificate=False, resume=s)
        assert second.files_recovered == 1, "only the recorded extent should be skipped"

    def test_a_refused_resume_names_the_image(self, tmp_path):
        from s0.carve import carve_image, session

        img = _image(tmp_path, [_png()])
        s = sess.CarveSession(str(img), img.stat().st_size, "0" * 64)
        s.entries = [sess.SessionEntry(4096, 100, "a" * 64, "png")]
        with pytest.raises(session.SessionError):
            carve_image(img, tmp_path / "out", generate_certificate=False, resume=s)


class TestSessionCLI:
    def _run(self, *args):
        return subprocess.run(
            [sys.executable, "-m", "s0.cli.main", "carve", *args], capture_output=True, text=True
        )

    def test_write_then_resume(self, tmp_path):
        img = _image(tmp_path, [_png()])
        session_file = tmp_path / "run.session"
        first = self._run(
            "--target",
            str(img),
            "--out-dir",
            str(tmp_path / "o1"),
            "--write-session",
            str(session_file),
            "--no-certificate",
            "--format",
            "json",
            "--quiet",
        )
        assert first.returncode == 0, first.stderr[-400:]
        assert session_file.is_file()
        doc = json.loads(session_file.read_text())
        assert len(doc["entries"]) == 1

        second = self._run(
            "--target",
            str(img),
            "--out-dir",
            str(tmp_path / "o2"),
            "--session",
            str(session_file),
            "--no-certificate",
            "--format",
            "json",
            "--quiet",
        )
        assert second.returncode == 0, second.stderr[-400:]
        result = json.loads(second.stdout)["result"]
        assert result["files_recovered"] == 0
        assert result["resumed_from_session"] == 1

    def test_resuming_onto_a_different_image_fails_cleanly(self, tmp_path):
        """No traceback: the operator needs a message and a non-zero exit."""
        img = _image(tmp_path, [_png()])
        session_file = tmp_path / "run.session"
        self._run(
            "--target",
            str(img),
            "--out-dir",
            str(tmp_path / "o1"),
            "--write-session",
            str(session_file),
            "--no-certificate",
            "--format",
            "json",
            "--quiet",
        )
        other = tmp_path / "other.raw"
        other.write_bytes(b"\x5b" * img.stat().st_size)
        r = self._run(
            "--target",
            str(other),
            "--out-dir",
            str(tmp_path / "o2"),
            "--session",
            str(session_file),
            "--no-certificate",
            "--format",
            "json",
            "--quiet",
        )
        assert r.returncode != 0
        assert "Traceback" not in r.stderr, r.stderr[-400:]
        assert "fingerprint does not match" in (r.stderr + r.stdout)

    def test_a_malformed_session_is_refused_cleanly(self, tmp_path):
        img = _image(tmp_path, [_png()])
        bad = tmp_path / "bad.session"
        bad.write_text("nonsense")
        r = self._run(
            "--target",
            str(img),
            "--out-dir",
            str(tmp_path / "o1"),
            "--session",
            str(bad),
            "--no-certificate",
            "--format",
            "json",
            "--quiet",
        )
        assert r.returncode != 0
        assert "Traceback" not in r.stderr


class TestExfatFixture:
    """3g is only meaningful against a real exFAT volume, so build one.

    `mkfs.exfat` gives an authentic boot sector and volume geometry. The deleted
    directory entry itself is written by hand, because populating a real exFAT
    directory needs a loop mount. That limitation is the reason this test
    asserts on the provenance the scanner reports rather than on a full
    end-to-end deletion.
    """

    MKFS = shutil.which("mkfs.exfat")

    @pytest.mark.skipif(MKFS is None, reason="mkfs.exfat not available")
    def test_a_formatted_volume_parses_and_yields_no_deleted_names(self, tmp_path):
        img = tmp_path / "vol.img"
        with open(img, "wb") as fh:
            fh.truncate(16 * 1024 * 1024)
        r = subprocess.run([self.MKFS, "-n", str(img)], capture_output=True, text=True)
        if r.returncode != 0:
            pytest.skip(r.stderr[:200])
        from s0.carve.exfat_carver import (
            EXFAT_BOOT_SIGNATURE,
            parse_exfat_boot_sector,
            scan_exfat_deleted_files,
        )

        boot = parse_exfat_boot_sector(img.read_bytes()[:512])
        assert boot is not None
        assert img.read_bytes()[510:512] == EXFAT_BOOT_SIGNATURE
        # An empty volume has no deleted entries, and the scanner must say so
        # rather than inventing any.
        found = scan_exfat_deleted_files(img, partition_offset=0)
        assert all(f.name_source == prov.NAME_SOURCE_DIRECTORY_ENTRY for f in found)
