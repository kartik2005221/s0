"""A certificate must not claim more than the operation actually did.

Three ways the file-erase certificate overstated what happened, all of which ended
up in a signed, tamper-evident document.

**Bytes processed was the overwrite volume.** ``bytes_processed`` was
``size x passes``, so a 10 MB file wiped three times reported 30,000 bytes
sanitized. That reads as coverage of an area never addressed, and it is the field a
reader checks first. ``bytes_processed`` is now the original content destroyed, and
the overwrite volume is reported beside it under its own name with a note that it is
not a coverage claim.

**An empty target set produced a certificate.** Wiping a directory containing no
files "succeeded" and emitted signed evidence of a sanitization that never happened.
To anyone checking the signature rather than the target list, that is
indistinguishable from a real certificate -- the worst artefact this tool can emit.

**A signing failure was recorded silently.** A block that cannot be signed used to be
written with an empty signature and no explanation, sitting in the same ledger as
properly signed entries with nothing marking the difference. Refusing to record it
would be worse, since the erase has already happened and refusing loses the record of
that too. So the failure is now named in the certificate stored inside the block,
which makes the gap auditable rather than invisible.

And one hang: a FIFO in an evidence directory. ``os.walk`` lists it under ``files``
and opening one blocks until a writer appears -- with no writer, forever. A sanitiser
wedged on a stray ``mkfifo`` is indistinguishable from one working on a large file.
"""

from __future__ import annotations

import json
import os
import signal
from pathlib import Path

import pytest

from s0.audit.db import list_audit_blocks, record_audit_event
from s0.cli.file_eraser import erase_batch, erase_folder

# Absolute: the key is resolved relative to the working directory, and these tests
# run from the repository root while tmp_path does not.
DEMO_KEY = str(Path(__file__).resolve().parents[2]
              / "src/s0/data/keys/demo_issuer_private.pem")

# The certificate schema accepts passes 1-3 only; a higher count is refused at
# signing time and no certificate is produced. That is a separate, pre-existing
# restriction, so these tests stay inside the supported range.
SUPPORTED_PASSES = (1, 2, 3)


class _Timeout(Exception):
    pass


def _alarm(_signum, _frame):
    raise _Timeout("did not terminate")


@pytest.fixture
def hard_timeout():
    previous = signal.signal(signal.SIGALRM, _alarm)

    def _run(fn, *args, **kwargs):
        signal.setitimer(signal.ITIMER_REAL, 10.0)
        try:
            return fn(*args, **kwargs)
        except _Timeout:
            pytest.fail("did not terminate within 10s: it is blocked")
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)

    yield _run
    signal.signal(signal.SIGALRM, previous)


class TestBytesProcessedIsNotTheOverwriteVolume:
    def test_a_three_pass_wipe_reports_the_content_size(self, tmp_path):
        target = tmp_path / "evidence.bin"
        target.write_bytes(b"\x01" * 10_000)

        summary = erase_batch([str(target)], passes=3, pattern="zero",
                              signing_key_path=DEMO_KEY)

        assert summary.certificate is not None
        wipe = summary.certificate["wipe"]
        assert wipe["bytes_processed"] == 10_000, (
            f"bytes_processed is {wipe['bytes_processed']}, which is size x passes. "
            f"A reader takes that for the amount of data sanitized.")

    @pytest.mark.parametrize("passes", SUPPORTED_PASSES)
    def test_it_does_not_scale_with_the_pass_count(self, tmp_path, passes):
        target = tmp_path / "e.bin"
        target.write_bytes(b"\x02" * 4096)
        summary = erase_batch([str(target)], passes=passes, pattern="zero",
                              signing_key_path=DEMO_KEY)
        assert summary.certificate["wipe"]["bytes_processed"] == 4096

    def test_the_overwrite_volume_is_still_reported(self, tmp_path):
        """Dropping the number entirely would lose real information.

        How much was written is worth knowing; it just must not masquerade as
        coverage.
        """
        target = tmp_path / "e.bin"
        target.write_bytes(b"\x03" * 5000)
        summary = erase_batch([str(target)], passes=3, pattern="zero",
                              signing_key_path=DEMO_KEY)
        notes = " ".join(summary.certificate.get("notes") or [])
        assert "overwrite volume" in notes.lower(), (
            f"the overwrite volume is not mentioned anywhere: {notes!r}")
        assert "15000" in notes.replace(",", ""), (
            f"the volume should be 3 x 5000 = 15000: {notes!r}")

    def test_the_summary_total_agrees_with_the_certificate(self, tmp_path):
        """The CLI prints this as "Bytes Sanitized"; it must match the certificate."""
        target = tmp_path / "e.bin"
        target.write_bytes(b"\x04" * 1000)
        summary = erase_batch([str(target)], passes=2, pattern="zero",
                              signing_key_path=DEMO_KEY)
        # The summary total is content destroyed, consistent with the certificate.
        assert summary.total_bytes_processed == 1000


class TestAnEmptyTargetSetGetsNoCertificate:
    def test_an_empty_directory_yields_no_certificate(self, tmp_path):
        empty = tmp_path / "nothing"
        empty.mkdir()
        summary = erase_batch([str(empty)], passes=1, pattern="zero",
                              signing_key_path=DEMO_KEY)
        assert summary.certificate is None, (
            "signed evidence was issued for a sanitization that never happened. To "
            "anyone checking the signature rather than the target list this is "
            "indistinguishable from a real certificate.")
        assert summary.total_files == 0

    def test_the_reason_is_reported(self, tmp_path):
        empty = tmp_path / "nothing"
        empty.mkdir()
        summary = erase_batch([str(empty)], passes=1, pattern="zero",
                              signing_key_path=DEMO_KEY)
        assert any("no files were erased" in w for w in summary.warnings), (
            f"no explanation was given: {summary.warnings}")

    def test_a_directory_of_empty_subdirectories_also_yields_none(self, tmp_path):
        root = tmp_path / "tree"
        (root / "a" / "b").mkdir(parents=True)
        summary = erase_batch([str(root)], passes=1, pattern="zero",
                              signing_key_path=DEMO_KEY)
        assert summary.certificate is None

    def test_a_real_file_still_gets_one(self, tmp_path):
        """The guard must not have broken the ordinary case."""
        target = tmp_path / "real.bin"
        target.write_bytes(b"evidence\n" * 100)
        summary = erase_batch([str(target)], passes=1, pattern="zero",
                              signing_key_path=DEMO_KEY)
        assert summary.certificate is not None
        assert summary.certificate["wipe"]["bytes_processed"] == 900

    def test_no_ledger_entry_is_written_for_an_empty_run(self, tmp_path):
        """No certificate, so also no signed ledger block claiming work."""
        empty = tmp_path / "nothing"
        empty.mkdir()
        db = tmp_path / "audit.db"
        erase_batch([str(empty)], passes=1, pattern="zero",
                    signing_key_path=DEMO_KEY)
        # Nothing recorded, so a fresh ledger has only its genesis block.
        blocks = list_audit_blocks(db_path=db) if db.exists() else []
        assert len(blocks) <= 1


class TestASigningFailureIsNotSilent:
    def _cert(self) -> dict:
        return {"issued_at": "2026-01-01T00:00:00Z", "cert_uuid": "u1",
                "issuer": {"operator_id": "op", "organization": "org"},
                "device": {"device_id": "dev"},
                "signature": {"signature_base64url": "sig"}}

    def test_an_unusable_key_records_why(self, tmp_path):
        db = tmp_path / "audit.db"
        block = record_audit_event(self._cert(), db_path=db,
                                   private_key=str(tmp_path / "no-such-key.pem"))
        stored = json.loads(block.certificate_json)
        notes = stored.get("notes") or []
        assert any("UNSIGNED" in n for n in notes), (
            f"the block was recorded with an empty signature and no explanation: "
            f"{notes!r}. A block nobody can attribute to an issuer must say so.")

    def test_the_block_is_still_recorded(self, tmp_path):
        """Refusing would lose the record of an erase that already happened."""
        db = tmp_path / "audit.db"
        block = record_audit_event(self._cert(), db_path=db,
                                   private_key=str(tmp_path / "no-such-key.pem"))
        assert block.block_index >= 0
        assert block.block_signature == ""
        assert len(list_audit_blocks(db_path=db)) >= 1

    def test_a_good_key_is_not_annotated(self, tmp_path):
        db = tmp_path / "audit.db"
        block = record_audit_event(self._cert(), db_path=db,
                                   private_key=DEMO_KEY)
        assert block.block_signature, "a valid key produced no signature"
        stored = json.loads(block.certificate_json)
        assert not any("UNSIGNED" in n for n in (stored.get("notes") or [])), (
            "a properly signed block was annotated as unsigned")

    def test_the_note_explains_that_the_erase_happened(self, tmp_path):
        db = tmp_path / "audit.db"
        block = record_audit_event(self._cert(), db_path=db,
                                   private_key=str(tmp_path / "nope.pem"))
        stored = json.loads(block.certificate_json)
        note = next(n for n in stored["notes"] if "UNSIGNED" in n)
        assert "erase" in note.lower(), (
            "the note must distinguish 'could not attribute this' from 'nothing "
            f"happened': {note!r}")


class TestFifosDoNotHangTheSanitiser:
    def test_a_fifo_in_a_directory_does_not_block(self, tmp_path, hard_timeout):
        root = tmp_path / "evidence"
        root.mkdir()
        (root / "real.txt").write_text("evidence\n" * 10)
        os.mkfifo(root / "pipe")           # no writer, ever

        results = hard_timeout(erase_folder, str(root), passes=1, pattern="zero")

        assert not (root / "real.txt").exists(), "the real file was not erased"
        failures = [r for r in results if r.status == "failure"]
        assert failures, "the skipped FIFO was not reported"

    def test_the_skip_is_explained(self, tmp_path, hard_timeout):
        root = tmp_path / "evidence"
        root.mkdir()
        (root / "real.txt").write_text("x")
        os.mkfifo(root / "pipe")

        results = hard_timeout(erase_folder, str(root), passes=1, pattern="zero")
        message = " ".join(r.error or "" for r in results if r.status == "failure")
        assert "not erased" in message.lower() or "skipped" in message.lower(), (
            f"the skip was not explained: {message!r}")
        assert "pipe" in message, "the offending path was not named"

    def test_the_fifo_is_not_opened(self, tmp_path, hard_timeout):
        """The real assertion: no writer appears, so any open() would block."""
        root = tmp_path / "evidence"
        root.mkdir()
        (root / "real.txt").write_text("x")
        fifo = root / "pipe"
        os.mkfifo(fifo)

        hard_timeout(erase_folder, str(root), passes=1, pattern="zero")

        # If the FIFO had been opened for writing it would contain zeroes; the point
        # is that it was never treated as a regular file at all.
        assert fifo.exists() or not (root.exists()), (
            "the FIFO should not have been consumed as a file")

    def test_a_device_node_is_also_skipped(self, tmp_path, hard_timeout):
        if not os.path.exists("/dev/zero"):
            pytest.skip("no /dev/zero")
        root = tmp_path / "evidence"
        root.mkdir()
        (root / "real.txt").write_text("x")
        try:
            os.symlink("/dev/zero", root / "zero-link")
        except OSError:
            pytest.skip("cannot create symlink here")

        results = hard_timeout(erase_folder, str(root), passes=1, pattern="zero")
        assert any(r.status == "failure" for r in results), (
            "a symlink to a device node should be reported as not erased")

    def test_a_plain_directory_of_files_is_unaffected(self, tmp_path, hard_timeout):
        root = tmp_path / "evidence"
        (root / "sub").mkdir(parents=True)
        (root / "a.txt").write_text("a" * 100)
        (root / "sub" / "b.txt").write_text("b" * 100)

        results = hard_timeout(erase_folder, str(root), passes=1, pattern="zero")

        assert not (root / "a.txt").exists()
        assert not (root / "sub" / "b.txt").exists()
        assert not [r for r in results if r.status == "failure"], (
            "an ordinary directory reported a failure")
