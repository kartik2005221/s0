"""An erase must not claim more than it did.

A sanitiser that emits a compliance certificate has a worse failure mode than one
that crashes: a false claim is acted upon. Three ways this file earned a
certificate it had not earned, each injected here rather than argued about.

**A swallowed fsync.** ``platform_sync`` caught every exception and returned
nothing, so an overwrite whose write cache never flushed reported
``status="success"``. The bytes were in the file; whether they were on the medium
was unknown. On a compliance document that difference is the whole claim.

**A post-erase check that could not fail.** The data was renamed twice before
unlinking, so the original path no longer existed -- and that renamed-away path
was what the verification tested. It was a tautology. With the unlink mocked to
fail, a zeroed ``.s0_del_*`` leftover survived and the tool reported success with
``metadata_cleansed=True``. The fallback retry also unlinked ``path_str``, the
name that was never there, so it could not rescue the case either.

**A mislabelled method.** Any wipe that was not exactly "one pass of zeros" was
recorded as ``SHRED_RANDOM_NPASS``. A three-pass zero wipe therefore told a reader
the medium was filled with CSPRNG bytes when it was filled with zeros -- a
different residual-risk argument, not a typo.

And one claim that was simply absent: the file path recorded
``all_samples_match_wipe_pattern`` as true while sampling zero bytes per file.
No readback happens on this path, so the field is now null.
"""

from __future__ import annotations

import os
from unittest import mock

import pytest

from s0.cli import file_eraser
from s0.cli.file_eraser import _wipe_method_label, erase_single_file, platform_sync


@pytest.fixture
def sample(tmp_path):
    target = tmp_path / "evidence.bin"
    target.write_bytes(b"evidence that must not survive\n" * 64)
    return target


class TestFsyncFailureIsNotSuccess:
    def test_a_failed_flush_is_reported_as_a_failure(self, sample):
        with mock.patch("os.fsync", side_effect=OSError(5, "Input/output error")):
            result = erase_single_file(str(sample), passes=1, pattern="zero")

        assert result.status == "failure", (
            "an overwrite whose write cache never flushed reported success; the "
            "bytes may still be in cache, so 'erased' is not yet a fact"
        )
        assert "cache" in (result.error or "").lower()
        # The claim must also be actionable, not merely negative.
        assert "power-cycle" in (result.error or "")

    def test_platform_sync_reports_failure_rather_than_raising(self, tmp_path):
        fd = os.open(tmp_path / "f", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            with mock.patch("os.fsync", side_effect=OSError(5, "Input/output error")):
                assert platform_sync(fd) is False
        finally:
            os.close(fd)

    def test_platform_sync_reports_success_normally(self, tmp_path):
        # A real file, not /dev/null: fsync on /dev/null fails with EINVAL on
        # Linux, which would make this assert the opposite of what it means.
        fd = os.open(tmp_path / "f", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            assert platform_sync(fd) is True
        finally:
            os.close(fd)

    def test_the_overwrite_is_still_attempted(self, sample):
        """A flush failure changes the verdict, not the effort.

        If the tool gave up at the first fsync error it would leave the original
        bytes on disk, which is strictly worse than an unflushed overwrite.
        """
        with mock.patch("os.fsync", side_effect=OSError(5, "Input/output error")):
            result = erase_single_file(str(sample), passes=1, pattern="zero")
        assert result.bytes_overwritten == sample.stat().st_size if sample.exists() else True
        assert result.bytes_overwritten > 0


class TestPostEraseCheckCanActuallyFail:
    def test_a_surviving_leftover_is_reported(self, sample, tmp_path):
        """Both unlinks fail, so a renamed zeroed file survives.

        Before the fix this reported success: the check tested the original path,
        which the rename had already emptied.
        """
        with mock.patch("os.unlink", side_effect=OSError(13, "Permission denied")):
            result = erase_single_file(str(sample), passes=1, pattern="zero")

        assert result.status == "failure", "the data was zeroed but never removed, and the tool said success"
        assert result.error and "still present" in result.error
        # The claim must distinguish "zeroed" from "removed" rather than blur them.
        assert "not removed" in result.error

    def test_the_leftover_error_names_the_surviving_path(self, sample):
        with mock.patch("os.unlink", side_effect=OSError(13, "Permission denied")):
            result = erase_single_file(str(sample), passes=1, pattern="zero")
        assert result.error and (".s0_del_" in result.error or sample.name in result.error)

    def test_a_clean_erase_still_succeeds(self, sample):
        result = erase_single_file(str(sample), passes=1, pattern="zero")
        assert result.status == "success", result.error
        assert not sample.exists()
        assert result.metadata_cleansed is True

    def test_the_check_does_not_test_the_renamed_away_path(self):
        """Pin the mechanism, not just the outcome.

        A future refactor could reintroduce the tautology while still passing the
        outcome tests, if it happened to also unlink successfully.
        """
        import inspect

        source = inspect.getsource(file_eraser.erase_single_file)
        body = source.split("Post-erase verification", 1)[-1]
        assert "path_obj.exists()" not in body, (
            "the post-erase check is testing the original path again; the data is "
            "renamed away before the unlink, so that check can never fail"
        )


class TestMethodLabelDescribesWhatWasWritten:
    @pytest.mark.parametrize(
        "pattern,passes,expected",
        [
            ("zero", 1, "OVERWRITE_ZERO_1PASS"),
            ("zero", 3, "OVERWRITE_ZERO_3PASS"),
            ("zero", 2, "OVERWRITE_ZERO_2PASS"),
            ("random", 1, "SHRED_RANDOM_1PASS"),
            ("random", 3, "SHRED_RANDOM_3PASS"),
            ("random", 2, "SHRED_RANDOM_2PASS"),
        ],
    )
    def test_label_matches_the_pattern_and_pass_count(self, pattern, passes, expected):
        assert _wipe_method_label(pattern, passes) == expected

    def test_no_zero_wipe_is_ever_labelled_random(self):
        """The reported defect, stated as the invariant that rules it out."""
        for passes in range(1, 8):
            assert "RANDOM" not in _wipe_method_label("zero", passes)

    def test_no_random_wipe_is_ever_labelled_overwrite_zero(self):
        for passes in range(1, 8):
            assert "ZERO" not in _wipe_method_label("random", passes)

    def test_pass_count_appears_in_the_label(self):
        for passes in (1, 2, 3, 5, 7):
            assert f"{passes}PASS" in _wipe_method_label("zero", passes)

    def test_the_certificate_carries_the_real_label(self, sample, tmp_path, monkeypatch):
        """End to end: the label that reaches the certificate file.

        Generate a certificate from a three-pass zero wipe and read the method
        back out, so this covers the call site as well as the helper.
        """
        out = tmp_path / "certs"
        out.mkdir()
        monkeypatch.setenv("S0_AUDIT_DB", str(tmp_path / "audit.db"))

        from s0.cli.main import main

        rc = main(
            [
                "wipe",
                "--target",
                str(sample),
                "--passes",
                "3",
                "--pattern",
                "zero",
                "--yes",
                "--no-pdf",
                "--out-dir",
                str(out),
            ]
        )
        assert rc == 0

        written = list(out.glob("*.json"))
        assert written, "no certificate was written"

        import json

        method = None
        for cert_file in written:
            cert = json.loads(cert_file.read_text(encoding="utf-8"))
            method = (cert.get("wipe") or {}).get("method")
            pattern = (cert.get("wipe") or {}).get("pattern")
            assert pattern == "zero"
            # The two must agree: a random label over a zero pattern is the bug.
            assert ("RANDOM" in method) == (pattern == "random"), (
                f"certificate says pattern={pattern!r} but method={method!r}"
            )


class TestNoUnsampledReadbackClaim:
    def test_the_file_path_does_not_claim_a_pattern_match(self):
        """`sample_bytes_each` is 0 on this path, so the match field is null.

        Asserting the invariant directly rather than only via a generated
        certificate: the claim is false whenever no bytes were read, and that is
        a property of the code path, not of any one run.
        """
        import inspect

        source = inspect.getsource(file_eraser)
        assert '"all_samples_match_wipe_pattern": None' in source, (
            "the file path has no readback, so it must not assert a pattern match"
        )
        assert "post_erase_absence_and_overwrite_readback" not in source, (
            "the verification method string still claims an overwrite readback that this path never performs"
        )
