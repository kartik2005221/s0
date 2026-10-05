"""A sanitiser must fail loudly, and a carver must not exit 0 while lying.

Four defects where the tool reported success it had not earned, and one where it
reported a Python traceback for an ordinary operator mistake.

**chunk_size <= 0 hung forever.** ``to_write = min(remaining, chunk_size)`` was
zero or negative, so ``remaining`` never advanced and the write loop span. Not an
error, not a crash -- an uninterruptible hang inside a sanitiser, which is the
worst failure mode available because the operator cannot tell it apart from
progress. The CLI validated this; the library entry points, which the web tier
calls in-process, did not.

**passes=0 destroyed the data and claimed to write nothing.** The overwrite loop
`for _ in range(passes)` never ran, so the file was truncated without being
overwritten: the original bytes gone, ``bytes_overwritten=0``, status success.
For a sanitiser that is the single worst outcome available -- silent, total
destruction of the target, reported as a no-op.

**A target that does not exist printed a traceback.** ``cmd_carve`` never checked,
so the size probe yielded 0, the engine opened a missing path, and the operator
saw a two-page stack trace for a typo in a filename. There was no catch-all in
main() at all, so *any* unexpected exception surfaced that way.

**Three silent successes.** ``--min-confidence 999`` carved nothing and exited 0;
``--extensions zzz`` matched nothing and exited 0; ``--write-session`` to an
unwritable path warned and exited 0, so a script driving an overnight carve
believed it was resumable when it was not.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
from pathlib import Path

import pytest

from s0.cli.file_eraser import erase_single_file

pytestmark = pytest.mark.skipif(
    not (shutil.which("s0") or (Path(sys.executable).parent / "s0").is_file()),
    reason="s0 entry point not available",
)


def _entry_point() -> str:
    found = shutil.which("s0") or str(Path(sys.executable).parent / "s0")
    assert Path(found).is_file(), f"s0 entry point not found at {found}"
    return found


def _run(*args: str, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [_entry_point(), *args],
        capture_output=True,
        text=True,
        env={"HOME": str(cwd), "PATH": "/usr/bin:/bin", "S0_AUDIT_DB": str(cwd / "audit.db")},
        cwd=str(cwd),
        timeout=180,
    )


@pytest.fixture
def workdir(tmp_path):
    (tmp_path / "img.raw").write_bytes(bytes(bytearray(range(256))) * 800)
    return tmp_path


class _Timeout(Exception):
    pass


def _alarm(_signum, _frame):
    raise _Timeout("did not terminate")


@pytest.fixture
def hard_timeout():
    """Run a call under a SIGALRM so a regression fails instead of wedging the suite.

    Every call to erase_single_file in this file goes through this. An earlier
    draft called it directly in two tests, and reverting the fix made the whole
    suite hang for two minutes instead of failing -- a regression test that
    takes the runner down with it is worse than no test.
    """
    if not hasattr(signal, "SIGALRM"):

        def _run_plain(fn, *args, **kwargs):
            return fn(*args, **kwargs)

        yield _run_plain
        return

    previous = signal.signal(signal.SIGALRM, _alarm)

    def _run(fn, *args, **kwargs):
        signal.setitimer(signal.ITIMER_REAL, 5.0)
        try:
            return fn(*args, **kwargs)
        except _Timeout:
            pytest.fail("call did not terminate within 5s: it is looping")
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)

    yield _run
    signal.signal(signal.SIGALRM, previous)


class TestWriteGeometryIsValidated:
    @pytest.mark.parametrize("chunk_size", [0, -1, -65536])
    def test_a_non_positive_chunk_size_fails_instead_of_hanging(self, tmp_path, hard_timeout, chunk_size):
        target = tmp_path / "t.bin"
        target.write_bytes(b"data that must survive a refusal\n")
        result = hard_timeout(erase_single_file, str(target), passes=1, pattern="zero", chunk_size=chunk_size)
        assert result.status == "failure", (
            f"chunk_size={chunk_size} did not fail; the write loop spins forever "
            f"because `remaining` never advances"
        )
        assert "chunk_size" in (result.error or "")

    def test_the_target_is_untouched_when_the_geometry_is_refused(self, tmp_path, hard_timeout):
        """A refusal must not have opened the file for writing on the way."""
        target = tmp_path / "t.bin"
        target.write_bytes(b"original bytes\n")
        hard_timeout(erase_single_file, str(target), passes=1, pattern="zero", chunk_size=0)
        assert target.read_bytes() == b"original bytes\n"

    def test_a_bool_chunk_size_is_refused(self, tmp_path, hard_timeout):
        """bool is an int subclass, so True would otherwise mean chunk_size=1."""
        target = tmp_path / "t.bin"
        target.write_bytes(b"x")
        result = hard_timeout(erase_single_file, str(target), passes=1, pattern="zero", chunk_size=True)  # type: ignore[arg-type]
        assert result.status == "failure"

    def test_a_valid_chunk_size_still_works(self, tmp_path, hard_timeout):
        target = tmp_path / "t.bin"
        target.write_bytes(b"data")
        result = hard_timeout(erase_single_file, str(target), passes=1, pattern="zero", chunk_size=4096)
        assert result.status == "success", result.error

    @pytest.mark.parametrize("passes", [0, -1])
    def test_a_non_positive_pass_count_is_refused(self, tmp_path, hard_timeout, passes):
        """Zero passes truncated the file without overwriting it and said success."""
        target = tmp_path / "t.bin"
        original = b"evidence that must not vanish\n"
        target.write_bytes(original)

        result = hard_timeout(erase_single_file, str(target), passes=passes, pattern="zero")

        assert result.status == "failure", (
            "a zero-pass wipe reported success; it destroys the original data "
            "while claiming to have written nothing"
        )
        assert target.read_bytes() == original, "the target was truncated by an operation that was refused"
        assert result.bytes_overwritten == 0

    def test_the_error_explains_why_zero_passes_is_refused(self, tmp_path, hard_timeout):
        target = tmp_path / "t.bin"
        target.write_bytes(b"x")
        result = hard_timeout(erase_single_file, str(target), passes=0, pattern="zero")
        assert "truncate" in (result.error or "").lower(), (
            "the message does not say why this is dangerous, so an integrator would work around it"
        )


class TestBadTargetsDoNotProduceTracebacks:
    @pytest.mark.parametrize(
        "argv",
        [
            ["carve", "--target", "/nonexistent-target-for-s0", "--no-certificate", "--no-pdf"],
            ["carve", "--target", "relative-missing", "--no-certificate", "--no-pdf"],
        ],
    )
    def test_a_missing_target_is_a_clean_error(self, workdir, argv):
        proc = _run(*argv, "--out-dir", str(workdir / "out"), cwd=workdir)
        combined = proc.stdout + proc.stderr
        assert "Traceback" not in combined, (
            f"a typo in --target produced a Python traceback:\n{combined[-800:]}"
        )
        assert proc.returncode != 0
        assert "not found" in combined.lower() or "no such" in combined.lower()

    def test_the_exit_code_is_noinput_not_a_crash(self, workdir):
        proc = _run(
            "carve",
            "--target",
            "/nonexistent-target-for-s0",
            "--out-dir",
            str(workdir / "out"),
            "--no-certificate",
            "--no-pdf",
            cwd=workdir,
        )
        assert proc.returncode == 66, f"expected EX_NOINPUT (66), got {proc.returncode}"

    def test_an_unexpected_exception_is_reported_without_a_traceback(self, workdir, monkeypatch, capsys):
        """main() had no catch-all, so any surprise printed a stack trace.

        Run in-process: a subprocess would not see the monkeypatched handler, and
        the test would silently assert nothing.
        """
        import s0.cli.main as cli

        monkeypatch.delenv("S0_TRACEBACK", raising=False)
        monkeypatch.setattr(
            cli, "cmd_list", lambda args: (_ for _ in ()).throw(RuntimeError("synthetic internal failure"))
        )

        rc = cli.main(["list"])
        combined = capsys.readouterr()
        text = combined.out + combined.err

        assert "Traceback" not in text, text[-500:]
        assert "RuntimeError" in text, "the actual error is hidden; the operator learns nothing"
        assert "synthetic internal failure" in text, "the exception message is not shown"
        assert rc == 70, f"an internal failure must not exit 0, got {rc}"

    def test_the_traceback_is_still_available_to_developers(self, workdir):
        """Hiding the traceback must not remove it from those who need it."""
        proc_env = dict(os.environ)
        proc_env.update({"HOME": str(workdir), "S0_TRACEBACK": "1", "S0_AUDIT_DB": str(workdir / "audit.db")})
        script = (
            "import s0.cli.main as m\n"
            "m.cmd_list = lambda args: (_ for _ in ()).throw(RuntimeError('boom'))\n"
            "m.main(['list'])\n"
        )
        proc = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            env=proc_env,
            cwd=str(workdir),
            timeout=120,
        )
        assert "Traceback" in proc.stderr, (
            "S0_TRACEBACK=1 did not produce a traceback, so a bug report cannot carry one"
        )


class TestSilentSuccessesAreGone:
    def test_out_of_range_min_confidence_is_a_usage_error(self, workdir):
        proc = _run(
            "carve",
            "--target",
            "img.raw",
            "--out-dir",
            str(workdir / "o1"),
            "--no-certificate",
            "--no-pdf",
            "--min-confidence",
            "999",
            cwd=workdir,
        )
        assert proc.returncode != 0, (
            "--min-confidence 999 succeeded having carved nothing; the web tier "
            "already refuses this, so the same value was accepted in one "
            "interface and refused in the other"
        )

    @pytest.mark.parametrize("value", ["-5", "101", "abc"])
    def test_invalid_confidence_values_are_rejected(self, workdir, value):
        proc = _run(
            "carve",
            "--target",
            "img.raw",
            "--out-dir",
            str(workdir / "o2"),
            "--no-certificate",
            "--no-pdf",
            "--min-confidence",
            value,
            cwd=workdir,
        )
        assert proc.returncode != 0

    @pytest.mark.parametrize("value", ["0", "50", "100"])
    def test_the_documented_range_is_accepted(self, workdir, value):
        proc = _run(
            "carve",
            "--target",
            "img.raw",
            "--out-dir",
            str(workdir / "o3"),
            "--no-certificate",
            "--no-pdf",
            "--min-confidence",
            value,
            cwd=workdir,
        )
        assert "Traceback" not in proc.stdout + proc.stderr

    def test_an_extension_filter_matching_nothing_is_an_error(self, workdir):
        proc = _run(
            "carve",
            "--target",
            "img.raw",
            "--out-dir",
            str(workdir / "o4"),
            "--no-certificate",
            "--no-pdf",
            "--extensions",
            "zzz",
            cwd=workdir,
        )
        assert proc.returncode != 0, (
            "--extensions zzz matched nothing and exited 0, which a script cannot "
            "distinguish from an image with no recoverable files"
        )

    def test_an_unfiltered_empty_carve_still_succeeds(self, workdir):
        """An image with nothing recoverable is a legitimate result, not an error.

        Only the *explicit filter* case is treated as suspicious, because that is
        where a typo is likely.
        """
        proc = _run(
            "carve",
            "--target",
            "img.raw",
            "--out-dir",
            str(workdir / "o5"),
            "--no-certificate",
            "--no-pdf",
            cwd=workdir,
        )
        assert proc.returncode == 0, "a carve that legitimately found nothing must not be an error"

    def test_an_unwritable_session_path_is_an_error(self, workdir):
        """A session that cannot be written means the next run starts from nothing."""
        proc = _run(
            "carve",
            "--target",
            "img.raw",
            "--out-dir",
            str(workdir / "o6"),
            "--no-certificate",
            "--no-pdf",
            "--write-session",
            "/proc/definitely/not/writable",
            cwd=workdir,
        )
        assert proc.returncode != 0, (
            "--write-session to an unwritable path warned and exited 0, so a "
            "script driving a long carve believed it was resumable"
        )
