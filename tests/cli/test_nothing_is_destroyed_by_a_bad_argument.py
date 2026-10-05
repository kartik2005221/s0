"""A bad argument must be refused before the first byte is written.

Three separate inputs used to be validated *after* the destructive work, and all three
ended the same way: the target was gone and there was no evidence of it.

| Input | Was | Now |
|---|---|---|
| `--out-dir` unwritable | erased, `PermissionError`, exit 70, "This is a bug in s0" | refused, exit 73, target intact |
| `--out-dir` is a regular file | erased, `FileExistsError`, exit 70 | refused, exit 73, target intact |
| `--key` is not a key | erased, no certificate, **exit 0** | refused, exit 78, target intact |
| `--operator` is not encodable | erased, no certificate, **exit 0** | refused, exit 64, target intact |

Two of those exited 0. `s0 wipe ... && echo done` printed "done" after destroying a file
and producing no certificate, which is the worst failure this tool can have: a caller
gating on the exit code had no signal at all.

The exit codes are the documented ones. 73 is `EX_CANTCREAT`, which the exit-code table
already assigned to "output file cannot be created"; the code was returning 70 because the
failure arrived as an unhandled exception rather than as a decision.

`--out-dir` is probed by creating and deleting a real file rather than calling
`os.access`, because `access` answers for the real uid and lies on read-only mounts and
with capabilities.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


def _entry() -> str:
    found = Path(sys.executable).parent / "s0"
    if found.is_file():
        return str(found)
    which = shutil.which("s0")
    if not which:
        pytest.skip("s0 entry point not available")
    return which


def _wipe(*args: str, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [_entry(), "wipe", "--yes", "--no-pdf", *args],
        capture_output=True,
        text=True,
        cwd=str(cwd),
        timeout=600,
        env={**os.environ, "HOME": str(cwd)},
    )


@pytest.fixture
def sandbox(tmp_path) -> Path:
    target = tmp_path / "evidence.txt"
    target.write_bytes(b"CONFIDENTIAL\n" * 100)
    return tmp_path


class TestTheTargetSurvivesABadOutDir:
    def test_unwritable_parent_directory(self, sandbox):
        """Reported as: erase, then `PermissionError`, exit 70, "This is a bug in s0"."""
        blocked = sandbox / "blocked"
        blocked.mkdir()
        blocked.chmod(stat.S_IRUSR | stat.S_IXUSR)
        try:
            proc = _wipe("--targets", "evidence.txt", "--out-dir", str(blocked / "sub"), cwd=sandbox)
            assert (sandbox / "evidence.txt").is_file(), (
                "the target was erased before the output directory was checked"
            )
            assert proc.returncode == 73, (
                f"expected 73 (EX_CANTCREAT), got {proc.returncode}: {proc.stdout[-300:]}{proc.stderr[-300:]}"
            )
            assert "bug in s0" not in proc.stdout + proc.stderr
            assert "not writable" in proc.stderr or "cannot create" in proc.stderr
        finally:
            blocked.chmod(stat.S_IRWXU)

    def test_out_dir_is_a_regular_file(self, sandbox):
        notadir = sandbox / "iam_a_file"
        notadir.write_text("occupied")
        proc = _wipe("--targets", "evidence.txt", "--out-dir", str(notadir), cwd=sandbox)
        assert (sandbox / "evidence.txt").is_file(), "the target was erased"
        assert proc.returncode == 73, f"expected 73, got {proc.returncode}: {proc.stderr[-300:]}"
        assert notadir.read_text() == "occupied", "s0 wrote into a path that was a regular file"

    def test_out_dir_under_a_file_cannot_be_created(self, sandbox):
        """`/file/sub` cannot exist; `mkdir(parents=True)` raises NotADirectoryError."""
        blocker = sandbox / "blocker"
        blocker.write_text("x")
        proc = _wipe("--targets", "evidence.txt", "--out-dir", str(blocker / "sub"), cwd=sandbox)
        assert (sandbox / "evidence.txt").is_file(), "the target was erased"
        assert proc.returncode == 73, f"expected 73, got {proc.returncode}: {proc.stderr[-300:]}"
        assert "bug in s0" not in proc.stdout + proc.stderr


class TestTheTargetSurvivesABadKey:
    def test_key_that_is_not_a_key(self, sandbox):
        """Reported as: erased, no certificate, exit 0."""
        bad = sandbox / "notakey.pem"
        bad.write_text("this is not a PEM key\n")
        proc = _wipe(
            "--targets", "evidence.txt", "--out-dir", str(sandbox / "out"), "--key", str(bad), cwd=sandbox
        )
        assert (sandbox / "evidence.txt").is_file(), (
            "the target was erased with an unusable --key; certificate generation then "
            "failed and the command still exited 0"
        )
        assert proc.returncode != 0, (
            "an unusable --key exited 0: a destroyed target, no certificate, and a success status"
        )
        assert "not a usable" in proc.stderr or "not a PEM" in proc.stderr, proc.stderr[-300:]


class TestTheTargetSurvivesUnencodableMetadata:
    def test_operator_with_an_invalid_byte(self, sandbox):
        """Reported as: erased, no certificate, exit 0.

        `$(printf 'op\\xff')` is what a shell produces for a non-UTF-8 argument. The
        canonicalizer encodes the payload as UTF-8 and raised UnicodeEncodeError from
        inside certificate generation -- after the erase.
        """
        proc = subprocess.run(
            [
                _entry(),
                "wipe",
                "--targets",
                "evidence.txt",
                "--yes",
                "--no-pdf",
                "--out-dir",
                str(sandbox / "out"),
                "--operator",
                b"op\xff".decode("utf-8", "surrogateescape"),
            ],
            capture_output=True,
            text=True,
            cwd=str(sandbox),
            timeout=600,
            env={**os.environ, "HOME": str(sandbox)},
        )
        assert (sandbox / "evidence.txt").is_file(), "the target was erased"
        assert proc.returncode != 0, "an unencodable --operator exited 0 after erasing the target"
        assert "UTF-8" in proc.stderr or "utf-8" in proc.stderr, proc.stderr[-300:]

    def test_control_characters_are_refused(self):
        """An ESC in an operator name reached `s0 audit list` and could repaint the
        operator's terminal, and U+202E can reorder text on screen. Both are network
        input over the web API."""
        sys.path.insert(0, str(REPO_ROOT / "src"))
        from s0.validation import validate_metadata_str

        for _label, value in (
            ("ESC", "op\x1b[31mred"),
            ("newline", "op\nsecond-line"),
            ("tab", "op\tsecond"),
            ("NUL", "op\x00"),
            ("DEL", "op\x7f"),
            ("U+202E RTL override", "op\u202evil"),
            ("U+2066 LRI", "op\u2066x"),
        ):
            with pytest.raises(ValueError, match="control character|bidirectional"):
                validate_metadata_str("operator", value)

    def test_ordinary_names_still_validate(self):
        sys.path.insert(0, str(REPO_ROOT / "src"))
        from s0.validation import validate_metadata_str

        for good in ("jane.doe@forensics.lab", "Lab Tech 3", "张三", "op/2024"):
            assert validate_metadata_str("operator", good) == good


class TestCarveAndImageAlsoPreflight:
    """`carve` ran a whole pass over the image before failing to write, and `image`
    copied the entire source before failing to write its manifest."""

    def test_carve_refuses_before_scanning(self, sandbox):
        image = sandbox / "c.img"
        image.write_bytes(bytes(range(256)) * 200)
        blocked = sandbox / "blocked"
        blocked.mkdir()
        blocked.chmod(stat.S_IRUSR | stat.S_IXUSR)
        try:
            proc = subprocess.run(
                [
                    _entry(),
                    "carve",
                    "--target",
                    str(image),
                    "--out-dir",
                    str(blocked / "sub"),
                    "--yes",
                    "--no-certificate",
                ],
                capture_output=True,
                text=True,
                cwd=str(sandbox),
                timeout=900,
                env={**os.environ, "HOME": str(sandbox)},
            )
            assert proc.returncode == 73, f"expected 73, got {proc.returncode}: {proc.stderr[-400:]}"
            assert "bug in s0" not in proc.stdout + proc.stderr
            assert "Bytes scanned" not in proc.stdout, (
                "carve scanned the whole image before discovering it could not write; "
                "on a real evidence image that is hours of work discarded"
            )
        finally:
            blocked.chmod(stat.S_IRWXU)

    def test_image_leaves_no_orphan_copy(self, sandbox):
        source = sandbox / "src.img"
        source.write_bytes(b"SOURCE DATA\n" * 500)
        dest = sandbox / "copy.img"
        blocked = sandbox / "blocked"
        blocked.mkdir()
        blocked.chmod(stat.S_IRUSR | stat.S_IXUSR)
        try:
            proc = subprocess.run(
                [
                    _entry(),
                    "image",
                    "--source",
                    str(source),
                    "--dest",
                    str(dest),
                    "--out-dir",
                    str(blocked / "sub"),
                    "--no-certificate",
                ],
                capture_output=True,
                text=True,
                cwd=str(sandbox),
                timeout=900,
                env={**os.environ, "HOME": str(sandbox)},
            )
            assert proc.returncode == 73, f"expected 73, got {proc.returncode}: {proc.stderr[-400:]}"
            assert not dest.exists(), (
                "a full copy of the source was left on disk with no manifest and no "
                "certificate attesting to it"
            )
        finally:
            blocked.chmod(stat.S_IRWXU)


class TestTheHappyPathsStillWork:
    """The pre-flight must not break a run that is going to succeed."""

    def test_erases_and_writes_a_certificate(self, sandbox):
        proc = _wipe("--targets", "evidence.txt", "--out-dir", str(sandbox / "out"), cwd=sandbox)
        assert proc.returncode == 0, f"{proc.stdout[-500:]}{proc.stderr[-500:]}"
        assert not (sandbox / "evidence.txt").exists(), "the target survived"
        certs = list((sandbox / "out").glob("*.json"))
        assert certs, f"no certificate written: {list((sandbox / 'out').iterdir())}"

    def test_the_probe_leaves_nothing_behind(self, sandbox):
        _wipe("--targets", "evidence.txt", "--out-dir", str(sandbox / "out"), cwd=sandbox)
        leftovers = [p.name for p in (sandbox / "out").iterdir() if p.name.startswith(".s0-write-probe")]
        assert not leftovers, f"the writability probe left files behind: {leftovers}"
