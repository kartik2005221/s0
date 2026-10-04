"""`--dry-run` must not write. Anywhere.

`--dry-run` is attached to every subcommand by the shared parent parser, with the
help text "plan only; never write to the target". For a long time only `wipe` on
its block-device path, and `live flash`, ever read it. Everything else took the
flag, ignored it, and did the destructive thing anyway:

    s0 wipe --targets FILE --dry-run    -> deleted the file, printed "Successful: 1"
    s0 wipe --target DIR  --dry-run     -> deleted the tree
    s0 image  --dry-run                 -> wrote a full image and a manifest
    s0 clone  --dry-run                 -> cloned
    s0 carve  --dry-run                 -> wrote carved files, recovery_index.json,
                                          and appended a block to the audit ledger

The wipe case had a specific cause: `cmd_wipe` dispatched file and folder targets
to `cmd_erase_files` -- which never reads `dry_run` -- *before* the dry-run gate,
so a preview deleted the evidence. That was the worst shape this bug could take,
because a dry run is what an operator reaches for when they are unsure.

The tests below assert on the filesystem and the ledger rather than on output, so
a future change that prints a reassuring plan and then writes anyway fails here.

The image/clone/carve cases are enforced structurally, at the single point where a
handler is invoked, so a command added later inherits the guarantee instead of
having to remember it.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    not (shutil.which("s0") or (Path(sys.executable).parent / "s0").is_file()),
    reason="s0 entry point not available")


def _entry_point() -> str:
    found = shutil.which("s0") or str(Path(sys.executable).parent / "s0")
    assert Path(found).is_file(), f"s0 entry point not found at {found}"
    return found


def _run(*args: str, home: Path) -> subprocess.CompletedProcess:
    """Run the real CLI inside *home*, with HOME redirected.

    cwd matters as much as HOME: without it the relative paths below resolve
    against the repository root, the targets do not exist, and the filesystem
    assertions pass *vacuously* -- nothing is found, so nothing changes. The
    "the command still works without the flag" tests exist to catch exactly that
    class of false pass.

    The ledger matters too: a carve that wrote no files but appended a block
    would still have altered evidence, which is what --dry-run exists to prevent.
    """
    env = {"HOME": str(home), "PATH": "/usr/bin:/bin",
           "S0_AUDIT_DB": str(home / "audit.db")}
    return subprocess.run([_entry_point(), *args], capture_output=True, text=True,
                          env=env, cwd=str(home), timeout=180)


def _md5(path: Path) -> str:
    return hashlib.md5(path.read_bytes(), usedforsecurity=False).hexdigest()


def _snapshot(root: Path) -> dict[str, tuple[int, str]]:
    """Every file under root, with its size and content digest."""
    out = {}
    for p in sorted(root.rglob("*")):
        if p.is_file():
            out[str(p.relative_to(root))] = (p.stat().st_size, _md5(p))
    return out


@pytest.fixture
def sandbox(tmp_path):
    """A source image with a genuinely carvable PNG buried in it.

    The PNG matters for the carve case: without a recoverable object, "carve wrote
    nothing" would pass for the wrong reason -- a carver given nothing to find
    writes nothing whether or not it honours the flag.
    """
    import io

    from PIL import Image

    (tmp_path / "keep.txt").write_text("evidence\n")
    tree = tmp_path / "tree" / "sub"
    tree.mkdir(parents=True)
    (tree / "a.txt").write_text("a\n")
    (tree / "b.txt").write_text("b\n")

    buf = io.BytesIO()
    Image.new("RGB", (64, 64), (200, 30, 30)).save(buf, "PNG")
    blob = bytes(bytearray(range(256))) * 800
    blob = blob[:1000] + buf.getvalue() + blob[1000:]
    (tmp_path / "src.raw").write_bytes(blob)

    out = tmp_path / "out"
    out.mkdir()
    return tmp_path


# Every command that writes output, with the arguments that make it write.
WRITING_COMMANDS = [
    pytest.param(["wipe", "--targets", "keep.txt", "--no-certificate", "--yes"],
                 id="wipe-file"),
    pytest.param(["wipe", "--target", "tree", "--no-certificate", "--yes"],
                 id="wipe-folder"),
    pytest.param(["wipe", "--target", "src.raw", "--no-certificate", "--yes"],
                 id="wipe-image"),
    pytest.param(["image", "--source", "src.raw", "--destination", "new.img"],
                 id="image"),
    pytest.param(["clone", "--source", "src.raw", "--destination", "clone.img"],
                 id="clone"),
    pytest.param(["carve", "--target", "src.raw", "--out-dir", "out",
                  "--no-certificate", "--no-pdf"],
                 id="carve"),
]


class TestDryRunWritesNothing:
    @pytest.mark.parametrize("argv", WRITING_COMMANDS)
    def test_no_file_is_created_modified_or_deleted(self, sandbox, argv):
        before = _snapshot(sandbox)
        proc = _run(*argv, "--dry-run", home=sandbox)

        assert proc.returncode == 0, (
            f"`s0 {' '.join(argv)} --dry-run` exited {proc.returncode}\n{proc.stderr}")

        after = _snapshot(sandbox)
        assert after == before, (
            "the dry run changed the filesystem:\n"
            f"  removed: {sorted(set(before) - set(after))}\n"
            f"  added:   {sorted(set(after) - set(before))}\n"
            f"  changed: {sorted(k for k in set(before) & set(after) if before[k] != after[k])}")

    @pytest.mark.parametrize("argv", WRITING_COMMANDS)
    def test_no_audit_ledger_block_is_appended(self, sandbox, argv):
        """A carve that writes no files but appends a ledger block still altered
        evidence, and the ledger is a chained structure: an appended block changes
        every hash after it."""
        ledger = sandbox / "audit.db"
        before = ledger.read_bytes() if ledger.exists() else b""
        proc = _run(*argv, "--dry-run", home=sandbox)
        after = ledger.read_bytes() if ledger.exists() else b""

        assert after == before, (
            f"{len(after) - len(before)} bytes were appended to the audit ledger "
            f"by a dry run:\n{proc.stderr}")

    @pytest.mark.parametrize("argv", WRITING_COMMANDS)
    def test_it_says_that_nothing_was_written(self, sandbox, argv):
        """A silent dry run is its own problem: the operator is left guessing."""
        proc = _run(*argv, "--dry-run", home=sandbox)
        combined = (proc.stdout + proc.stderr).lower()
        assert "dry run" in combined, (
            f"`s0 {' '.join(argv)} --dry-run` said nothing about being a dry run:\n"
            f"{combined[-500:]}")


class TestWithoutDryRunTheCommandStillWorks:
    """The guard must not have turned these commands into no-ops.

    A dry-run fix that quietly disables the real operation is not a fix, so each
    command is also run for real and asserted to have done its job.
    """

    def test_image_really_writes_without_the_flag(self, sandbox):
        proc = _run("image", "--source", "src.raw", "--destination", "new.img",
                    home=sandbox)
        assert proc.returncode == 0, proc.stderr
        assert (sandbox / "new.img").stat().st_size == (sandbox / "src.raw").stat().st_size

    def test_carve_really_writes_without_the_flag(self, sandbox):
        proc = _run("carve", "--target", "src.raw", "--out-dir", "out",
                    "--no-certificate", "--no-pdf", home=sandbox)
        assert proc.returncode == 0, proc.stderr
        assert list((sandbox / "out").iterdir()), (
            "carve wrote nothing without --dry-run, so the dry-run test above "
            "would have passed for the wrong reason")


class TestReadOnlyCommandsAreUnaffected:
    """The guard keys on a command allowlist; read-only commands must pass through.

    `list` and `plan` already mean "show me", and `plan` is documented as a
    dry run. Intercepting them would be a regression in the other direction.
    """

    @pytest.mark.parametrize("argv", [
        ["list"],
        ["plan", "--target", "src.raw"],
        ["plan", "--target", "src.raw", "--json"],
    ])
    def test_read_only_commands_still_run_under_dry_run(self, sandbox, argv):
        proc = _run(*argv, "--dry-run", home=sandbox)
        assert proc.returncode == 0, (
            f"`s0 {' '.join(argv)} --dry-run` exited {proc.returncode}\n{proc.stderr}")

        # Combined output, not stdout alone: whether a command's text rendering
        # goes to stdout or stderr is the separate, still-open piped-output
        # contract. What matters here is only that the command ran at all.
        combined = (proc.stdout + proc.stderr).strip()
        assert combined, (
            f"`s0 {' '.join(argv)} --dry-run` produced no output at all; it was "
            f"intercepted by the dry-run guard instead of running")

    def test_plan_json_still_emits_a_document_under_dry_run(self, sandbox):
        """plan --json is the machine-readable contract, so it must stay on stdout."""
        import json

        proc = _run("plan", "--target", "src.raw", "--json", "--dry-run", home=sandbox)
        assert proc.returncode == 0, proc.stderr
        payload = json.loads(proc.stdout)
        assert payload, "plan --json emitted an empty document"


class TestTheWipeDryRunStillExplainsItself:
    def test_a_refused_target_is_named_in_the_dry_run(self, sandbox):
        """A dry run is when an operator learns a target would be refused.

        Silently returning 0 for a target that would have been REFUSED teaches an
        operator that the command works on it.
        """
        ledger = sandbox / ".s0" / "s0_audit.db"
        ledger.parent.mkdir(parents=True, exist_ok=True)
        ledger.write_bytes(b"")

        proc = _run("wipe", "--targets", str(ledger), "--no-certificate",
                    "--dry-run", home=sandbox)
        combined = (proc.stdout + proc.stderr).lower()
        assert "refus" in combined, (
            "the dry run did not mention that the target is protected:\n"
            f"{combined[-500:]}")

    def test_the_dry_run_names_the_target_and_the_parameters(self, sandbox):
        proc = _run("wipe", "--targets", "keep.txt", "--no-certificate",
                    "--passes", "3", "--pattern", "random", "--dry-run", home=sandbox)
        combined = proc.stdout + proc.stderr
        assert "keep.txt" in combined
        assert "3" in combined and "random" in combined, (
            "the dry run did not report the parameters that would be used, so it "
            "is not a usable preview")
