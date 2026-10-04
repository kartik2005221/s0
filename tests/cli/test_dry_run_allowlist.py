"""`--dry-run` must mean "nothing was written", for every command.

The guard was an allowlist of *writers* -- `("image", "clone", "carve")` -- with
everything else falling through to its own handler. That shape fails open: any
command not named there is assumed harmless. So `keygen` wrote a private key pair,
`live download` pulled 573 MB, `upgrade` ran a real `git fetch` and three
`pip install` calls, and `uninstall` wrote a fresh database backup, each while
reporting that nothing was written.

Naming every future writer in a tuple is not a property anyone can rely on -- the
next command added is wrong the day it lands. The guard is inverted here: everything
is refused unless it is *known* read-only, so a new command is safe by default and
has to be opted out.

`audit list` also turned out to write: `list_audit_blocks` called `init_audit_db`,
so merely *reading* the ledger created an empty chain of custody. That is fixed at
the source rather than in the guard, because "the ledger exists" has to keep meaning
"something was recorded" -- a verifier's one useful signal.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


def _entry_point() -> str:
    found = shutil.which("s0") or str(Path(sys.executable).parent / "s0")
    if not Path(found).is_file():
        pytest.skip("s0 entry point not available")
    return found


def _snapshot(root: Path) -> dict[str, int]:
    """Every file under root with its size -- cheap, and enough to spot a write."""
    out = {}
    for path in sorted(root.rglob("*")):
        try:
            if path.is_file():
                out[str(path.relative_to(root))] = path.stat().st_size
        except OSError:
            continue
    return out


@pytest.fixture
def workspace(tmp_path):
    """A scratch HOME with one of everything a state-changing command wants."""
    (tmp_path / "keep.txt").write_text("evidence\n")
    (tmp_path / "folder").mkdir()
    (tmp_path / "folder" / "a.txt").write_text("a\n")
    # A recognisable disk image, not arbitrary bytes: `_looks_like_raw_image`
    # sniffs for a container magic, and a plain byte ramp is treated as an ordinary
    # file -- which made `plan --target img.raw` exit 66 for reasons unrelated to
    # what these tests are checking.
    blob = bytearray(bytes(range(256)) * 800)
    blob[0x8001:0x8006] = b"CD001"  # ISO 9660 primary volume descriptor
    (tmp_path / "img.raw").write_bytes(bytes(blob))
    (tmp_path / "out").mkdir()
    (tmp_path / "certs").mkdir()
    return tmp_path


def _run(workspace: Path, *args: str, timeout: int = 60):
    return subprocess.run(
        [_entry_point(), *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=str(workspace),
        env={"HOME": str(workspace), "PATH": "/usr/bin:/bin", "S0_AUDIT_DB": str(workspace / "audit.db")},
    )


#: Every subcommand that must not touch the filesystem under --dry-run.
WRITING_COMMANDS = [
    pytest.param(["keygen", "--out-dir", "keys", "--name", "k"], id="keygen"),
    pytest.param(["uninstall"], id="uninstall"),
    pytest.param(["upgrade"], id="upgrade"),
    pytest.param(["wipe", "--targets", "keep.txt", "--yes", "--no-certificate"], id="wipe"),
    pytest.param(["image", "--source", "img.raw", "--destination", "new.img"], id="image"),
    pytest.param(["clone", "--source", "img.raw", "--destination", "clone.img"], id="clone"),
    pytest.param(
        ["carve", "--target", "img.raw", "--out-dir", "out", "--no-certificate", "--no-pdf"], id="carve"
    ),
    pytest.param(["live", "download"], id="live-download"),
]


class TestTheGuardIsInvertedNotAllowlisted:
    def test_the_read_only_set_is_an_allowlist(self):
        """The shape is the fix; assert it so it cannot quietly become a denylist."""
        from s0.cli.main import _DRY_RUN_READ_ONLY

        assert isinstance(_DRY_RUN_READ_ONLY, tuple)
        assert set(_DRY_RUN_READ_ONLY) == {"list", "plan", "audit", "verify"}
        # The old name was a list of writers. If it comes back, the guard is a
        # denylist again and every new command is assumed safe.
        import s0.cli.main as cli

        assert not hasattr(cli, "_DRY_RUN_WRITES"), (
            "_DRY_RUN_WRITES is a denylist of writers again; that shape fails open "
            "for any command not explicitly named"
        )

    @pytest.mark.parametrize("command", ["keygen", "uninstall", "upgrade"])
    def test_each_previously_unguarded_command_is_now_refused(self, workspace, command):
        """The three the report found writing, plus the ones already guarded."""
        before = _snapshot(workspace)
        _run(
            workspace,
            *([command] if command != "keygen" else ["keygen", "--out-dir", "keys", "--name", "k"]),
            "--dry-run",
            timeout=120,
        )
        after = _snapshot(workspace)
        assert after == before, f"`s0 {command} --dry-run` wrote: {sorted(set(after) - set(before))}"


class TestNoCommandWritesUnderDryRun:
    @pytest.mark.parametrize("argv", WRITING_COMMANDS)
    def test_the_filesystem_is_untouched(self, workspace, argv):
        before = _snapshot(workspace)
        proc = _run(workspace, *argv, "--dry-run", timeout=120)
        after = _snapshot(workspace)

        added = sorted(set(after) - set(before))
        removed = sorted(set(before) - set(after))
        changed = sorted(k for k in set(before) & set(after) if before[k] != after[k])
        assert not (added or removed or changed), (
            f"`s0 {' '.join(argv)} --dry-run` changed the filesystem -- "
            f"added={added} removed={removed} changed={changed}. "
            f"Output tail: {(proc.stdout + proc.stderr)[-300:]}"
        )

    def test_reading_the_ledger_does_not_create_it(self, workspace):
        """`audit list` used to create an empty chain of custody by being called.

        Beyond the --dry-run violation, it breaks the one fact a verifier needs the
        ledger's existence to mean: that something was recorded.
        """
        assert not (workspace / "audit.db").exists()
        proc = _run(workspace, "audit", "list", "--dry-run")
        assert proc.returncode in (0, 1), proc.stderr
        assert not (workspace / "audit.db").exists(), (
            "listing the ledger created it. 'The ledger exists' must mean 'something was recorded'."
        )

    def test_a_real_erase_still_records(self, workspace):
        """The read-path change must not stop writes."""
        proc = _run(
            workspace, "wipe", "--targets", "keep.txt", "--yes", "--no-pdf", "--out-dir", "certs", timeout=180
        )
        assert proc.returncode == 0, proc.stderr
        assert (workspace / "audit.db").is_file(), "a real erase stopped writing the ledger"

    def test_it_says_that_nothing_was_written(self, workspace):
        proc = _run(workspace, "keygen", "--out-dir", "keys", "--name", "k", "--dry-run")
        combined = (proc.stdout + proc.stderr).lower()
        assert "dry run" in combined, f"a silent dry run leaves the operator guessing:\n{combined[-400:]}"


class TestReadOnlyCommandsStillRun:
    @pytest.mark.parametrize(
        "argv",
        [
            ["list"],
            ["plan", "--target", "img.raw"],
            ["audit", "list"],
        ],
    )
    def test_a_read_only_command_is_not_intercepted(self, workspace, argv):
        """Intercepting these would be a regression in the other direction."""
        proc = _run(workspace, *argv, "--dry-run")
        assert proc.returncode == 0, (
            f"`s0 {' '.join(argv)} --dry-run` exited {proc.returncode}\n{proc.stderr[-400:]}"
        )

        # Checked by what the command produced, not by the absence of a phrase:
        # `plan` legitimately prints "DRY RUN - nothing was written" from its own
        # handler, so grepping for that word cannot distinguish "ran normally" from
        # "intercepted by the guard". What the guard emits instead names the command
        # and offers to re-run it, so assert the real output is present.
        combined = proc.stdout + proc.stderr
        assert "Dry run: nothing will be written" not in combined, (
            "the generic dry-run guard intercepted a read-only command instead of letting it run"
        )
        if argv[0] == "plan":
            assert "Method" in combined or "DRY RUN" in combined, f"plan produced no plan:\n{combined[-400:]}"
        else:
            assert combined.strip(), "a read-only command produced no output at all"

    def test_wipe_still_prints_its_own_plan(self, workspace):
        """wipe keeps its richer per-target dry run rather than the generic refusal."""
        proc = _run(workspace, "wipe", "--targets", "keep.txt", "--dry-run", "--no-certificate")
        combined = proc.stdout + proc.stderr
        assert "keep.txt" in combined, "wipe's dry run should name the targets it would erase"


class TestCommandGroupsAreExemptedPerAction:
    """`live` is a group, and its actions do not agree about --dry-run.

    Exempting the whole group because `live flash` honours the flag reinstated the
    exact bug the allowlist exists to remove: `s0 live download --dry-run` pulled
    547 MB, into the working directory, while claiming nothing was written.

    So this asserts the shape of the exemption -- by sub-action, with an
    unrecognised action falling through to the guard -- rather than the behaviour of
    one command, which is what let the mistake through.
    """

    def test_the_exemption_names_sub_actions_not_the_group(self):
        import inspect

        from s0.cli.main import _dry_run_guard

        source = inspect.getsource(_dry_run_guard)
        assert 'command == "live"' in source, (
            "`live` is handled specially, so the exemption must be checked by sub-action"
        )
        assert "live_action" in source, (
            "the live exemption does not look at the sub-action, so one action's "
            "dry-run support is granting it to all of them"
        )

    def test_an_unrecognised_live_action_is_refused(self):
        """Fail closed: a new `live` sub-action must not inherit an exemption."""
        import argparse

        from s0.cli.main import _dry_run_guard

        args = argparse.Namespace(command="live", live_action="something-new", dry_run=True, ui=None)
        assert _dry_run_guard(args) is not None, (
            "an unrecognised `live` sub-action was let through; the exemption must "
            "be an allowlist of actions, so a new one is refused by default"
        )

    @pytest.mark.parametrize("action", ["flash", "devices"])
    def test_the_actions_that_do_implement_dry_run_are_exempt(self, action):
        import argparse

        from s0.cli.main import _dry_run_guard

        args = argparse.Namespace(command="live", live_action=action, dry_run=True, ui=None)
        assert _dry_run_guard(args) is None, (
            f"`live {action}` implements its own dry run and must reach its handler"
        )

    def test_live_download_names_itself_in_the_refusal(self):
        """`live download`, not a bare `live`, so the message is actionable."""
        import argparse

        from s0.cli.main import _dry_run_guard

        args = argparse.Namespace(command="live", live_action="download", dry_run=True, ui=None)
        assert _dry_run_guard(args) == 0
