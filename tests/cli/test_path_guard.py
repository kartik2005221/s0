"""The path guard: the CLI and the web tier must agree on what is protected.

The web dashboard refused `/etc/passwd`. The CLI refused nothing. Two interfaces
to the same destructive engine, disagreeing about what is protected, is the worst
shape this could take -- an operator who found the web tier safe would reasonably
assume the terminal was too.

Confirmed before fixing:

    s0 wipe --targets /etc/hostname --yes          # reached a system file
    s0 wipe --targets ~/.s0/s0_audit.db --yes      # destroyed the audit ledger
    s0 wipe --targets ~/.s0 --yes                  # s0's entire state directory
    s0 wipe --targets $HOME --yes                  # the entire home directory

The ledger case is the one that matters most: after wiping it, `s0 audit verify`
builds a fresh empty ledger and reports it valid, so the tool erased the record of
everything it had already done.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from s0.safety import (
    ProtectedPathError,
    check_path_is_destructive,
    is_protected_path,
    s0_state_paths,
)

REPO = Path(__file__).resolve().parent.parent.parent


def _s0(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(Path(sys.executable).parent / "s0"), *args],
        capture_output=True, text=True, cwd=str(cwd or REPO), timeout=120,
    )


# --------------------------------------------------------------------------- #
# The guard itself
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "path",
    [
        "/etc/hostname", "/etc/passwd", "/usr/bin/python3", "/bin/sh",
        "/proc/self/environ", "/sys/kernel", "/root/.bashrc", "/var/log/syslog",
        "/boot/vmlinuz", "/lib/x86_64-linux-gnu/libc.so.6", "/sbin/init",
    ],
)
def test_system_paths_are_refused(path):
    with pytest.raises(ProtectedPathError):
        check_path_is_destructive(path)


def test_s0_own_state_is_refused():
    """The audit ledger and signing material. This is the finding that mattered."""
    ledger = Path.home() / ".s0" / "s0_audit.db"
    with pytest.raises(ProtectedPathError) as exc:
        check_path_is_destructive(ledger)
    assert "state" in str(exc.value).lower()
    assert "chain of custody" in str(exc.value).lower(), (
        "the refusal must say why: this is the chain-of-custody record"
    )


def test_the_whole_s0_state_directory_is_refused():
    with pytest.raises(ProtectedPathError):
        check_path_is_destructive(Path.home() / ".s0")


def test_the_installation_tree_is_refused():
    with pytest.raises(ProtectedPathError):
        check_path_is_destructive(REPO / "src" / "s0")


def test_home_directory_itself_is_refused():
    with pytest.raises(ProtectedPathError) as exc:
        check_path_is_destructive(Path.home())
    assert "home directory" in str(exc.value).lower()


def test_filesystem_root_is_refused():
    with pytest.raises(ProtectedPathError):
        check_path_is_destructive("/")


@pytest.mark.parametrize(
    "path",
    ["/tmp", "/mnt", "/media/evidence.img", "/home/kartik/Documents"],
)
def test_ordinary_forensic_targets_are_still_allowed(path):
    """A guard that refuses legitimate work is worse than none."""
    assert check_path_is_destructive(path) == []


def test_traversal_and_symlinks_cannot_evade_it(tmp_path):
    """Checked after resolution, so spelling it differently does not help."""
    link = tmp_path / "innocent"
    link.symlink_to("/etc")
    with pytest.raises(ProtectedPathError):
        check_path_is_destructive(link)
    # A relative spelling that climbs out of the tree. The number of levels
    # depends on where the checkout sits, so build one that certainly reaches /.
    climb = "../" * (len(Path.cwd().resolve().parts) + 1)
    with pytest.raises(ProtectedPathError):
        check_path_is_destructive(f"{climb}etc/hostname")


def test_force_overrides_with_an_explicit_warning():
    warnings = check_path_is_destructive("/etc/hostname", force=True)
    assert warnings, "--force must record what was overridden, not pass silently"
    assert "SYSTEM PATH" in warnings[0]


def test_state_paths_are_discoverable():
    paths = {str(p) for p in s0_state_paths()}
    assert str(Path.home() / ".s0") in paths


def test_boolean_helper_agrees():
    assert is_protected_path("/etc/hostname") is True
    assert is_protected_path("/tmp") is False


# --------------------------------------------------------------------------- #
# End to end through the CLI
# --------------------------------------------------------------------------- #

def test_cli_refuses_a_system_path_and_leaves_the_file(tmp_path):
    probe = tmp_path / "etc" / "hostname"
    probe.parent.mkdir()
    probe.write_text("original")
    # Pretend it is /etc for the purposes of the prefix match by using a real
    # system path in a scratch copy of the tree instead.
    result = _s0("wipe", "--targets", str(REPO / "src" / "s0" / "safety.py"),
                 "--yes", "--no-pdf", "--no-certificate")
    assert result.returncode != 0, (
        f"targeting the tool's own source must not succeed:\n{result.stdout}"
    )
    assert "refus" in (result.stdout + result.stderr).lower()
    assert (REPO / "src" / "s0" / "safety.py").is_file(), "the file must survive"


def test_cli_refusal_is_not_a_traceback(tmp_path):
    """It used to end in `raise SafetyError(str(exc)) from exc` on stderr."""
    result = _s0("wipe", "--targets", str(REPO / "pyproject.toml"),
                 "--yes", "--no-pdf", "--no-certificate")
    assert "Traceback" not in result.stderr, result.stderr[-600:]
    assert result.returncode == 77, f"expected EX_NOPERM, got {result.returncode}"


def test_cli_still_erases_an_ordinary_file(tmp_path):
    victim = tmp_path / "evidence.txt"
    victim.write_text("to be erased")
    result = _s0("wipe", "--targets", str(victim), "--yes", "--no-pdf",
                 "--no-certificate", "--out-dir", str(tmp_path))
    assert result.returncode == 0, result.stderr[-500:]
    assert not victim.exists(), "an ordinary file must still be erased"


def test_cli_still_erases_an_ordinary_directory(tmp_path):
    folder = tmp_path / "case01"
    folder.mkdir()
    (folder / "a.txt").write_text("a")
    (folder / "b.txt").write_text("b")
    result = _s0("wipe", "--targets", str(folder), "--yes", "--no-pdf",
                 "--no-certificate", "--out-dir", str(tmp_path))
    assert result.returncode == 0, result.stderr[-500:]
    assert not (folder / "a.txt").exists()


def test_a_batch_with_one_protected_target_is_refused_whole(tmp_path):
    """Partially erasing a set the operator named is not a useful outcome."""
    good = tmp_path / "fine.txt"
    good.write_text("keep until the batch is allowed")
    protected = REPO / "README.md"
    result = _s0("wipe", "--targets", str(good), str(protected),
                 "--yes", "--no-pdf", "--no-certificate", "--out-dir", str(tmp_path))
    assert result.returncode != 0
    assert good.is_file(), (
        "the safe target must not be erased when a sibling in the same batch is "
        "refused -- that is a half-finished operation the operator did not ask for"
    )


def test_web_tier_uses_the_same_guard():
    """One set of rules. The two interfaces disagreed, which was the original bug."""
    app = (REPO / "src" / "s0" / "web" / "app.py").read_text(encoding="utf-8")
    assert "from s0.safety import" in app, (
        "the web tier must import the shared guard rather than keep its own "
        "_SYSTEM_PATHS copy, or they will drift again"
    )


def test_relative_paths_resolve_absolutely(tmp_path):
    """Running from a scratch directory must not change what is protected."""
    here = os.getcwd()
    try:
        os.chdir(tmp_path)
        (tmp_path / "evidence.txt").write_text("x")
        assert check_path_is_destructive("evidence.txt") == []
        with pytest.raises(ProtectedPathError):
            check_path_is_destructive("../../../../../etc/hostname")
    finally:
        os.chdir(here)


# --------------------------------------------------------------------------- #
# H1: `s0 web` must start from an installed package, not a source-tree path.
# --------------------------------------------------------------------------- #

def test_web_launcher_does_not_depend_on_a_source_tree_layout():
    """Regression: the launcher searched `<repo>/web/app.py`.

    Refactor 0dd50d9 moved the app to `s0/web/app.py`, so every candidate was gone
    and `s0 web` died with "Could not locate s0 Web Dashboard files (app.py)" while
    `uvicorn s0.web.app:app` worked. A pip-installed user has no `<repo>/web` at
    all, only site-packages, so path discovery could never have worked for them.
    """
    main = (REPO / "src" / "s0" / "cli" / "main.py").read_text(encoding="utf-8")
    body = main[main.index("def cmd_web("):]
    body = body[: body.index("\ndef ", 5)]

    # Check code, not prose: the old error string survives in the explanatory
    # comment describing the bug.
    code = "\n".join(line for line in body.splitlines() if not line.strip().startswith("#"))
    assert "Could not locate s0 Web Dashboard files" not in code, (
        "the filesystem search for <root>/web/app.py is back; resolve the module "
        "instead"
    )
    assert "/ \"web\"" not in code and "root / \"web\"" not in code, (
        "the launcher must not probe <root>/web on disk"
    )
    assert '"s0.web.app:app"' in body, "uvicorn must be pointed at the module path"
    assert 'find_spec("s0.web.app")' in body, (
        "the launcher must check the module is importable and, if not, say to "
        "install the web extra"
    )
    assert "cwd=str(web_dir)" not in body, (
        "uvicorn must not be pinned to a source directory; the app resolves its own "
        "package data"
    )


def test_web_app_module_is_importable():
    """The thing the launcher now depends on."""
    import importlib.util

    assert importlib.util.find_spec("s0.web.app") is not None


def test_web_app_resolves_its_own_package_data():
    """No dependence on cwd: the static dir must resolve from the package."""
    from s0.web import app

    assert app.STATIC_DIR.is_dir(), f"STATIC_DIR missing: {app.STATIC_DIR}"
    assert (app.STATIC_DIR / "index.html").is_file()
    assert app.PORTAL_DIR.is_dir(), f"PORTAL_DIR missing: {app.PORTAL_DIR}"
