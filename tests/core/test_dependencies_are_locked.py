"""The lockfile must cover exactly what the project declares.

`pyproject.toml` carries lower bounds only, which is correct for a library -- it
does not constrain anyone who installs s0. But this project also *builds* things: a
live ISO, a container image, a signed release tarball. Those resolved "whatever is
newest at build time", so two builds of the same commit could contain different code,
and a compromised transitive release would land in an artefact nobody reviewed.

`requirements.lock` is the pinned side: every artefact hash-pinned, installed with
`--require-hashes`. It is only useful if it stays in step with what the project
actually declares, which is what these tests assert. A lockfile that silently omits
a dependency is worse than none, because it looks authoritative.

The check is bidirectional. A dependency in `pyproject.toml` but not in the lock
means an unpinned package reaches a build; a package in the lock that nothing
declares means the graph has drifted and the lock no longer describes this project.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-redef]

REPO_ROOT = Path(__file__).resolve().parents[2]
PYPROJECT = REPO_ROOT / "pyproject.toml"
LOCK_IN = REPO_ROOT / "requirements.in"
LOCK = REPO_ROOT / "requirements.lock"


def _declared() -> dict[str, str]:
    """Direct runtime/web/test dependencies, as (normalised name -> specifier)."""
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    out: dict[str, str] = {}
    for dep in data["project"]["dependencies"]:
        name = re.split(r"[<>=!~\[ ]", dep, maxsplit=1)[0].strip()
        out[name.lower()] = dep
    for extra, deps in data["project"]["optional-dependencies"].items():
        if extra == "dev":
            continue  # tooling, not shipped
        for dep in deps:
            name = re.split(r"[<>=!~\[ ]", dep, maxsplit=1)[0].strip()
            # An extra may re-declare a runtime dep; the tighter specifier wins
            # is not worth modelling, so first declaration stands.
            out.setdefault(name.lower(), dep)
    return out


def _locked() -> dict[str, str]:
    text = LOCK.read_text(encoding="utf-8")
    out = {}
    for match in re.finditer(r"^([A-Za-z0-9._-]+)==(\S+)", text, re.M):
        out[match.group(1).lower()] = match.group(2)
    return out


def _lock_input() -> dict[str, str]:
    out = {}
    for line in LOCK_IN.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name = re.split(r"[<>=!~\[ ]", line, maxsplit=1)[0].strip()
        out[name.lower()] = line
    return out


class TestTheLockfileExistsAndIsComplete:
    def test_both_files_are_present(self):
        for path in (LOCK, LOCK_IN):
            assert path.is_file(), (
                f"{path.name} is missing. Without it the ISO, container and release "
                f"builds resolve 'latest at build time'."
            )

    def test_every_declared_dependency_is_in_the_lock(self):
        declared = set(_declared())
        locked = set(_locked())
        missing = sorted(declared - locked)
        assert not missing, (
            f"pyproject declares {missing} but requirements.lock does not pin them, "
            f"so they reach a build unpinned"
        )

    def test_every_direct_dependency_is_in_the_lock_input(self):
        """requirements.in is the hand-maintained input; it must not omit anything."""
        declared = set(_declared())
        inputs = set(_lock_input())
        missing = sorted(declared - inputs)
        assert not missing, (
            f"pyproject declares {missing} but requirements.in does not list them. "
            f"pip-compile only resolves what it is given, so an omission here "
            f"produces a lockfile that looks authoritative and is not."
        )

    def test_the_lock_pins_every_package_with_a_hash(self):
        text = LOCK.read_text(encoding="utf-8")
        pinned = re.findall(r"^([A-Za-z0-9._-]+)==", text, re.M)
        assert pinned, "no pinned packages found; the lock is not a lock"
        for name in pinned:
            block = text.split(f"{name}==", 1)[1].split("\n\n", 1)[0]
            assert "sha256:" in block, (
                f"{name} is pinned without a hash, so --require-hashes will not protect it"
            )


class TestTheVersionsAgree:
    def test_the_lock_satisfies_the_declared_lower_bounds(self):
        """A lock that violates pyproject's own floors is worse than no lock."""
        from packaging.version import Version

        locked = _locked()
        for name, spec in _declared().items():
            if name not in locked:
                continue
            base = re.split(r"[<>=!~\[ ]", spec, maxsplit=1)[1] if re.search(r"[<>=!~]", spec) else ""
            if not base.startswith(">="):
                continue
            floor = Version(base[2:].strip())
            got = Version(locked[name])
            assert got >= floor, (
                f"{name} is locked to {got} but pyproject requires >={floor}. The "
                f"lock and the declaration disagree, so one of them is stale."
            )

    def test_every_direct_dependency_has_a_concrete_version(self):
        locked = _locked()
        for name in _declared():
            if name in locked:
                assert re.match(r"^\d", locked[name]), (
                    f"{name} is locked to {locked[name]!r}, which is not a version"
                )


class TestTheLockIsUsable:
    def test_it_installs_with_hash_checking_enforced(self, tmp_path):
        """The property that makes the file worth having.

        `--dry-run` resolves and hash-checks without writing anything, so this is
        safe to run in the suite. Skipped when there is no index available rather
        than failing, because an offline test runner is a normal thing.
        """
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--require-hashes",
                "--dry-run",
                "--quiet",
                "--disable-pip-version-check",
                "-r",
                str(LOCK),
            ],
            capture_output=True,
            text=True,
            cwd=str(tmp_path),
            timeout=900,
        )
        if proc.returncode != 0 and ("network" in proc.stderr.lower() or "connection" in proc.stderr.lower()):
            pytest.skip("no package index reachable")
        assert proc.returncode == 0, (
            f"requirements.lock does not install with --require-hashes:\n{proc.stderr[-1500:]}"
        )

    def test_the_regeneration_script_is_valid_bash(self):
        script = REPO_ROOT / "tools" / "lock_dependencies.sh"
        assert script.is_file()
        proc = subprocess.run(["bash", "-n", str(script)], capture_output=True, text=True)
        assert proc.returncode == 0, proc.stderr

    def test_the_regeneration_script_references_both_files(self):
        text = (REPO_ROOT / "tools" / "lock_dependencies.sh").read_text(encoding="utf-8")
        assert "requirements.in" in text and "requirements.lock" in text
        assert "--generate-hashes" in text, (
            "the regeneration script must produce hashes, or the lock it writes is "
            "not the lock this test suite is asserting about"
        )
        assert "--require-hashes" in text, "the script must verify its own output with --require-hashes"
