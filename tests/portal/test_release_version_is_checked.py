"""A release tag has to match the version the code declares.

`release.yml` refused to publish when the changelog had no section for the tag. It did not
check the tag against the *code*, so this was publishable:

    git tag v3.0.0 && git push --tags

with `pyproject.toml` still at 2.4.4. The workflow builds, hashes, uploads and signs a wheel
that calls itself 2.4.4 and publishes it as 3.0.0. Everything downstream that trusts the
filename or the embedded version -- a lockfile pin, an ISO manifest, `pip install s0==3.0.0`
-- gets something that disagrees with itself, and an uploaded artefact cannot be corrected in
place.

These run the checker as a subprocess against real trees, including deliberately broken ones,
because the failure mode being guarded against is the checker silently passing.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CHECKER = REPO_ROOT / "tools" / "check_release_version.py"

SOURCES = ("pyproject.toml", "s0_config.json")


def _run(root: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(CHECKER), *args, "--root", str(root)],
        capture_output=True,
        text=True,
        timeout=120,
    )


@pytest.fixture
def tree(tmp_path) -> Path:
    """A copy of the real version declarations, so a test edit does not change the answer."""
    for name in SOURCES:
        shutil.copy(REPO_ROOT / name, tmp_path / name)
    (tmp_path / "src" / "s0").mkdir(parents=True)
    shutil.copy(REPO_ROOT / "src" / "s0" / "__init__.py", tmp_path / "src" / "s0" / "__init__.py")
    return tmp_path


def _current_version() -> str:
    proc = _run(REPO_ROOT)
    assert proc.returncode == 0, proc.stderr
    for line in proc.stdout.splitlines():
        if line.strip().startswith("pyproject.toml"):
            return line.split()[-1]
    raise AssertionError(f"could not read the version:\n{proc.stdout}")


class TestTheCurrentTreeIsConsistent:
    def test_the_repository_passes_with_no_tag(self):
        proc = _run(REPO_ROOT)
        assert proc.returncode == 0, proc.stderr
        assert "internally consistent" in proc.stdout

    def test_all_three_sources_are_reported(self):
        """Not two. An earlier version silently skipped the computed `__version__`."""
        proc = _run(REPO_ROOT)
        for name in ("pyproject.toml", "src/s0/__init__.py", "s0_config.json"):
            assert name in proc.stdout, f"{name} was not checked:\n{proc.stdout}"

    def test_the_matching_tag_is_accepted(self):
        version = _current_version()
        proc = _run(REPO_ROOT, f"v{version}")
        assert proc.returncode == 0, proc.stderr
        assert "matches the declared version" in proc.stdout


class TestAMismatchedTagIsRefused:
    def test_a_future_tag_is_refused(self):
        proc = _run(REPO_ROOT, "v99.0.0")
        assert proc.returncode == 1
        assert "would upload a wheel that reports itself as" in proc.stderr

    def test_the_refusal_says_the_tag_cannot_be_corrected_in_place(self):
        """The reason to fix it *before* pushing the tag, rather than after."""
        proc = _run(REPO_ROOT, "v99.0.0")
        assert "cannot be corrected in place" in proc.stderr

    def test_a_tag_without_the_v_prefix_is_still_matched(self):
        version = _current_version()
        proc = _run(REPO_ROOT, version)
        assert proc.returncode == 0, proc.stderr


class TestDisagreeingSourcesAreRefused:
    def test_a_config_that_disagrees_with_pyproject_is_refused(self, tree):
        path = tree / "s0_config.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["version"] = "9.9.9"
        path.write_text(json.dumps(data), encoding="utf-8")

        proc = _run(tree)
        assert proc.returncode == 1
        assert "disagree with each other" in proc.stderr

    def test_every_mismatch_is_reported_at_once(self, tree):
        """Not the first one. Finding them one at a time wastes a release attempt."""
        path = tree / "s0_config.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["version"] = "9.9.9"
        path.write_text(json.dumps(data), encoding="utf-8")

        proc = _run(tree)
        for name in ("pyproject.toml", "s0_config.json"):
            assert name in proc.stderr, f"{name} missing from the report:\n{proc.stderr}"


class TestTheReleaseWorkflowRunsItBeforeAnythingIsPublished:
    def test_the_gate_is_wired_into_release_yml(self):
        import yaml

        wf = yaml.safe_load((REPO_ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8"))
        steps = yaml.safe_dump(wf["jobs"]["publish"]["steps"])
        assert "check_release_version.py" in steps, (
            "the checker exists but the release workflow never runs it"
        )

    def test_it_runs_before_the_release_notes_are_extracted(self):
        """Fail before anything is built, hashed, uploaded or signed."""
        import yaml

        wf = yaml.safe_load((REPO_ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8"))
        steps = wf["jobs"]["publish"]["steps"]
        names = [s.get("name", "") for s in steps]
        version_at = next((i for i, n in enumerate(names) if "matches the version" in n), None)
        notes_at = next((i for i, n in enumerate(names) if "Release Notes" in n), None)
        assert version_at is not None and notes_at is not None
        assert version_at < notes_at, (
            f"the version check runs at step {version_at}, after release notes at "
            f"{notes_at}; it has to come first"
        )

    def test_a_weekly_schedule_exists_on_ci(self):
        """Most of what CI checks rots without a commit happening."""
        import yaml

        wf = yaml.safe_load((REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
        schedules = wf[True].get("schedule") or []
        assert schedules, (
            "CI only runs on push and pull_request, so pip-audit reports on a dependency "
            "set that may be weeks stale and nothing in the history shows when that began"
        )
