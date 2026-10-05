"""The CI gates have to be gates.

A CI step that reports a problem without failing the job is worse than no step: it reads as
a check that passed. Every gate added here is asserted on two things -- that the step
exists, and that its failure actually propagates -- because "I added a check" and "the
check can fail" are different claims.

These are assertions about `.github/workflows/ci.yml` as text and as parsed YAML. They are
not a substitute for the workflow running, and they cannot verify that the GitHub
expression syntax is valid; `rhysd/actionlint` is already pinned in this repository for
that, and it is the tool that catches a malformed `if:` rather than a missing check.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"


@pytest.fixture(scope="module")
def ci() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def _steps(ci: dict, job: str) -> list[dict]:
    return ci["jobs"][job]["steps"]


def _find(ci: dict, job: str, needle: str) -> dict | None:
    for step in _steps(ci, job):
        blob = yaml.safe_dump(step)
        if needle in step.get("name", "") or needle in blob:
            return step
    return None


class TestTheProbedToolsAreInstalledSoSkipsCannotHideFailures:
    """A skip is a pass as far as CI is concerned.

    The suite skips whole groups of tests when `ffmpeg`, `zstd`, `mke2fs`, `mkfs.exfat` or
    `node` are absent. On a runner without them, a broken carve path or a broken portal
    crypto bundle is green. So the tools are installed, and their absence is a failure
    rather than a quiet skip.
    """

    @pytest.mark.parametrize("tool", ["ffmpeg", "zstd", "e2fsprogs", "exfatprogs"])
    def test_each_tool_is_installed(self, ci, tool):
        step = _find(ci, "test", "Install system tools")
        assert step is not None, "no step installs the tools the suite probes for"
        run = step["run"]
        assert tool in run, f"{tool} is probed for by tests but never installed"

    @pytest.mark.parametrize(
        "tool", ["ffmpeg", "zstd", "mke2fs", "debugfs", "mkfs.exfat", "node", "shellcheck"]
    )
    def test_a_missing_tool_fails_the_job(self, ci, tool):
        step = _find(ci, "test", "Fail if a probed tool is absent")
        assert step is not None, (
            "a missing tool is only reported, not failed on; that leaves the skip silent "
            "in exactly the case the install step was added to prevent"
        )
        run = step["run"]
        assert tool in run, f"{tool} is not in the fail-on-absence list"
        assert "exit 1" in run, "the step reports a missing tool without failing"

    def test_node_is_present_checked_rather_than_silently_absent(self, ci):
        """Node is the runner's, not a pinned action.

        This repository pins every action to a commit SHA, and inventing one is not an
        option: a wrong SHA is a workflow that fails on its first run. Asserting the
        tool is *present* gets the safety property without the fabricated pin.
        """
        report = _find(ci, "test", "Report which probed tools")
        assert report is not None and "node" in report["run"]
        # Check for a `uses:` line, not the bare string: the workflow deliberately *mentions*
        # setup-node in a comment explaining why it is not used, and matching the word
        # flagged that comment.
        uses_lines = [
            line
            for line in WORKFLOW.read_text(encoding="utf-8").splitlines()
            if "uses:" in line and "setup-node" in line
        ]
        assert not uses_lines, (
            f"setup-node is used without a verified commit SHA: {uses_lines}. Pin it to a "
            f"real commit, or drop the step and rely on the runner's Node."
        )


class TestCoverageHasAFloorAndItCanFail:
    @pytest.fixture(scope="class")
    def pytest_step(self, ci) -> dict:
        step = _find(ci, "test", "Pytest")
        assert step is not None, "there is no pytest step to measure coverage in"
        return step

    def test_coverage_is_actually_measured(self, pytest_step):
        assert "--cov=src/s0" in pytest_step["run"], (
            "coverage is not being measured, so a floor would be a number nobody computed"
        )

    def test_the_floor_is_enforced_by_the_run(self, pytest_step):
        assert "--cov-fail-under" in pytest_step["run"], (
            "coverage is reported but not gated; a drop below the floor would pass"
        )

    def test_the_floor_is_below_the_measured_number(self, pytest_step):
        """A floor at or above current coverage fails the moment a line is added.

        That is the wrong incentive -- it teaches people to raise the floor instead of
        write the test. The floor is a ratchet: it catches coverage *falling*.
        """
        import re

        match = re.search(r"--cov-fail-under=\$\{\{.*?'(\d+)'", pytest_step["run"])
        assert match, "the floor is not a literal number in a matrix expression"
        floor = int(match.group(1))
        assert 60 <= floor <= 75, (
            f"the coverage floor is {floor}%; measured coverage on this branch is 72%, so "
            f"a floor outside 60-75 is either already failing or too loose to notice a drop"
        )

    def test_a_failing_floor_is_reported_separately(self, ci):
        """So a green pytest with a failing floor cannot be misread as a pass."""
        step = _find(ci, "test", "Coverage floor is enforced")
        assert step is not None, (
            "the floor is only enforced through a pytest exit code; nothing surfaces it in the job summary"
        )
        assert "SystemExit" in step["run"] or "exit 1" in step["run"], (
            "the enforcement step does not fail on a low number"
        )


class TestEveryActionIsPinnedToACommit:
    """A tag is mutable; a commit is not.

    Separate from `test_workflow_actions_are_pinned.py` in intent: that file checks the
    repository's pinning convention, this records why it matters for the gates above --
    a gate that silently stops running because its action was re-pointed is not a gate.
    """

    def test_no_action_is_referenced_by_a_tag_or_branch(self, ci):
        import re

        offenders = []
        for job_name, job in ci["jobs"].items():
            for step in job.get("steps", []):
                uses = step.get("uses")
                if not uses or not uses.startswith("actions/"):
                    continue
                ref = uses.split("@", 1)[-1]
                if not re.fullmatch(r"[0-9a-f]{40}", ref):
                    offenders.append(f"{job_name}: {uses}")
        assert not offenders, f"actions referenced by something other than a commit SHA: {offenders}"
