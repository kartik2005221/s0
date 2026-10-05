"""`s0 plan` must describe what `s0 wipe` will actually do.

For a regular file, `wipe --target` does one of two quite different destructive things:
keep the file and overwrite it in place, or erase it and unlink it. The route is decided by
`_looks_like_raw_image`, which tests content -- at least 1 MiB, 512-byte aligned, and
either a known image signature or a whole number of 1 MiB / 63-sector CD-track units. The
extension is not the test.

`plan` used to report "1-pass zero overwrite of <path>" for both, so an operator reading
the plan could not tell that the file they were about to name would be **deleted**:

    $ s0 plan --target s3.img     # 64 KiB of random bytes
      Target    /tmp/s3.img (image, IMAGE_FILE, 64.00 KiB)
      Summary   1-pass zero overwrite of /tmp/s3.img (image, IMAGE_FILE, 65,536 bytes)
    $ s0 wipe --target s3.img --yes
      -> the file does not exist afterwards

`s0 plan` exists so an operator can find that out without running the destructive command.
A plan that describes the wrong operation is worse than no plan.
"""

from __future__ import annotations

import os
import shutil
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


def _run(*args: str, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [_entry(), *args],
        capture_output=True,
        text=True,
        cwd=str(cwd),
        timeout=600,
        env={**os.environ, "HOME": str(cwd)},
    )


@pytest.fixture
def images(tmp_path):
    """The two ends of the heuristic, as measured."""
    small = tmp_path / "small.img"
    small.write_bytes(os.urandom(64 * 1024))
    one_mb = tmp_path / "one_mb.img"
    one_mb.write_bytes(os.urandom(1024 * 1024))
    two_mb = tmp_path / "two_mb.img"
    two_mb.write_bytes(os.urandom(2 * 1024 * 1024))
    return {"small": small, "one_mb": one_mb, "two_mb": two_mb}


class TestPlanSaysWhichFilesWillBeDeleted:
    @pytest.mark.parametrize("name,expected_kept", [("one_mb", True), ("two_mb", True)])
    def test_an_image_is_reported_as_kept(self, images, name, expected_kept):
        proc = _run("plan", "--target", str(images[name]), cwd=images[name].parent)
        combined = proc.stdout + proc.stderr
        assert "File outcome" in combined, f"plan says nothing about the file's fate:\n{combined[-500:]}"
        assert "kept - overwritten in place" in combined, combined[-600:]
        assert "will be deleted" not in combined

    def test_a_small_file_is_reported_as_deleted(self, images):
        proc = _run("plan", "--target", str(images["small"]), cwd=images["small"].parent)
        combined = proc.stdout + proc.stderr
        assert "ERASED AND REMOVED" in combined, (
            f"plan does not warn that this file will be deleted:\n{combined[-600:]}"
        )
        assert "the file will be deleted" in combined

    def test_the_reason_names_the_actual_test_that_fired(self, images):
        """Claiming a signature that is not there makes the explanation useless."""
        proc = _run("plan", "--target", str(images["two_mb"]), cwd=images["two_mb"].parent)
        combined = proc.stdout + proc.stderr
        assert "whole number of 1 MiB" in combined, (
            "random bytes of 2 MiB are recognised by size and alignment, not by any "
            f"image signature; the plan should say so:\n{combined[-600:]}"
        )

    def test_the_thresholds_are_stated(self, images):
        """The 1 MiB minimum is the whole reason for the surprise, so it is documented."""
        proc = _run("plan", "--target", str(images["small"]), cwd=images["small"].parent)
        combined = (proc.stdout + proc.stderr).lower()
        assert "1 mib" in combined, f"the 1 MiB minimum is not stated:\n{combined[-600:]}"
        assert "512-byte" in combined or "512 byte" in combined, combined[-600:]


class TestPlanAgreesWithWhatWipeActuallyDoes:
    """Run both, and compare the prediction against the outcome."""

    def test_a_file_predicted_deleted_is_deleted(self, images):
        target = images["small"]
        plan = _run("plan", "--target", str(target), cwd=target.parent)
        assert "will be deleted" in plan.stdout + plan.stderr, (
            "precondition: plan did not predict deletion, so this test proves nothing"
        )
        wipe = _run(
            "wipe", "--target", str(target), "--yes", "--no-pdf", "--no-certificate", cwd=target.parent
        )
        assert wipe.returncode == 0, wipe.stdout[-400:] + wipe.stderr[-400:]
        assert not target.exists(), "plan said the file would be deleted and it survived"

    def test_a_file_predicted_kept_is_kept(self, images):
        target = images["two_mb"]
        plan = _run("plan", "--target", str(target), cwd=target.parent)
        assert "kept - overwritten in place" in plan.stdout + plan.stderr, (
            "precondition: plan did not predict the file would be kept"
        )
        wipe = _run(
            "wipe", "--target", str(target), "--yes", "--no-pdf", "--no-certificate", cwd=target.parent
        )
        assert wipe.returncode == 0, wipe.stdout[-400:] + wipe.stderr[-400:]
        assert target.exists(), "plan said the file would be kept and it was removed"
        assert target.read_bytes() == b"\x00" * target.stat().st_size, "the file was kept but not overwritten"


class TestTheRuleIsDocumented:
    def test_the_cli_reference_states_the_keep_or_delete_rule(self):
        text = (REPO_ROOT / "docs" / "guides" / "cli-reference.md").read_text(encoding="utf-8")
        lowered = text.lower()
        assert "file outcome" in lowered, (
            "the CLI reference does not mention the File outcome line, so an operator "
            "reading the docs still does not know when a file is deleted"
        )
        for fact in ("1 mib", "512-byte", "unlink"):
            assert fact in lowered, f"the documented rule omits {fact!r}"

    def test_the_skill_tells_an_agent_to_plan_first(self):
        skill = REPO_ROOT / "skills" / "s0-forensics" / "SKILL.md"
        text = skill.read_text(encoding="utf-8")
        assert "s0 plan" in text, "the skill no longer mentions s0 plan at all"
        # An agent driving this needs to know a file target can be deleted.
        combined = (
            text
            + "\n"
            + "\n".join(
                p.read_text(encoding="utf-8") for p in sorted((skill.parent / "references").glob("*.md"))
            ).lower()
        )
        assert "plan" in combined
