"""The output contract must be documented as it actually behaves.

`--format` was documented as: *"'text' degrades to one record per line when stdout
is not a terminal."* That was never implemented. `s0 list > out.txt` produced an
empty file, and `s0 list --format text | grep foo` found nothing, because the human
table goes to stderr.

The behaviour underneath is deliberate and tested: stdout is reserved for
machine-readable output and stderr for humans. `test_text_mode_writes_tables_to_stderr`
and `test_every_command_emits_a_clean_envelope` both depend on it -- the second
requires that *anything* appearing on stdout parses as the JSON envelope, so a
records-on-stdout text mode would contradict it.

So the defect was in the promise, not the implementation, and these tests pin the
promise to the behaviour. Implementing the documented behaviour instead would have
meant the same flag producing two different formats depending on whether a terminal
was attached: working interactively, silently different in a pipeline.

Two things are asserted. That the documentation matches the implementation, and that
the contract still holds -- so neither side can drift alone.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
UI_PY = REPO_ROOT / "src" / "s0" / "cli" / "ui.py"
CLI_REFERENCE = REPO_ROOT / "docs" / "guides" / "cli-reference.md"

#: Wording that described the behaviour which was never built. If any of these come
#: back, the false promise is back with them.
DEAD_PROMISES = (
    "degrades to one record per line",
    "one record per line when stdout is not a terminal",
)


class TestTheFalsePromiseIsGone:
    @pytest.mark.parametrize("path", [UI_PY, CLI_REFERENCE])
    def test_no_file_still_promises_records_on_stdout(self, path):
        text = path.read_text(encoding="utf-8").lower()
        for phrase in DEAD_PROMISES:
            assert phrase not in text, (
                f"{path.relative_to(REPO_ROOT)} promises {phrase!r}, which was never "
                f"implemented. Either implement it or document the real contract.")

    def test_the_format_flag_says_where_output_goes(self):
        text = UI_PY.read_text(encoding="utf-8")
        assert "stderr" in text, (
            "the --format help does not say that text output goes to stderr, which "
            "is the single most surprising thing about the tool for a new user")

    def test_the_reference_doc_explains_the_contract(self):
        text = CLI_REFERENCE.read_text(encoding="utf-8")
        assert "stdout is for machines" in text.lower() or (
            "stdout" in text and "stderr" in text and "empty" in text), (
            "the CLI reference does not state the stdout/stderr contract, so a "
            "reader has to discover it by redirection")

    def test_the_reference_shows_the_redirect_that_works(self):
        """Someone who arrived from the old promise needs the replacement."""
        text = CLI_REFERENCE.read_text(encoding="utf-8")
        assert "--format csv" in text, (
            "the reference does not show the command that actually produces "
            "redirectable output")


class TestTheContractStillHolds:
    """The behaviour the corrected documentation now describes."""

    @pytest.fixture
    def run(self, tmp_path):
        entry = shutil.which("s0") or str(Path(sys.executable).parent / "s0")
        if not Path(entry).is_file():
            pytest.skip("s0 entry point not available")

        def _run(*args: str):
            return subprocess.run(
                [entry, *args], capture_output=True, text=True,
                env={"HOME": str(tmp_path), "PATH": "/usr/bin:/bin",
                     "S0_AUDIT_DB": str(tmp_path / "audit.db")},
                cwd=str(tmp_path), timeout=180)

        return _run

    def test_text_writes_the_table_to_stderr_and_nothing_to_stdout(self, run):
        proc = run("list")
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout == "", (
            "text mode wrote to stdout; the documented contract says stdout stays "
            "empty so that stdout is reserved for machine-readable output")
        assert proc.stderr.strip(), "text mode produced no human output either"

    def test_json_writes_a_parseable_envelope_to_stdout(self, run):
        proc = run("list", "--json")
        assert proc.returncode == 0, proc.stderr
        payload = json.loads(proc.stdout)
        assert payload["schema"].startswith("s0.")
        assert payload["status"] in ("success", "failure", "partial", "aborted", "refused")

    def test_csv_writes_rows_to_stdout(self, run):
        proc = run("list", "--format", "csv")
        assert proc.returncode == 0, proc.stderr
        lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
        assert lines, "csv mode wrote nothing to stdout"
        assert lines[0].startswith("path,"), f"unexpected csv header: {lines[0]!r}"

    def test_redirecting_text_mode_produces_an_empty_file(self, tmp_path):
        """The exact surprise the old documentation set up.

        Asserted rather than avoided: it is the behaviour an operator needs to
        recognise, and the documentation now explains it. If this ever starts
        producing records, the contract has changed and both the docs and this test
        need updating together.
        """
        entry = shutil.which("s0") or str(Path(sys.executable).parent / "s0")
        if not Path(entry).is_file():
            pytest.skip("s0 entry point not available")
        out_file = tmp_path / "devices.txt"
        with open(out_file, "w") as fh:
            subprocess.run(
                [entry, "list"], stdout=fh, stderr=subprocess.PIPE, text=True,
                env={"HOME": str(tmp_path), "PATH": "/usr/bin:/bin",
                     "S0_AUDIT_DB": str(tmp_path / "audit.db")},
                cwd=str(tmp_path), timeout=180, check=True)
        assert out_file.read_text() == "", (
            "text mode wrote to a redirected stdout. If this is intended, the "
            "documented contract is wrong and must be corrected; if not, the "
            "machine/human stream split has been broken.")

    @pytest.mark.parametrize("argv", [["list"], ["list", "--json"],
                                      ["list", "--format", "csv"]])
    def test_no_format_ever_mixes_streams(self, run, argv):
        """Nothing may appear on stdout that is not the requested format.

        This is the invariant the envelope test depends on, and it is what makes
        `s0 <cmd> --json | jq` safe even when the command fails.
        """
        proc = run(*argv)
        if "--format" in " ".join(argv) or "--json" in argv:
            assert proc.stdout.strip(), "a machine format produced no stdout"
            json.loads(proc.stdout) if "--json" in argv else None
        else:
            assert proc.stdout == ""
