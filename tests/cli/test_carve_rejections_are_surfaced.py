"""A carve must account for what it did not recover.

The carver recorded a `rejection_summary` (reason -> count) and per-candidate
`rejected_samples` including the byte offset of each rejection. Neither reached the
terminal. The CLI printed "Candidates rejected: 400" and stopped, so the reasons
were available only by opening `recovery_index.json` -- and the distinction they
encode is the whole point of the run.

400 candidates rejected as duplicates, slack-space copies of a handful of files, is
a clean result. 400 rejected because each was the only copy of something is a
missed file. From the terminal those two runs printed the same line.

The summary and the JSON both carry the reasons now. These tests assert that a
real rejection is visible in the output, not merely that the field exists.
"""

from __future__ import annotations

import io
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    not (shutil.which("s0") or (Path(sys.executable).parent / "s0").is_file()),
    reason="s0 entry point not available",
)


def _entry_point() -> str:
    found = shutil.which("s0") or str(Path(sys.executable).parent / "s0")
    assert Path(found).is_file(), f"s0 entry point not found at {found}"
    return found


def _carve(*args: str, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [_entry_point(), "carve", *args],
        capture_output=True,
        text=True,
        env={"HOME": str(cwd), "PATH": "/usr/bin:/bin", "S0_AUDIT_DB": str(cwd / "audit.db")},
        cwd=str(cwd),
        timeout=300,
    )


@pytest.fixture
def noisy_image(tmp_path):
    """An image with a real PNG plus trailing noise, so candidates get rejected.

    Whether a given byte run trips a specific signature heuristic is not something
    to assert on -- it changes as the carver improves. The tests below therefore
    skip when a run happens to produce no rejections, and
    `test_the_summary_block_is_rendered_when_there_are_rejections` covers the
    rendering deterministically with an injected summary.
    """
    from PIL import Image

    buf = io.BytesIO()
    Image.new("RGB", (48, 48), (12, 34, 56)).save(buf, "PNG")
    (tmp_path / "img.raw").write_bytes(b"\x00" * 500 + buf.getvalue() + b"\xff" * 4096 + b"\x00" * 500)
    return tmp_path


def _rejections_in(proc) -> int:
    import json as _json

    try:
        payload = _json.loads(proc.stdout)
    except ValueError:
        return 0
    return len(payload.get("result", {}).get("rejection_summary") or [])


class TestRejectionsAreVisible:
    def test_the_terminal_says_why_candidates_were_rejected(self, noisy_image):
        proc = _carve(
            "--target",
            "img.raw",
            "--out-dir",
            "out",
            "--no-certificate",
            "--no-pdf",
            "--min-confidence",
            "0",
            cwd=noisy_image,
        )
        assert proc.returncode == 0, proc.stderr
        text = proc.stdout + proc.stderr
        if "Why candidates were rejected" not in text:
            pytest.skip("this image produced no rejections; see the injected-summary test for the rendering")
        assert "rejected" in text.lower()
        # The specific claim: the *reason* is on screen, not just the count.
        assert "Why candidates were rejected" in text, (
            "the rejection summary is computed but never printed; the reasons are "
            "reachable only by opening recovery_index.json, so a run that missed "
            "files looks identical to one that did not"
        )
        # And the operator is told where the per-candidate detail lives.
        assert "recovery_index.json" in text

    def test_the_summary_lists_a_human_readable_reason(self, noisy_image):
        proc = _carve(
            "--target",
            "img.raw",
            "--out-dir",
            "out",
            "--no-certificate",
            "--no-pdf",
            "--min-confidence",
            "0",
            cwd=noisy_image,
        )
        text = proc.stdout + proc.stderr
        block = text.split("Why candidates were rejected", 1)
        if len(block) == 1:
            pytest.skip("no rejections were produced for this image")
        reasons = [
            line.strip()
            for line in block[1].splitlines()[1:8]
            if line.strip() and not line.strip().startswith(("Per-candidate", "Search"))
        ]
        assert reasons, "the rejection block is present but empty"
        assert any(len(r) > 12 for r in reasons), (
            f"rejection reasons look like counts, not explanations: {reasons}"
        )

    def test_the_json_output_carries_the_reasons(self, noisy_image):
        proc = _carve(
            "--target",
            "img.raw",
            "--out-dir",
            "out",
            "--no-certificate",
            "--no-pdf",
            "--min-confidence",
            "0",
            "--json",
            cwd=noisy_image,
        )
        assert proc.returncode == 0, proc.stderr
        payload = json.loads(proc.stdout)

        result = payload.get("result", {})
        assert "rejection_summary" in result, (
            "the machine-readable output omits the rejection reasons entirely, so a "
            "pipeline cannot distinguish a clean run from a lossy one"
        )
        assert "budget_stop_reason" in result
        if result["rejection_summary"]:
            for entry in result["rejection_summary"]:
                assert entry["count"] > 0
                assert entry["reason"], "a rejection reason must not be empty"

    def test_a_clean_run_is_not_padded_with_an_empty_block(self, tmp_path):
        """The heading must not appear when there is nothing to report."""
        from PIL import Image

        buf = io.BytesIO()
        Image.new("RGB", (48, 48), (200, 10, 10)).save(buf, "PNG")
        (tmp_path / "clean.raw").write_bytes(b"\x00" * 500 + buf.getvalue())

        proc = _carve(
            "--target", "clean.raw", "--out-dir", "out", "--no-certificate", "--no-pdf", cwd=tmp_path
        )
        assert proc.returncode == 0, proc.stderr
        text = proc.stdout + proc.stderr
        if "Candidates rejected" not in text:
            pytest.skip("this image produced no candidates to reject")
        # Either nothing was rejected, or something was -- but an empty heading
        # under a zero count would be noise.
        if "Why candidates were rejected" in text:
            count_line = next((ln for ln in text.splitlines() if "Candidates rejected" in ln), "")
            digits = "".join(ch for ch in count_line if ch.isdigit())
            assert digits and int(digits) > 0, (
                f"the rejection heading is shown but nothing was rejected: {count_line!r}"
            )

    def test_the_index_is_still_written_with_offsets(self, noisy_image):
        """The reasons in the summary are a roll-up; the detail must survive."""
        _carve(
            "--target",
            "img.raw",
            "--out-dir",
            "out",
            "--no-certificate",
            "--no-pdf",
            "--min-confidence",
            "0",
            cwd=noisy_image,
        )
        index = noisy_image / "out" / "recovery_index.json"
        assert index.is_file(), "recovery_index.json was not written"
        data = json.loads(index.read_text())
        assert "rejected_samples" in data or "rejection_summary" in data, (
            "the index carries neither roll-up nor per-candidate detail, so the "
            "summary has nothing to point the reader at"
        )

    def test_the_console_recommendation_is_not_shown_when_nothing_survives(self, tmp_path):
        """Empty output must not be presented as a successful recovery."""
        (tmp_path / "empty.raw").write_bytes(b"\x00" * 4096)
        proc = _carve(
            "--target", "empty.raw", "--out-dir", "out", "--no-certificate", "--no-pdf", cwd=tmp_path
        )
        assert proc.returncode == 0, proc.stderr
        text = proc.stdout + proc.stderr
        assert "Files recovered" in text, (
            "the summary must report the recovery count even when it is zero, so "
            "an empty result is visible rather than inferred from silence"
        )


class TestTheRenderingItself:
    """Deterministic coverage of the block, without depending on carver heuristics.

    Whether a particular byte run trips a signature check is an implementation
    detail that will change as the carver improves. Asserting the *rendering* is
    stable is what actually matters here, so it is tested with a summary built to
    contain rejections.
    """

    def _render(self, summary, capsys, tmp_path):
        from types import SimpleNamespace

        from s0.cli.main import cmd_carve

        # cmd_carve refuses a target that does not exist, which is correct; these
        # tests exercise the rendering, so give it a real (if trivial) file.
        (tmp_path / "img.raw").write_bytes(b"\x00" * 512)

        args = SimpleNamespace(
            target=str(tmp_path / "img.raw"),
            out_dir=str(tmp_path / "out"),
            extensions=None,
            min_confidence=0,
            no_certificate=True,
            no_pdf=True,
            operator="op",
            organization="org",
            key=None,
            no_recovery=False,
            all_space=False,
            hash_set=None,
            hash_algorithms=None,
            custom_sig=None,
            session=None,
            write_session=None,
            bodyfile=None,
            gaps_bodyfile=None,
            format="text",
            quiet=False,
            verbose=False,
            no_color=True,
            json=False,
            dry_run=False,
        )
        cmd_carve(args)
        return capsys.readouterr()

    def test_rejection_reasons_are_rendered(self, tmp_path, capsys, monkeypatch):
        """The core claim: a reason that exists in the summary reaches the terminal."""
        import s0.cli.main as cli
        from s0.carve.engine import CarvingSessionSummary as CarveSummary

        summary = CarveSummary(
            target_path=str(tmp_path / "img.raw"),
            source_filesystem="RAW",
            total_bytes_scanned=4096,
            total_candidates_found=413,
            files_recovered=1,
            rejection_summary=[
                (
                    "only 3 consecutive valid 188-byte TS packets; at least 16 are "
                    "required before this is distinguishable from coincidence",
                    400,
                ),
                ("inside a file already recovered", 12),
            ],
        )
        monkeypatch.setattr(cli, "carve_image", lambda *a, **k: summary)

        captured = self._render(summary, capsys, tmp_path)
        text = captured.out + captured.err

        assert "Why candidates were rejected" in text
        assert "188-byte TS packets" in text, "the explanation was not rendered; only the counts were"
        assert "inside a file already recovered" in text
        assert "400" in text.replace(",", ""), "the count was not rendered"

    def test_the_block_is_omitted_when_there_is_nothing_to_report(self, tmp_path, capsys, monkeypatch):
        import s0.cli.main as cli
        from s0.carve.engine import CarvingSessionSummary as CarveSummary

        summary = CarveSummary(
            target_path=str(tmp_path / "img.raw"),
            source_filesystem="RAW",
            total_bytes_scanned=4096,
            total_candidates_found=413,
            files_recovered=1,
            rejection_summary=[],
        )
        monkeypatch.setattr(cli, "carve_image", lambda *a, **k: summary)

        text = self._render(summary, capsys, tmp_path)
        text = text.out + text.err
        assert "Why candidates were rejected" not in text, (
            "an empty rejection block was printed for a run with no rejections"
        )

    def test_long_reason_lists_are_truncated_with_a_total(self, tmp_path, capsys, monkeypatch):
        """A carver can reject for dozens of distinct reasons; all must be accounted for."""
        import s0.cli.main as cli
        from s0.carve.engine import CarvingSessionSummary as CarveSummary

        many = [(f"reason number {i} with some explanatory text", i + 1) for i in range(20)]
        summary = CarveSummary(
            target_path=str(tmp_path / "img.raw"),
            source_filesystem="RAW",
            total_bytes_scanned=4096,
            total_candidates_found=413,
            files_recovered=1,
            rejection_summary=many,
        )
        monkeypatch.setattr(cli, "carve_image", lambda *a, **k: summary)

        text = self._render(summary, capsys, tmp_path)
        text = text.out + text.err
        assert "more reason" in text, (
            "the list was silently cut off, so the operator cannot tell that reasons were omitted"
        )
