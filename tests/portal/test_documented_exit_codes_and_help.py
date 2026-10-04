"""Documented contracts must match what the code does.

Three ways documentation goes stale here, all of them invisible until someone
follows the docs and it fails:

* **Exit codes.** The reference claimed a "consistent three-value exit code contract"
  and then listed thirteen codes, so a caller trusting the summary would trust the
  wrong thing. It also described `2` for a CLI that maps argparse's 2 to 64, and
  defined 77 as "insufficient privileges" while `image` uses it to mean "refused to
  overwrite".
* **Help screens.** Ten `--help` transcripts pasted by hand, every one missing the
  global output flags.
* **The batch-verify loop.** Grepped stdout for a status line, but text output goes
  to stderr -- so it printed FAILED for every valid certificate.

The exit-code table is now cross-checked against `s0.terminal` in both directions,
so a code that is neither documented nor real cannot survive.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
REFERENCE = REPO_ROOT / "docs" / "guides" / "cli-reference.md"
SKILL = REPO_ROOT / "skills" / "s0-forensics" / "SKILL.md"
README = REPO_ROOT / "README.md"

import s0.terminal as terminal

REAL_CODES = {v for k, v in vars(terminal).items() if k.startswith("EX_") and isinstance(v, int)}


def _documented_codes() -> set[int]:
    return {int(m) for m in re.findall(r"^\| `(\d+)`", REFERENCE.read_text(), re.M)}


class TestTheExitCodeTableIsTrue:
    def test_the_table_is_not_empty(self):
        assert _documented_codes(), "no exit codes parsed; the regex has drifted"

    def test_every_documented_code_is_a_real_one(self):
        bogus = sorted(_documented_codes() - REAL_CODES)
        assert not bogus, (
            f"the reference documents exit codes the CLI cannot return: {bogus}. Real: {sorted(REAL_CODES)}"
        )

    def test_every_real_code_is_documented(self):
        missing = sorted(REAL_CODES - _documented_codes())
        assert not missing, (
            f"the CLI can return {missing} but the reference does not list them, so "
            f"a caller handling documented codes would mishandle these"
        )

    def test_the_three_value_claim_is_gone(self):
        """It claimed three codes and then listed thirteen."""
        text = REFERENCE.read_text().lower()
        assert "three-value exit code contract" not in text, (
            "the reference still claims a three-value contract while listing thirteen codes"
        )

    def test_arparsers_exit_two_is_documented_as_sixty_four(self):
        assert "| `2` |" not in REFERENCE.read_text(), (
            "the table still lists exit code 2, which main() remaps to EX_USAGE (64)"
        )

    def test_seventy_seven_says_it_can_mean_refused(self):
        """`image` onto an existing destination exits 77; that is not a privilege."""
        row = next(line for line in REFERENCE.read_text().splitlines() if line.startswith("| `77` |"))
        assert "Refused" in row or "refused" in row, (
            f"77 is documented as insufficient privileges only, but it is also how "
            f"s0 says 'declined': {row.strip()}"
        )


class TestTheBatchVerifyExampleWorks:
    def test_no_documented_example_greps_stdout_for_text_output(self):
        """Text output is on stderr; stdout is empty. Grepping it always fails."""
        for path in REFERENCE.rglob("*.md"):
            for lineno, line in enumerate(path.read_text().splitlines(), 1):
                stripped = line.strip()
                if not stripped.startswith(("|", "`", "s0 ", "for ", "if ")):
                    continue
                if "| grep" not in stripped and "grep -" not in stripped:
                    continue
                # A pipeline that ends in grep must not be reading text output.
                assert "--json" in stripped or "--format" in stripped, (
                    f"{path.name}:{lineno} pipes s0 output into grep without "
                    f"--json or --format. Human-readable output goes to stderr and "
                    f"stdout is empty, so the grep cannot match: {stripped}"
                )

    def test_the_replacement_example_gates_on_the_exit_code(self):
        text = REFERENCE.read_text()
        assert "s0 verify" in text
        assert "--quiet" in text and ">/dev/null" in text, (
            "the batch-verify example should gate on the exit code with output "
            "suppressed, which is the only machine contract"
        )


class TestHelpScreensAreGenerated:
    def test_the_generator_agrees_with_the_file(self):
        proc = subprocess.run(
            [sys.executable, str(REPO_ROOT / "tools" / "gen_help_reference.py"), "--check"],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
            timeout=300,
        )
        assert proc.returncode == 0, (
            f"the Help Screen blocks are stale:\n{proc.stdout[-500:]}{proc.stderr[-800:]}"
        )

    def test_every_block_carries_the_global_output_flags(self):
        text = REFERENCE.read_text()
        blocks = re.findall(r'\{% tab title="Help Screen" %\}\n\n```\n(.*?)```', text, re.S)
        assert len(blocks) >= 10, f"only {len(blocks)} help blocks found"
        for block in blocks:
            assert "--format" in block, (
                "a pasted help screen is missing the global output flags:\n"
                f"{block.splitlines()[0] if block else '(empty)'}"
            )

    def test_the_generator_is_wired_into_ci(self):
        ci = (REPO_ROOT / ".github/workflows/ci.yml").read_text()
        assert "gen_help_reference.py --check" in ci, (
            "the generator exists but nothing runs it, so the blocks will drift again"
        )


class TestReadmeClaimsMatchTheRepo:
    def test_no_claim_of_a_file_that_is_not_committed(self):
        text = README.read_text()
        # Markdown links only. A prose mention explaining that the path is *not*
        # committed is the opposite of a broken claim, and matching backticks would
        # flag this test's own documentation of the fix.
        for target in re.findall(r"\]\((\.agents/[^)]+)\)", text):
            assert (REPO_ROOT / target).exists(), (
                f"the README links `{target}`, which is absent from a fresh clone"
            )

    def test_the_nist_revision_is_consistent(self):
        """The badge said Rev.1 while the text and compliance docs say Rev.2."""
        text = README.read_text()
        # Separator-agnostic: shields.io badges encode spaces as _ or -.
        badge = re.search(r"800[-_]{2}88[-_]Rev\.?(\d)", text)
        assert badge, "could not find the revision in the compliance badge"
        assert badge.group(1) == "2", (
            f"the badge claims Rev.{badge.group(1)} while docs/compliance and the body text are Rev.2"
        )

    def test_the_tagline_makes_no_capability_count_claim(self):
        """It said "Five forensic capabilities" beside "three core modules".

        Those counted different things, which is the problem: a reader has no way to
        reconcile them. The tagline now names the capabilities instead of counting
        them. "three core modules" further down is a *module* count and is accurate --
        the module list follows it -- so it is not what this asserts.
        """
        text = README.read_text()
        assert "Five forensic capabilities" not in text, (
            "the tagline promises a count the body does not use; name the "
            "capabilities instead of counting them differently elsewhere"
        )
        tagline = next(line for line in text.splitlines() if line.startswith("*One unified toolchain"))
        assert not re.search(r"\b(One|Two|Three|Four|Five|Six|Seven)\b.*capabilit", tagline, re.I), (
            f"the tagline still counts capabilities: {tagline.strip()}"
        )


class TestTheSkillQuotesRealOutput:
    def test_the_system_path_refusal_row_is_accurate(self):
        """It claimed exit 2 and a `REFUSED:` prefix; the CLI gives 77 and `error:`."""
        text = SKILL.read_text()
        row = next(
            (
                line
                for line in text.splitlines()
                if "Refusing to target system path" in line and line.startswith("|")
            ),
            "",
        )
        assert row, "the refusal row has disappeared"
        assert "77" in row, f"the row does not say the real exit code: {row}"
        assert "REFUSED:" not in row, (
            "the row quotes a `REFUSED:` prefix the CLI does not print; it prints `error:`"
        )

    def test_the_skill_does_not_recommend_sudo_for_the_web_dashboard(self):
        assert "sudo s0 web" not in SKILL.read_text(), (
            "the skill recommends running a destructive dashboard API as root"
        )

    def test_the_skill_names_the_flags_a_safety_skill_must_name(self):
        text = SKILL.read_text()
        for flag in ("--no-certificate", "--purge-all", "--keep-audit", "--force"):
            assert flag in text, (
                f"the skill never mentions {flag}. An agent that does not know a flag "
                f"exists will invent a workflow to avoid it."
            )

    def test_the_skill_documents_the_web_api(self):
        text = SKILL.read_text()
        assert "/api/erase-files" in text, (
            "the skill mentions `s0 web` but gives an agent nothing to use: no token flow, no route list"
        )
        assert "X-S0-Auth-Token" in text, "the skill does not say how to authenticate to the web API"

    def test_evals_cover_refusal_dry_run_and_web(self):
        import json

        data = json.loads((REPO_ROOT / "skills/s0-forensics/evals/evals.json").read_text())
        evals = data if isinstance(data, list) else data["evals"]
        prompts = " ".join(e["prompt"] + e["expected_output"] for e in evals)
        assert len(evals) >= 8, f"only {len(evals)} evals"
        for topic, needle in (
            ("refusal", "/etc/passwd"),
            ("dry run", "--dry-run"),
            ("audit", "audit verify"),
            ("web", "/api/"),
        ):
            assert needle in prompts, f"no eval covers {topic}"


class TestTheEnvelopeIsActuallyPopulated:
    """The envelope advertised four invocation fields that were always empty.

    `invocation.args` was `{}` and `started_at`, `finished_at` and
    `duration_seconds` were `null` on every command. A field every call site has to
    remember is a field none of them remember, and a schema that promises something
    the tool never emits is worse than no schema.
    """

    def _envelope(self, tmp_path, *args):
        import json
        import shutil as sh
        import subprocess as sp

        entry = sh.which("s0") or str(Path(sys.executable).parent / "s0")
        if not Path(entry).is_file():
            pytest.skip("s0 entry point not available")
        proc = sp.run(
            [entry, *args, "--json"],
            capture_output=True,
            text=True,
            cwd=str(tmp_path),
            timeout=180,
            env={"HOME": str(tmp_path), "PATH": "/usr/bin:/bin"},
        )
        if not proc.stdout.strip():
            pytest.skip(f"no JSON on stdout: {proc.stderr[-200:]}")
        return json.loads(proc.stdout)

    def test_timestamps_are_present(self, tmp_path):
        invocation = self._envelope(tmp_path, "list")["invocation"]
        assert invocation["started_at"], "started_at was null"
        assert invocation["finished_at"], "finished_at was null"
        assert invocation["duration_seconds"] is not None, "duration_seconds was null"

    def test_timestamps_are_rfc3339_with_a_z_suffix(self, tmp_path):
        import re

        invocation = self._envelope(tmp_path, "list")["invocation"]
        pattern = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
        for field in ("started_at", "finished_at"):
            assert pattern.match(invocation[field]), (
                f"{field} is {invocation[field]!r}; canonical JSON requires RFC 3339 UTC with a Z suffix"
            )

    def test_finished_is_not_before_started(self, tmp_path):
        invocation = self._envelope(tmp_path, "list")["invocation"]
        assert invocation["finished_at"] >= invocation["started_at"]

    def test_args_records_the_flags_used(self, tmp_path):
        invocation = self._envelope(tmp_path, "list")["invocation"]
        assert invocation["args"], (
            "invocation.args is still {}; the envelope cannot be correlated with what was run"
        )

    def test_a_key_value_never_reaches_the_envelope(self):
        """stdout is the envelope, so a key path in it is a leak."""
        import json

        from s0.cli.ui import _redact_argv

        recorded = _redact_argv(["--json", "--key", "/secret/issuer.pem", "--limit", "5", "cert.json"])
        serialised = json.dumps(recorded)
        assert "/secret/issuer.pem" not in serialised, (
            f"the --key value leaked into the envelope: {serialised}"
        )
        assert recorded["--key"] == "<redacted>"
        # The flag is still recorded, so the envelope says what was attempted.
        assert "--key" in recorded

    def test_a_redacted_value_does_not_become_a_key(self):
        """`{"/secret/issuer.pem": "<redacted>"}` puts the value in the key slot."""
        from s0.cli.ui import _redact_argv

        assert "/secret/issuer.pem" not in _redact_argv(["--key", "/secret/issuer.pem"])

    @pytest.mark.parametrize("flag", ["--key", "--signing-key", "--key-path", "--token", "--auth-token"])
    def test_every_secret_bearing_flag_is_redacted(self, flag):
        from s0.cli.ui import _redact_argv

        recorded = _redact_argv([flag, "s3cret-value"])
        assert "s3cret-value" not in str(recorded)


class TestDetectionWarningsReachTheEnvelope:
    def test_a_warning_is_not_only_logged(self):
        """`s0 list --json` said warnings:[] while stderr complained three times."""
        from s0.cli import devices

        assert hasattr(devices, "drain_detection_warnings"), (
            "detection warnings are not collected for the machine-readable output"
        )

    def test_draining_empties_the_queue(self):
        from s0.cli.devices import _DETECTION_WARNINGS, drain_detection_warnings

        _DETECTION_WARNINGS.append("synthetic")
        try:
            assert "synthetic" in drain_detection_warnings()
            assert drain_detection_warnings() == [], "warnings repeated on the next command"
        finally:
            _DETECTION_WARNINGS.clear()
