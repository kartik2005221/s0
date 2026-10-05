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

import inspect
import os
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


#: Exit code 2 has no `EX_` constant: `s0.terminal` defines `EX_USAGE` as 64, so
#: argparse's own 2 is remapped and 2 is left to whatever s0's internal guards return.
#: It is reachable -- `wipe` returns it for a mounted-filesystem refusal and an
#: out-of-range `--passes`, `live` for a missing ISO -- and a caller handling only
#: named codes would mishandle it. Documented separately in the exit-code table.
UNNAMED_BUT_REACHABLE = {2}


def _documented_codes() -> set[int]:
    return {int(m) for m in re.findall(r"^\| `(\d+)`", REFERENCE.read_text(), re.M)}


def _all_known_codes() -> set[int]:
    return REAL_CODES | UNNAMED_BUT_REACHABLE


#: Writes one real, demo-signed block into $S0_AUDIT_DB using the repo's own APIs, so
#: the audit test drives real code rather than a hand-built SQLite row.
SIGN_ONE_LEDGER_BLOCK = """
import os
from pathlib import Path
from s0.audit.db import init_audit_db, record_audit_event
from s0.certificate import build_certificate, sign_certificate
from s0.crypto import load_private_pem

repo = Path(os.environ["S0_REPO"])
db = Path(os.environ["S0_AUDIT_DB"])
init_audit_db(db)
priv = load_private_pem(repo / "src/s0/data/keys/demo_issuer_private.pem")
cert = build_certificate(
    organization="Acme", operator_id="op-test", tool_name="s0",
    tool_version="2.4.4", platform="linux", device_id="sha256:deadbeef",
    device_type="removable_disk", storage_type="HDD",
    method="OVERWRITE_ZERO_1PASS", nist_category="Clear",
    start_time="2026-01-01T00:00:00Z", end_time="2026-01-01T00:01:00Z",
    bytes_processed=4096, capacity_bytes=8192,
)
record_audit_event(sign_certificate(cert, priv), operation_type="DRIVE_ERASE", db_path=db)
"""


class TestTheExitCodeTableIsTrue:
    def test_the_table_is_not_empty(self):
        assert _documented_codes(), "no exit codes parsed; the regex has drifted"

    def test_every_documented_code_is_a_real_one(self):
        bogus = sorted(_documented_codes() - _all_known_codes())
        assert not bogus, (
            f"the reference documents exit codes the CLI cannot return: {bogus}. "
            f"Real: {sorted(_all_known_codes())}"
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

    def test_exit_two_is_documented_as_a_refusal_not_a_usage_error(self):
        """`main()` remaps *argparse's* 2 to 64, but s0's own guards return 2.

        The old assertion was `"| `2` |" not in the reference`, on the reasoning that
        argparse's 2 is remapped. That conflated two different meanings of the number:
        `wipe` returns 2 for a mounted-filesystem refusal and for an out-of-range
        `--passes`, and `live` returns 2 for a missing ISO. Those are not usage
        errors, and leaving them undocumented means a caller who handles the named
        codes has no branch for them.

        So 2 is now documented, and the row must not describe it as bad flags -- that
        is 64, and conflating them is how a caller treats a refusal as a typo.
        """
        row = next(
            (line for line in REFERENCE.read_text().splitlines() if line.startswith("| `2` |")),
            "",
        )
        assert row, "exit code 2 is reachable but undocumented"
        assert "64" in row, (
            f"the row for 2 must say it is NOT argparse's usage error, which is 64: {row.strip()}"
        )
        assert "Bad flags" not in row and "bad flags" not in row, (
            f"the row for 2 describes it as bad flags, which is 64's meaning: {row.strip()}"
        )

    def test_an_untrusted_audit_key_exits_one_not_sixty_five(self):
        """The 65 row claimed `audit verify` returns 65 when it cannot attribute a block.

        Driven through the real command rather than by reading the source, because
        `cmd_audit` does return `EX_DATAERR` for two unrelated cases (an unreadable
        `--key`, an implausibly large ledger) -- so grepping the function would prove
        nothing about the path in question.

        The trust set is a directory holding a valid key that did not sign the ledger,
        so the chain's hashes verify and the attribution step is what fails.
        """
        import pathlib as _pl
        import shutil as _shutil
        import subprocess as _sp
        import sys as _sys
        import tempfile as _tf

        entry = _shutil.which("s0") or str(_pl.Path(_sys.executable).parent / "s0")
        if not _pl.Path(entry).is_file():
            pytest.skip("s0 entry point not available")

        with _tf.TemporaryDirectory() as tmp:
            root = _pl.Path(tmp)
            # A *populated* directory holding a key that did not sign the ledger.
            # An empty directory is rejected earlier with exit 66 ("no *.pem found"),
            # which is a different question: it never reaches the attribution check.
            env = {
                **os.environ,
                "HOME": str(root),
                "S0_AUDIT_DB": str(root / "audit.db"),
                "S0_REPO": str(REPO_ROOT),
                "PYTHONPATH": str(REPO_ROOT / "src"),
            }
            other_keys = root / "other-keys"
            other_keys.mkdir()
            generated = _sp.run(
                [entry, "keygen", "--out-dir", str(other_keys), "--name", "other"],
                capture_output=True,
                text=True,
                cwd=str(REPO_ROOT),
                env=env,
                timeout=180,
            )
            assert generated.returncode == 0, f"keygen failed: {generated.stderr[-300:]}"
            # Keep only the public half: a trust directory is globbed for *.pem, and
            # handing it the private key is rejected earlier as an unreadable key.
            for private in other_keys.glob("*_private.pem"):
                private.unlink()
            assert list(other_keys.glob("*.pem")), "keygen produced no public key"
            gen = _sp.run(
                [_sys.executable, "-c", SIGN_ONE_LEDGER_BLOCK],
                capture_output=True,
                text=True,
                cwd=str(REPO_ROOT),
                env=env,
                timeout=180,
            )
            assert gen.returncode == 0, f"could not build a ledger: {gen.stderr[-400:]}"
            assert (root / "audit.db").is_file(), "no ledger was written"

            proc = _sp.run(
                [entry, "audit", "verify", "--key", str(other_keys)],
                capture_output=True,
                text=True,
                cwd=str(REPO_ROOT),
                env=env,
                timeout=180,
            )
            text = proc.stdout + proc.stderr
            assert "UNVERIFIABLE" in text, (
                f"expected the untrusted-key state, got exit {proc.returncode}:\n{text[-400:]}"
            )
            assert proc.returncode == 1, (
                f"`s0 audit verify` with an untrusted key exited {proc.returncode}. The "
                f"table says 1 and the 65 row now says this path is not 65; if this "
                f"fails, one of those is wrong and the message is:\n{text[-300:]}"
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

    def test_each_help_block_documents_the_command_of_its_own_section(self):
        """The bug this guards: blocks were filled in document order.

        The generator kept a list of ten commands and handed them to the ten
        `Help Screen` tabs in the order the tabs appeared. The tabs are not in that
        order, so five blocks landed in the wrong section -- `## s0 carve` showed
        `s0 clone`, `## s0 verify` showed `s0 audit` -- and `## s0 upgrade`, which
        does have a section, was given no help at all. `--check` could not catch it,
        because it compares each block to what the generator produced and the
        generator is what misplaced them.

        Now the command is derived from the heading above each tab, so the invariant
        worth asserting is simply that a block's `usage:` line names its own section.
        """
        text = REFERENCE.read_text()
        offsets: list[tuple[int, str]] = []
        offset = 0
        heading = ""
        for line in text.splitlines(keepends=True):
            if line.startswith("#"):
                heading = line.strip()
            offsets.append((offset, heading))
            offset += len(line)

        tab_re = re.compile(r'\{% tab title="Help Screen" %\}\n\n```\n(.*?)```', re.S)
        checked = 0
        for m in tab_re.finditer(text):
            before = [h for o, h in offsets if o <= m.start()]
            section = before[-1] if before else ""
            section_cmd = re.sub(r"^#+\s*s0\s+", "", section).strip()
            section_cmd = re.sub(r"\s*\(.*?\)\s*$", "", section_cmd).strip()
            block = m.group(1)
            usage = block.splitlines()[0] if block.splitlines() else ""
            # `s0 audit list --help` prints `usage: s0 audit ...`, because audit's
            # two verbs are a positional choice rather than real subparsers.
            root = section_cmd.split()[0]
            expected = f"usage: s0 {root if root == 'audit' else section_cmd}"
            assert usage.startswith(expected), (
                f"section {section!r} shows help for a different command:\n"
                f"  expected {expected!r}\n  block starts {usage!r}"
            )
            checked += 1
        assert checked >= 10, f"only {checked} help blocks checked"

    def test_the_help_check_ignores_interpreter_layout_differences(self):
        """`--check` must not depend on which Python version runs it.

        argparse changed how it renders an option with both a long and a short form:
        3.11 prints `--passes PASSES, -p PASSES`, 3.13+ prints `--passes, -p PASSES`.
        The longer spelling also pushes the description column right, sometimes onto
        its own line. CI ran `--check` on 3.10 through 3.13 while the committed blocks
        came from one interpreter, so the gate failed on every version but that one --
        over a comma and some padding.

        The check compares a content skeleton instead. This simulates the old layout
        over the real committed document and asserts the skeleton is unaffected while
        the raw text is not.
        """
        sys.path.insert(0, str(REPO_ROOT / "tools"))
        import gen_help_reference as gen

        text = REFERENCE.read_text()

        def to_old_style(line: str) -> list[str]:
            m = gen.HELP_LINE.match(line)
            if not m or not m.group("invocation").startswith("--"):
                return [line]
            mm = re.match(r"^(--[A-Za-z0-9-]+), (-[A-Za-z]) (.+)$", m.group("invocation"))
            if not mm:
                return [line]
            old = f"{mm.group(1)} {mm.group(3)}, {mm.group(2)} {mm.group(3)}"
            tail = m.group("help")
            if len(old) + 2 > 24:  # argparse wraps the description onto its own line
                return [m.group("indent") + old, " " * 26 + (tail or "")]
            return [m.group("indent") + old + ("   " + tail if tail else "")]

        simulated: list[str] = []
        for line in text.replace("\r\n", "\n").split("\n"):
            simulated.extend(to_old_style(line))
        simulated_text = "\n".join(simulated)

        assert simulated_text != text, (
            "the simulation changed nothing, so this test is not exercising the "
            "version difference it claims to"
        )
        disk = gen._skeleton(gen.TAB.search(text).group("body"))
        old_style = gen._skeleton(gen.TAB.search(simulated_text).group("body"))
        assert disk == old_style, (
            "the help skeleton changed under the pre-3.13 layout, so --check would "
            "still fail on Python 3.10-3.12"
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
        # The row lives in references/error-handling.md, which the agent may not
        # open. Reading only SKILL.md made this test pass for the wrong reason, so
        # the search follows the whole skill. SKILL.md separately states 77 inline.
        text = SKILL.read_text() + "\n" + (SKILL.parent / "references" / "error-handling.md").read_text()
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
        """Naming the operator command is fine; telling the agent to run it is not.

        This was a bare substring check, which cannot tell "run `sudo s0 web`" from
        "the documented operator command is `sudo s0 web`, which you must not run".
        The skill has to name it, or the agent cannot explain to the operator why the
        dashboard reports limited mode. So the guard is now that every mention sits in
        a sentence prohibiting it.
        """
        text = SKILL.read_text()
        prohibited = ("must not", "never", "do not", "not run it")
        mentions = [m.start() for m in re.finditer(r"sudo s0 web", text)]
        assert mentions, (
            "the skill never mentions `sudo s0 web`, so an agent cannot tell the "
            "operator why the dashboard is in limited mode"
        )
        for pos in mentions:
            window = text[max(0, pos - 200) : pos + 200].lower()
            assert any(word in window for word in prohibited), (
                "`sudo s0 web` appears with no instruction not to run it, so an agent "
                f"reads it as the command to use: ...{text[max(0, pos - 100) : pos + 60]}..."
            )

    def test_the_skill_names_the_flags_a_safety_skill_must_name(self):
        text = SKILL.read_text()
        for flag in ("--no-certificate", "--purge-all", "--force"):
            assert flag in text, (
                f"the skill never mentions {flag}. An agent that does not know a flag "
                f"exists will invent a workflow to avoid it."
            )

    def test_the_skill_names_no_flag_that_the_parser_does_not_accept(self):
        """The inverse guard, and the more useful one.

        The previous version of this test asserted the skill mentioned
        `--keep-audit`, which existed only to be a no-op for a userbase s0 never
        had. That flag is gone, so the assertion was demanding documentation of
        something an agent can no longer type.

        "Mention it or drop it" is only half a contract. The half that actually
        bit was the other direction: the skill naming flags the parser rejects.
        An agent reading this file would build a command line, get `unrecognized
        arguments`, and either retry forever or conclude s0 is broken. So walk
        every flag-shaped token in the skill and require the parser to accept it.
        """
        unknown = sorted(f for f in _skill_flags_for_the_cli() - _all_parser_flags())
        assert not unknown, (
            "the skill documents flags the CLI does not accept, so an agent "
            f"following it builds a command line that fails: {unknown}"
        )


def _skill_flags_for_the_cli() -> set[str]:
    """Flags the skill presents as belonging to the `s0` CLI.

    Scanned line by line so that flags belonging to some *other* program are not
    charged to s0. The skill legitimately mentions
    `python tools/gen_carving_reference.py --check`, and that `--check` is a real
    option of a real script -- just not of the CLI an agent is being taught to
    drive. A line that names a script or a `tools/` path is therefore skipped.
    """
    flags: set[str] = set()
    for line in SKILL.read_text().splitlines():
        if re.search(r"\b[\w./-]+\.py\b|\btools/", line):
            continue
        flags.update(re.findall(r"(?<!\w)--[a-z][a-z0-9-]*", line))
    return flags


def _all_parser_flags() -> set[str]:
    """Every option string accepted by any subcommand, plus the global ones."""
    sys.path.insert(0, str(REPO_ROOT / "src"))
    from s0.cli.main import build_parser

    flags: set[str] = set()
    stack = [build_parser()]
    while stack:
        current = stack.pop()
        for action in current._actions:
            flags.update(a for a in action.option_strings if a.startswith("--"))
            choices = getattr(action, "choices", None)
            if isinstance(choices, dict):
                stack.extend(choices.values())
    return flags

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


class TestImageAndCloneAreDistinguishable:
    """They shared help text verbatim, so `--help` could not say which is which."""

    def test_their_help_differs_and_says_what_each_does(self):
        import shutil
        import subprocess as sp

        entry = shutil.which("s0") or str(Path(sys.executable).parent / "s0")
        if not Path(entry).is_file():
            pytest.skip("s0 entry point not available")

        def help_for(command: str) -> str:
            proc = sp.run([entry, command, "--help"], capture_output=True, text=True, timeout=60)
            return proc.stdout

        image_help, clone_help = help_for("image"), help_for("clone")
        assert image_help != clone_help, (
            "s0 image and s0 clone produce identical help; a reader cannot tell that "
            "one writes a file and the other overwrites a device"
        )

        assert "FILE" in image_help.upper()
        assert "device" in clone_help.lower(), (
            "clone's help must say it writes a device, since that is the destructive part"
        )

    def test_both_still_work_the_same_way(self):
        """Distinguishing the help must not change the accepted options."""
        from s0.cli.main import build_parser

        parser = build_parser()
        skip = {"func", "command"}

        def keys(argv):
            namespace = parser.parse_args(argv)
            return {k for k in vars(namespace) if k not in skip}

        # Keys, not (key, value) pairs: `command` is "image" for one and "clone" for
        # the other, so comparing values would fail for a difference that is the
        # point rather than a regression.
        assert keys(["image", "--source", "a", "--destination", "b"]) == keys(
            ["clone", "--source", "a", "--destination", "b"]
        ), "the two commands no longer accept the same options"


class TestReadmeSaysWhereOutputGoes:
    def test_the_quick_start_warns_about_redirecting(self):
        """ "`s0 list > devices.txt` writes an empty file, and the README is where
        a new user meets that."""
        text = README.read_text()
        quick_start = text.split("## Quick Start", 1)
        assert len(quick_start) == 2, "no Quick Start section"
        section = quick_start[1].split("\n## ", 1)[0]
        assert "stderr" in section and "--json" in section, (
            "the quick start must say that human output goes to stderr and stdout "
            "is only used by --json/--format"
        )


class TestTheSkillAgreesWithTheCode:
    """The skill is what an agent trusts. Every claim in it must be checkable.

    Two of its claims were not, and both were the kind an agent cannot detect on its
    own: it listed two API routes that return 404, and it gave an exit code of 0 for
    a case that exits 75. An agent following either would report a successful
    verification of a certificate signed with a publicly known key.
    """

    @staticmethod
    def _skill_text() -> str:
        return (
            SKILL.read_text()
            + "\n"
            + "\n".join(p.read_text() for p in sorted((SKILL.parent / "references").glob("*.md")))
        )

    def test_every_route_the_skill_names_actually_exists(self):
        """`/api/list` and `/api/clone` were both documented and both 404."""
        import re as _re

        sys.path.insert(0, str(REPO_ROOT / "src"))
        from s0.web.app import app

        real = {
            _re.sub(r"\{[^}]+\}", "{}", r.path)
            for r in app.routes
            if getattr(r, "path", "").startswith(("/api", "/healthz"))
        }
        # Scan with positions so each mention can be read in context. The skill is
        # *supposed* to say "there is no /api/list", and a bare set-membership check
        # cannot tell that correction apart from the mistake it replaces.
        text = self._skill_text()
        negation = ("no ", "not ", "404", "does not exist")
        named: set[str] = set()
        for m in _re.finditer(r"(/api/[A-Za-z0-9_./{}-]+|/healthz)", text):
            window = text[max(0, m.start() - 60) : m.end() + 60].lower()
            if any(word in window for word in negation):
                continue
            named.add(_re.sub(r"\{[^}]+\}", "{}", m.group(1)).rstrip("/"))
        unknown = sorted(n for n in named if n not in real)
        assert not unknown, (
            f"the skill documents routes that do not exist and would 404: {unknown}. "
            f"Real routes: {sorted(real)}"
        )

    def test_the_skill_names_the_route_an_agent_has_to_poll(self):
        """Every state-changing route returns a job id, so the poll route is not optional."""
        text = self._skill_text()
        assert "/api/job/{job_id}" in text or "/api/job/" in text, (
            "the skill says state-changing calls return a job id to poll but never "
            "names the route to poll, so an agent has no way to collect a result"
        )

    def test_the_skill_does_not_claim_a_refused_plan_succeeds(self):
        """`s0 plan` on a mounted target exits 77. The skill said 0 in two places."""
        text = self._skill_text()
        for bad in ("exits 0 — it is a dry run", "exits **0**, because it is a dry run"):
            assert bad not in text, f"the skill still claims a refused plan succeeds: {bad!r}"

    def test_the_cross_origin_rule_matches_the_cookie_only_check(self):
        """Header auth skips the origin check; the skill said it did not."""
        from s0.web.app import verify_auth_token

        src = inspect.getsource(verify_auth_token)
        assert "_require_same_origin(request)" in src
        # The call must be inside the cookie branch, not at the top of the function.
        cookie_branch = src.index("cookie = request.cookies.get")
        origin_call = src.index("_require_same_origin(request)")
        assert cookie_branch < origin_call, (
            "if the origin check is no longer cookie-only, this test's premise is "
            "wrong and the skill's wording needs revisiting"
        )
        text = self._skill_text()
        assert "X-S0-Auth-Token` header** they are *not*" in text or ("header" in text and "not*" in text), (
            "the skill states the cross-origin rule unconditionally, but the check "
            "only covers cookie auth -- which is the one path agents do not use"
        )


class TestReleaseNotesFailLoudly:
    """A release whose notes are generic looks like a release that worked.

    `release.yml` extracted notes for the tag being released and, when the section was
    absent, substituted `Release <tag> of s0 (Sector Zero) forensic data sanitization
    suite.` The substitution was invisible: the step succeeded, the notes file was
    written, and the release was published. So a v3 tag cut while the changelog still
    ended at 2.4.4 shipped a release page with no content, and the only way anyone
    found out was to look at the page.

    A missing section is a release-preparation bug, so it stops the release. The
    extraction also lived inline in the workflow, which is the one place a silent
    fallback is most expensive and least likely to be exercised; it is now
    `tools/release_notes.py`, testable on its own.
    """

    EXTRACTOR = REPO_ROOT / "tools" / "release_notes.py"

    def test_notes_are_extracted_for_a_section_that_exists(self, tmp_path):
        import importlib.util

        spec = importlib.util.spec_from_file_location("release_notes", self.EXTRACTOR)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)

        changelog = tmp_path / "CHANGELOG.md"
        changelog.write_text(
            "# Changelog\n\n"
            "## [Unreleased]\n\n### Fixed\n\n- Something not yet released.\n\n---\n\n"
            "## [9.9.9-rc.1] - 2026-01-01\n\n"
            "### Added\n\n- A fake entry used only to test extraction.\n\n---\n\n"
            "## [0.0.1] - 2025-01-01\n\n### Added\n\n- The first thing s0 ever did.\n",
            encoding="utf-8",
        )

        for spelling in ("9.9.9-rc.1", "v9.9.9-rc.1"):
            notes, source = module.extract(spelling, (changelog,))
            assert "A fake entry" in notes, f"{spelling}: {notes!r}"
            assert "not yet released" not in notes, (
                f"{spelling}: the Unreleased section leaked into the tagged notes"
            )
            assert "first thing s0 ever did" not in notes, f"{spelling}: the next section leaked in"
            assert source == changelog

    def test_a_missing_section_raises_rather_than_returning_generic_text(self, tmp_path):
        import importlib.util

        spec = importlib.util.spec_from_file_location("release_notes", self.EXTRACTOR)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)

        changelog = tmp_path / "CHANGELOG.md"
        changelog.write_text(
            "## [Unreleased]\n\n### Fixed\n\n- Not released yet.\n\n"
            "## [2.4.4] - 2025-09-01\n\n### Added\n\n- The last released thing.\n",
            encoding="utf-8",
        )

        with pytest.raises(module.MissingSection) as excinfo:
            module.extract("3.0.0", (changelog,))
        message = str(excinfo.value)
        assert "no release notes for version '3.0.0'" in message
        # It must name what it did find, or the operator has to go looking.
        assert "Unreleased" in message and "2.4.4" in message, (
            f"the failure does not list the sections that exist: {message}"
        )
        # And it must not contain the generic fallback that caused this.
        assert "forensic data sanitization suite" not in message

    def test_an_empty_section_is_treated_as_missing(self, tmp_path):
        """An empty heading would otherwise publish an empty release page."""
        import importlib.util

        spec = importlib.util.spec_from_file_location("release_notes", self.EXTRACTOR)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)

        changelog = tmp_path / "CHANGELOG.md"
        changelog.write_text("## [4.0.0] - 2026-02-01\n\n---\n\n## [3.0.0]\n\n### Added\n\n- Real.\n")
        with pytest.raises(module.MissingSection) as excinfo:
            module.extract("4.0.0", (changelog,))
        assert "empty" in str(excinfo.value)

    def test_the_workflow_uses_the_extractor_and_has_no_fallback(self):
        workflow = (REPO_ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        assert "forensic data sanitization suite" not in workflow, (
            "release.yml still contains the generic-notes fallback that let a v3 tag publish with no content"
        )
        assert "CHANGELOG.md" in workflow, (
            "release.yml does not read the canonical changelog at the repository root"
        )
        assert "sys.exit" in workflow, "release.yml must be able to fail when the notes section is missing"


class TestTheChangelogHasOneSource:
    """There were two changelogs and the release workflow read the stale one."""

    def test_the_root_changelog_is_canonical(self):
        mirror = (REPO_ROOT / "docs" / "project" / "changelog.md").read_text(encoding="utf-8")
        assert "GENERATED FILE" in mirror[:400], (
            "docs/project/changelog.md does not declare itself generated, so an editor "
            "will happily change the copy instead of the source"
        )
        assert "canonical changelog is" in mirror[:800], (
            "the mirror does not point a reader at the canonical file"
        )

    def test_the_mirror_is_current(self):
        proc = subprocess.run(
            [sys.executable, str(REPO_ROOT / "tools" / "sync_changelog.py"), "--check"],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
            timeout=120,
        )
        assert proc.returncode == 0, (
            f"docs/project/changelog.md no longer matches CHANGELOG.md:\n{proc.stderr}\n"
            f"Run: python tools/sync_changelog.py --write"
        )

    def test_the_gitbook_summary_link_still_resolves(self):
        summary = (REPO_ROOT / "docs" / "SUMMARY.md").read_text(encoding="utf-8")
        assert "project/changelog.md" in summary, (
            "docs/SUMMARY.md no longer links the changelog, so GitBook stops publishing "
            "the page the mirror exists to keep alive"
        )

    def test_no_stale_test_count_is_claimed(self):
        """A test count in a changelog is stale the moment anyone adds a test."""
        for name in ("CHANGELOG.md", "docs/project/changelog.md"):
            text = (REPO_ROOT / name).read_text(encoding="utf-8")
            assert "1071 collected" not in text, (
                f"{name} still claims '1071 collected: 1061 passed, 10 skipped', which "
                f"was already wrong and is not checked by anything"
            )

    def test_the_unreleased_section_documents_the_2x_migration(self):
        text = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        assert "### Breaking changes and migration from 2.x" in text, (
            "there is no migration section, so a 2.x user has no way to find out that "
            "the package names, layout, key path, exit codes, dry-run behaviour and "
            "installer ref all changed"
        )
        for topic in ("s0-core", "s0-cli", "default_key_path", "64", "--dry-run", "S0_INSTALL_REF"):
            assert topic in text, f"the migration section does not mention {topic!r}"
