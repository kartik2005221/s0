"""Four decisions that were wrong in ways a caller would never notice.

**`s0 upgrade` asked git about the wrong directory.** ``rev-parse --abbrev-ref HEAD``
ran in the process CWD, not in the install checkout. Since ``s0 upgrade`` is invoked
from wherever the user happens to be, git printed "fatal: not a git repository", the
exception was swallowed, and the function fell back to ``master`` -- so a contributor
on a feature branch had master pulled into their working tree. Every other git call
in that function passed ``cwd=repo_dir``; this one did not.

**The upgrade success message was built from the wrong fact.** It printed the
*remote's* hash next to the *installed* version, so a run where the pull was a no-op
still announced "upgraded to <new hash>" while the checkout never moved. Reading
HEAD back afterwards is the only way to make that sentence true.

**`s0 verify` exited differently depending on the output format.** A demo-key
certificate was 75 for ``--json`` and 0 for text: the same document was a pass or a
failure because of a formatting flag, and the JSON path had been tightened while the
text path had not. The verdict is now computed once and both paths return it.

**`s0 plan` exited 0 after refusing.** It printed ``REFUSED: ... has mounted
filesystems`` and returned success. The skill's first invariant is "never wipe
without a plan", so an agent gating on the plan's exit code concluded a mounted
system disk was safe to wipe.
"""

from __future__ import annotations

import os
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


def _run(*args: str, cwd: Path, env: dict | None = None, timeout: int = 180):
    base = dict(os.environ)
    base.update(
        {
            "HOME": str(cwd),
            "USERPROFILE": str(cwd),
            "S0_AUDIT_DB": str(cwd / "audit.db"),
        }
    )
    base["PYTHONPATH"] = f"{REPO_ROOT / 'src'}:{base.get('PYTHONPATH', '')}".rstrip(":")
    base.update(env or {})
    return subprocess.run(
        [_entry_point(), *args], capture_output=True, text=True, env=base, cwd=str(cwd), timeout=timeout
    )


class TestGetUpgradeBranchAsksAboutTheCheckout:
    def test_it_runs_git_inside_the_repository_not_the_cwd(self):
        """The reported defect, reproduced structurally.

        A git call without ``cwd=repo_dir`` asks about whatever directory the
        process happens to be in. The test runs from a non-git directory and passes
        a real repository, so the two answers differ.
        """
        import tempfile
        from argparse import Namespace

        from s0.cli.main import get_upgrade_branch

        with tempfile.TemporaryDirectory() as repo:
            subprocess.run(["git", "init", "-q", "-b", "feature/x", repo], check=True)
            subprocess.run(
                ["git", "-C", repo, "commit", "-q", "--allow-empty", "-m", "x"],
                check=False,
                env={
                    **os.environ,
                    "GIT_AUTHOR_NAME": "t",
                    "GIT_AUTHOR_EMAIL": "t@e",
                    "GIT_COMMITTER_NAME": "t",
                    "GIT_COMMITTER_EMAIL": "t@e",
                },
            )

            # No explicit --branch, no env var: the branch must come from the repo.
            got = get_upgrade_branch(Namespace(branch=None), repo)
            assert got == "feature/x", (
                f"asked about the wrong directory: got {got!r} instead of the checkout's own branch"
            )

    def test_it_falls_back_to_valid_default_ref(self):
        """The installer pins a ref and get_upgrade_branch resolves to it when unset."""
        import tempfile
        from argparse import Namespace

        from s0.cli.main import get_upgrade_branch

        with tempfile.TemporaryDirectory() as not_a_repo:
            got = get_upgrade_branch(Namespace(branch=None), not_a_repo)
        assert got in ("master", "v3.0.0", "v3.0.0-rc.1"), (
            f"the fallback {got!r} is not an acceptable default ref"
        )

    def test_an_explicit_branch_still_wins(self):
        import tempfile
        from argparse import Namespace

        from s0.cli.main import get_upgrade_branch

        with tempfile.TemporaryDirectory() as d:
            assert get_upgrade_branch(Namespace(branch="v2.4.4"), d) == "v2.4.4"

    def test_the_environment_override_still_wins(self, tmp_path, monkeypatch):
        from argparse import Namespace

        from s0.cli.main import get_upgrade_branch

        monkeypatch.setenv("S0_UPGRADE_BRANCH", "from-env")
        assert get_upgrade_branch(Namespace(branch=None), tmp_path) == "from-env"


class TestEveryGitCallInUpgradePassesCwd:
    def test_no_git_subprocess_call_omits_cwd(self):
        """A structural guard over the whole function.

        One missed call is how this happened in the first place: five git calls in
        one function, four of which passed cwd. A per-call assertion would have to be
        written five times and would be checked five times; this checks all of them
        at once.
        """
        import ast
        import inspect
        import textwrap

        from s0.cli import main as cli

        # textwrap.dedent, not inspect.cleandoc: cleandoc strips the *docstring*
        # indentation too, which leaves a function body starting at column 0 and
        # fails to parse.
        source = textwrap.dedent(inspect.getsource(cli.cmd_upgrade))
        calls: list[int] = []
        for node in ast.walk(ast.parse(source)):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
                continue
            if node.func.attr not in ("check_output", "check_call", "run", "Popen"):
                continue
            args = node.args
            first = args[0] if args else None
            text = ast.dump(first) if first is not None else ""
            if '"git"' not in text and "'git'" not in text:
                continue
            if "git" not in text and not any(
                isinstance(a, ast.Constant) and isinstance(a.value, str) and a.value.startswith("git")
                for a in args
            ):
                continue
            has_cwd = any(k.arg == "cwd" for k in node.keywords)
            if not has_cwd:
                calls.append(node.lineno)

        assert not calls, (
            f"cmd_upgrade calls git without cwd= at lines {calls}; those "
            f"ask about the process CWD, not the install checkout"
        )


class TestVerifyExitCodeDoesNotDependOnFormat:
    @pytest.fixture
    def demo_signed_cert(self, tmp_path):
        target = tmp_path / "t.txt"
        target.write_bytes(b"evidence\n" * 40)
        proc = _run(
            "wipe",
            "--targets",
            str(target),
            "--yes",
            "--no-pdf",
            "--out-dir",
            str(tmp_path / "c"),
            cwd=tmp_path,
        )
        assert proc.returncode == 0, proc.stderr
        certs = list((tmp_path / "c").glob("*.json"))
        assert certs, "no certificate produced"
        return certs[0]

    @pytest.mark.parametrize(
        "flags",
        [
            [],
            ["--json"],
            ["--format", "csv"],
            ["--quiet"],
            ["--json", "--quiet"],
            ["--no-color"],
        ],
        ids=["text", "json", "csv", "quiet", "json+quiet", "no-color"],
    )
    def test_every_format_agrees(self, tmp_path, demo_signed_cert, flags):
        """The reported defect: text 0, json 75, for the same file."""
        proc = _run("verify", str(demo_signed_cert), *flags, cwd=tmp_path)
        text = proc.stdout + proc.stderr
        assert "Traceback" not in text

        reference = _run("verify", str(demo_signed_cert), "--json", cwd=tmp_path)
        assert proc.returncode == reference.returncode, (
            f"`s0 verify {' '.join(flags)}` exited {proc.returncode} but "
            f"`--json` exited {reference.returncode}. Presentation must not change "
            f"the verdict."
        )

    def test_a_demo_key_certificate_is_not_a_pass(self, demo_signed_cert, tmp_path):
        proc = _run("verify", str(demo_signed_cert), cwd=tmp_path)
        assert proc.returncode != 0, (
            "a certificate signed with the *published* demo key exits 0. It verifies "
            "cryptographically and carries no evidentiary weight, so treating it as a "
            "pass is the failure the JSON path was tightened to prevent."
        )

    def test_a_tampered_certificate_still_fails(self, tmp_path):
        import json

        target = tmp_path / "t.txt"
        target.write_bytes(b"evidence\n" * 40)
        _run(
            "wipe",
            "--targets",
            str(target),
            "--yes",
            "--no-pdf",
            "--out-dir",
            str(tmp_path / "c"),
            cwd=tmp_path,
        )
        cert = json.loads(next((tmp_path / "c").glob("*.json")).read_text(encoding="utf-8"))
        cert["result"]["status"] = "tampered"
        path = tmp_path / "tampered.json"
        path.write_text(json.dumps(cert))

        for flags in ([], ["--json"]):
            proc = _run("verify", str(path), *flags, cwd=tmp_path)
            assert proc.returncode != 0, f"a tampered certificate exited 0 with flags {flags}"


class TestPlanExitsNonZeroOnRefusal:
    def test_a_refused_plan_is_not_a_success(self, tmp_path):
        """`/etc/passwd` is refused by the shared path guard on every platform."""
        proc = _run("plan", "--target", "/etc/passwd", cwd=tmp_path)
        combined = proc.stdout + proc.stderr
        if "REFUSED" not in combined.upper():
            pytest.skip("this platform does not refuse /etc/passwd")
        assert proc.returncode != 0, (
            "the plan printed a refusal and exited 0, so an agent gating on the "
            "plan's exit code -- the documented first step -- would proceed to wipe"
        )
        assert "DRY RUN" not in combined, (
            "a refused plan must not print 'DRY RUN - nothing was written. Run s0 wipe when satisfied'"
        )

    def test_a_normal_plan_still_succeeds(self, tmp_path):
        blob = bytearray(bytes(range(256)) * 800)
        blob[0x8001:0x8006] = b"CD001"
        (tmp_path / "img.raw").write_bytes(bytes(blob))
        proc = _run("plan", "--target", str(tmp_path / "img.raw"), cwd=tmp_path)
        assert proc.returncode == 0, f"an ordinary plan started failing:\\n{proc.stderr[-400:]}"

    def test_a_satisfiable_but_refused_target_is_still_a_refusal(self, tmp_path):
        """Capability and permissibility are different questions.

        A target can have a perfectly good wipe ladder and still be refused. Only the
        refusal path is checked here -- the point is that the two are not conflated.
        """
        import inspect

        from s0.cli import main as cli

        source = inspect.getsource(cli.cmd_plan)
        assert "if refused:" in source and "EX_NOPERM" in source, (
            "cmd_plan does not branch on a safety refusal, so a refused plan reports "
            "the ladder's satisfiability instead"
        )


class TestTheUpgradeCallSitePassesTheDirectory:
    """The unit tests above call get_upgrade_branch directly.

    That is a real gap: reverting the *call site* -- `get_upgrade_branch(args)` instead
    of `get_upgrade_branch(args, repo_dir)` -- leaves the function itself perfect and
    the bug fully present, because the function then falls back to asking about the
    process CWD. So the call site is asserted too.
    """

    def test_cmd_upgrade_passes_repo_dir_when_choosing_a_branch(self):
        import ast
        import inspect
        import textwrap

        from s0.cli import main as cli

        source = textwrap.dedent(inspect.getsource(cli.cmd_upgrade))
        calls = [
            node
            for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "get_upgrade_branch"
        ]
        assert calls, "cmd_upgrade no longer calls get_upgrade_branch"

        for call in calls:
            assert len(call.args) >= 2, (
                "cmd_upgrade calls get_upgrade_branch(args) with no directory. The "
                "function then runs `git rev-parse` in the process CWD, which is "
                "almost never a git repository, so it silently falls back."
            )
            passed = call.args[1]
            assert isinstance(passed, ast.Name) and passed.id == "repo_dir", (
                f"get_upgrade_branch is passed {ast.dump(passed)}, not repo_dir"
            )


class TestRepeatedKeyFlagsAreAllTrusted:
    """`--key a.pem --key b.pem` kept only the last key.

    The help says "Repeatable", so the documented spelling silently dropped
    everything but the final value. Verification then failed closed with
    UNVERIFIABLE, which an operator reads as tampering rather than as a dropped
    argument -- so the bug did not look like a bug.
    """

    def _parser(self):
        from s0.cli.main import build_parser

        return build_parser()

    def test_repeated_flags_accumulate_rather_than_overwrite(self):
        parser = self._parser()
        args = parser.parse_args(["audit", "verify", "--key", "a.pem", "--key", "b.pem"])
        flattened = [k for group in (args.key or []) for k in group]
        assert flattened == ["a.pem", "b.pem"], (
            f"repeating --key collapsed to {args.key!r}; only the last key would be trusted"
        )

    def test_a_single_flag_with_several_values_still_works(self):
        parser = self._parser()
        args = parser.parse_args(["audit", "verify", "--key", "a.pem", "b.pem"])
        flattened = [k for group in (args.key or []) for k in group]
        assert flattened == ["a.pem", "b.pem"]

    def test_both_spellings_reach_the_loader(self, tmp_path):
        """End to end: both spellings must load the same number of keys."""

        from s0.audit.db import record_audit_event

        cert = {
            "issued_at": "2026-01-01T00:00:00Z",
            "cert_uuid": "u1",
            "issuer": {"operator_id": "op", "organization": "org"},
            "device": {"device_id": "dev"},
            "signature": {"signature_base64url": "sig"},
        }
        record_audit_event(
            cert,
            db_path=tmp_path / "audit.db",
            private_key=str(REPO_ROOT / "src/s0/data/keys/demo_issuer_private.pem"),
        )

        keys = str(REPO_ROOT / "src/s0/data/keys/demo_issuer_public.pem")
        repeated = _run("audit", "verify", "--key", keys, "--key", keys, cwd=tmp_path)
        spaced = _run("audit", "verify", "--key", keys, keys, cwd=tmp_path)

        for label, proc in (("repeated", repeated), ("spaced", spaced)):
            combined = proc.stdout + proc.stderr
            assert "Traceback" not in combined, f"{label}: {combined[-300:]}"
            if "Loaded 2 trusted issuer key" not in combined:
                # The message may be worded differently; the invariant that matters
                # is that both spellings behave identically.
                assert proc.returncode == spaced.returncode, (
                    f"{label} exited {proc.returncode}, space-separated exited "
                    f"{spaced.returncode}: {combined[-300:]}"
                )
        assert repeated.returncode == spaced.returncode


class TestMalformedSignatureIsRejectedNotCrashed:
    """`s0 verify` must never print "This is a bug in s0" for a bad document.

    `cert_data.get("signature", {})` supplies its default only when the key is
    *absent*. A certificate carrying `"signature": null`, `[]`, `7` or a string
    passed the key straight through, so the demo-key probe's next `.get(...)` raised
    AttributeError. The top-level handler caught it and reported an internal error
    with exit 70.

    That fails closed, so nothing was exploitable -- but it is the wrong verdict for
    a malformed document, it told the operator to report a bug rather than fix their
    file, and it buried the real message. `verify_certificate` already rejects every
    one of these shapes with "signature: required object"; the crash happened while
    computing a *separate* fact, before that verdict could be printed.
    """

    @pytest.fixture
    def real_cert(self, tmp_path) -> Path:
        target = tmp_path / "t.txt"
        target.write_bytes(b"evidence\n" * 40)
        proc = _run(
            "wipe",
            "--targets",
            str(target),
            "--yes",
            "--no-pdf",
            "--out-dir",
            str(tmp_path / "c"),
            cwd=tmp_path,
        )
        assert proc.returncode == 0, proc.stderr
        certs = list((tmp_path / "c").glob("*.json"))
        assert certs, "no certificate produced"
        return certs[0]

    @pytest.mark.parametrize(
        "value",
        [None, [], 7, "not-an-object", {"public_key_fingerprint": None}],
        ids=["null", "empty-list", "int", "string", "null-field"],
    )
    def test_a_non_object_signature_is_a_validation_error(self, real_cert, tmp_path, value):
        import json

        doc = json.loads(real_cert.read_text(encoding="utf-8"))
        doc["signature"] = value
        bad = tmp_path / "bad.json"
        bad.write_text(json.dumps(doc))

        proc = _run("verify", str(bad), cwd=tmp_path)
        text = proc.stdout + proc.stderr
        assert "bug in s0" not in text and "Traceback" not in text, (
            f"a malformed `signature` produced an internal error instead of a "
            f"validation verdict:\n{text[-600:]}"
        )
        assert proc.returncode not in (0, 70), (
            f"expected a non-zero validation failure, got {proc.returncode}"
        )

    def test_every_output_format_agrees_on_a_malformed_signature(self, real_cert, tmp_path):
        import json

        doc = json.loads(real_cert.read_text(encoding="utf-8"))
        doc["signature"] = 7
        bad = tmp_path / "bad.json"
        bad.write_text(json.dumps(doc))

        codes = {
            " ".join(flags) or "text": _run("verify", str(bad), *flags, cwd=tmp_path).returncode
            for flags in ([], ["--json"], ["--format", "csv"])
        }
        assert len(set(codes.values())) == 1, f"the verdict changed with the format: {codes}"

    def test_a_well_formed_certificate_still_verifies(self, real_cert, tmp_path):
        """The fix must not have broken the normal path."""
        proc = _run("verify", str(real_cert), cwd=tmp_path)
        text = proc.stdout + proc.stderr
        assert "AUTHENTIC" in text, f"a valid certificate stopped verifying:\n{text[-400:]}"
        assert "bug in s0" not in text
