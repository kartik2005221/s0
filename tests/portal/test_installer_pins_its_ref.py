"""The installer must install something, from somewhere you chose.

`install.sh` cloned the remote's **default branch** and then ran `pip install -e .`
in whatever came back. Two things were left implicit and both bit:

*The default branch may not be installable.* It is not pinned to anything, so the
ref depends on repository settings at the moment of the clone. A branch predating
the `src/` package layout carries no `pyproject.toml` or `setup.py`, and the
operator got `does not appear to be a Python project` from pip several steps later,
with nothing connecting that message to the clone that caused it.

*`upgrade.sh` disagreed with `install.sh`.* It hard-coded `origin/master` while the
installer's clone followed the default branch, so an upgrade could move an install
to a different ref than the one it was installed from -- or fail outright on a
layout that had no package metadata.

The Windows upgrade scripts had the same hard-coded `master` as the shell one.

These tests assert the *property* -- one ref, chosen explicitly, honoured
identically by every installer -- rather than the particular string, so renaming
the default later does not silently reintroduce a moving target.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
INSTALL_DIR = REPO_ROOT / "site" / "scripts"

SCRIPTS = sorted(p for p in INSTALL_DIR.iterdir() if p.suffix in (".sh", ".ps1", ".cmd"))


def _sandbox_ref(module) -> str:
    """The ref currently written in a sandbox copy, whatever value the repo holds.

    Read rather than assumed: these tests must hold whatever the declared default,
    whether `master` or a release tag like `v3.0.0`.
    """
    found = module.read_refs()
    refs = {ref for values in found.values() for ref in values}
    assert len(refs) == 1, f"the sandbox does not start from a single ref: {found}"
    return refs.pop()


def _declared_default() -> str:
    """The one ref every file agrees on, read via the setter without changing anything."""
    proc = subprocess.run(
        [sys.executable, str(REPO_ROOT / "tools" / "set_install_ref.py"), "--show"],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    refs = set()
    for line in proc.stdout.splitlines():
        refs.update(part.strip() for part in line.split("  ")[-1].split(",") if part.strip())
    assert len(refs) == 1, f"the declared default is not single-valued: {sorted(refs)}"
    return refs.pop()


def _text(name: str) -> str:
    path = INSTALL_DIR / name
    assert path.is_file(), f"{name} is missing from {INSTALL_DIR}"
    return path.read_text(encoding="utf-8", errors="ignore")


class TestTheRefIsChosenNotInherited:
    def test_install_does_not_rely_on_the_remote_default_branch(self):
        s = _text("install.sh")
        assert "origin/HEAD" not in s
        # A clone with no --branch/--revision follows the default branch silently.
        for match in re.finditer(r"git clone[^\n]*", s):
            clone = match.group(0)
            assert "--branch" in clone or "--revision" in clone, (
                f"this clone does not name a ref, so it silently follows the remote default: {clone!r}"
            )

    @pytest.mark.parametrize("name", ["install.sh", "upgrade.sh", "upgrade.ps1", "upgrade.cmd"])
    def test_no_installer_hardcodes_a_ref_other_than_the_declared_default(self, name):
        """No installer may name a ref that is not the agreed default.

        This used to be `test_no_installer_hardcodes_master`, on the reasoning that
        `master` is "not installable and moves independently of what the installer was
        asked for". Both halves of that were true *on this branch*: `master` predates
        the `src/` layout and carries no package metadata, and a branch is a moving
        target. After the merge neither is true of `master` -- it is the released
        line, and it is what `tools/set_install_ref.py master` exists to declare.

        So the property worth keeping is not a particular string. It is that an
        installer names *one* ref and that ref is the declared default, so no script
        can quietly disagree with the others and no operator inherits a ref nobody
        chose. `test_no_installer_hardcodes_origin_slash_master` keeps the original
        intent for the genuinely unpinned form.
        """
        default = _declared_default()
        text = _text(name)
        offenders = [
            line.strip()
            for line in text.splitlines()
            if "master" in line and not line.strip().startswith(("#", "REM", "'"))
        ]
        for line in offenders:
            # A line may mention master only as the value it is being set to.
            assert default == "master", (
                f"{name} names master: {line!r}, but the declared default is "
                f"{default!r}. An installer may not name a ref the other files do not "
                f"agree on."
            )

    @pytest.mark.parametrize("name", ["install.sh", "upgrade.sh", "upgrade.ps1", "upgrade.cmd"])
    def test_no_installer_hardcodes_origin_slash_master(self, name):
        """`origin/master` is the genuinely unpinned form, at any declared default.

        Distinct from the test above: setting `S0_REF=master` and cloning `master` are
        explicit and reviewable, while `origin/master` written into a script is a
        second, invisible choice of ref that no setter can reach.
        """
        offenders = [
            line.strip()
            for line in _text(name).splitlines()
            if "origin/master" in line and not line.strip().startswith(("#", "REM", "'"))
        ]
        assert not offenders, (
            f"{name} hard-codes origin/master: {offenders}. That is a second ref "
            f"choice, invisible to tools/set_install_ref.py."
        )

    # The PowerShell installers were missing from this list, and a comment said so --
    # "neither reads S0_INSTALL_REF ... reported separately". That gap is now closed,
    # so they are in the list. Widening this list is what found it; leaving them out
    # with a note is how it stayed broken.
    @pytest.mark.parametrize("name", ["install.sh", "upgrade.sh", "install.ps1", "upgrade.ps1"])
    def test_the_ref_is_overridable_from_the_environment(self, name):
        text = _text(name)
        assert "S0_INSTALL_REF" in text, (
            f"{name} pins a ref an operator cannot change, so a broken or "
            f"unreleased ref cannot be worked around without editing the script"
        )

    @pytest.mark.parametrize("name", ["install.ps1", "upgrade.ps1"])
    def test_the_powershell_ref_variable_is_defined_before_it_is_used(self, name):
        """`upgrade.ps1` ran `git fetch origin $S0Ref` with `$S0Ref` never assigned.

        PowerShell expands an undefined variable to nothing, so that was
        `git fetch origin -q`, which resolves origin/HEAD -- the remote's default branch
        -- rather than the ref the machine was installed from. A user pinning a release
        tag was silently moved to whatever the default branch was, with no indication in
        the output.

        Asserted as ordering rather than by executing PowerShell: the failure mode is
        "used before assigned", and a presence check would pass on a definition that
        appears below the use.
        """
        text = _text(name)
        assignment = re.search(r"^\$S0Ref\s*=", text, re.M)
        assert assignment, f"{name} uses $S0Ref but never assigns it"
        # Assert on the git *commands*, not on every mention of the name. Two other
        # kinds of mention exist in these files and neither is a use: the comment that
        # documents this bug, and the error string "git clone of ref '$S0Ref' failed".
        # Scanning for the bare variable reports both, and the test then fails on
        # correct code -- which is how a test gets deleted instead of the bug getting
        # fixed.
        src_lines = text.splitlines()
        assignment_line = next(i for i, line in enumerate(src_lines) if line.startswith("$S0Ref"))
        commands = [
            (i, line)
            for i, line in enumerate(src_lines)
            if "$S0Ref" in line and re.search(r"^\s*(?:&\s*)?git\s", line)
        ]
        assert commands, f"{name} does not appear to use $S0Ref in any git command"
        for i, line in commands:
            assert i > assignment_line, (
                f"{name} runs `{line.strip()}` at line {i + 1}, before $S0Ref is "
                f"assigned at line {assignment_line + 1}"
            )

    @pytest.mark.parametrize("name", ["install.ps1", "upgrade.ps1"])
    def test_the_powershell_override_precedence_matches_the_shell_installers(self, name):
        """S0_INSTALL_REF, then S0_BRANCH, then the default.

        Two installers with different override rules is its own bug: the same
        environment would pin one ref on Linux and another on Windows.
        """
        text = _text(name)
        assert re.search(r"\$env:S0_INSTALL_REF", text), f"{name} must read S0_INSTALL_REF first"
        assert re.search(r"\$env:S0_BRANCH", text), (
            f"{name} must still honour the legacy S0_BRANCH, as install.sh does"
        )
        first = text.index("$env:S0_INSTALL_REF")
        second = text.index("$env:S0_BRANCH")
        assert first < second, f"{name} checks S0_BRANCH before S0_INSTALL_REF"

    def test_install_ps1_pins_the_branch_on_both_clone_attempts(self):
        """`git clone` with no `--branch` follows the remote's default.

        install.ps1 did exactly that, so the Windows installer could not pin a ref at
        all -- S0_INSTALL_REF was accepted and ignored. The full-clone fallback needs the
        flag too: a fallback that dropped the pin would install a *different* ref than
        the one that just failed.
        """
        text = _text("install.ps1")
        # Match invocations only. A bare `git clone` also matches the human-readable
        # error string "git clone of ref '$S0Ref' failed...", which is not a command and
        # has no --branch to find.
        clones = [
            line
            for line in text.splitlines()
            if re.match(r"\s*(?:&\s*)?git clone\b", line) and not line.lstrip().startswith("#")
        ]
        assert clones, "install.ps1 has no clone to check"
        for clone in clones:
            assert "--branch" in clone, (
                f"a clone without --branch follows the remote default branch: {clone.strip()}"
            )

    def test_the_ref_is_defined_exactly_once_and_clearly(self):
        s = _text("install.sh")
        # The default is itself a parameter expansion, so [^}]* cannot match it.
        definition = re.search(r'^S0_REF="\$\{S0_INSTALL_REF:-\$\{S0_BRANCH:-[^}]+\}\}"$', s, re.M)
        assert definition, (
            "S0_REF is not defined from S0_INSTALL_REF with a documented default; "
            "an undefined variable would make git clone fail in a confusing way"
        )


class TestTheCheckoutIsVerifiedBeforeUse:
    def test_a_checkout_without_package_metadata_is_refused_clearly(self):
        """The failure must name the cause and the remedy.

        Otherwise the operator sees pip's "does not appear to be a Python project"
        with no indication that the clone was the problem.
        """
        s = _text("install.sh")
        assert "pyproject.toml" in s and "setup.py" in s, (
            "the installer never checks that what it cloned is installable"
        )
        # The check has to come after the clone and before the pip install.
        clone_at = s.index("git clone")
        # Match the guard itself, not the comment that explains it -- the comment
        # mentions pyproject.toml well before the clone.
        check_at = re.search(r'\[ ! -f "pyproject\.toml" \]', s).start()
        pip_at = s.index(".venv/bin/python3 -m pip install")
        assert clone_at < check_at < pip_at, "the layout check must run after cloning and before installing"

    def test_a_failed_update_is_not_reported_as_success(self):
        """`git pull ... || true` followed by 'existing install updated'."""
        s = _text("install.sh")
        assert re.search(r"git pull[^\n]*\|\|\s*true", s) is None, (
            "a failed update is swallowed and then reported as an update"
        )
        assert "existing install updated" in s, "the update path disappeared entirely rather than being fixed"

    def test_the_reported_version_is_measured_not_hardcoded(self):
        """It used to print a literal 2.4.4 regardless of what was installed."""
        s = _text("install.sh")
        banner = re.search(r"installed successfully", s)
        assert banner, "the success banner is missing"
        # Look at the statements that build the banner, not just its final line.
        preceding = s[max(0, banner.start() - 400) : banner.end()]
        assert "--version" in preceding, (
            "the success banner prints a literal version rather than the one that was actually installed"
        )


class TestTheInstallersAgree:
    def test_install_and_upgrade_resolve_the_same_default_ref(self):
        """If they disagree, upgrade moves the install to a different ref."""
        install = re.search(r'S0_REF="\$\{S0_INSTALL_REF:-\$\{S0_BRANCH:-([^}]+)\}\}"', _text("install.sh"))
        upgrade = re.search(r'S0_REF="\$\{S0_INSTALL_REF:-\$\{S0_BRANCH:-([^}]+)\}\}"', _text("upgrade.sh"))
        assert install and upgrade, (
            "install.sh and upgrade.sh must both derive S0_REF from the same "
            "variables, or an upgrade can land on a different ref"
        )
        assert install.group(1) == upgrade.group(1), (
            f"install.sh defaults to {install.group(1)!r} but upgrade.sh defaults to {upgrade.group(1)!r}"
        )

    def test_upgrade_checks_out_the_ref_it_fetched(self):
        """`git pull origin <ref>` can fast-forward onto a different branch."""
        for name in ("upgrade.sh", "upgrade.ps1", "upgrade.cmd"):
            text = _text(name)
            assert "FETCH_HEAD" in text, (
                f"{name} does not check out the ref it fetched; `git pull` can move "
                f"the install onto whatever the current branch points at"
            )


class TestHonestyAboutWhatIsVerified:
    def test_the_installer_does_not_claim_signature_verification(self):
        s = _text("install.sh")
        claims = [
            line
            for line in s.splitlines()
            if "signature" in line.lower() and "not" not in line.lower() and "no " not in line.lower()
        ]
        assert not claims, f"the installer appears to claim signature verification: {claims}"

    def test_the_limits_are_stated(self):
        s = _text("install.sh").lower()
        assert "no signature verification" in s, (
            "the installer does not tell the operator that it trusts the ref "
            "without verifying a signature, which is a material omission for an "
            "installer fetched with curl | bash"
        )


class TestTheRefHasOneSetter:
    """The default ref was written out by hand in four places, and nothing kept them
    in step. `install.sh`, `upgrade.sh`, `upgrade.cmd` and the two `s0 upgrade`
    fallbacks in `main.py` each carried their own copy of the literal, so the only way
    to change it correctly was to find all five by hand -- and the only way to find out
    you had missed one was to break an install.

    `tools/set_install_ref.py` rewrites them together, and these tests assert the
    property that makes that safe: there is one script, it covers every location, and
    they currently agree.
    """

    SETTER = REPO_ROOT / "tools" / "set_install_ref.py"

    def test_the_setter_exists_and_is_documented(self):
        assert self.SETTER.is_file(), f"{self.SETTER} is missing"
        text = self.SETTER.read_text(encoding="utf-8")
        # The two commands the owner runs at merge and at release. A script that
        # cannot tell you when to use it is a script nobody runs at the right moment.
        assert "set_install_ref.py master" in text
        assert "set_install_ref.py v3.0.0" in text

    def test_the_setter_covers_every_location_the_ref_is_written(self):
        text = self.SETTER.read_text(encoding="utf-8")
        for name in ("install.sh", "upgrade.sh", "upgrade.cmd", "install.ps1", "upgrade.ps1"):
            assert name in text, f"the setter does not mention {name}"
        assert "main.py" in text, "the setter does not cover the `s0 upgrade` fallbacks"

    def test_every_location_the_ref_is_written_agrees_right_now(self):
        proc = subprocess.run(
            [sys.executable, str(self.SETTER), "--check"],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
            timeout=120,
        )
        assert proc.returncode == 0, (
            f"the default install ref is not consistent across the files that write it:\n"
            f"{proc.stdout}{proc.stderr}\n"
            f"Fix with: python tools/set_install_ref.py <ref>"
        )

    @pytest.fixture
    def sandbox(self, tmp_path):
        """A throwaway copy of the files the setter writes.

        The setter's tests must not edit the repository. An earlier version of these
        tests really did rewrite the installers and restore them afterwards, which made
        the suite order-dependent: a later test reading the tree saw whatever the
        previous one left behind, and `tests/portal` passed or failed depending on
        where the run started. Pointing the module at a copy keeps the assertions
        honest without the shared mutable state.
        """
        import importlib.util

        shutil.copytree(REPO_ROOT / "site" / "scripts", tmp_path / "scripts")
        (tmp_path / "src" / "s0" / "cli").mkdir(parents=True)
        shutil.copy2(
            REPO_ROOT / "src" / "s0" / "cli" / "main.py", tmp_path / "src" / "s0" / "cli" / "main.py"
        )

        spec = importlib.util.spec_from_file_location("set_install_ref", self.SETTER)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)

        module.REPO_ROOT = tmp_path
        module.MAIN_PY = tmp_path / "src" / "s0" / "cli" / "main.py"
        module.SCRIPT_TARGETS = tuple(
            (tmp_path / "scripts" / path.name, pattern) for path, pattern in module.SCRIPT_TARGETS
        )
        return module, tmp_path

    @pytest.mark.parametrize("bad", ["v3.0.0.", "mastre", "master2", "release", ""])
    def test_the_setter_refuses_a_ref_it_cannot_verify(self, sandbox, bad):
        """A typo written into five files is only discovered by a broken install."""
        module, _tmp = sandbox
        reason = module.validate(bad, "master")
        assert reason is not None, f"the setter would accept {bad!r}"
        assert "not an acceptable install ref" in reason

    @pytest.mark.parametrize("good", ["master", "v3.0.0", "v3.0.0-rc.1"])
    def test_the_setter_accepts_the_refs_the_owner_actually_uses(self, sandbox, good):
        module, _tmp = sandbox
        assert module.validate(good, "master") is None, (
            f"the setter would refuse {good!r}: {module.validate(good, 'master')}"
        )
        known = set(module.read_refs())
        module._rewrite_scripts(good)
        module._rewrite_main_py(good)
        after = module.read_refs()
        assert set(after) == known, "the setter changed which files it knows about"
        assert {r for refs in after.values() for r in refs} == {good}, (
            f"setting {good!r} left the files at {after}"
        )

    @pytest.mark.parametrize("target_ref", ["master", "v3.0.0", "v3.0.0-rc.1"])
    def test_setting_release_or_master_ref_removes_agent_harness_completely(self, sandbox, target_ref):
        """Switching to master or a release tag leaves no trace of the feature branch."""
        module, _tmp = sandbox
        module._rewrite_scripts(target_ref)
        module._rewrite_main_py(target_ref)
        after = module.read_refs()
        for path, refs in after.items():
            assert "agent/harness" not in refs, f"{path} still references agent/harness in refs: {refs}"
            content = path.read_text(encoding="utf-8")
            assert "agent/harness" not in content, f"{path} still contains 'agent/harness' in text"

    def test_setting_a_ref_touches_only_the_ref(self, sandbox):
        """Rewriting must not reformat, reorder or truncate the file it edits.

        An early version of this script rebuilt `main.py` by splitting on a string and
        reassembling the halves, and dropped 1,223 lines of it. A test that mutates the
        real tree cannot catch that without also breaking the tree, which is why this
        runs against a copy.
        """
        module, _tmp = sandbox
        before_scripts = {path: path.read_text(encoding="utf-8") for path, _ in module.SCRIPT_TARGETS}
        before_main = module.MAIN_PY.read_text(encoding="utf-8")

        module._rewrite_scripts("v9.9.9-rc.1")
        module._rewrite_main_py("v9.9.9-rc.1")

        for path, _pattern in module.SCRIPT_TARGETS:
            changed = [
                (a, b)
                for a, b in zip(
                    before_scripts[path].split("\n"),
                    path.read_text(encoding="utf-8").split("\n"),
                    strict=False,
                )
                if a != b
            ]
            assert len(changed) == 1, (
                f"{path.name}: expected exactly one changed line, got {len(changed)}: {changed[:3]}"
            )

        after_main = module.MAIN_PY.read_text(encoding="utf-8")
        assert 'return "v9.9.9-rc.1"' in after_main
        # The tag comment is one line longer than the branch comment; nothing else.
        expected_diff = 1 if _sandbox_ref(module) == "master" else 0
        assert len(after_main.split("\n")) == len(before_main.split("\n")) + expected_diff, (
            f"line count went {len(before_main.splitlines())} -> "
            f"{len(after_main.splitlines())}; expected diff {expected_diff} for the tag comment"
        )
        for marker in ("def cmd_upgrade(", "def cmd_uninstall(", "def build_parser("):
            assert after_main.count(marker) == before_main.count(marker), (
                f"{marker} count changed: the rewrite lost or duplicated code"
            )

    def test_a_stale_anchor_fails_loudly_instead_of_leaving_the_ref_unset(self, sandbox):
        module, _tmp = sandbox
        current = _sandbox_ref(module)
        text = module.MAIN_PY.read_text(encoding="utf-8")
        module.MAIN_PY.write_text(
            text.replace(f'return "{current}"', "return compute_ref()"), encoding="utf-8"
        )
        with pytest.raises(SystemExit) as excinfo:
            module._rewrite_main_py("master")
        message = str(excinfo.value)
        # Two distinct anchors can go stale -- the return statement, and the
        # comment above it -- so this asserts the property both must satisfy:
        # the setter refuses, and it says what to do rather than writing nothing
        # and reporting success.
        assert "Fix the anchors" in message, f"the failure does not say what to do: {message}"
        assert str(module.MAIN_PY.relative_to(module.REPO_ROOT)) in message, (
            f"the failure does not name the file it gave up on: {message}"
        )

    def test_a_hand_edit_to_one_installer_is_caught(self, sandbox):
        """The property the setter exists to maintain, demonstrated by breaking it."""
        module, tmp = sandbox
        current = _sandbox_ref(module)
        other = "master" if current != "master" else "v3.0.0"
        install_sh = tmp / "scripts" / "install.sh"
        install_sh.write_text(
            install_sh.read_text(encoding="utf-8").replace(current, other), encoding="utf-8"
        )
        found = module.read_refs()
        distinct = {ref for refs in found.values() for ref in refs}
        assert len(distinct) > 1, f"a hand-edit to one installer went undetected: {found}"
