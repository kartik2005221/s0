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
from pathlib import Path

import pytest

INSTALL_DIR = Path(__file__).resolve().parents[2] / "site" / "install"

SCRIPTS = sorted(p for p in INSTALL_DIR.iterdir() if p.suffix in (".sh", ".ps1", ".cmd"))


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
    def test_no_installer_hardcodes_master(self, name):
        """`origin/master` is exactly the un-pinned ref that caused the problem."""
        text = _text(name)
        offenders = [
            line.strip()
            for line in text.splitlines()
            if "master" in line and not line.strip().startswith(("#", "REM", "'"))
        ]
        assert not offenders, (
            f"{name} still names master: {offenders}. That ref is not installable "
            f"and moves independently of what the installer was asked for."
        )

    @pytest.mark.parametrize("name", ["install.sh", "upgrade.sh"])
    def test_the_ref_is_overridable_from_the_environment(self, name):
        text = _text(name)
        assert "S0_INSTALL_REF" in text, (
            f"{name} pins a ref an operator cannot change, so a broken or "
            f"unreleased ref cannot be worked around without editing the script"
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
