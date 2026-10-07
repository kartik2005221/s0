"""No path may be interpolated into a PowerShell command string.

`install.cmd` and `uninstall.cmd` edit the user's PATH by shelling out to
PowerShell, and they built the command by pasting the path into a single-quoted
PowerShell string:

    powershell -Command "$b = '%BIN_DIR%'; ..."

A user directory containing an apostrophe -- ``C:\\Users\\O'Brien`` -- closes that
string early, and everything after it is parsed as PowerShell rather than as data.
The result is an installer whose behaviour depends on the name of a folder: quoting
the path does not help, because the injection happens *inside* the quotes.

So the path is passed through the environment instead. ``$env:S0_BIN_TO_PATH`` is a
value read at runtime, not syntax substituted at build time, so no path can change
the shape of the command.

These tests assert the structural property -- no cmd variable appears inside a
PowerShell ``-Command`` string -- rather than attempting to execute the injection.
That is a deliberate limitation, not an oversight: this suite runs on Linux, where
there is no ``cmd.exe``, so a test that shelled out would be skipped exactly where
it could not be trusted anyway. The property is checkable everywhere, and it is the
property that matters: the bug class is textual.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
INSTALL_DIR = REPO_ROOT / "site" / "scripts"

CMD_FILES = sorted(INSTALL_DIR.glob("*.cmd"))
PS_FILES = sorted(INSTALL_DIR.glob("*.ps1"))

# Only the *quoted argument* to -Command. Matching to end-of-line would sweep up the
# trailing cmd redirection -- `> "%TEMP%\_s0_newpath.txt"` -- whose %TEMP% is ordinary
# cmd syntax outside the PowerShell string and perfectly correct there.
POWERSHELL_LINE = re.compile(r'powershell[^\n]*-Command\s+"([^"]*)"', re.I)
# A cmd variable reference: %NAME%.
CMD_VAR = re.compile(r"%[A-Za-z_][A-Za-z0-9_]*%")


def _command_payloads(path: Path) -> list[tuple[int, str]]:
    out = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
        for match in POWERSHELL_LINE.finditer(line):
            out.append((lineno, match.group(1)))
    return out


class TestTheCorpusIsPresent:
    def test_the_cmd_installers_exist(self):
        assert CMD_FILES, f"no .cmd installers found under {INSTALL_DIR}"

    def test_the_installer_actually_shells_out_to_powershell(self):
        """Guard the guard.

        If a future refactor stopped using PowerShell, every assertion below would
        pass because there would be nothing to check.
        """
        assert _command_payloads(INSTALL_DIR / "install.cmd"), (
            "install.cmd no longer invokes powershell -Command; this file's checks "
            "assume it does and would otherwise be vacuous"
        )


class TestNoPathIsInterpolatedIntoPowerShell:
    @pytest.mark.parametrize("path", CMD_FILES, ids=lambda p: p.name)
    def test_no_cmd_variable_appears_inside_a_command_string(self, path):
        offenders = [
            f"{path.name}:{lineno}: {payload.strip()[:90]}"
            for lineno, payload in _command_payloads(path)
            if CMD_VAR.search(payload)
        ]
        assert not offenders, (
            f"a cmd variable is interpolated into a PowerShell -Command string: "
            f"{offenders}. A path containing an apostrophe closes the PowerShell "
            f"string early and the remainder is executed as code."
        )

    @pytest.mark.parametrize("path", CMD_FILES, ids=lambda p: p.name)
    def test_paths_are_passed_through_the_environment(self, path):
        """The fix has to be present, not just the bug absent."""
        payloads = [payload for _lineno, payload in _command_payloads(path)]
        if not payloads:
            pytest.skip(f"{path.name} does not use powershell -Command")
        assert all("$env:" in payload for payload in payloads), (
            f"{path.name} builds its PowerShell command without reading the path "
            f"from the environment, so the quoting hazard may still be present."
        )

    @pytest.mark.parametrize("path", CMD_FILES, ids=lambda p: p.name)
    def test_every_env_var_read_is_one_we_set(self, path):
        """A typo in the variable name would leave the path empty, silently."""
        text = path.read_text(encoding="utf-8", errors="ignore")
        # `set "NAME=value"` -- the value follows the `=`, so match up to it.
        declared = set(re.findall(r'set "(S0_[A-Za-z0-9_]*)=', text))
        used = set()
        for _lineno, payload in _command_payloads(path):
            used.update(re.findall(r"\$env:(S0_[A-Za-z0-9_]*)", payload))
        if not used:
            # Nothing reads a path from the environment, so there is no name to
            # mistype. upgrade.cmd uses plain %S0_REF% cmd expansion, which is
            # correct for a .cmd file and not covered by this hazard.
            pytest.skip(f"{path.name} reads no path from the environment")
        missing = sorted(used - declared)
        assert not missing, (
            f"{path.name} reads {missing} from the environment but never sets "
            f"them; PowerShell would silently receive an empty path"
        )


class TestTheWindowsInstallersStillAgree:
    def test_install_and_uninstall_use_the_same_variable_names(self):
        """Mismatched names would make uninstall a no-op rather than an error."""
        install = (INSTALL_DIR / "install.cmd").read_text(encoding="utf-8", errors="ignore")
        uninstall = (INSTALL_DIR / "uninstall.cmd").read_text(encoding="utf-8", errors="ignore")
        # Only the path variables, not S0_REF: that one names a git ref and is used
        # as ordinary cmd expansion in both.
        skip = {"S0_REF"}
        install_vars = set(re.findall(r"\$env:(S0_[A-Za-z0-9_]*)", install)) - skip
        uninstall_vars = set(re.findall(r"\$env:(S0_[A-Za-z0-9_]*)", uninstall)) - skip
        assert install_vars, "install.cmd sets up no S0_* path variables"
        assert uninstall_vars, "uninstall.cmd sets up no S0_* path variables"
        # Uninstall may clean up *more* than install adds -- it also removes the
        # venv's Scripts directory, which install never put on PATH. What must hold
        # is the other direction: anything install adds, uninstall must remove.
        assert install_vars <= uninstall_vars, (
            f"install.cmd adds {sorted(install_vars - uninstall_vars)} to PATH but "
            f"uninstall.cmd never removes it, so a reinstall leaves stale entries "
            f"behind forever"
        )


class TestThePs1Installers:
    @pytest.mark.parametrize("path", PS_FILES, ids=lambda p: p.name)
    def test_path_handling_uses_powershell_variables(self, path):
        """The .ps1 installers are PowerShell, so they need no env-var workaround.

        install.ps1 additionally embeds a generated .cmd shim in a here-string, where
        %~dp0 and %ERRORLEVEL% are correct cmd syntax being *written out* rather than
        a variable PowerShell is meant to expand. So this asserts the positive
        property -- that PATH handling reads $env: -- rather than policing every %,
        which would have to understand here-string quoting to avoid false positives.
        """
        text = path.read_text(encoding="utf-8", errors="ignore")
        if "Environment]::SetEnvironmentVariable" not in text:
            pytest.skip(f"{path.name} does not edit PATH")
        assert "$env:" in text, f"{path.name} edits PATH without reading the path from $env:"
