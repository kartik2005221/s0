"""The native wipe engines must ship inside the package.

``windows/`` and ``macos/`` were top-level packages at the repository root,
imported as ``windows.cli.s0_eraser``. ``pyproject.toml`` packages only ``s0*``,
so for anyone who installed s0 rather than running it from a checkout, both engines
were **absent from the installed distribution**. The imports are lazy, so nothing
raised at import time -- the failure surfaced much later as a drive wipe reporting
a zero or unreadable capacity, because size detection fell back to 0 and `cmd_wipe`
rejected the target with "has zero or unreadable capacity" before reaching its own
"repo root is on sys.path" hint.

That is fail-closed rather than dangerous, so no test noticed: nothing asserted the
engines were reachable from an installed copy. These tests do.

Two things are checked, because either alone is insufficient:

* the *configuration* -- that the packaging filters name a location which contains
  the engines, so a future `include` edit cannot quietly drop them again;
* the *artefact* -- that a real wheel actually contains them.

The artefact check is skipped when the build backend cannot run offline, but it is
the check that would have caught this, so it is worth the build time.
"""

from __future__ import annotations

import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

ENGINE_MODULES = (
    "s0.platform.windows.s0_eraser",
    "s0.platform.macos.s0_eraser",
)


class TestEnginesLiveInsideThePackage:
    @pytest.mark.parametrize("module", ENGINE_MODULES)
    def test_the_engine_is_importable_by_its_packaged_name(self, module):
        import importlib

        assert importlib.import_module(module) is not None, (
            f"{module} is not importable; the native engines must be importable "
            f"from an installed s0, not only from a checkout"
        )

    def test_the_old_top_level_names_are_gone(self):
        """Nothing may still import `windows.cli.s0_eraser`.

        That import only ever worked from a source checkout, so it is the exact
        shape of bug being removed.
        """
        offenders = []
        for path in list((REPO_ROOT / "src").rglob("*.py")):
            for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                stripped = line.strip()
                # Only real import statements. A docstring is allowed to *mention*
                # the old name -- the migration note in s0/platform/__init__.py
                # does, and matching prose would make this test fail on the very
                # file that documents the change.
                if not (stripped.startswith("import ") or stripped.startswith("from ")):
                    continue
                if "windows.cli" in stripped or "macos.cli" in stripped:
                    offenders.append(f"{path.relative_to(REPO_ROOT)}: {stripped}")
        assert not offenders, (
            f"these files still import the repository-root engine names, which do "
            f"not exist in an installed distribution: {offenders}"
        )

    def test_the_engines_are_not_shipped_as_top_level_packages(self):
        """A top-level `windows` package would collide in site-packages."""
        assert not (REPO_ROOT / "src" / "windows").exists()
        assert not (REPO_ROOT / "src" / "macos").exists()

    def test_the_existing_platform_module_still_works(self):
        """The engines moved *into* an existing package; its API must survive.

        `src/s0/platform/` already existed with is_block_device and friends. Its
        __init__.py was briefly overwritten during the move, which silently
        removed is_block_device and broke every target probe in the CLI. This
        guards the module that already lived here.
        """
        from s0 import platform

        for name in (
            "is_block_device",
            "is_windows_volume_path",
            "looks_like_windows_volume_letter",
            "darwin_raw_device_path",
        ):
            assert hasattr(platform, name), (
                f"s0.platform.{name} disappeared; the native engines were moved "
                f"into this package and must not have displaced it"
            )


class TestThePackagingConfigurationShipsThem:
    def test_the_package_filter_covers_the_engines(self):
        text = (REPO_ROOT / "pyproject.toml").read_text()
        assert '"s0*"' in text, "the package filter no longer includes s0*, so nothing would ship"
        assert "s0.platform" in text or '"s0*"' in text, (
            "the engines live under s0.platform, which 's0*' covers -- assert this "
            "explicitly so a narrowing of the filter is caught here"
        )

    def test_the_filter_does_not_admit_top_level_platform_packages(self):
        text = (REPO_ROOT / "pyproject.toml").read_text()
        for bad in ('"windows"', '"macos"'):
            assert bad not in text, (
                f"{bad} appears in the packaging configuration; shipping a "
                f"top-level package with that name would collide with any other "
                f"distribution in site-packages"
            )


@pytest.mark.slow
class TestAWheelActuallyContainsTheEngines:
    """The check that would have caught this in the first place."""

    @pytest.fixture(scope="class")
    def wheel(self, tmp_path_factory):
        out = tmp_path_factory.mktemp("wheel")
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "wheel",
                "--no-deps",
                "--no-build-isolation",
                "-w",
                str(out),
                str(REPO_ROOT),
            ],
            capture_output=True,
            text=True,
            timeout=900,
        )
        if proc.returncode != 0:
            pytest.skip(f"wheel build unavailable offline: {proc.stderr[-300:]}")
        wheels = list(out.glob("*.whl"))
        if not wheels:
            pytest.skip("no wheel produced")
        return wheels[0]

    def test_the_engines_are_present(self, wheel):
        names = set(zipfile.ZipFile(wheel).namelist())
        for module in ENGINE_MODULES:
            path = module.replace(".", "/") + ".py"
            assert path in names, (
                f"{path} is missing from {wheel.name}. An installed s0 cannot wipe "
                f"a drive on this platform, and nothing else would report it."
            )

    def test_the_platform_package_data_is_present(self, wheel):
        """The engines import CONFIG and friends from the parent package."""
        names = set(zipfile.ZipFile(wheel).namelist())
        assert "s0/platform/__init__.py" in names

    def test_the_skill_is_still_present(self, wheel):
        """A guard against the move disturbing the rest of the distribution."""
        names = set(zipfile.ZipFile(wheel).namelist())
        assert any(n.startswith("skills/") for n in names), "the agent skill disappeared from the wheel"
        assert any("s0/data/keys" in n for n in names), "the packaged data directory is missing"
