"""Tests for scripts/release.py release automation script."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from release import (
    check_sync_status,
    get_current_config_version,
    sync_all_files,
    validate_version,
)


def test_validate_version():
    """Test semver validation."""
    validate_version("2.4.2")
    validate_version("3.0.0")
    validate_version("1.0.0-rc1")
    validate_version("2.4.3-alpha.1")

    with pytest.raises(ValueError, match="Invalid semver"):
        validate_version("invalid")
    with pytest.raises(ValueError, match="Invalid semver"):
        validate_version("1.2")
    with pytest.raises(ValueError, match="Invalid semver"):
        validate_version("v2.4.2")


def test_get_current_config_version():
    """Test reading current version from s0_config.json."""
    ver = get_current_config_version()
    assert isinstance(ver, str)
    validate_version(ver)


def test_check_sync_status():
    """Test check_sync_status returns 0 when repo is in sync."""
    assert check_sync_status() == 0


def test_dry_run_sync():
    """Test dry-run file synchronization does not mutate disk."""
    initial_ver = get_current_config_version()
    modified = sync_all_files("9.9.9", dry_run=True)
    assert len(modified) > 0

    # Ensure s0_config.json was not actually changed
    assert get_current_config_version() == initial_ver


def test_cli_invocation_check():
    """Test running scripts/release.py --check via subprocess."""
    ver = get_current_config_version()
    script_path = REPO_ROOT / "scripts" / "release.py"
    res = subprocess.run([sys.executable, str(script_path), "--check"], capture_output=True, text=True)
    assert res.returncode == 0
    assert f"All files are in sync with v{ver}" in res.stdout
