"""Unit tests for s0 live and s0 iso command suite."""

import argparse
import io
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from s0_cli.live_manager import (
    _format_size,
    cmd_live_build,
    cmd_live_devices,
    cmd_live_flash,
    get_removable_usb_devices,
    register_live_parser,
)


def test_format_size():
    assert _format_size(500) == "500.00 B"
    assert _format_size(1024 * 1024 * 500) == "500.00 MB"
    assert _format_size(1024 * 1024 * 1024 * 16) == "16.00 GB"


def test_register_live_parser():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command")
    register_live_parser(sub)

    # Test 'live' subcommands
    args = parser.parse_args(["live", "devices", "--json"])
    assert args.command == "live"
    assert args.live_action == "devices"
    assert args.json is True


def test_cmd_live_devices_empty():
    with patch("s0_cli.live_manager.get_removable_usb_devices", return_value=[]):
        args = argparse.Namespace(json=False)
        assert cmd_live_devices(args) == 0

        args_json = argparse.Namespace(json=True)
        assert cmd_live_devices(args_json) == 0


def test_cmd_live_devices_with_mocked_drives(capsys):
    mock_devs = [
        {
            "path": "/dev/sdb",
            "model": "SanDisk Ultra 3.0",
            "size_bytes": 32000000000,
            "size_human": "32.00 GB",
            "platform": "linux",
        }
    ]
    with patch("s0_cli.live_manager.get_removable_usb_devices", return_value=mock_devs):
        args = argparse.Namespace(json=False)
        assert cmd_live_devices(args) == 0
        captured = capsys.readouterr()
        assert "SanDisk Ultra 3.0" in captured.out
        assert "/dev/sdb" in captured.out


def test_cmd_live_build_platform_guard(monkeypatch, capsys):
    monkeypatch.setattr(sys, "platform", "darwin")
    args = argparse.Namespace(out_dir=".")
    rc = cmd_live_build(args)
    assert rc == 1
    captured = capsys.readouterr()
    assert "natively requires the Linux kernel" in captured.err


def test_cmd_live_flash_safety_refusal(tmp_path, capsys):
    # Create fake ISO
    fake_iso = tmp_path / "s0-live-v2.4.0-amd64.hybrid.iso"
    fake_iso.write_bytes(b"\x00" * (101 * 1024 * 1024))  # 101 MB

    # Target drive that is not a removable USB device
    with patch("s0_cli.live_manager.get_removable_usb_devices", return_value=[]):
        args = argparse.Namespace(
            target="/dev/sda",  # internal OS disk
            iso=str(fake_iso),
            yes=True,
            force=False,
        )
        with patch("os.geteuid", return_value=0):
            rc = cmd_live_flash(args)
            assert rc == 2
            captured = capsys.readouterr()
            assert "Refusing to write to unverified or potentially internal disk" in captured.err


def test_cmd_live_download_redirect_decline(tmp_path, monkeypatch, capsys):
    from s0_cli.live_manager import cmd_live_download

    # Mock latest release with no ISO
    rel_latest = {"tag_name": "v2.4.1", "assets": []}
    # Mock older release with ISO
    rel_older = {
        "tag_name": "v2.4.0",
        "assets": [
            {
                "name": "s0-live-v2.4.0-amd64.hybrid.iso",
                "size": 500000000,
                "browser_download_url": "https://example.com/iso",
            }
        ],
    }

    with patch("s0_cli.live_manager._fetch_github_release", return_value=rel_latest), \
         patch("urllib.request.urlopen") as mock_url:
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps([rel_latest, rel_older]).encode("utf-8")
        mock_url.return_value.__enter__.return_value = mock_resp

        # User types 'n' to decline redirect
        monkeypatch.setattr("sys.stdin.isatty", lambda: True)
        monkeypatch.setattr("builtins.input", lambda prompt: "n")

        args = argparse.Namespace(version="latest", out_dir=str(tmp_path), yes=False)
        rc = cmd_live_download(args)
        assert rc == 0
        captured = capsys.readouterr()
        assert "does not contain a bootable Live ISO asset" in captured.err
        assert "Download cancelled by user" in captured.out
