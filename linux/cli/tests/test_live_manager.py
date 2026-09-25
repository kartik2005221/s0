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

    args_dl = parser.parse_args(["live", "download", "--allow-older"])
    assert args_dl.command == "live"
    assert args_dl.live_action == "download"
    assert args_dl.allow_older is True


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


def test_cmd_live_download_redirect_decline_exits_nonzero(tmp_path, monkeypatch, capsys):
    from s0_cli.live_manager import cmd_live_download

    rel_latest = {"tag_name": "v2.4.1", "assets": []}
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

        # User presses Enter without typing (default to no)
        monkeypatch.setattr("sys.stdin.isatty", lambda: True)
        monkeypatch.setattr("builtins.input", lambda prompt: "")

        args = argparse.Namespace(version="latest", out_dir=str(tmp_path), allow_older=False)
        rc = cmd_live_download(args)
        assert rc == 1
        captured = capsys.readouterr()
        assert "does not contain a bootable Live ISO asset" in captured.err
        assert "Download cancelled by user" in captured.out


def test_cmd_live_download_non_interactive_fails_without_allow_older(tmp_path, monkeypatch, capsys):
    from s0_cli.live_manager import cmd_live_download

    rel_latest = {"tag_name": "v2.4.1", "assets": []}
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

        # Non-interactive stdin
        monkeypatch.setattr("sys.stdin.isatty", lambda: False)

        args = argparse.Namespace(version="latest", out_dir=str(tmp_path), allow_older=False)
        rc = cmd_live_download(args)
        assert rc == 1
        captured = capsys.readouterr()
        assert "Pass --allow-older to automatically download" in captured.err


def test_cmd_live_download_redirect_accept_interactive(tmp_path, monkeypatch, capsys):
    import hashlib
    from s0_cli.live_manager import cmd_live_download

    iso_bytes = b"MOCK_BOOTABLE_ISO_BYTES_V240"
    iso_sha = hashlib.sha256(iso_bytes).hexdigest()

    rel_latest = {"tag_name": "v2.4.1", "assets": []}
    rel_older = {
        "tag_name": "v2.4.0",
        "assets": [
            {
                "name": "s0-live-v2.4.0-amd64.hybrid.iso",
                "size": len(iso_bytes),
                "browser_download_url": "https://example.com/s0-live-v2.4.0-amd64.hybrid.iso",
            },
            {
                "name": "s0-live-v2.4.0-amd64.hybrid.iso.sha256",
                "size": 98,
                "browser_download_url": "https://example.com/s0-live-v2.4.0-amd64.hybrid.iso.sha256",
            },
        ],
    }

    def fake_fetch_release(repo, version):
        if version in ("latest", "v2.4.1"):
            return rel_latest
        return rel_older

    def fake_urlopen(req, *args, **kwargs):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        if "sha256" in url:
            return io.BytesIO(f"{iso_sha}  s0-live-v2.4.0-amd64.hybrid.iso\n".encode("utf-8"))
        elif "iso" in url:
            return io.BytesIO(iso_bytes)
        elif "releases" in url:
            return io.BytesIO(json.dumps([rel_latest, rel_older]).encode("utf-8"))
        return io.BytesIO(b"")

    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt: "y")

    with patch("s0_cli.live_manager._fetch_github_release", side_effect=fake_fetch_release), \
         patch("urllib.request.urlopen", side_effect=fake_urlopen):
        args = argparse.Namespace(version="latest", out_dir=str(tmp_path), allow_older=False)
        rc = cmd_live_download(args)
        assert rc == 0

        target_file = tmp_path / "s0-live-v2.4.0-amd64.hybrid.iso"
        assert target_file.is_file()
        assert target_file.read_bytes() == iso_bytes

        captured = capsys.readouterr()
        assert "Fallback release identified: v2.4.0" in captured.out
        assert "Redirecting download to release v2.4.0..." in captured.out
        assert "Integrity Verified: SHA-256 matches official release" in captured.out


def test_cmd_live_download_non_interactive_with_allow_older(tmp_path, monkeypatch, capsys):
    import hashlib
    from s0_cli.live_manager import cmd_live_download

    iso_bytes = b"MOCK_BOOTABLE_ISO_NON_INTERACTIVE"
    iso_sha = hashlib.sha256(iso_bytes).hexdigest()

    rel_latest = {"tag_name": "v2.4.1", "assets": []}
    rel_older = {
        "tag_name": "v2.4.0",
        "assets": [
            {
                "name": "s0-live-v2.4.0-amd64.hybrid.iso",
                "size": len(iso_bytes),
                "browser_download_url": "https://example.com/s0-live-v2.4.0-amd64.hybrid.iso",
            },
            {
                "name": "s0-live-v2.4.0-amd64.hybrid.iso.sha256",
                "size": 98,
                "browser_download_url": "https://example.com/s0-live-v2.4.0-amd64.hybrid.iso.sha256",
            },
        ],
    }

    def fake_fetch_release(repo, version):
        if version in ("latest", "v2.4.1"):
            return rel_latest
        return rel_older

    def fake_urlopen(req, *args, **kwargs):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        if "sha256" in url:
            return io.BytesIO(f"{iso_sha}  s0-live-v2.4.0-amd64.hybrid.iso\n".encode("utf-8"))
        elif "iso" in url:
            return io.BytesIO(iso_bytes)
        elif "releases" in url:
            return io.BytesIO(json.dumps([rel_latest, rel_older]).encode("utf-8"))
        return io.BytesIO(b"")

    monkeypatch.setattr("sys.stdin.isatty", lambda: False)

    with patch("s0_cli.live_manager._fetch_github_release", side_effect=fake_fetch_release), \
         patch("urllib.request.urlopen", side_effect=fake_urlopen):
        args = argparse.Namespace(version="latest", out_dir=str(tmp_path), allow_older=True)
        rc = cmd_live_download(args)
        assert rc == 0

        target_file = tmp_path / "s0-live-v2.4.0-amd64.hybrid.iso"
        assert target_file.is_file()
        assert target_file.read_bytes() == iso_bytes

        captured = capsys.readouterr()
        assert "Non-interactive mode: proceeding with fallback release v2.4.0 (--allow-older specified)." in captured.out
        assert "Integrity Verified: SHA-256 matches official release" in captured.out


def test_cmd_live_download_older_release_checksum_verification_mismatch(tmp_path, monkeypatch, capsys):
    import hashlib
    from s0_cli.live_manager import cmd_live_download

    iso_bytes = b"ACTUAL_DOWNLOADED_ISO_CONTENT"
    tampered_sha = "0000000000000000000000000000000000000000000000000000000000000000"

    rel_latest = {"tag_name": "v2.4.1", "assets": []}
    rel_older = {
        "tag_name": "v2.4.0",
        "assets": [
            {
                "name": "s0-live-v2.4.0-amd64.hybrid.iso",
                "size": len(iso_bytes),
                "browser_download_url": "https://example.com/s0-live-v2.4.0-amd64.hybrid.iso",
            },
            {
                "name": "s0-live-v2.4.0-amd64.hybrid.iso.sha256",
                "size": 98,
                "browser_download_url": "https://example.com/s0-live-v2.4.0-amd64.hybrid.iso.sha256",
            },
        ],
    }

    def fake_fetch_release(repo, version):
        if version in ("latest", "v2.4.1"):
            return rel_latest
        return rel_older

    def fake_urlopen(req, *args, **kwargs):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        if "sha256" in url:
            return io.BytesIO(f"{tampered_sha}  s0-live-v2.4.0-amd64.hybrid.iso\n".encode("utf-8"))
        elif "iso" in url:
            return io.BytesIO(iso_bytes)
        elif "releases" in url:
            return io.BytesIO(json.dumps([rel_latest, rel_older]).encode("utf-8"))
        return io.BytesIO(b"")

    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt: "y")

    with patch("s0_cli.live_manager._fetch_github_release", side_effect=fake_fetch_release), \
         patch("urllib.request.urlopen", side_effect=fake_urlopen):
        args = argparse.Namespace(version="latest", out_dir=str(tmp_path), allow_older=False)
        rc = cmd_live_download(args)
        assert rc == 1

        target_file = tmp_path / "s0-live-v2.4.0-amd64.hybrid.iso"
        assert not target_file.exists()  # Deleted due to mismatch

        captured = capsys.readouterr()
        assert "Integrity Error: Checksum mismatch!" in captured.err


def test_cmd_live_download_does_not_leak_auth_token_on_asset_download(tmp_path, monkeypatch):
    """Ensure GITHUB_TOKEN is not included in download headers for release assets (Bug #3)."""
    import hashlib
    from s0_cli.live_manager import cmd_live_download

    iso_bytes = b"ISO_CONTENT"
    iso_sha = hashlib.sha256(iso_bytes).hexdigest()

    rel = {
        "tag_name": "v2.4.1",
        "assets": [
            {
                "name": "s0-live-v2.4.1-amd64.hybrid.iso",
                "size": len(iso_bytes),
                "browser_download_url": "https://github.com/releases/download/v2.4.1/s0-live.iso",
            },
            {
                "name": "s0-live-v2.4.1-amd64.hybrid.iso.sha256",
                "size": 98,
                "browser_download_url": "https://github.com/releases/download/v2.4.1/s0-live.iso.sha256",
            },
        ],
    }

    monkeypatch.setenv("GITHUB_TOKEN", "ghp_SECRET_TOKEN_DO_NOT_LEAK")
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)

    download_requests = []

    def fake_urlopen(req, *args, **kwargs):
        download_requests.append(req)
        url = req.full_url if hasattr(req, "full_url") else str(req)
        if "sha256" in url:
            return io.BytesIO(f"{iso_sha}  s0-live-v2.4.1-amd64.hybrid.iso\n".encode("utf-8"))
        elif "iso" in url:
            return io.BytesIO(iso_bytes)
        return io.BytesIO(b"")

    with patch("s0_cli.live_manager._fetch_github_release", return_value=rel), \
         patch("urllib.request.urlopen", side_effect=fake_urlopen):
        args = argparse.Namespace(version="latest", out_dir=str(tmp_path), allow_older=False)
        rc = cmd_live_download(args)
        assert rc == 0

    assert len(download_requests) >= 2
    for r in download_requests:
        headers = {k.lower(): v for k, v in r.headers.items()}
        assert "authorization" not in headers

