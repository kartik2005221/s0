"""Tests for Cross-Platform File & Folder Eraser Module (Linux, Windows, macOS)."""

import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pytest
from macos.trustwipe_eraser import (
    erase_folder_macos,
    erase_single_file_macos,
)
from trustwipe_cli.file_eraser import (
    detect_cow_and_filesystem,
    erase_batch,
    erase_folder,
    erase_single_file,
    platform_cleanse_attributes,
    platform_sync,
)
from windows.trustwipe_eraser import (
    erase_folder_windows,
    erase_single_file_windows,
)


def test_recursive_folder_erasure(tmp_path: Path):
    """Test full recursive sanitization of nested folders and files."""
    root_dir = tmp_path / "top_secret_folder"
    sub_dir = root_dir / "sub_folder"
    sub_dir.mkdir(parents=True)

    f1 = root_dir / "file1.txt"
    f2 = sub_dir / "file2.conf"
    f3 = sub_dir / "file3.dat"

    f1.write_bytes(b"TOP SECRET INTELLIGENCE DATA")
    f2.write_bytes(b"INTERNAL SYSTEM CONFIGURATION")
    f3.write_bytes(b"FORENSIC TARGET CLUSTERS")

    summary = erase_batch([root_dir], passes=1, pattern="zero")

    assert summary.total_files == 3
    assert summary.successful_files == 3
    assert summary.failed_files == 0
    assert not f1.exists()
    assert not f2.exists()
    assert not f3.exists()
    assert not sub_dir.exists()
    assert not root_dir.exists()
    assert summary.certificate is not None
    assert summary.certificate["result"]["verification"]["all_samples_match_wipe_pattern"] is True


def test_cross_platform_cow_and_filesystem_detection(tmp_path: Path):
    test_f = tmp_path / "sample.bin"
    test_f.write_bytes(b"TEST BYTES")

    fs_name, cow_warning = detect_cow_and_filesystem(str(test_f))
    assert isinstance(fs_name, str)
    # cow_warning is None on ext4/tmpfs, or str if on btrfs/zfs/apfs/refs
    if cow_warning is not None:
        assert "CoW" in cow_warning or "Copy-on-Write" in cow_warning


def test_platform_attribute_cleanse_and_sync(tmp_path: Path):
    test_f = tmp_path / "read_only.txt"
    test_f.write_bytes(b"READ ONLY DATA")

    platform_cleanse_attributes(str(test_f))

    with open(test_f, "r+b") as f:
        f.write(b"\x00" * len(b"READ ONLY DATA"))
        f.flush()
        platform_sync(f.fileno())

    res = erase_single_file(test_f, passes=1, pattern="zero")
    assert res.status == "success"
    assert not test_f.exists()


def test_windows_eraser_standalone_module(tmp_path: Path):
    """Test Windows-specific eraser functions."""
    win_dir = tmp_path / "win_test_dir"
    win_dir.mkdir()
    f1 = win_dir / "evidence_win.docx"
    f1.write_bytes(b"WIN32 EVIDENCE CONTENT")

    res = erase_single_file_windows(f1, passes=1, pattern="zero")
    assert res.status == "success"
    assert not f1.exists()

    # Test folder erasure
    sub = win_dir / "nested"
    sub.mkdir()
    f2 = sub / "passwords.txt"
    f2.write_bytes(b"SECRET PASSWORDS")

    f_results = erase_folder_windows(win_dir, passes=1, pattern="zero")
    assert len(f_results) == 1
    assert f_results[0].status == "success"
    assert not win_dir.exists()


def test_macos_eraser_standalone_module(tmp_path: Path):
    """Test macOS-specific eraser functions."""
    mac_dir = tmp_path / "mac_test_dir"
    mac_dir.mkdir()
    f1 = mac_dir / "evidence_mac.pdf"
    f1.write_bytes(b"DARWIN EVIDENCE CONTENT")

    res = erase_single_file_macos(f1, passes=1, pattern="zero")
    assert res.status == "success"
    assert not f1.exists()

    # Test folder erasure
    sub = mac_dir / "nested_mac"
    sub.mkdir()
    f2 = sub / "keychain_dump.txt"
    f2.write_bytes(b"MACOS KEYCHAIN DUMP")

    f_results = erase_folder_macos(mac_dir, passes=1, pattern="zero")
    assert len(f_results) == 1
    assert f_results[0].status == "success"
    assert not mac_dir.exists()
