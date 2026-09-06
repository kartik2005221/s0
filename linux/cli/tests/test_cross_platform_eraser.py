"""Tests for Cross-Platform File & Folder Eraser Module (Linux, Windows, macOS)."""

import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pytest
from macos.s0_eraser import (
    erase_batch_macos,
    erase_folder_macos,
    erase_single_file_macos,
)
from s0_cli.file_eraser import (
    detect_cow_and_filesystem,
    erase_batch,
    erase_folder,
    erase_single_file,
    platform_cleanse_attributes,
    platform_sync,
)
from s0_core import certificate as cert_mod
from s0_core import crypto as core_crypto
from windows.s0_eraser import (
    WIN32_FIND_STREAM_DATA,
    enumerate_ntfs_streams_win32,
    erase_batch_windows,
    erase_folder_windows,
    erase_single_file_windows,
    scrub_alternate_data_streams,
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


def test_windows_batch_signed_certificate(tmp_path: Path):
    """Test Windows eraser batch operation and cryptographic Ed25519 certificate issuance."""
    test_dir = tmp_path / "win_batch_test"
    test_dir.mkdir()
    f1 = test_dir / "confidential_win.docx"
    f1.write_bytes(b"CONFIDENTIAL WIN32 DOCUMENT")
    sub = test_dir / "sub"
    sub.mkdir()
    f2 = sub / "finance.xlsx"
    f2.write_bytes(b"FINANCIAL SPREADSHEET CONTENT")

    results, signed_cert = erase_batch_windows([test_dir], passes=1, pattern="zero")

    assert len(results) == 2
    assert all(r.status == "success" for r in results)
    assert not test_dir.exists()
    assert signed_cert is not None

    # Schema validation
    problems = cert_mod.validate(signed_cert, require_signature=True)
    assert problems == [], f"Certificate schema validation failed: {problems}"

    # Verify certificate content
    assert signed_cert["tool"]["platform"] == "windows"
    assert signed_cert["wipe"]["nist_category"] == "Clear"
    assert signed_cert["signature"]["algorithm"] == "Ed25519"
    assert signed_cert["result"]["status"] == "success"

    # Cryptographic verification against pinned public key
    pub_key_path = REPO_ROOT / "core" / "keys" / "demo_issuer_public.pem"
    pub_key = core_crypto.load_public_pem(pub_key_path)
    ok, reason = cert_mod.verify_certificate(signed_cert, [pub_key])
    assert ok, f"Certificate verification failed: {reason}"


def test_macos_batch_signed_certificate(tmp_path: Path):
    """Test macOS eraser batch operation and cryptographic Ed25519 certificate issuance."""
    test_dir = tmp_path / "mac_batch_test"
    test_dir.mkdir()
    f1 = test_dir / "confidential_mac.pdf"
    f1.write_bytes(b"CONFIDENTIAL MACOS DOCUMENT")
    sub = test_dir / "sub_mac"
    sub.mkdir()
    f2 = sub / "passwords.plist"
    f2.write_bytes(b"PASSWORDS PLIST DATA")

    results, signed_cert = erase_batch_macos([test_dir], passes=1, pattern="zero")

    assert len(results) == 2
    assert all(r.status == "success" for r in results)
    assert not test_dir.exists()
    assert signed_cert is not None

    # Schema validation
    problems = cert_mod.validate(signed_cert, require_signature=True)
    assert problems == [], f"Certificate schema validation failed: {problems}"

    # Verify certificate content
    assert signed_cert["tool"]["platform"] == "macos"
    assert signed_cert["wipe"]["nist_category"] == "Clear"
    assert signed_cert["signature"]["algorithm"] == "Ed25519"
    assert signed_cert["result"]["status"] == "success"

    # Cryptographic verification against pinned public key
    pub_key_path = REPO_ROOT / "core" / "keys" / "demo_issuer_public.pem"
    pub_key = core_crypto.load_public_pem(pub_key_path)
    ok, reason = cert_mod.verify_certificate(signed_cert, [pub_key])
    assert ok, f"Certificate verification failed: {reason}"


def test_windows_dynamic_ads_enumeration_mock(monkeypatch, tmp_path: Path):
    """Verify that dynamic Win32 stream enumeration correctly parses stream structures."""
    # Test ctypes structure definition
    struct_inst = WIN32_FIND_STREAM_DATA()
    assert hasattr(struct_inst, "StreamSize")
    assert hasattr(struct_inst, "cStreamName")

    # In non-Windows Linux test environment, native call safely returns []
    native_streams = enumerate_ntfs_streams_win32(str(tmp_path))
    assert native_streams == []

    # Mock kernel32 to test the enumeration logic directly
    import ctypes

    class MockKernel32:
        def __init__(self):
            self._call_count = 0

        def FindFirstStreamW(self, filename, level, find_data, flags):
            # Populate first stream: ":Zone.Identifier:$DATA"
            data = ctypes.cast(find_data, ctypes.POINTER(WIN32_FIND_STREAM_DATA)).contents
            data.cStreamName = ":Zone.Identifier:$DATA"
            data.StreamSize = 128
            self._call_count = 1
            return 12345  # valid handle

        def FindNextStreamW(self, h_find, find_data):
            if self._call_count == 1:
                # Populate second stream: ":CustomPayload:$DATA"
                data = ctypes.cast(find_data, ctypes.POINTER(WIN32_FIND_STREAM_DATA)).contents
                data.cStreamName = ":CustomPayload:$DATA"
                data.StreamSize = 512
                self._call_count = 2
                return 1
            # End of streams
            return 0

        def FindClose(self, h_find):
            return 1

    mock_windll = type("MockWinDll", (), {"kernel32": MockKernel32()})()
    monkeypatch.setattr(ctypes, "windll", mock_windll, raising=False)

    streams = enumerate_ntfs_streams_win32(str(tmp_path / "dummy.txt"))
    assert len(streams) == 2
    assert streams[0] == (":Zone.Identifier:$DATA", 128)
    assert streams[1] == (":CustomPayload:$DATA", 512)


def test_windows_cli_main(monkeypatch, tmp_path: Path):
    """Test windows/s0_eraser.py main CLI invocation."""
    from windows.s0_eraser import main as win_main

    f = tmp_path / "cli_target_win.txt"
    f.write_bytes(b"DATA FOR WIN MAIN TEST")
    cert_file = tmp_path / "custom_cert.json"

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "s0_eraser.py",
            "--targets",
            str(f),
            "--passes",
            "1",
            "--pattern",
            "zero",
            "--cert-out",
            str(cert_file),
        ],
    )

    exit_code = win_main()
    assert exit_code == 0
    assert not f.exists()
    assert cert_file.exists()

    data = json.loads(cert_file.read_text(encoding="utf-8"))
    assert data["tool"]["platform"] == "windows"
    assert data["signature"]["algorithm"] == "Ed25519"


def test_macos_cli_main(monkeypatch, tmp_path: Path):
    """Test macos/s0_eraser.py main CLI invocation."""
    from macos.s0_eraser import main as mac_main

    f = tmp_path / "cli_target_mac.txt"
    f.write_bytes(b"DATA FOR MAC MAIN TEST")
    cert_file = tmp_path / "custom_mac_cert.json"

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "s0_eraser.py",
            "--targets",
            str(f),
            "--passes",
            "1",
            "--pattern",
            "zero",
            "--cert-out",
            str(cert_file),
        ],
    )

    exit_code = mac_main()
    assert exit_code == 0
    assert not f.exists()
    assert cert_file.exists()

    data = json.loads(cert_file.read_text(encoding="utf-8"))
    assert data["tool"]["platform"] == "macos"
    assert data["signature"]["algorithm"] == "Ed25519"


