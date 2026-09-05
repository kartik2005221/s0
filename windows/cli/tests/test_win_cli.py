"""Tests for Windows CLI module."""

import json
import os
import sys
from pathlib import Path
import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from windows.cli import (
    WIN32_FIND_STREAM_DATA,
    detect_windows_filesystem,
    enumerate_ntfs_streams_win32,
    erase_batch_windows,
    erase_folder_windows,
    erase_single_file_windows,
    scrub_alternate_data_streams,
)
from windows.cli.trustwipe_eraser import main as win_main
from trustwipe_core import certificate as cert_mod
from trustwipe_core import crypto as core_crypto


def test_win_cli_single_file_erase(tmp_path: Path):
    f = tmp_path / "test_doc.docx"
    f.write_bytes(b"SENSITIVE FINANCIAL AUDIT DATA")

    res = erase_single_file_windows(f, passes=1, pattern="zero")
    assert res.status == "success"
    assert res.bytes_overwritten == len(b"SENSITIVE FINANCIAL AUDIT DATA")
    assert not f.exists()


def test_win_cli_folder_erase(tmp_path: Path):
    root = tmp_path / "win_folder"
    root.mkdir()
    sub = root / "sub"
    sub.mkdir()
    (root / "file1.txt").write_bytes(b"SECRET 1")
    (sub / "file2.txt").write_bytes(b"SECRET 2")

    results = erase_folder_windows(root, passes=1, pattern="random")
    assert len(results) == 2
    assert all(r.status == "success" for r in results)
    assert not root.exists()


def test_win_cli_batch_certificate(tmp_path: Path):
    target_dir = tmp_path / "batch_dir"
    target_dir.mkdir()
    (target_dir / "target.dat").write_bytes(b"FORENSIC TARGET DATA")

    results, cert = erase_batch_windows([target_dir], passes=1, pattern="zero")
    assert len(results) == 1
    assert cert is not None
    assert cert["tool"]["platform"] == "windows"
    assert cert["signature"]["algorithm"] == "Ed25519"

    # Verify certificate
    pub_key_path = REPO_ROOT / "core" / "keys" / "demo_issuer_public.pem"
    pub_key = core_crypto.load_public_pem(pub_key_path)
    ok, reason = cert_mod.verify_certificate(cert, [pub_key])
    assert ok, reason


def test_win_cli_main_entrypoint(monkeypatch, tmp_path: Path):
    target = tmp_path / "cli_main.txt"
    target.write_bytes(b"ENTRYPOINT TEST")
    cert_file = tmp_path / "win_out.json"

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "trustwipe_eraser.py",
            "--targets",
            str(target),
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
    assert not target.exists()
    assert cert_file.exists()

    data = json.loads(cert_file.read_text(encoding="utf-8"))
    assert data["tool"]["platform"] == "windows"
