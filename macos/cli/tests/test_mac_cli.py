"""Tests for macOS CLI module."""

import json
import os
import sys
from pathlib import Path
import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from macos.cli import (
    MacFileEraseResult,
    detect_macos_filesystem,
    erase_batch_macos,
    erase_folder_macos,
    erase_single_file_macos,
    macos_clear_attributes,
    macos_full_fsync,
)
from macos.cli.trustwipe_eraser import main as mac_main
from trustwipe_core import certificate as cert_mod
from trustwipe_core import crypto as core_crypto


def test_mac_cli_single_file_erase(tmp_path: Path):
    f = tmp_path / "classified_doc.pdf"
    f.write_bytes(b"TOP SECRET CLASSIFIED DATA")

    res = erase_single_file_macos(f, passes=1, pattern="zero")
    assert res.status == "success"
    assert res.bytes_overwritten == len(b"TOP SECRET CLASSIFIED DATA")
    assert not f.exists()


def test_mac_cli_folder_erase(tmp_path: Path):
    root = tmp_path / "mac_folder"
    root.mkdir()
    sub = root / "nested"
    sub.mkdir()
    (root / "report.txt").write_bytes(b"FORENSIC REPORT ALPHA")
    (sub / "attachment.bin").write_bytes(b"BINARY PAYLOAD DATA")

    results = erase_folder_macos(root, passes=1, pattern="random")
    assert len(results) == 2
    assert all(r.status == "success" for r in results)
    assert not root.exists()


def test_mac_cli_batch_certificate(tmp_path: Path):
    target_dir = tmp_path / "batch_mac"
    target_dir.mkdir()
    (target_dir / "evidence.dat").write_bytes(b"EVIDENCE CHAIN DATA")

    results, cert = erase_batch_macos([target_dir], passes=1, pattern="zero")
    assert len(results) == 1
    assert cert is not None
    assert cert["tool"]["platform"] == "macos"
    assert cert["signature"]["algorithm"] == "Ed25519"

    # Verify certificate
    pub_key_path = REPO_ROOT / "core" / "keys" / "demo_issuer_public.pem"
    pub_key = core_crypto.load_public_pem(pub_key_path)
    ok, reason = cert_mod.verify_certificate(cert, [pub_key])
    assert ok, reason


def test_mac_cli_main_entrypoint(monkeypatch, tmp_path: Path):
    target = tmp_path / "cli_main_mac.txt"
    target.write_bytes(b"MACOS ENTRYPOINT TEST")
    cert_file = tmp_path / "mac_out.json"

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

    exit_code = mac_main()
    assert exit_code == 0
    assert not target.exists()
    assert cert_file.exists()

    data = json.loads(cert_file.read_text(encoding="utf-8"))
    assert data["tool"]["platform"] == "macos"


def test_mac_cli_fullfsync_fallback():
    """Verify macos_full_fsync falls back to os.fsync on non-Darwin."""
    import tempfile
    with tempfile.NamedTemporaryFile() as tmp:
        # Should not raise even on Linux (falls back to os.fsync)
        macos_full_fsync(tmp.fileno())
