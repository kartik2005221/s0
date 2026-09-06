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


def test_mac_cli_wipe_safety_refusal():
    from macos.cli import check_macos_wipe_safety

    # disk0 / rdisk0 without force must be refused
    with pytest.raises(PermissionError, match="SAFETY REFUSAL"):
        check_macos_wipe_safety("/dev/disk0", force=False)

    with pytest.raises(PermissionError, match="SAFETY REFUSAL"):
        check_macos_wipe_safety("/dev/rdisk0", force=False)

    with pytest.raises(PermissionError, match="SAFETY REFUSAL"):
        check_macos_wipe_safety("/dev/disk0s2", force=False)

    # Removable drive or force override should pass safety check
    check_macos_wipe_safety("/dev/rdisk2")
    check_macos_wipe_safety("/dev/disk2s1")
    check_macos_wipe_safety("/dev/disk0", force=True)


def test_mac_cli_wipe_partition_success(tmp_path: Path):
    from macos.cli import wipe_drive_or_partition_macos

    # Create mock secondary partition / USB drive (1 MiB)
    drive_img = tmp_path / "mac_usb_drive.raw"
    drive_img.write_bytes(b"TOP SECRET APFS SECTORS" * 45000)

    result, cert = wipe_drive_or_partition_macos(
        str(drive_img),
        passes=1,
        pattern="zero",
        mock_size=drive_img.stat().st_size,
    )

    assert result.status == "success"
    assert result.verification_passed is True
    assert result.samples_checked == 32
    assert result.bytes_overwritten == drive_img.stat().st_size

    # Verify drive raw bytes are entirely 0x00
    wiped_data = drive_img.read_bytes()
    assert wiped_data == b"\x00" * len(wiped_data)

    # Verify cryptographic certificate
    assert cert is not None
    assert cert["tool"]["platform"] == "macos"
    assert cert["signature"]["algorithm"] == "Ed25519"
    pub_key = core_crypto.load_public_pem(REPO_ROOT / "core" / "keys" / "demo_issuer_public.pem")
    ok, reason = cert_mod.verify_certificate(cert, [pub_key])
    assert ok, reason


def test_mac_cli_wipe_drive_main(monkeypatch, tmp_path: Path):
    drive_img = tmp_path / "mac_usb_stick.img"
    drive_img.write_bytes(b"CONFIDENTIAL MAC DATA" * 1024)
    cert_file = tmp_path / "mac_drive_cert.json"

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "trustwipe_eraser.py",
            "--wipe-drive",
            str(drive_img),
            "--yes",
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
    assert cert_file.exists()
    cert_data = json.loads(cert_file.read_text(encoding="utf-8"))
    assert cert_data["tool"]["platform"] == "macos"
    assert cert_data["result"]["status"] == "success"


def test_mac_cli_pdf_and_qr_generation(monkeypatch, tmp_path: Path, capsys):
    f = tmp_path / "mac_report_target.txt"
    f.write_bytes(b"DATA FOR MAC PDF REPORT TEST")
    out_dir = tmp_path / "reports_mac"

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "trustwipe_eraser.py",
            "--targets",
            str(f),
            "--out-dir",
            str(out_dir),
        ],
    )

    exit_code = mac_main()
    assert exit_code == 0
    captured = capsys.readouterr().out
    assert "S0 (macOS NATIVE)" in captured
    assert "PDF Certificate" in captured

    # Verify JSON, PDF, and QR artifacts
    jsons = list(out_dir.glob("*.json"))
    pdfs = list(out_dir.glob("*.pdf"))
    qrs = list(out_dir.glob("*.qr.png"))
    assert len(jsons) == 1
    assert len(pdfs) == 1
    assert len(qrs) == 1
    assert pdfs[0].stat().st_size > 0
    assert qrs[0].stat().st_size > 0


def test_mac_cli_no_pdf_flag(monkeypatch, tmp_path: Path):
    f = tmp_path / "mac_nopdf_target.txt"
    f.write_bytes(b"DATA FOR MAC NO PDF TEST")
    out_dir = tmp_path / "reports_mac_nopdf"

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "trustwipe_eraser.py",
            "--targets",
            str(f),
            "--out-dir",
            str(out_dir),
            "--no-pdf",
        ],
    )

    exit_code = mac_main()
    assert exit_code == 0
    assert len(list(out_dir.glob("*.json"))) == 1
    assert len(list(out_dir.glob("*.pdf"))) == 0

