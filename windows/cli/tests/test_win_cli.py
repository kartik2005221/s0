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
from windows.cli.s0_eraser import main as win_main
from s0_core import certificate as cert_mod
from s0_core import crypto as core_crypto


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
            "s0_eraser.py",
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


def test_win_cli_wipe_safety_refusal():
    from windows.cli import check_windows_wipe_safety

    # C: must be refused
    with pytest.raises(PermissionError, match="SAFETY REFUSAL"):
        check_windows_wipe_safety("C:")

    with pytest.raises(PermissionError, match="SAFETY REFUSAL"):
        check_windows_wipe_safety(r"\\.\C:")

    with pytest.raises(PermissionError, match="SAFETY REFUSAL"):
        check_windows_wipe_safety("c:\\")

    # PhysicalDrive0 without force must be refused
    with pytest.raises(PermissionError, match="SAFETY REFUSAL"):
        check_windows_wipe_safety(r"\\.\PhysicalDrive0", force=False)

    # Secondary drives should pass safety check
    check_windows_wipe_safety("D:")
    check_windows_wipe_safety(r"\\.\PhysicalDrive1")
    check_windows_wipe_safety(r"\\.\PhysicalDrive0", force=True)


def test_win_cli_wipe_partition_success(tmp_path: Path):
    from windows.cli import wipe_drive_or_partition_windows

    # Create mock secondary partition / USB drive (1 MiB)
    drive_img = tmp_path / "usb_pendrive.raw"
    drive_img.write_bytes(b"SENSITIVE SECTORS" * 65536)  # ~1.1 MiB

    result, cert = wipe_drive_or_partition_windows(
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
    assert cert["tool"]["platform"] == "windows"
    assert cert["signature"]["algorithm"] == "Ed25519"
    pub_key = core_crypto.load_public_pem(REPO_ROOT / "core" / "keys" / "demo_issuer_public.pem")
    ok, reason = cert_mod.verify_certificate(cert, [pub_key])
    assert ok, reason


def test_win_cli_wipe_drive_main(monkeypatch, tmp_path: Path):
    drive_img = tmp_path / "usb_stick.img"
    drive_img.write_bytes(b"CONFIDENTIAL USB DATA" * 1024)
    cert_file = tmp_path / "win_drive_cert.json"

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "s0_eraser.py",
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

    exit_code = win_main()
    assert exit_code == 0
    assert cert_file.exists()
    cert_data = json.loads(cert_file.read_text(encoding="utf-8"))
    assert cert_data["tool"]["platform"] == "windows"
    assert cert_data["result"]["status"] == "success"


def test_win_cli_pdf_and_qr_generation(monkeypatch, tmp_path: Path, capsys):
    f = tmp_path / "win_report_target.txt"
    f.write_bytes(b"DATA FOR WIN PDF REPORT TEST")
    out_dir = tmp_path / "reports_win"

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "s0_eraser.py",
            "--targets",
            str(f),
            "--out-dir",
            str(out_dir),
        ],
    )

    exit_code = win_main()
    assert exit_code == 0
    captured = capsys.readouterr().out
    assert "S0 (WINDOWS NATIVE)" in captured
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


def test_win_cli_no_pdf_flag(monkeypatch, tmp_path: Path):
    f = tmp_path / "win_nopdf_target.txt"
    f.write_bytes(b"DATA FOR WIN NO PDF TEST")
    out_dir = tmp_path / "reports_win_nopdf"

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "s0_eraser.py",
            "--targets",
            str(f),
            "--out-dir",
            str(out_dir),
            "--no-pdf",
        ],
    )

    exit_code = win_main()
    assert exit_code == 0
    assert len(list(out_dir.glob("*.json"))) == 1
    assert len(list(out_dir.glob("*.pdf"))) == 0


def test_win_cli_subcommand_dispatch(tmp_path: Path):
    target = tmp_path / "sub_test.txt"
    target.write_bytes(b"SUBCOMMAND DISPATCH TEST")
    out_dir = tmp_path / "sub_out"

    # Test invoking with 'wipe' subcommand directly via win_main(argv)
    code = win_main([
        "wipe",
        "--targets", str(target),
        "--out-dir", str(out_dir),
        "--no-pdf",
    ])
    assert code == 0
    assert not target.exists()


def test_win_cli_flag_aliases(monkeypatch, tmp_path: Path):
    target = tmp_path / "alias_test.txt"
    target.write_bytes(b"FLAG ALIAS TEST")
    out_dir = tmp_path / "alias_out"
    key_file = REPO_ROOT / "core" / "keys" / "demo_issuer_private.pem"

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "s0_eraser.py",
            "-t", str(target),
            "-p", "1",
            "--key", str(key_file),
            "--operator", "op-test-win",
            "--out-dir", str(out_dir),
            "--no-pdf",
        ],
    )
    assert win_main() == 0
    assert not target.exists()


