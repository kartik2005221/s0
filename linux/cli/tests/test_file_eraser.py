"""Unit tests for s0 Module 1: Secure File & Folder Eraser."""

import os
from pathlib import Path

import pytest
from s0_cli.file_eraser import (
    erase_single_file,
    erase_folder,
    erase_batch,
    get_file_extents,
)
from s0_core.certificate import verify_certificate
from s0_core.crypto import load_public_pem


@pytest.fixture
def temp_test_env(tmp_path):
    # Create test directory with sample files
    test_dir = tmp_path / "target_dir"
    test_dir.mkdir()

    file1 = test_dir / "secret1.txt"
    file1.write_bytes(b"TOP-SECRET-DATA-PAN-AADHAAR" * 100)

    file2 = test_dir / "secret2.bin"
    file2.write_bytes(b"NON_NULL_TEST_PAYLOAD" * 200)

    sub_dir = test_dir / "nested"
    sub_dir.mkdir()
    file3 = sub_dir / "secret3.doc"
    file3.write_bytes(b"CLASSIFIED INTELLIGENCE REPORT" * 50)

    return test_dir, file1, file2, sub_dir, file3


def test_erase_single_file_zero_pass(tmp_path):
    f = tmp_path / "evidence.dat"
    data = b"CONFIDENTIAL EVIDENCE 12345" * 200
    f.write_bytes(data)
    size = len(data)

    res = erase_single_file(f, passes=1, pattern="zero")
    assert res.status == "success"
    assert res.original_size == size
    assert res.bytes_overwritten == size
    assert res.metadata_cleansed is True
    assert not f.exists()


def test_erase_single_file_random_multi_pass(tmp_path):
    f = tmp_path / "evidence_rnd.dat"
    data = b"CLASSIFIED" * 100
    f.write_bytes(data)
    size = len(data)

    res = erase_single_file(f, passes=3, pattern="random")
    assert res.status == "success"
    assert res.original_size == size
    assert res.bytes_overwritten == size * 3
    assert not f.exists()


def test_erase_nonexistent_file(tmp_path):
    f = tmp_path / "does_not_exist.txt"
    res = erase_single_file(f)
    assert res.status == "failure"
    assert "not an existing regular file" in res.error


def test_erase_folder_recursive(temp_test_env):
    test_dir, file1, file2, sub_dir, file3 = temp_test_env
    assert test_dir.exists()
    assert file1.exists()
    assert file3.exists()

    results = erase_folder(test_dir, passes=1, pattern="zero")
    assert len(results) == 3
    assert all(r.status == "success" for r in results)
    assert not test_dir.exists()
    assert not file1.exists()
    assert not file3.exists()


def test_erase_batch_with_certificate(temp_test_env):
    test_dir, file1, file2, sub_dir, file3 = temp_test_env
    demo_pub_key = Path(__file__).resolve().parents[3] / "core" / "keys" / "demo_issuer_public.pem"

    summary = erase_batch(
        [file1, sub_dir],
        passes=1,
        pattern="zero",
        operator_id="op-test",
        organization="Forensic Lab",
    )

    assert summary.total_files == 2  # file1 and file3 inside sub_dir
    assert summary.successful_files == 2
    assert summary.failed_files == 0
    assert summary.certificate is not None

    pub = load_public_pem(demo_pub_key)
    ok, reason = verify_certificate(summary.certificate, [pub])
    assert ok is True
    assert "valid Ed25519 signature" in reason


def test_erase_symlink_rejected(tmp_path):
    """Verify that symlinks to files or directories are safely rejected without following."""
    real_file = tmp_path / "real_file.txt"
    real_file.write_bytes(b"REAL_PROTECTED_DATA")

    symlink_file = tmp_path / "symlink_file.txt"
    symlink_file.symlink_to(real_file)

    res = erase_single_file(symlink_file)
    assert res.status == "failure"
    assert "symlink" in res.error.lower()

    # The target of the symlink must remain untouched!
    assert real_file.exists()
    assert real_file.read_bytes() == b"REAL_PROTECTED_DATA"


def test_s0_wipe_cli_file_pdf_and_qr(tmp_path):
    from s0_cli.main import main as s0_main
    target = tmp_path / "erase_target.txt"
    target.write_bytes(b"DATA FOR S0 ERASE PDF TEST")
    out_dir = tmp_path / "s0_erase_out"

    rc = s0_main(["wipe", "--targets", str(target), "--out-dir", str(out_dir)])
    assert rc == 0
    assert not target.exists()

    jsons = list(out_dir.glob("*.json"))
    pdfs = list(out_dir.glob("*.pdf"))
    qrs = list(out_dir.glob("*.qr.png"))
    assert len(jsons) == 1
    assert len(pdfs) == 1
    assert len(qrs) == 1
    assert pdfs[0].stat().st_size > 0
    assert qrs[0].stat().st_size > 0

    # Test auto-detection via single --target
    target2 = tmp_path / "erase_target2.txt"
    target2.write_bytes(b"DATA FOR SINGLE TARGET AUTO DETECT")
    rc2 = s0_main(["wipe", "--target", str(target2), "--out-dir", str(out_dir)])
    assert rc2 == 0
    assert not target2.exists()


def test_erase_hardlink_safety(tmp_path):
    from s0_cli.file_eraser import erase_single_file

    orig = tmp_path / "original.txt"
    orig.write_bytes(b"SHARED HARDLINK DATA")

    link = tmp_path / "hardlink.txt"
    os.link(orig, link)

    assert orig.stat().st_nlink == 2

    # 1. Refuse erasure without --force
    res = erase_single_file(orig, force=False)
    assert res.status == "failure"
    assert "hard links" in res.error
    assert orig.exists()
    assert link.exists()

    # 2. Allow with force=True
    res_force = erase_single_file(orig, force=True)
    assert res_force.status == "success"
    assert not orig.exists()

