"""Unit tests for TrustWipe Module 2: Secure File & Folder Eraser."""

import os
from pathlib import Path

import pytest
from trustwipe_cli.file_eraser import (
    erase_single_file,
    erase_folder,
    erase_batch,
    get_file_extents,
)
from trustwipe_core.certificate import verify_certificate
from trustwipe_core.crypto import load_public_pem


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
        operator_id="op-ntro-test",
        organization="NTRO Forensic Lab",
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
