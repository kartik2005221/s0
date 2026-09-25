"""Unit tests for s0 forensic bit-stream imaging and drive cloning."""

import hashlib
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
from s0_cli.imager import BadSectorRange, ImagingOptions, acquire_image
from s0_cli.main import main
from s0_core.certificate import verify_certificate
from s0_core.crypto import load_public_pem


@pytest.fixture
def temp_workspace():
    with tempfile.TemporaryDirectory() as td:
        yield Path(td)


def test_basic_image_acquisition(temp_workspace):
    # 1. Create source file with test data
    src_file = temp_workspace / "evidence_disk.raw"
    test_data = b"FORENSIC_EVIDENCE_SECTOR_0" * 4096 + os.urandom(65536)
    src_file.write_bytes(test_data)

    dst_file = temp_workspace / "image_replica.raw"
    out_dir = temp_workspace / "manifests"

    options = ImagingOptions(
        source=str(src_file),
        destination=str(dst_file),
        block_size=16384,
        out_dir=str(out_dir),
        operator="investigator-42",
        organization="Cyber Forensics Unit",
    )

    result = acquire_image(options)

    # 2. Verify bit-stream identity
    assert result.success is True
    assert dst_file.is_file()
    assert dst_file.read_bytes() == test_data

    # 3. Verify cryptographic hashes
    expected_sha256 = hashlib.sha256(test_data).hexdigest()
    expected_md5 = hashlib.md5(test_data).hexdigest()
    assert result.source_sha256 == expected_sha256
    assert result.source_md5 == expected_md5
    assert result.bad_sectors_count == 0

    # 4. Verify manifest file contents
    assert result.manifest_path is not None
    manifest_p = Path(result.manifest_path)
    assert manifest_p.is_file()
    manifest_data = json.loads(manifest_p.read_text(encoding="utf-8"))
    assert manifest_data["operation"] == "FORENSIC_IMAGING"
    assert manifest_data["cryptographic_hashes"]["sha256"] == expected_sha256
    assert manifest_data["source"]["capacity_bytes"] == len(test_data)
    assert manifest_data["destination"]["bytes_written"] == len(test_data)


def test_safety_refusal_same_target(temp_workspace):
    src_file = temp_workspace / "same.raw"
    src_file.write_bytes(b"data" * 1024)

    options = ImagingOptions(
        source=str(src_file),
        destination=str(src_file),
    )

    from s0_cli.devices import SafetyError
    with pytest.raises(SafetyError, match="cannot be the same target"):
        acquire_image(options)


def test_fault_tolerant_bad_sector_handling(temp_workspace):
    src_file = temp_workspace / "failing_disk.raw"
    # Create 8KB of test data
    test_data = bytearray(b"A" * 8192)
    src_file.write_bytes(test_data)
    dst_file = temp_workspace / "recovered.raw"

    options = ImagingOptions(
        source=str(src_file),
        destination=str(dst_file),
        block_size=4096,
        sector_size=512,
        error_recovery=True,
        out_dir=str(temp_workspace),
    )

    # Simulate read error on second 4KB chunk, and sector read failure at offset 4608
    original_open = open
    class MockFailingFile:
        def __init__(self, real_f):
            self._f = real_f
            self._has_errored = False

        def read(self, size=-1):
            pos = self._f.tell()
            if pos == 4096 and not self._has_errored:
                self._has_errored = True
                raise OSError("Simulated hardware I/O read error")
            if pos == 4608:
                raise OSError("Simulated bad physical sector (UNC error)")
            return self._f.read(size)

        def seek(self, offset, whence=0):
            return self._f.seek(offset, whence)

        def tell(self):
            return self._f.tell()

        def close(self):
            return self._f.close()

    def mock_open(path, mode="r", *args, **kwargs):
        f = original_open(path, mode, *args, **kwargs)
        if "r" in mode and str(path) == str(src_file):
            return MockFailingFile(f)
        return f

    with patch("builtins.open", side_effect=mock_open):
        result = acquire_image(options)

    assert result.success is True
    assert result.bad_sectors_count == 1
    assert result.bad_bytes_count == 512
    # Verify that the destination file was padded with zeros at the bad sector
    dst_bytes = dst_file.read_bytes()
    assert len(dst_bytes) == 8192
    assert dst_bytes[4608:4608 + 512] == b"\x00" * 512
    assert dst_bytes[:4608] == b"A" * 4608


def test_cli_image_and_certificate_signing(temp_workspace):
    src_file = temp_workspace / "evidence.raw"
    data = b"FORENSIC_ACQUISITION_VERIFICATION_TEST" * 500
    src_file.write_bytes(data)

    dst_file = temp_workspace / "target_replica.raw"
    out_dir = temp_workspace / "out"

    demo_key = Path("core/keys/demo_issuer_private.pem")
    demo_pub = Path("core/keys/demo_issuer_public.pem")

    cmd = [
        "image",
        "--source", str(src_file),
        "--destination", str(dst_file),
        "--out-dir", str(out_dir),
        "--operator", "op-cert-test",
        "--organization", "Forensics Lab",
    ]
    if demo_key.is_file():
        cmd.extend(["--key", str(demo_key)])

    ret = main(cmd)
    assert ret == 0
    assert dst_file.is_file()
    assert dst_file.read_bytes() == data

    # Check that manifest file and signed certificate exist
    manifests = list(out_dir.glob("acquisition_manifest_*.json"))
    assert len(manifests) == 1

    certs = list(out_dir.glob("certificate_*.json"))
    if demo_key.is_file():
        assert len(certs) == 1
        cert_data = json.loads(certs[0].read_text(encoding="utf-8"))
        assert cert_data["wipe"]["method"] == "FORENSIC_IMAGING"
        pub = load_public_pem(demo_pub)
        ok, reason = verify_certificate(cert_data, [pub])
        assert ok is True, f"Certificate verification failed: {reason}"


def test_cli_clone_alias(temp_workspace):
    src_file = temp_workspace / "source_clone.raw"
    src_file.write_bytes(b"CLONE_TARGET_VERIFICATION" * 100)
    dst_file = temp_workspace / "dest_clone.raw"

    ret = main([
        "clone",
        "--source", str(src_file),
        "--destination", str(dst_file),
        "--out-dir", str(temp_workspace),
        "--no-certificate",
    ])
    assert ret == 0
    assert dst_file.read_bytes() == src_file.read_bytes()


def test_cli_image_warns_on_default_demo_key(temp_workspace, capsys):
    """R2-2: s0 image without --key must warn that demo key is being used."""
    src_file = temp_workspace / "source_warn.raw"
    src_file.write_bytes(b"DATA" * 64)
    dst_file = temp_workspace / "dest_warn.raw"

    ret = main([
        "image",
        "--source", str(src_file),
        "--destination", str(dst_file),
        "--out-dir", str(temp_workspace),
    ])
    assert ret == 0
    captured = capsys.readouterr()
    assert "NOTICE: Operation signed with unaccredited demonstration key" in captured.err

