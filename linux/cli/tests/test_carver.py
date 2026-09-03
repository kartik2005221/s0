"""Unit tests for TrustWipe Module 3: Advanced File Carving & Recovery."""

import hashlib
from pathlib import Path

import pytest
from trustwipe_cli.carver import (
    calculate_shannon_entropy,
    carve_image,
    score_carved_candidate,
    get_signature_by_ext,
)
from trustwipe_core.certificate import verify_certificate
from trustwipe_core.crypto import load_public_pem


def test_shannon_entropy():
    # Zero / uniform byte data has 0 entropy
    zero_bytes = b"\x00" * 1024
    assert calculate_shannon_entropy(zero_bytes) == 0.0

    # Random / high-entropy data has near 8.0 entropy
    import secrets
    rnd_bytes = secrets.token_bytes(4096)
    ent = calculate_shannon_entropy(rnd_bytes)
    assert 7.5 <= ent <= 8.0


def test_confidence_scoring_jpeg():
    sig = get_signature_by_ext("jpg")
    assert sig is not None

    # Construct realistic JPEG header and footer
    jpeg_data = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00" + b"\xff\xdb" + b"\xaa" * 500 + b"\xff\xd9"
    score, heuristics = score_carved_candidate(sig, jpeg_data, has_valid_footer=True)
    assert score >= 80
    assert any("Valid magic header" in h for h in heuristics)
    assert any("Valid format footer" in h for h in heuristics)


def test_carve_disk_image_with_planted_files(tmp_path):
    disk_img = tmp_path / "forensic_target.raw"
    out_dir = tmp_path / "carved_output"

    # Synthetic disk image: junk padding + planted JPEG + planted PNG + planted PDF + junk padding
    jpeg_payload = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01" + b"\x55\xaa" * 200 + b"\xff\xd9"
    png_payload = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + b"\x12\x34" * 100 + b"IEND\xaeB`\x82"
    pdf_payload = b"%PDF-1.5\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n" + b"stream\nTEST EVIDENCE DATA\nendstream\n" + b"%%EOF"

    junk_block = b"\x5a" * 65536

    with open(disk_img, "wb") as f:
        f.write(junk_block)
        f.write(jpeg_payload)
        f.write(junk_block)
        f.write(png_payload)
        f.write(junk_block)
        f.write(pdf_payload)
        f.write(junk_block)

    summary = carve_image(
        disk_img,
        out_dir,
        min_confidence=60,
        operator_id="op-ntro-forensic",
        organization="NTRO Forensic Lab",
    )

    assert summary.files_recovered >= 3
    rec_exts = {c.extension for c in summary.carved_files}
    assert "jpg" in rec_exts
    assert "png" in rec_exts
    assert "pdf" in rec_exts

    # Verify SHA-256 of carved items match original payloads
    jpeg_item = next(c for c in summary.carved_files if c.extension == "jpg")
    assert jpeg_item.sha256 == hashlib.sha256(jpeg_payload).hexdigest()
    assert jpeg_item.confidence_score >= 80

    png_item = next(c for c in summary.carved_files if c.extension == "png")
    assert png_item.sha256 == hashlib.sha256(png_payload).hexdigest()

    pdf_item = next(c for c in summary.carved_files if c.extension == "pdf")
    assert pdf_item.sha256 == hashlib.sha256(pdf_payload).hexdigest()

    # Verify Signed Recovery Manifest Certificate
    assert summary.manifest_certificate is not None
    demo_pub_key = Path(__file__).resolve().parents[3] / "core" / "keys" / "demo_issuer_public.pem"
    pub = load_public_pem(demo_pub_key)
    ok, reason = verify_certificate(summary.manifest_certificate, [pub])
    assert ok is True
    assert "valid Ed25519 signature" in reason


def test_carve_filtered_extensions(tmp_path):
    disk_img = tmp_path / "filter_test.raw"
    out_dir = tmp_path / "filtered_out"

    jpeg_payload = b"\xff\xd8\xff\xe0\x00\x10JFIF" + b"\x11" * 100 + b"\xff\xd9"
    png_payload = b"\x89PNG\r\n\x1a\n" + b"\x22" * 100 + b"IEND\xaeB`\x82"

    with open(disk_img, "wb") as f:
        f.write(jpeg_payload + (b"\x00" * 1024) + png_payload)

    # Filter strictly for JPG
    summary = carve_image(disk_img, out_dir, extensions=["jpg"])
    assert summary.files_recovered == 1
    assert summary.carved_files[0].extension == "jpg"


def test_scoring_multi_formats():
    """Verify confidence scoring across diverse file formats (GIF, GZIP, ZIP, BMP, ELF, SQLite)."""
    import json

    # GIF
    sig_gif = get_signature_by_ext("gif")
    assert sig_gif is not None
    gif_data = b"GIF89a\x20\x00\x20\x00\x80\x00\x00" + b"\xaa" * 50 + b"\x3b"
    score_gif, _ = score_carved_candidate(sig_gif, gif_data, has_valid_footer=True)
    assert score_gif >= 80

    # GZIP
    sig_gz = get_signature_by_ext("gz")
    assert sig_gz is not None
    gz_data = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03" + b"\x55" * 100
    score_gz, _ = score_carved_candidate(sig_gz, gz_data)
    assert score_gz >= 60

    # ZIP
    sig_zip = get_signature_by_ext("zip")
    assert sig_zip is not None
    zip_data = b"PK\x03\x04" + b"\x12" * 100 + b"PK\x01\x02" + b"\x34" * 50 + b"PK\x05\x06"
    score_zip, _ = score_carved_candidate(sig_zip, zip_data, has_valid_footer=True)
    assert score_zip >= 80

    # BMP
    sig_bmp = get_signature_by_ext("bmp")
    assert sig_bmp is not None
    bmp_data = b"BM" + (b"\x00" * 12) + b"\x28\x00\x00\x00" + b"\xff" * 100
    score_bmp, _ = score_carved_candidate(sig_bmp, bmp_data)
    assert score_bmp >= 60

    # ELF
    sig_elf = get_signature_by_ext("elf")
    assert sig_elf is not None
    elf_data = b"\x7fELF\x02\x01\x01\x00" + b"\x77" * 200
    score_elf, _ = score_carved_candidate(sig_elf, elf_data)
    assert score_elf >= 60

    # SQLite
    sig_sql = get_signature_by_ext("sqlite")
    assert sig_sql is not None
    sql_data = b"SQLite format 3\x00\x10\x00\x01\x01" + b"\x00" * 500
    score_sql, _ = score_carved_candidate(sig_sql, sql_data)
    assert score_sql >= 60


def test_adversarial_carving_zero_and_empty_images(tmp_path):
    """Verify carver behavior on adversarial inputs (zeros, empty file, corrupt data)."""
    import json
    out_dir = tmp_path / "out_adversarial"

    # 1. Empty file (0 bytes)
    empty_img = tmp_path / "empty.raw"
    empty_img.write_bytes(b"")
    sum_empty = carve_image(empty_img, out_dir / "empty")
    assert sum_empty.files_recovered == 0
    assert sum_empty.total_bytes_scanned == 0

    # 2. Entirely zero-filled image (1 MiB of 0x00)
    zero_img = tmp_path / "zeros.raw"
    zero_img.write_bytes(b"\x00" * (1024 * 1024))
    sum_zero = carve_image(zero_img, out_dir / "zeros")
    assert sum_zero.files_recovered == 0
    assert sum_zero.total_bytes_scanned == 1024 * 1024

    # 3. Truncated / corrupt image (Header present but file terminates before footer)
    corrupt_img = tmp_path / "corrupt.raw"
    corrupt_img.write_bytes(b"\xff\xd8\xff\xe0\x00\x10JFIF" + b"\x99" * 64)
    sum_corrupt = carve_image(corrupt_img, out_dir / "corrupt", min_confidence=80)
    # High confidence threshold rejects header-only incomplete JPEG without footer
    assert sum_corrupt.files_recovered == 0

    # 4. Check recovery_index.json generation
    rec_idx = out_dir / "zeros" / "recovery_index.json"
    assert rec_idx.exists()
    idx_content = json.loads(rec_idx.read_text())
    assert idx_content["files_recovered"] == 0
    assert "recovered_files" in idx_content
