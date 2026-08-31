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
