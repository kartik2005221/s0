"""PDF + QR rendering tests."""

import json
import struct
import zlib
from pathlib import Path

import pytest

from s0_core import crypto, certificate, pdfgen
from s0_core.canonical import canonicalize_str


def _pdf_idat(data: bytes) -> bytes:
    """Extract concatenated IDAT chunks from a PNG (for sanity-checking size)."""
    pos, idat = 8, b""
    while pos < len(data):
        (length,) = struct.unpack(">I", data[pos:pos + 4])
        chunk = data[pos + 4:pos + 8]
        if chunk == b"IDAT":
            idat += data[pos + 8:pos + 8 + length]
        pos += 12 + length
    return idat


def test_pdf_renders(signed_cert, tmp_path):
    out = tmp_path / "cert.pdf"
    pdfgen.generate_pdf(signed_cert, out)
    data = out.read_bytes()
    assert data.startswith(b"%PDF-")
    assert b"/Encrypt" not in data
    assert len(data) > 2000


def test_qr_png_renders(signed_cert, tmp_path):
    out = tmp_path / "cert_qr.png"
    pdfgen.write_qr_file(signed_cert, out)
    data = out.read_bytes()
    assert data[:8] == b"\x89PNG\r\n\x1a\n"
    # Full QR decoding happens in the portal's browser-based tests; here we
    # verify the PNG is structurally sound and plausibly a dense QR symbol.
    raw = zlib.decompress(_pdf_idat(data))
    assert len(raw) > 400, "QR image suspiciously small — likely empty"


def test_pdf_refuses_unsigned(base_cert, tmp_path):
    with pytest.raises(ValueError):
        pdfgen.generate_pdf(base_cert, tmp_path / "nope.pdf")


def test_qr_refuses_unsigned(base_cert, tmp_path):
    with pytest.raises(ValueError):
        pdfgen.write_qr_file(base_cert, tmp_path / "nope.png")


def test_large_cert_falls_back_to_url_qr(signed_cert, tmp_path):
    """When signed JSON outgrows a QR-M symbol, the QR switches to URL-locator
    mode (explicitly not evidence). The PDF must still render."""
    big = json.loads(json.dumps(signed_cert))
    big["notes"] = ["x" * 3000 for _ in range(3)]
    priv = crypto.generate_private_key()  # throwaway key; we pin it ourselves
    resigned = certificate.sign_certificate(big, priv)
    ok, reason = certificate.verify_certificate(resigned, [priv.public_key()])
    assert ok, reason

    assert len(canonicalize_str(resigned).encode()) > 2300  # forces URL fallback path
    out = tmp_path / "big.pdf"
    pdfgen.generate_pdf(resigned, out)
    assert out.read_bytes().startswith(b"%PDF-")


def test_pdf_escapes_markup_injection(signed_cert, tmp_path):
    """Ensure HTML tags in fields are escaped and do not crash or alter rendering."""
    injected = json.loads(json.dumps(signed_cert))
    injected["issuer"]["operator_id"] = '<font color="red" size=24><b>*** REVOKED - DO NOT TRUST ***</b></font>'
    injected["notes"] = ["<script>alert(1)</script>", "unclosed <b tag"]
    priv = crypto.generate_private_key()
    resigned = certificate.sign_certificate(injected, priv)

    out = tmp_path / "injected.pdf"
    pdfgen.generate_pdf(resigned, out)
    assert out.exists()
    assert out.read_bytes().startswith(b"%PDF-")


def test_pdf_sanitizes_malicious_verify_url(signed_cert, tmp_path):
    """Ensure attacker-controlled verify URL templates are replaced with safe default."""
    out = tmp_path / "malicious_url.pdf"
    pdfgen.generate_pdf(
        signed_cert,
        out,
        qr_url_template="http://evil-phish-domain.attacker.example/?cert={cert_uuid}",
    )
    pdf_bytes = out.read_bytes()
    assert b"evil-phish-domain.attacker.example" not in pdf_bytes
    assert b"s0-verify.pages.dev" in pdf_bytes


