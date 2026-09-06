"""Human-readable PDF certificate with embedded QR code.

The QR encodes the FULL signed certificate in canonical JSON when it fits
(offline self-verifying — the strongest option), otherwise a verification URL
containing the certificate id (a locator, explicitly NOT evidence — see
CANONICAL_JSON.md). The PDF is a rendering of the signed JSON, never the other
way around: the JSON remains the artifact of record.
"""

from __future__ import annotations

import json
import io
from pathlib import Path

import qrcode
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import Image, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from .canonical import canonicalize_str

__all__ = ["generate_pdf", "QR_URL_TEMPLATE_DEFAULT"]

# Placeholder for a real deployment's portal URL; informational only.
QR_URL_TEMPLATE_DEFAULT = "https://trustwipe-vp.vercel.app/?cert={cert_uuid}"


_STATUS_COLORS = {
    "success": colors.HexColor("#1b7f3b"),
    "reset_triggered": colors.HexColor("#1b5e9f"),
    "partial": colors.HexColor("#c08500"),
    "failure": colors.HexColor("#a32020"),
}


def _make_qr_bytes(data: str) -> bytes:
    img = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, border=2)
    img.add_data(data)
    img.make(fit=True)
    buf = io.BytesIO()
    img.make_image(fill_color="black", back_color="white").save(buf, format="PNG")
    return buf.getvalue()


def _make_qr_image(data: str, out_dir: Path, name: str = "cert_qr.png") -> Path:
    path = out_dir / name
    path.write_bytes(_make_qr_bytes(data))
    return path


def generate_pdf(
    cert: dict,
    out_path: str | Path,
    *,
    qr_url_template: str = QR_URL_TEMPLATE_DEFAULT,
) -> Path:
    """Render a SIGNED certificate dict to PDF. Raises if the cert has no signature."""
    if "signature" not in cert:
        raise ValueError("refusing to render an UNSIGNED certificate to PDF")
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    status = cert["result"]["status"]
    device = cert.get("device", {})
    wipe = cert.get("wipe", {})
    result = cert.get("result", {})
    verif = result.get("verification") or {}
    sig = cert["signature"]

    # QR content: full signed cert if it fits comfortably in a QR-M symbol.
    full_json = canonicalize_str(cert)
    if len(full_json.encode("utf-8")) <= 2300:
        qr_data, qr_caption = full_json, "Full signed certificate (offline-verifiable)"
    else:
        qr_data = qr_url_template.format(cert_uuid=cert["cert_uuid"])
        qr_caption = "Verification URL (locator only — verify the signature)"

    doc = SimpleDocTemplate(
        str(out_path), pagesize=A4,
        title=f"TrustWipe Wipe Certificate {cert['cert_uuid']}",
        author=cert["issuer"]["organization"],
    )
    styles = getSampleStyleSheet()
    mono = ParagraphStyle("mono", parent=styles["Code"], fontSize=7, leading=9)
    story = []

    story.append(Paragraph("<b>TRUSTWIPE — SECURE WIPE CERTIFICATE</b>", styles["Title"]))
    banner = Table(
        [[Paragraph(
            f"<para color='white'><b>{status.upper()}</b> — NIST 800-88 category: "
            f"<b>{wipe.get('nist_category', '?')}</b></para>",
            styles["Normal"])]],
        colWidths=[170 * mm],
    )
    banner.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), _STATUS_COLORS.get(status, colors.grey)),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(banner)
    story.append(Spacer(1, 6 * mm))

    def rows(pairs):
        out = []
        for k, v in pairs:
            # Pre-built flowables (e.g. monospace Paragraph for long signatures)
            # pass through untouched; plain values get wrapped.
            if not isinstance(v, (Paragraph, Table)):
                v = Paragraph(str(v))
            out.append([Paragraph(f"<b>{k}</b>"), v])
        return out

    body_style = [
        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f0f0f0")),
    ]

    story.append(Paragraph("Device", styles["Heading3"]))
    t = Table(rows([
        ("Certificate UUID", cert["cert_uuid"]),
        ("Issued at", cert["issued_at"]),
        ("Issuer", f"{cert['issuer']['organization']} / operator {cert['issuer']['operator_id']}"),
        ("Tool", f"{cert['tool']['name']} {cert['tool']['version']} ({cert['tool']['platform']})"),
        ("Device ID", device.get("device_id", "?")),
        ("Type / storage", f"{device.get('device_type', '?')} / {device.get('storage_type', '?')}"),
        ("Model / serial", f"{device.get('model', '—')} / {device.get('serial_number', '—')}"),
        ("Capacity", f"{device.get('capacity_bytes', 0):,} bytes"),
    ]), colWidths=[45 * mm, 125 * mm])
    t.setStyle(TableStyle(body_style))
    story.append(t)
    story.append(Spacer(1, 4 * mm))

    story.append(Paragraph("Wipe performed", styles["Heading3"]))
    t = Table(rows([
        ("Method", wipe.get("method", "?")),
        ("NIST 800-88 tier", wipe.get("nist_category", "?")),
        ("Passes / pattern", f"{wipe.get('passes', '—')} / {wipe.get('pattern', '—')}"),
        ("Started / ended", f"{wipe.get('start_time')} → {wipe.get('end_time')}"),
        ("Bytes processed", f"{wipe.get('bytes_processed', 0):,}"),
        ("Result status", result.get("status", "?")),
    ] + ([("Errors", "; ".join(result.get("errors", [])))] if result.get("errors") else [])
      + ([("Post-wipe verification",
           f"{verif.get('method', '?')}: {verif.get('samples_checked', 0)} samples × "
           f"{verif.get('sample_bytes_each', 0)} B, all match: "
           f"{verif.get('all_samples_match_wipe_pattern')}")] if verif else [])),
        colWidths=[45 * mm, 125 * mm])
    t.setStyle(TableStyle(body_style))
    story.append(t)

    if cert.get("notes"):
        story.append(Spacer(1, 4 * mm))
        story.append(Paragraph("Notes", styles["Heading3"]))
        for n in cert["notes"]:
            story.append(Paragraph(f"• {n}", styles["Normal"]))

    story.append(Spacer(1, 6 * mm))
    story.append(Paragraph("Cryptographic signature", styles["Heading3"]))
    sig_rows = rows([
        ("Algorithm", sig.get("algorithm", "?")),
        ("Issuer key fingerprint", sig.get("public_key_fingerprint", "?")),
        ("Payload SHA-256", sig.get("signed_payload_hash", "(not recorded)")),
        ("Signature (base64url)", Paragraph(sig["signature_base64url"], mono)),
        ("Verify offline", "Scan the QR with any verifier, or run: s0 verify cert.json --key issuer_public.pem"),
    ])
    t = Table(sig_rows, colWidths=[45 * mm, 125 * mm])
    t.setStyle(TableStyle(body_style))
    story.append(t)
    story.append(Spacer(1, 6 * mm))

    qr_bytes = _make_qr_bytes(qr_data)
    qr_img = Image(io.BytesIO(qr_bytes), width=42 * mm, height=42 * mm)
    qr_tbl = Table([[qr_img, Paragraph(
        f"<font size='8'>{qr_caption}<br/><br/>The QR and this PDF are renderings of the "
        f"signed JSON, which is the artifact of record. Signature covers every field above; "
        f"any alteration invalidates it.</font>", styles["Normal"])]],
        colWidths=[50 * mm, 120 * mm])
    story.append(qr_tbl)

    verify_url = qr_url_template.format(cert_uuid=cert["cert_uuid"])
    if verify_url.startswith("http"):
        story.append(Spacer(1, 4 * mm))
        story.append(Paragraph(
            f'<font size="8">🔗 <a href="{verify_url}" color="#1d4ed8">'
            f'<u>Verify this certificate online at {verify_url}</u></a></font>',
            styles["Normal"],
        ))

    doc.build(story)
    return out_path


def write_qr_file(cert: dict, out_path: str | Path) -> Path:
    """Standalone QR PNG of the full signed certificate."""
    if "signature" not in cert:
        raise ValueError("refusing to render an UNSIGNED certificate to QR")
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    _make_qr_image(canonicalize_str(cert), out_path.parent, out_path.name)
    return out_path
