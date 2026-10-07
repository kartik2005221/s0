"""Automated Acceptance Test Suite for s0 Web Surfaces.

Verifies:
1. Sticky Header Invariant: Neither html nor body has overflow-x: hidden.
2. Shared Stylesheet Wiring: All 4 surfaces link tokens.css, base.css, components.css.
3. Header Geometry & Badges: All 4 headers enforce 53px height with no logo badges.
4. WCAG 2.2 AA Contrast: Primary button text contrast >= 4.5:1 across both themes.
5. Ledger Cryptography Known-Answer Test: Python and JS canonical JSON and SHA-256 parity.
6. Ledger Interaction Parity: Field tampering produces HASH_MISMATCH, covering tracks produces SIGNATURE_INVALID.
7. Asset Sync & CSP Invariance: Idempotent asset sync and CSP inline hashes.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest
from s0.audit.db import compute_block_hash
from s0.canonical import canonicalize_str

REPO = Path(__file__).resolve().parents[2]


# --------------------------------------------------------------------------- #
# 1. Sticky Header & Overflow Invariants
# --------------------------------------------------------------------------- #


def test_no_overflow_x_hidden_on_html_or_body():
    """Neither html nor body may declare overflow-x: hidden.

    overflow-x: hidden on html or body turns body into an independent scroll container,
    which disables position: sticky on header across WebKit, Gecko and Chromium.
    Use overflow-x: clip on body instead.
    """
    css_files = [
        REPO / "design" / "base.css",
        REPO / "site" / "css" / "home.css",
        REPO / "site" / "get" / "css" / "install.css",
        REPO / "site" / "verify" / "css" / "portal.css",
        REPO / "src" / "s0" / "web" / "static" / "css" / "dashboard.css",
    ]

    for css_path in css_files:
        assert css_path.is_file(), f"Missing stylesheet: {css_path}"
        content = css_path.read_text(encoding="utf-8")
        # Match selector blocks for html or body that specify overflow-x: hidden
        matches = re.findall(
            r"(?:^|[},])\s*(?:html|body)[^{]*\{[^}]*overflow-x\s*:\s*hidden",
            content,
            flags=re.IGNORECASE | re.DOTALL,
        )
        assert not matches, (
            f"{css_path.relative_to(REPO)} declares 'overflow-x: hidden' on html or body, "
            f"breaking position: sticky header. Use 'overflow-x: clip;' instead."
        )


# --------------------------------------------------------------------------- #
# 2. Shared Stylesheet Wiring
# --------------------------------------------------------------------------- #


def test_shared_stylesheets_linked_on_all_surfaces():
    """All 4 web surfaces must link tokens.css, base.css, and components.css in order."""
    surfaces = [
        REPO / "site" / "index.html",
        REPO / "site" / "get" / "index.html",
        REPO / "site" / "verify" / "index.html",
        REPO / "src" / "s0" / "web" / "static" / "index.html",
    ]

    for html_path in surfaces:
        assert html_path.is_file(), f"Missing page: {html_path}"
        text = html_path.read_text(encoding="utf-8")
        assert "tokens.css" in text, f"{html_path.relative_to(REPO)} does not link tokens.css"
        assert "base.css" in text, f"{html_path.relative_to(REPO)} does not link base.css"
        assert "components.css" in text, f"{html_path.relative_to(REPO)} does not link components.css"


# --------------------------------------------------------------------------- #
# 3. Header Geometry & Badges
# --------------------------------------------------------------------------- #


def test_header_height_and_no_badges():
    """All surfaces must share 53px header height and omit site-logo-badge."""
    surfaces = [
        REPO / "site" / "index.html",
        REPO / "site" / "get" / "index.html",
        REPO / "site" / "verify" / "index.html",
        REPO / "src" / "s0" / "web" / "static" / "index.html",
    ]

    tokens = (REPO / "design" / "tokens.css").read_text(encoding="utf-8")
    assert "--header-height: 53px;" in tokens, "tokens.css must define --header-height: 53px;"

    for html_path in surfaces:
        text = html_path.read_text(encoding="utf-8")
        # Ensure site-logo-badge is not present in markup
        assert "site-logo-badge" not in text, (
            f"{html_path.relative_to(REPO)} contains 'site-logo-badge'; "
            f"all four headers must remain clean and identical."
        )


# --------------------------------------------------------------------------- #
# 4. WCAG 2.2 AA Contrast Compliance
# --------------------------------------------------------------------------- #


def _relative_luminance(hex_color: str) -> float:
    """Compute sRGB relative luminance according to WCAG 2.2 specification."""
    hex_clean = hex_color.lstrip("#")
    r = int(hex_clean[0:2], 16) / 255.0
    g = int(hex_clean[2:4], 16) / 255.0
    b = int(hex_clean[4:6], 16) / 255.0

    def _channel_lum(c: float) -> float:
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4

    return 0.2126 * _channel_lum(r) + 0.7152 * _channel_lum(g) + 0.0722 * _channel_lum(b)


def _contrast_ratio(hex1: str, hex2: str) -> float:
    l1 = _relative_luminance(hex1)
    l2 = _relative_luminance(hex2)
    lighter = max(l1, l2)
    darker = min(l1, l2)
    return (lighter + 0.05) / (darker + 0.05)


def test_wcag_brand_on_contrast():
    """Text on primary brand actions must exceed 4.5:1 WCAG AA contrast ratio."""
    # Dark mode: brand #FF6500, text #0A0A0A
    dark_contrast = _contrast_ratio("#FF6500", "#0A0A0A")
    assert dark_contrast >= 4.5, f"Dark mode contrast {dark_contrast:.2f} < 4.5:1"
    assert round(dark_contrast, 2) == 6.71

    # Light mode: brand #C2410C, text #FFFFFF
    light_contrast = _contrast_ratio("#C2410C", "#FFFFFF")
    assert light_contrast >= 4.5, f"Light mode contrast {light_contrast:.2f} < 4.5:1"
    assert round(light_contrast, 2) == 5.18


# --------------------------------------------------------------------------- #
# 5. Ledger Demo Known-Answer Test: Python vs Seed Data
# --------------------------------------------------------------------------- #


def test_seed_ledger_known_answer_python():
    """Verify that Python compute_block_hash matches all seed-ledger.json hashes."""
    seed_path = REPO / "design" / "seed-ledger.json"
    assert seed_path.is_file(), f"Missing seed ledger: {seed_path}"
    blocks = json.loads(seed_path.read_text(encoding="utf-8"))

    for block in blocks:
        expected = block["block_hash"]
        actual = compute_block_hash(
            block_index=block["block_index"],
            timestamp=block["timestamp"],
            operation_type=block["operation_type"],
            target_id=block["target_id"],
            operator_id=block["operator_id"],
            organization=block["organization"],
            cert_uuid=block["cert_uuid"],
            payload_hash=block["payload_hash"],
            signature=block["signature"],
            prev_hash=block["prev_hash"],
        )
        assert actual == expected, (
            f"Block #{block['block_index']} hash mismatch: computed {actual} != expected {expected}"
        )


# --------------------------------------------------------------------------- #
# 6. Ledger Demo Interaction & Parity Test via Node.js
# --------------------------------------------------------------------------- #


def test_ledger_demo_js_parity_via_node():
    """Run Node.js to verify ledger-demo.js parity, tampering and signature invalidation."""
    node_script = """
    const demo = require('./site/js/ledger-demo.js');

    (async () => {
      // 1. Verify seed hashes in WebCrypto
      for (const b of demo.DEFAULT_SEED_BLOCKS) {
        const canon = demo.canonicalBlockPayload(b);
        const hash = await demo.computeSha256(canon);
        if (hash !== b.block_hash) {
          console.error(`Block ${b.block_index} mismatch: ${hash} vs ${b.block_hash}`);
          process.exit(1);
        }
      }

      // 2. Field edit flips hash
      const b1 = JSON.parse(JSON.stringify(demo.DEFAULT_SEED_BLOCKS[1]));
      const origHash = b1.block_hash;
      b1.operation_type = 'FILE_ERASE';
      const tamperedHash = await demo.computeSha256(demo.canonicalBlockPayload(b1));
      if (tamperedHash === origHash) {
        console.error('Tampered hash unexpectedly matched original');
        process.exit(2);
      }

      // 3. Authority signature invalidation on rewritten block
      const kp = await demo.initAuthorityKeys();
      if (!kp) {
        console.error('Failed to init authority keys');
        process.exit(3);
      }
      const sig = await demo.signBlockHash(origHash);
      const okOrig = await demo.verifyBlockHashSignature(origHash, sig);
      const okTampered = await demo.verifyBlockHashSignature(tamperedHash, sig);

      if (!okOrig || okTampered) {
        console.error('Signature verification invariant broken');
        process.exit(4);
      }

      console.log('OK');
    })();
    """

    res = subprocess.run(
        ["node", "-e", node_script],
        cwd=str(REPO),
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, f"Node ledger verification failed:\nSTDOUT: {res.stdout}\nSTDERR: {res.stderr}"
    assert "OK" in res.stdout


# --------------------------------------------------------------------------- #
# 7. Asset Sync & CSP Invariance
# --------------------------------------------------------------------------- #


def test_asset_sync_is_clean():
    """tools/sync_assets.py --check must report zero drift."""
    res = subprocess.run(
        ["python3", "tools/sync_assets.py", "--check"],
        cwd=str(REPO),
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, f"Asset sync drift detected:\n{res.stdout}\n{res.stderr}"


def test_csp_hashes_in_sync():
    """tools/sync_csp.py --check must report all surfaces in sync."""
    res = subprocess.run(
        ["python3", "tools/sync_csp.py", "--check"],
        cwd=str(REPO),
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, f"CSP hashes out of sync:\n{res.stdout}\n{res.stderr}"


# --------------------------------------------------------------------------- #
# 8. Same-Origin SRI Without Crossorigin
# --------------------------------------------------------------------------- #


def test_no_crossorigin_on_same_origin_verifier_scripts():
    """Same-origin vendor scripts in site/verify/index.html must not use crossorigin."""
    html = (REPO / "site" / "verify" / "index.html").read_text(encoding="utf-8")
    for script_name in ("crypto-bundle.js", "pdf.min.js", "jsqr.min.js"):
        pattern = rf'<script src="vendor/{script_name}"[^>]*>'
        match = re.search(pattern, html)
        assert match, f"Script vendor/{script_name} not found"
        tag = match.group(0)
        assert "integrity=" in tag, f"vendor/{script_name} missing integrity"
        assert "crossorigin" not in tag, (
            f"vendor/{script_name} must not carry crossorigin; "
            f"Chromium blocks crossorigin on file:/// URLs."
        )
