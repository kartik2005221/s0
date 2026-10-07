"""Glossary lint: ensure retired terms do not appear in user-facing web files.

Retired terms (per 2026-10-07 design brief):
  - "compliance certificate" -> "erasure certificate"
  - "Forensic Workstation"   -> "Dashboard"
  - "Install Portal" / "Installation Portal" -> "Get s0" / "Get"
  - "Verification Portal"    -> "Verifier"
  - "zero-trust" / "air-gapped" -> on web pages, use "Runs entirely in your browser, nothing is uploaded" / "offline client-side"
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]

USER_FACING_HTML = [
    REPO / "site" / "index.html",
    REPO / "site" / "get" / "index.html",
    REPO / "site" / "verify" / "index.html",
    REPO / "site" / "404.html",
    REPO / "src" / "s0" / "web" / "static" / "index.html",
]

RETIRED_TERMS = [
    (r"\bcompliance certificate\b", "erasure certificate"),
    (r"\bForensic Workstation\b", "Dashboard"),
    (r"\bInstall(?:ation)? Portal\b", "Get s0 / Get"),
    (r"\bVerification Portal\b", "Verifier"),
    (r"\bzero-trust\b", "offline client-side verification"),
]


@pytest.mark.parametrize("html_file", USER_FACING_HTML, ids=lambda p: str(p.relative_to(REPO)))
def test_user_facing_html_contains_no_retired_terms(html_file: Path):
    assert html_file.is_file(), f"File missing: {html_file}"
    # Strip HTML comments to test user-visible markup
    text = re.sub(r"<!--.*?-->", "", html_file.read_text(encoding="utf-8"), flags=re.S)
    
    violations = []
    for pattern, preferred in RETIRED_TERMS:
        matches = re.findall(pattern, text, flags=re.IGNORECASE)
        if matches:
            violations.append(f"Found '{matches[0]}' (replace with '{preferred}')")
            
    assert not violations, f"{html_file.relative_to(REPO)} contains retired terms: {violations}"
