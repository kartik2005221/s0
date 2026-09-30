"""Cross-surface consistency: the three portals and the dashboard must not drift.

A product with four web surfaces that disagree about colour, security headers,
fonts and links is not one product. These tests make the agreement mechanical
rather than aspirational.

Enforced here:

* design tokens are byte-identical everywhere (one source of truth)
* no surface re-declares a token value
* every surface has a strict CSP with no ``unsafe-inline`` in ``script-src``
* the CSP inline-script hashes actually match the HTML
* vendored JavaScript is pinned with Subresource Integrity
* no third-party font/CDN references anywhere
* navigation and footer links are the same set on every public surface
* security headers are present everywhere
* no emoji in user-facing markup
"""

from __future__ import annotations

import base64
import hashlib
import re
from pathlib import Path

import pytest
from s0.resources import repo_root

REPO = Path(__file__).resolve().parents[2]
SHARED_TOKENS = REPO / "shared" / "tokens.css"
TOKEN_COPIES = [
    REPO / "portals/install" / "css" / "tokens.css",
    REPO / "portals/verify" / "css" / "tokens.css",
    REPO / "src" / "s0" / "web" / "static" / "css" / "tokens.css",
]
SURFACE_CSS = [
    REPO / "portals/install" / "css" / "install.css",
    REPO / "portals/verify" / "css" / "portal.css",
    REPO / "src" / "s0" / "web" / "static" / "css" / "dashboard.css",
]
PUBLIC_HTML = [
    REPO / "portals/install" / "index.html",
    REPO / "portals/verify" / "index.html",
]
HEADERS = [
    REPO / "portals/install" / "_headers",
    REPO / "portals/verify" / "_headers",
]

# Tokens a surface may declare as a *literal value*. A surface declaring one of
# these in its own :root is bypassing the shared file.
TOKEN_NAME_RE = re.compile(r"^\s*(--[a-z0-9-]+)\s*:", re.I)
LEGACY_TOKEN_RE = re.compile(
    r"^\s*--(bg|text|primary|secondary|accent|success|danger|warning|info|border|code|header|btn)"
    r"[a-z0-9-]*\s*:\s*(#[0-9A-Fa-f]{3,8}|rgba?\()",
    re.I | re.M)


# --------------------------------------------------------------------------- #
# tokens
# --------------------------------------------------------------------------- #


def test_token_copies_are_identical_to_the_source():
    canonical = SHARED_TOKENS.read_bytes()
    for copy in TOKEN_COPIES:
        assert copy.is_file(), f"missing generated token copy: {copy.relative_to(REPO)}"
        text = copy.read_text(encoding="utf-8")
        assert canonical.decode("utf-8") in text, (
            f"{copy.relative_to(REPO)} has drifted from shared/tokens.css; "
            f"run: python tools/sync_tokens.py")


@pytest.mark.parametrize("css", SURFACE_CSS, ids=lambda p: p.parent.parent.name)
def test_surface_css_imports_the_shared_tokens(css):
    rel = css.relative_to(REPO)
    assert css.is_file(), f"missing stylesheet {rel}"
    text = css.read_text(encoding="utf-8")
    assert '@import url("tokens.css")' in text, (
        f"{rel} does not import the shared tokens; every colour must come from "
        f"shared/tokens.css")
    # @import must be the first rule or the whole sheet is ignored.
    first = next(l.strip() for l in text.splitlines() if l.strip())
    assert first.startswith("@import"), f"{rel}: @import is not the first rule"


@pytest.mark.parametrize("css", SURFACE_CSS, ids=lambda p: p.parent.parent.name)
def test_no_surface_redeclares_a_token_value(css):
    """A surface that hard-codes a colour has forked the design system."""
    rel = css.relative_to(REPO)
    offenders = [m.group(0).strip() for m in LEGACY_TOKEN_RE.finditer(css.read_text())]
    assert not offenders, (
        f"{rel} still declares literal token values, e.g. {offenders[:3]}. "
        f"Every colour must resolve through shared/tokens.css.")


def test_shared_tokens_cover_the_full_surface_area():
    text = SHARED_TOKENS.read_text(encoding="utf-8")
    required = [
        "--surface-canvas", "--surface-raised", "--surface-overlay", "--surface-sunken",
        "--text-primary", "--text-secondary", "--text-tertiary",
        "--border-subtle", "--border-strong", "--border-focus",
        "--brand", "--brand-hover",
        "--status-ok", "--status-warn", "--status-danger", "--status-info",
        "--focus-ring", "--font-sans", "--font-mono",
    ]
    missing = [t for t in required if f"{t}:" not in text]
    assert not missing, f"shared/tokens.css is missing {missing}"


def test_shared_tokens_honour_system_preference_and_explicit_choice():
    text = SHARED_TOKENS.read_text(encoding="utf-8")
    assert "prefers-color-scheme: light" in text, (
        "a portal must respect the OS light/dark preference when the operator has "
        "expressed no choice of their own")
    assert ':root:not([data-theme="dark"])' in text, (
        "the system preference must not override an explicit dark choice")
    assert '[data-theme="light"]' in text


def test_shared_tokens_disable_animation_for_reduced_motion():
    text = SHARED_TOKENS.read_text(encoding="utf-8")
    assert "prefers-reduced-motion: reduce" in text, (
        "WCAG 2.2 SC 2.3.3: non-essential animation must be switchable off")


# --------------------------------------------------------------------------- #
# security headers
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("headers", HEADERS, ids=lambda p: p.parent.name)
def test_every_public_surface_has_a_strict_csp(headers):
    rel = headers.relative_to(REPO)
    text = headers.read_text(encoding="utf-8")
    csp_lines = [l for l in text.splitlines() if l.strip().startswith("Content-Security-Policy:")]
    assert csp_lines, f"{rel} serves no Content-Security-Policy"
    csp = csp_lines[0]

    assert "default-src 'none'" in csp, f"{rel}: default-src must be 'none', not '*'"
    assert "object-src 'none'" in csp
    assert "base-uri 'none'" in csp
    assert "frame-ancestors 'none'" in csp

    script_src = re.search(r"script-src([^;]*);", csp)
    assert script_src, f"{rel}: no script-src directive"
    assert "unsafe-inline" not in script_src.group(1), (
        f"{rel}: script-src allows 'unsafe-inline'. This is the directive that "
        f"actually matters -- an injected inline script could rewrite a verdict.")
    assert "'self'" in script_src.group(1)
    assert "sha256-" in script_src.group(1), (
        f"{rel}: the inline theme resolver is unhashed, so it would be blocked")


@pytest.mark.parametrize("headers", HEADERS, ids=lambda p: p.parent.name)
def test_every_public_surface_sends_the_baseline_security_headers(headers):
    rel = headers.relative_to(REPO)
    text = headers.read_text(encoding="utf-8")
    for header in ("X-Content-Type-Options: nosniff",
                   "Referrer-Policy:",
                   "Permissions-Policy:",
                   "Content-Security-Policy:"):
        assert header in text, f"{rel} is missing {header.split(':')[0]}"
    assert "Strict-Transport-Security" in text, f"{rel}: no HSTS"


@pytest.mark.parametrize("html", PUBLIC_HTML, ids=lambda p: p.parent.name)
def test_csp_hashes_match_the_inline_blocks(html):
    """A hash-based CSP is only correct if the hash matches. Drift makes the
    whole page stop executing, which is loud -- but it must not happen in a
    release, so it is checked here."""
    rel = html.relative_to(REPO)
    headers_path = html.parent / "_headers"
    text = headers_path.read_text(encoding="utf-8")
    csp = next(l for l in text.splitlines() if l.strip().startswith("Content-Security-Policy:"))
    listed = set(re.findall(r"'?(sha256-[A-Za-z0-9+/=]+)'?", csp))

    source = html.read_text(encoding="utf-8")
    blocks = re.findall(r"<script>(.*?)</script>", source, flags=re.S)
    assert blocks, f"{rel} has no inline script to hash"
    for block in blocks:
        digest = "sha256-" + base64.b64encode(
            hashlib.sha256(block.encode("utf-8")).digest()).decode("ascii")
        assert digest in listed, (
            f"{rel}: inline script is not covered by the CSP hash {digest}. "
            f"Run: python tools/sync_csp.py --write")


@pytest.mark.parametrize("html", PUBLIC_HTML, ids=lambda p: p.parent.name)
def test_no_unsafe_inline_csp_in_the_document(html):
    rel = html.relative_to(REPO)
    text = html.read_text(encoding="utf-8")
    # Comments explain *why* the policy is absent; they are not policy.
    stripped = re.sub(r"<!--.*?-->", "", text, flags=re.S)
    assert "unsafe-inline" not in stripped, (
        f"{rel} still carries an inline meta CSP. A static site cannot use "
        f"per-response nonces, so the policy belongs in _headers as a hash.")
    assert 'http-equiv="Content-Security-Policy"' not in stripped, (
        f"{rel} ships a meta CSP; the _headers policy is the one that counts, and "
        f"having both means only the weaker is applied by some clients.")


# --------------------------------------------------------------------------- #
# vendored assets
# --------------------------------------------------------------------------- #


def test_vendored_javascript_is_pinned_with_sri():
    html = (REPO / "portals/verify" / "index.html").read_text(encoding="utf-8")
    vendor = REPO / "portals/verify" / "vendor"
    tools = re.findall(r'<script src="(vendor/[^"]+)"', html)
    assert tools, "no vendored tools found in the verification portal"
    for rel in tools:
        tag = re.search(rf'<script src="{re.escape(rel)}"[^>]*>', html)
        assert tag, rel
        assert "integrity=" in tag.group(0), (
            f"{rel} is loaded without Subresource Integrity")
        assert 'crossorigin="anonymous"' in tag.group(0), (
            f"{rel}: SRI requires crossorigin=anonymous or the check is a no-op")
        want = "sha384-" + base64.b64encode(
            hashlib.sha384((vendor / rel.split("/")[-1]).read_bytes()).digest()
        ).decode("ascii")
        assert want in tag.group(0), (
            f"{rel}: integrity hash does not match the file. The browser will "
            f"REFUSE TO EXECUTE it. Expected {want}")


def test_vendored_assets_have_licence_attribution():
    notices = REPO / "THIRD_PARTY_NOTICES.md"
    assert notices.is_file(), "THIRD_PARTY_NOTICES.md is required for vendored code"
    text = notices.read_text(encoding="utf-8")
    for component in ("pdf.js", "jsQR", "JetBrains Mono", "Rubik"):
        assert component in text, f"THIRD_PARTY_NOTICES.md does not mention {component}"
    assert "Apache-2.0" in text, "pdf.js and jsQR are Apache-2.0 and must be recorded"
    assert "SIL OFL" in text, "the bundled fonts are SIL OFL and must be recorded"


def test_every_vendored_file_is_listed_in_the_manifest():
    manifest = REPO / "portals/verify" / "vendor" / "manifest.json"
    assert manifest.is_file(), "vendor/manifest.json is required to pin re-vendoring"
    import json
    data = json.loads(manifest.read_text(encoding="utf-8"))
    listed = {e["path"] for e in data["files"]}
    on_disk = {f"vendor/{p.name}" for p in (REPO / "portals/verify" / "vendor").iterdir()
               if p.is_file() and p.suffix in (".js",)}
    assert on_disk <= listed, f"unlisted vendored files: {sorted(on_disk - listed)}"
    for entry in data["files"]:
        actual = hashlib.sha256((REPO / "portals/verify" / entry["path"]).read_bytes()).hexdigest()
        assert actual == entry["sha256"], f"{entry['path']}: manifest hash is stale"


# --------------------------------------------------------------------------- #
# third-party references
# --------------------------------------------------------------------------- #


def test_no_third_party_font_or_cdn_reference_anywhere():
    offenders = []
    for pattern in ("**/*.html", "**/*.css"):
        for path in REPO.glob(pattern):
            if any(part in {".venv", "node_modules", ".git"} for part in path.parts):
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            for needle in ("fonts.googleapis.com", "fonts.gstatic.com", "use.typekit.net"):
                if needle in text:
                    offenders.append(f"{path.relative_to(REPO)} -> {needle}")
    assert not offenders, (
        "self-host every font. A portal that phones a CDN leaks the visitor's IP "
        "and breaks the air-gapped live-ISO claim.\n  " + "\n  ".join(offenders))


def test_every_surface_self_hosts_its_fonts():
    for html in PUBLIC_HTML + [REPO / "portals/verify" / "tests" / "test_runner.html"]:
        text = html.read_text(encoding="utf-8")
        assert "fonts/fonts.css" in text or "../fonts/fonts.css" in text, (
            f"{html.relative_to(REPO)} does not load the self-hosted font sheet")


def test_install_portal_fonts_are_present_on_disk():
    d = REPO / "portals/install" / "fonts"
    assert (d / "fonts.css").is_file()
    woff2 = list(d.glob("*.woff2"))
    assert len(woff2) >= 4, "the install portal needs the woff2 files it references"
    for face in (d / "fonts.css").read_text(encoding="utf-8").split("@font-face"):
        for url in re.findall(r"url\('([^']+)'\)", face):
            assert (d / url).is_file(), f"portals/install/fonts/{url} is referenced but missing"


# --------------------------------------------------------------------------- #
# navigation
# --------------------------------------------------------------------------- #


EXPECTED_NAV = {
    "docs": "s0-docs.gitbook.io",
    "install": "s0-install.pages.dev",
    "verify": "s0-verify.pages.dev",
    "github": "github.com/kartik2005221/s0",
}


@pytest.mark.parametrize("html", PUBLIC_HTML, ids=lambda p: p.parent.name)
def test_navigation_links_to_every_s0_surface(html):
    text = html.read_text(encoding="utf-8")
    for label, host in EXPECTED_NAV.items():
        assert host in text, f"{html.relative_to(REPO)} does not link to {label} ({host})"


def test_every_external_link_is_safe():
    """target=_blank without rel=noopener hands the new page a window.opener
    reference back to this one."""
    offenders = []
    for html in PUBLIC_HTML + [REPO / "src" / "s0" / "web" / "static" / "index.html"]:
        text = html.read_text(encoding="utf-8")
        for tag in re.findall(r"<a\b[^>]*>", text, flags=re.I):
            if 'target="_blank"' in tag and "noopener" not in tag:
                offenders.append(f"{html.relative_to(REPO)}: {tag[:80]}")
    assert not offenders, "add rel=\"noopener noreferrer\":\n  " + "\n  ".join(offenders)


def test_portals_declare_language_and_viewport():
    for html in PUBLIC_HTML + [REPO / "src" / "s0" / "web" / "static" / "index.html"]:
        text = html.read_text(encoding="utf-8")
        assert '<html lang="en">' in text, f"{html.relative_to(REPO)} has no lang attribute"
        assert 'name="viewport"' in text, f"{html.relative_to(REPO)} has no viewport meta"


def test_async_status_regions_are_announced():
    """WCAG 2.2 SC 4.1.3: a status the user must perceive cannot require focus."""
    for html in PUBLIC_HTML + [REPO / "src" / "s0" / "web" / "static" / "index.html"]:
        text = html.read_text(encoding="utf-8")
        if 'aria-live' in text:
            continue
        offenders = [h for h in re.findall(r'id="([A-Za-z0-9_]*(?:status|progress|log|result)[A-Za-z0-9_]*)"',
                                           text, flags=re.I)]
        assert not offenders, (
            f"{html.relative_to(REPO)} has {offenders} but declares no aria-live region; "
            f"screen-reader users will not hear the outcome")


# --------------------------------------------------------------------------- #
# output hygiene
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("html", PUBLIC_HTML + [REPO / "src" / "s0" / "web" / "static" / "index.html"],
                         ids=lambda p: p.parent.name)
def test_no_emoji_in_user_facing_markup(html):
    """Emoji render inconsistently across terminals, break monospace alignment
    and are read out unpredictably. s0 uses geometric Unicode only."""
    text = html.read_text(encoding="utf-8")
    emoji = re.compile("[\U0001F300-\U0001FAFF☀-➿⬀-⯿️]")
    found = emoji.findall(text)
    assert not found, f"{html.relative_to(REPO)} contains emoji {sorted(set(found))}"


def test_brand_colour_is_identical_on_every_surface():
    """The accent is chosen once, in shared/tokens.css, and nowhere else."""
    brand = re.search(r"^\s*--brand:\s*(#[0-9A-Fa-f]{6})",
                      SHARED_TOKENS.read_text(encoding="utf-8"), re.M)
    assert brand, "shared/tokens.css does not define --brand"
    for css in SURFACE_CSS:
        text = css.read_text(encoding="utf-8")
        assert f"--brand: {brand.group(1)}" not in text, (
            f"{css.relative_to(REPO)} redefines the brand colour")
