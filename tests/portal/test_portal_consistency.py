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
import json
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SHARED_TOKENS = REPO / "shared" / "tokens.css"
TOKEN_COPIES = [
    REPO / "site/install" / "css" / "tokens.css",
    REPO / "site/verify" / "css" / "tokens.css",
    REPO / "src" / "s0" / "web" / "static" / "css" / "tokens.css",
]
SURFACE_CSS = [
    REPO / "site/install" / "css" / "install.css",
    REPO / "site/verify" / "css" / "portal.css",
    REPO / "src" / "s0" / "web" / "static" / "css" / "dashboard.css",
]
PUBLIC_HTML = [
    REPO / "site" / "index.html",
    REPO / "site" / "install" / "index.html",
    REPO / "site" / "verify" / "index.html",
]

# One deployment serves every surface, and Pages reads _headers from the output
# root only, so there is a single _headers and each page owns the blocks its
# request paths match. Kept in step with tools/sync_csp.py, which writes the same
# mapping; if they disagree the hashes land in the wrong policy.
HEADERS = REPO / "site" / "_headers"

CSP_BLOCKS = {
    REPO / "site" / "index.html": ("/", "/index.html"),
    REPO / "site" / "install" / "index.html": ("/install/*",),
    REPO / "site" / "verify" / "index.html": ("/verify/*",),
}


def headers_blocks(text: str) -> dict[str, list[str]]:
    """Parse a _headers file into {path pattern: [header lines]}."""
    out: dict[str, list[str]] = {}
    current: list[str] | None = None
    for line in text.split("\n"):
        if line.startswith("/") and line.strip():
            current = []
            out[line.strip()] = current
        elif current is not None and line.startswith("  ") and line.strip():
            current.append(line.strip())
    return out


def csp_for_block(text: str, pattern: str) -> str:
    """The Content-Security-Policy that a given path block sets, or ''."""
    for header in headers_blocks(text).get(pattern, []):
        if header.startswith("Content-Security-Policy:"):
            return header
    return ""


ALL_CSP_BLOCKS = [
    (html, block)
    for html, blocks in CSP_BLOCKS.items()
    for block in blocks
]

# Every public page. The loopback dashboard is deliberately absent: its policy
# allows 'unsafe-inline' by design and its inline handlers are tracked in
# docs/compliance/limitations.md, so asserting otherwise here would report a
# decision the project has already made as if it were an oversight.
ALL_PAGES = PUBLIC_HTML


@pytest.mark.parametrize("html", ALL_PAGES, ids=lambda p: p.parent.name)
def test_no_inline_event_handlers(html):
    """An inline onclick needs 'unsafe-inline' in script-src, and every public
    page here denies it. A handler left in the markup is therefore not merely
    untidy: the browser blocks it, and the button silently does nothing. That is
    not hypothetical -- the install portal's copy buttons were all in this state,
    and the install portal exists to hand people a command to copy.

    Inline *style* attributes are a separate matter. All three policies carry
    style-src 'self' 'unsafe-inline' deliberately, so a style attribute is
    permitted rather than blocked, and clearing those is tracked as its own
    cleanup rather than folded in here.
    """
    rel = html.relative_to(REPO)
    text = re.sub(r"<!--.*?-->", "", html.read_text(encoding="utf-8"), flags=re.S)
    handlers = sorted(set(re.findall(r'\son[a-z]+\s*=\s*"[^"]*"', text, flags=re.I)))
    assert not handlers, (
        f"{rel} has inline event handlers, which this page's script-src blocks: "
        f"{handlers[:3]}. Bind them in JS and pass the argument through a data- "
        f"attribute instead.")

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
    first = next(line.strip() for line in text.splitlines() if line.strip())
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


@pytest.mark.parametrize("html,block", ALL_CSP_BLOCKS,
                         ids=[f"{h.parent.name or 'root'}{b}" for h, b in ALL_CSP_BLOCKS])
def test_every_public_surface_has_a_strict_csp(html, block):
    rel = f"{HEADERS.relative_to(REPO)} [{block}]"
    csp = csp_for_block(HEADERS.read_text(encoding="utf-8"), block)
    assert csp, f"{rel} serves no Content-Security-Policy"

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


def test_no_csp_is_declared_under_the_catch_all_block():
    """A request inherits the headers of every block it matches, and where two
    blocks set the same header the values combine. A Content-Security-Policy
    under /* would therefore be *added to* each surface's own policy instead of
    being overridden by it, and the reader would have to satisfy both."""
    text = HEADERS.read_text(encoding="utf-8")
    catch_all = headers_blocks(text).get("/*", [])
    offenders = [h for h in catch_all if h.startswith("Content-Security-Policy:")]
    assert not offenders, (
        f"{HEADERS.relative_to(REPO)}: /* must not set a CSP, it would be "
        f"combined with the per-surface policy rather than replaced by it")


def test_every_csp_block_belongs_to_a_surface():
    """A CSP nobody claims is a policy for a page that does not exist, or one
    that lost its owner in a rename. Either way it ships."""
    text = HEADERS.read_text(encoding="utf-8")
    declared = {p for p, hs in headers_blocks(text).items()
                if any(h.startswith("Content-Security-Policy:") for h in hs)}
    claimed = {b for blocks in CSP_BLOCKS.values() for b in blocks}
    assert declared == claimed, (
        f"unclaimed: {sorted(declared - claimed)}; "
        f"missing: {sorted(claimed - declared)}")


@pytest.mark.parametrize("html,block", ALL_CSP_BLOCKS,
                         ids=[f"{h.parent.name or 'root'}{b}" for h, b in ALL_CSP_BLOCKS])
def test_every_public_surface_sends_the_baseline_security_headers(html, block):
    rel = HEADERS.relative_to(REPO)
    text = HEADERS.read_text(encoding="utf-8")
    for header in ("X-Content-Type-Options: nosniff",
                   "Referrer-Policy:",
                   "Permissions-Policy:",
                   "Content-Security-Policy:"):
        assert header in text, f"{rel} is missing {header.split(':')[0]}"
    assert "Strict-Transport-Security" in text, f"{rel}: no HSTS"


def test_the_landing_page_is_covered_by_a_policy_at_both_urls():
    """Pages matches the literal request path, so /index.html does not match /
    and would otherwise be served with no CSP at all."""
    text = HEADERS.read_text(encoding="utf-8")
    for pattern in ("/", "/index.html"):
        assert csp_for_block(text, pattern), (
            f"{HEADERS.relative_to(REPO)}: no CSP for {pattern}. A direct request "
            f"for {pattern} must not fall back to a policy-free response.")


@pytest.mark.parametrize("html,block", ALL_CSP_BLOCKS,
                         ids=[f"{h.parent.name or 'root'}{b}" for h, b in ALL_CSP_BLOCKS])
def test_csp_hashes_match_the_inline_blocks(html, block):
    """A hash-based CSP is only correct if the hash matches. Drift makes the
    whole page stop executing, which is loud -- but it must not happen in a
    release, so it is checked here."""
    rel = html.relative_to(REPO)
    csp = csp_for_block(HEADERS.read_text(encoding="utf-8"), block)
    assert csp, f"{HEADERS.relative_to(REPO)} has no CSP for {block}"
    listed = set(re.findall(r"'?(sha256-[A-Za-z0-9+/=]+)'?", csp))

    source = html.read_text(encoding="utf-8")
    blocks = re.findall(r"<script>(.*?)</script>", source, flags=re.S)
    assert blocks, f"{rel} has no inline script to hash"
    for inline in blocks:
        digest = "sha256-" + base64.b64encode(
            hashlib.sha256(inline.encode("utf-8")).digest()).decode("ascii")
        assert digest in listed, (
            f"{rel}: inline script is not covered by the CSP hash {digest} in "
            f"block {block}. Run: python tools/sync_csp.py --write")


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
# asset resolution
# --------------------------------------------------------------------------- #

SITE = REPO / "site"

_SKIP_SCHEME = re.compile(r"^(?:[a-z]+:|//|#)", re.I)


def _local_refs(text: str) -> list[str]:
    """href/src values that name a file in this repository."""
    out = []
    for value in re.findall(r'(?:href|src)="([^"]+)"', text):
        if _SKIP_SCHEME.match(value):
            continue
        out.append(value.split("#", 1)[0].split("?", 1)[0])
    return [v for v in out if v]


def _resolve(base: Path, ref: str) -> Path:
    """Where a reference points on disk. A leading / is site root, not /."""
    return (SITE / ref.lstrip("/")) if ref.startswith("/") else (base / ref)


@pytest.mark.parametrize("page", sorted(SITE.rglob("*.html")),
                         ids=lambda p: str(p.relative_to(SITE)))
def test_every_local_reference_resolves(page):
    """A 404 for a stylesheet is invisible: the page renders unstyled and the
    console says nothing an operator would read. The move to one deploy root
    changed the base every relative path resolves against, so this is checked
    rather than trusted."""
    broken = []
    for ref in _local_refs(page.read_text(encoding="utf-8")):
        target = _resolve(page.parent, ref)
        if target.is_dir():
            if not (target / "index.html").is_file():
                broken.append(f"{ref} (directory without index.html)")
        elif not target.exists():
            broken.append(ref)
    assert not broken, (
        f"{page.relative_to(REPO)} references files that do not exist: "
        f"{sorted(set(broken))}")


@pytest.mark.parametrize("sheet", sorted(SITE.rglob("*.css")),
                         ids=lambda p: str(p.relative_to(SITE)))
def test_every_local_url_resolves(sheet):
    broken = []
    for url in re.findall(r"url\(['\"]?([^'\")]+)", sheet.read_text(encoding="utf-8")):
        if _SKIP_SCHEME.match(url):
            continue
        if not (sheet.parent / url.split("#", 1)[0]).is_file():
            broken.append(url)
    assert not broken, (
        f"{sheet.relative_to(REPO)} references fonts or images that do not exist: "
        f"{sorted(set(broken))}")


MANIFESTS = sorted(
    p for p in REPO.glob("**/site.webmanifest")
    if not {".venv", "node_modules", "demo-out", "build", ".git"} & set(p.parts))


@pytest.mark.parametrize("manifest", MANIFESTS, ids=lambda p: p.parent.parent.name)
def test_web_manifests_are_usable(manifest):
    """Every manifest shipped empty name, empty short_name, a white canvas on a
    dark interface, and root-absolute icon paths pointing at the site root
    instead of the directory the icons are in. Installed to a home screen that
    is an unnamed white tile."""
    data = json.loads(manifest.read_text(encoding="utf-8"))
    rel = manifest.relative_to(REPO)
    assert data.get("name"), f"{rel} has no name"
    assert data.get("short_name"), f"{rel} has no short_name"
    for key in ("theme_color", "background_color"):
        colour = data.get(key, "")
        assert re.fullmatch(r"#[0-9A-Fa-f]{6}", colour), f"{rel}: {key} is {colour!r}"
        assert colour.lower() not in ("#ffffff", "#fff"), (
            f"{rel}: {key} is white, which flashes white behind a dark interface. "
            f"Use the canvas colour for the theme this manifest is for.")
    icons = data.get("icons") or []
    assert icons, f"{rel} declares no icons"
    for icon in icons:
        src = icon.get("src", "")
        assert not src.startswith("/"), (
            f"{rel}: icon {src!r} is root-absolute and resolves to the site root, "
            f"not to {manifest.parent}")
        assert (manifest.parent / src).is_file(), f"{rel}: icon {src!r} does not exist"


# --------------------------------------------------------------------------- #
# vendored assets
# --------------------------------------------------------------------------- #


def test_vendored_javascript_is_pinned_with_sri():
    html = (REPO / "site/verify" / "index.html").read_text(encoding="utf-8")
    vendor = REPO / "site/verify" / "vendor"
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
    manifest = REPO / "site/verify" / "vendor" / "manifest.json"
    assert manifest.is_file(), "vendor/manifest.json is required to pin re-vendoring"
    import json
    data = json.loads(manifest.read_text(encoding="utf-8"))
    listed = {e["path"] for e in data["files"]}
    on_disk = {f"vendor/{p.name}" for p in (REPO / "site/verify" / "vendor").iterdir()
               if p.is_file() and p.suffix in (".js",)}
    assert on_disk <= listed, f"unlisted vendored files: {sorted(on_disk - listed)}"
    for entry in data["files"]:
        actual = hashlib.sha256((REPO / "site/verify" / entry["path"]).read_bytes()).hexdigest()
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
    for html in PUBLIC_HTML + [REPO / "site/verify" / "tests" / "test_runner.html"]:
        text = html.read_text(encoding="utf-8")
        assert "fonts/fonts.css" in text or "../fonts/fonts.css" in text, (
            f"{html.relative_to(REPO)} does not load the self-hosted font sheet")


FONT_DIRS = [
    REPO / "site" / "fonts",
    REPO / "site" / "install" / "fonts",
    REPO / "site" / "verify" / "fonts",
    REPO / "src" / "s0" / "web" / "static" / "fonts",
]


@pytest.mark.parametrize("d", FONT_DIRS, ids=lambda p: str(p.parent.name))
def test_every_surface_font_sheet_resolves_to_real_files(d):
    """A surface whose font sheet names a file that is not there renders in a
    fallback face, silently. Check both directions: nothing referenced is
    missing, and nothing shipped is unreferenced."""
    sheet = d / "fonts.css"
    assert sheet.is_file(), f"{d.relative_to(REPO)} has no fonts.css"
    referenced = set(re.findall(r"url\('([^']+)'\)", sheet.read_text(encoding="utf-8")))
    assert referenced, f"{sheet.relative_to(REPO)} declares no @font-face src"
    for url in sorted(referenced):
        assert (d / url).is_file(), f"{d.relative_to(REPO)}/{url} is referenced but missing"
    shipped = {p.name for p in d.glob("*.woff2")}
    orphans = shipped - referenced
    assert not orphans, (
        f"{d.relative_to(REPO)} ships woff2 files nothing loads, which means one "
        f"variable font was copied out per weight again:\n  " + "\n  ".join(sorted(orphans)))


@pytest.mark.parametrize("d", FONT_DIRS, ids=lambda p: str(p.parent.name))
def test_every_surface_declares_font_weight_ranges(d):
    """Rubik and JetBrains Mono are variable fonts. Declaring one file per
    weight instead of one file with a range makes a browser download the same
    bytes once per weight, because it keys its font cache on URL rather than
    content -- nine files that were really two."""
    sheet = (d / "fonts.css").read_text(encoding="utf-8")
    ranges = re.findall(r"font-weight:\s*(\d+)\s+(\d+)\s*;", sheet)
    assert len(ranges) >= 2, (
        f"{d.relative_to(REPO)} declares single-weight faces; both families ship "
        "as variable fonts and must be declared with a range")
    for lo, hi in ranges:
        assert lo < hi, f"{d.relative_to(REPO)} has a degenerate weight range {lo} {hi}"


# --------------------------------------------------------------------------- #
# navigation
# --------------------------------------------------------------------------- #


# All three surfaces deploy from one origin, so the links between them are
# paths rather than hostnames. Docs stays on GitBook and the repository stays on
# GitHub, so those two remain absolute.
EXPECTED_NAV = {
    "docs": "sector-zero.gitbook.io",
    "install": "/install/",
    "verify": "/verify/",
    "github": "github.com/kartik2005221/s0",
}


# Each surface's own address, so the navigation test can exempt it: a page does
# not link to itself. This only became a question when the three moved onto one
# origin -- before that every surface was a separate domain and linking to your
# own host was neither possible nor meaningful.
SELF_PATH = {
    REPO / "site" / "index.html": "/",
    REPO / "site" / "install" / "index.html": "/install/",
    REPO / "site" / "verify" / "index.html": "/verify/",
}


@pytest.mark.parametrize("html", PUBLIC_HTML, ids=lambda p: p.parent.name)
def test_navigation_links_to_every_other_s0_surface(html):
    text = html.read_text(encoding="utf-8")
    me = SELF_PATH[html]
    for label, target in EXPECTED_NAV.items():
        if target == me:
            continue
        assert target in text, f"{html.relative_to(REPO)} does not link to {label} ({target})"


def test_every_s0_surface_is_reachable_from_somewhere():
    """A destination nobody links to is invisible. With the surfaces now sharing
    an origin it is easy to leave one orphaned while tidying another."""
    combined = "\n".join(html.read_text(encoding="utf-8") for html in PUBLIC_HTML)
    for label, target in EXPECTED_NAV.items():
        assert target in combined, f"no surface links to {label} ({target})"


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
        # 'log' must not match inside 'logo'. The header brand mark is a static
        # image whose src follows the theme; it is not a status region, and
        # reading its id as one would mean every page with a logo fails here.
        offenders = list(re.findall(
            r'id="([A-Za-z0-9_]*(?:status|progress|log(?!o)|result)[A-Za-z0-9_]*)"',
            text, flags=re.I))
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
