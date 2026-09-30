#!/usr/bin/env python3
"""Recompute the Content-Security-Policy inline-script hashes for the portals.

A static site cannot use per-response CSP nonces, because a nonce must be
fresh on every response. The correct pattern for a static page is a hash-based
policy: every inline block is hashed at build time, and the hash is baked into
the response headers. A single byte of drift in an inline block makes the whole
page stop executing -- loudly, which is the point.

    python tools/sync_csp.py            # report the current hashes
    python tools/sync_csp.py --write    # patch the placeholders in _headers
    python tools/sync_csp.py --check    # exit 1 if any placeholder is stale
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

# (html, _headers, script_src_tag, style_src_tag)
# (html, _headers, extra directives) -- `extra` is appended verbatim so each
# surface keeps the directives it genuinely needs (pdf.js needs worker-src).
SURFACES = [
    (REPO / "portals/install" / "index.html",
     REPO / "portals/install" / "_headers", ""),
    (REPO / "portals/verify" / "index.html",
     REPO / "portals/verify" / "_headers",
     "worker-src 'self' blob:; "),
]

_PLACEHOLDER = re.compile(r"'sha256-WILL_BE_FILLED'")


def inline_blocks(html: str, tag: str) -> list[str]:
    """Exact contents of every <tag>...</tag> with no attributes (inline)."""
    return re.findall(rf"<{tag}>(.*?)</{tag}>", html, flags=re.S)


def sha256_b64(text: str) -> str:
    return "sha256-" + base64.b64encode(
        hashlib.sha256(text.encode("utf-8")).digest()).decode("ascii")


def csp_for(html_path: Path, extra: dict[str, str] | None = None) -> str:
    html = html_path.read_text(encoding="utf-8")
    script_hashes = " ".join("'sha256-WILL_BE_FILLED'" for _ in inline_blocks(html, "script"))
    style_hashes = " ".join("'sha256-WILL_BE_FILLED'" for _ in inline_blocks(html, "style"))
    if not script_hashes:
        script_hashes = "'self'"
    if not style_hashes:
        style_hashes = "'self'"
    return (
        "default-src 'none'; "
        f"script-src 'self' {script_hashes}{' blob:' if (extra or {}).get('worker') else ''}; "
        f"style-src 'self' {style_hashes}; "
        "font-src 'self'; "
        "img-src 'self' data: blob:; "
        "connect-src 'self'; "
        "manifest-src 'self'; "
        "base-uri 'none'; "
        "form-action 'none'; "
        "frame-ancestors 'none'; "
        "object-src 'none'; "
        "upgrade-insecure-requests"
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--write", action="store_true", help="patch the _headers files")
    ap.add_argument("--check", action="store_true", help="fail if any placeholder is stale")
    args = ap.parse_args()

    stale = []
    for html_path, headers_path, _extra in SURFACES:
        if not headers_path.is_file():
            continue
        text = headers_path.read_text(encoding="utf-8")
        if not _PLACEHOLDER.search(text):
            print(f"{headers_path.relative_to(REPO)}: no placeholders (already written)")
            continue

        html = html_path.read_text(encoding="utf-8")
        tools = inline_blocks(html, "script")
        styles = inline_blocks(html, "style")

        # A CSP hash source is only valid when quoted; an unquoted
        # 'sha256-...' makes the browser discard the entire directive, silently
        # removing the protection it was meant to provide.
        script_src = " ".join(["'self'"] + [f"'{sha256_b64(b)}'" for b in tools]) \
            if tools else "'self'"
        # Presentational inline styles (the style="" attributes that exist for
        # layout, not behaviour) require 'unsafe-inline' in style-src. Script
        # injection is the actual threat model here, so script-src stays strict
        # and this relaxation is scoped to CSS only.
        style_src = "'self' 'unsafe-inline'"
        csp_line = (
            "  Content-Security-Policy: default-src 'none'; "
            f"script-src {script_src}; "
            f"style-src {style_src}; "
            "font-src 'self'; img-src 'self' data: blob:; connect-src 'self'; "
            f"{_extra}"
            "manifest-src 'self'; base-uri 'none'; form-action 'none'; "
            "frame-ancestors 'none'; object-src 'none'; upgrade-insecure-requests"
        )
        out_lines = []
        inserted = False
        for line in text.split("\n"):
            if line.strip().startswith("Content-Security-Policy:"):
                if not inserted:
                    out_lines.append(csp_line)
                    inserted = True
                continue
            out_lines.append(line)
        out = "\n".join(out_lines)

        rel = headers_path.relative_to(REPO)
        if args.write:
            headers_path.write_text(out, encoding="utf-8")
            print(f"wrote {rel}: {len(tools)} inline script(s), {len(styles)} inline style(s)")
        else:
            print(f"{rel}:")
            for b in tools:
                print(f"  script {sha256_b64(b)}")
            for b in styles:
                print(f"  style  {sha256_b64(b)}")
            if args.check:
                stale.append(str(rel))

    if args.check and stale:
        print("\nerror: these files still contain unfilled CSP placeholders:",
              file=sys.stderr)
        for s in stale:
            print(f"  {s}", file=sys.stderr)
        print("\nRun: python tools/sync_csp.py --write", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
