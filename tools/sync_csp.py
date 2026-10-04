#!/usr/bin/env python3
"""Recompute the Content-Security-Policy inline-script hashes for every surface.

A static site cannot use per-response CSP nonces, because a nonce must be
fresh on every response. The correct pattern for a static page is a hash-based
policy: every inline block is hashed at build time, and the hash is baked into
the response headers. A single byte of drift in an inline block makes the whole
page stop executing -- loudly, which is the point.

    python tools/sync_csp.py            # report the current hashes
    python tools/sync_csp.py --write    # rewrite the CSP line of each block
    python tools/sync_csp.py --check    # exit 1 if any block's hashes are stale

One _headers now carries three policies, because Pages reads that file from the
output root only and all three surfaces deploy from the same place. Each surface
owns the blocks its paths match, so a block is patched from exactly one HTML
file. The landing page owns two: Pages matches the literal request path, and
/index.html is not /.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import re
import sys
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

HEADERS = REPO / "site" / "_headers"


@dataclass(frozen=True)
class Surface:
    """One page, the _headers blocks it owns, and the directives it needs.

    `connect` and `worker` exist because a policy has to permit what a page
    actually does. The landing page calls the GitHub releases API for its version
    badge. The verifier runs pdf.js, which needs a worker built from a blob.
    Neither permission is granted anywhere else: the install portal, which people
    pipe into root, gets no third-party origin and no worker.
    """

    html: Path
    blocks: tuple[str, ...]
    connect: str = "'self'"
    worker: bool = False
    comment: str = ""


SURFACES = (
    Surface(
        REPO / "site" / "index.html",
        ("/", "/index.html"),
        connect="'self' https://api.github.com/",
        comment="landing page",
    ),
    Surface(
        REPO / "site" / "install" / "index.html",
        ("/install/*",),
        comment="install portal",
    ),
    Surface(
        REPO / "site" / "verify" / "index.html",
        ("/verify/*",),
        worker=True,
        comment="verification portal",
    ),
)

_BLOCK_START = re.compile(r"^/\S*\s*$")
_CSP = re.compile(r"^\s*Content-Security-Policy:")


def inline_blocks(html: str, tag: str) -> list[str]:
    """Exact contents of every <tag>...</tag> with no attributes (inline)."""
    return re.findall(rf"<{tag}>(.*?)</{tag}>", html, flags=re.S)


def sha256_b64(text: str) -> str:
    return "sha256-" + base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode("ascii")


def parse_blocks(text: str) -> dict[str, int]:
    """Map each path pattern to the line index of its Content-Security-Policy.

    Returns only patterns that actually carry a CSP, so a block without one is
    simply absent rather than being mistaken for a block whose CSP is missing.
    """
    found: dict[str, int] = {}
    pattern: str | None = None
    for i, line in enumerate(text.split("\n")):
        if _BLOCK_START.match(line):
            pattern = line.strip()
        elif _CSP.match(line) and pattern is not None:
            found[pattern] = i
    return found


def csp_for(surface: Surface) -> str:
    """The policy a surface should ship, with real hashes."""
    html = surface.html.read_text(encoding="utf-8")
    scripts = inline_blocks(html, "script")
    # A CSP hash source is only valid when quoted; an unquoted 'sha256-...'
    # makes the browser discard the entire directive, silently removing the
    # protection it was meant to provide.
    script_src = " ".join(["'self'"] + [f"'{sha256_b64(b)}'" for b in scripts]) if scripts else "'self'"
    # Presentational inline styles (style="" attributes that exist for layout,
    # not behaviour) require 'unsafe-inline' in style-src. Script injection is
    # the actual threat model here, so script-src stays strict and this
    # relaxation is scoped to CSS only.
    style_src = "'self' 'unsafe-inline'"
    worker = "worker-src 'self' blob:; " if surface.worker else ""
    return (
        "  Content-Security-Policy: "
        "default-src 'none'; "
        f"script-src {script_src}; "
        f"style-src {style_src}; "
        "font-src 'self'; "
        "img-src 'self' data: blob:; "
        f"connect-src {surface.connect}; "
        f"{worker}"
        "manifest-src 'self'; "
        "base-uri 'none'; "
        "form-action 'none'; "
        "frame-ancestors 'none'; "
        "object-src 'none'; "
        "upgrade-insecure-requests"
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--write", action="store_true", help="rewrite each block's CSP line")
    ap.add_argument("--check", action="store_true", help="fail if any block's hashes are stale")
    args = ap.parse_args()

    if not HEADERS.is_file():
        print(f"error: {HEADERS.relative_to(REPO)} not found", file=sys.stderr)
        return 1

    lines = HEADERS.read_text(encoding="utf-8").split("\n")
    found = parse_blocks("\n".join(lines))

    stale: list[str] = []
    unknown = set(found) - {b for s in SURFACES for b in s.blocks}
    if unknown:
        print(f"error: _headers has CSP blocks owned by no surface: {sorted(unknown)}", file=sys.stderr)
        return 1

    for surface in SURFACES:
        want = csp_for(surface)
        html = surface.html.read_text(encoding="utf-8")
        scripts = inline_blocks(html, "script")
        styles = inline_blocks(html, "style")

        missing = [b for b in surface.blocks if b not in found]
        if missing:
            print(
                f"error: {HEADERS.relative_to(REPO)} has no CSP block for {surface.comment} at {missing}",
                file=sys.stderr,
            )
            return 1

        for block in surface.blocks:
            line = lines[found[block]].rstrip()
            if args.write:
                lines[found[block]] = want
                print(
                    f"wrote {HEADERS.relative_to(REPO)} [{block}] "
                    f"({surface.comment}): {len(scripts)} inline script(s)"
                )
            elif line != want:
                stale.append(f"{block} ({surface.comment})")

        if not args.write:
            print(f"{surface.comment}: {surface.html.relative_to(REPO)}")
            for b in scripts:
                print(f"  script {sha256_b64(b)}")
            for b in styles:
                print(f"  style  {sha256_b64(b)}")

    if args.write:
        HEADERS.write_text("\n".join(lines), encoding="utf-8")

    if args.check and stale:
        print("\nerror: these blocks do not match their page's inline scripts:", file=sys.stderr)
        for s in stale:
            print(f"  {s}", file=sys.stderr)
        print("\nRun: python tools/sync_csp.py --write", file=sys.stderr)
        return 1
    if args.check:
        print(f"CSP inline-script hashes in sync across {len(SURFACES)} surfaces")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
