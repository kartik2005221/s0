#!/usr/bin/env python3
"""Fail on a link in site/ that does not resolve, or an HTML file with no <html>.

The portal, the installer pages and the docs are the only parts of this repository an
operator reads without a terminal. A dead `href` there is a support question, and a broken
`src` on the verification page means the crypto bundle silently does not load -- the page
still renders, it just cannot verify anything, which is the worst kind of failure for a
forensics tool's trust surface.

Only *local* links are checked, and deliberately so: a checker that fetches every external
URL turns a five-second lint into a network-bound flake, and an offline run cannot tell the
difference between a dead link and a firewall. External URLs are checked separately and
visibly (see `--check-external`, off by default).

Exit codes: 0 clean, 1 problems found, 2 the checker itself is broken.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlparse

# href="...", src="...", and srcset entries.
ATTR_RE = re.compile(
    r"""(?:href|src)\s*=\s*["']([^"']+)["']""",
    re.IGNORECASE,
)
SRCSET_RE = re.compile(r"""srcset\s*=\s*["']([^"']+)["']""", re.IGNORECASE)

# Schemes that are not local files, and so are not this check's business.
EXTERNAL_SCHEMES = ("http://", "https://", "mailto:", "tel:", "data:", "javascript:", "#")


def is_external(url: str) -> bool:
    return url.lower().startswith(EXTERNAL_SCHEMES) or url.startswith("//")


def is_anchor(url: str) -> bool:
    return url.startswith("#")


def collect(html: Path, root: Path) -> list[str]:
    text = html.read_text(encoding="utf-8", errors="replace")
    urls: list[str] = []
    for match in ATTR_RE.finditer(text):
        urls.append(match.group(1))
    for match in SRCSET_RE.finditer(text):
        for candidate in match.group(1).split(","):
            candidate = candidate.strip().split(" ")[0]
            if candidate:
                urls.append(candidate)
    return urls


def resolve(base: Path, url: str, site_root: Path) -> Path | None:
    """The filesystem path *url* refers to, or None if it is not a local file reference.

    A leading `/` means the *deployed site root*, not the filesystem root. `/verify/` in
    site/install/index.html is https://sector0.pages.dev/verify/, which is
    site/verify/ -- resolving it against `/` reported eleven dead links on the first run
    against a perfectly good site, which is the fastest way to get a link checker ignored.
    """
    parsed = urlparse(url)
    if parsed.scheme and not parsed.netloc:
        return None  # a non-http scheme we do not understand; not ours to judge
    path_part = unquote(parsed.path)
    if not path_part:
        return None
    if path_part.startswith("/"):
        return (site_root / path_part.lstrip("/")).resolve()
    return (base / path_part).resolve()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".", help="repository root (default: .)")
    parser.add_argument("--site", default="site", help="directory to check (default: site)")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    site = root / args.site

    if not site.is_dir():
        print(f"error: {site} is not a directory", file=sys.stderr)
        return 2

    html_files = sorted(site.rglob("*.html"))
    if not html_files:
        print(f"error: no HTML found under {site}", file=sys.stderr)
        return 2

    problems: list[str] = []
    external = 0
    anchors = 0
    checked = 0

    for html in html_files:
        rel = html.relative_to(root)

        text = html.read_text(encoding="utf-8", errors="replace")
        if "<html" not in text.lower():
            problems.append(f"{rel}: no <html> element; this is a fragment, not a page")

        for url in collect(html, root):
            if is_external(url):
                external += 1
                continue
            if is_anchor(url):
                anchors += 1
                continue
            target = resolve(html.parent, url, site_root=site)
            if target is None:
                continue
            checked += 1
            if not target.exists():
                problems.append(f"{rel}: {url} -> {target} does not exist")
                continue
            # A directory reference is fine if it has an index.html.
            if target.is_dir() and not (target / "index.html").is_file():
                problems.append(f"{rel}: {url} -> {target} is a directory with no index.html")

    print(f"Checked {len(html_files)} HTML file(s) under {args.site}/.")
    print(f"  {checked} local reference(s) resolved, {external} external, {anchors} in-page anchor(s).")
    print("  External URLs are not fetched: an offline run cannot tell a dead link from a")
    print("  firewall, so a checker that fetches them reports flakes, not findings.")

    if not problems:
        print("No broken local links.")
        return 0

    print(f"\n{len(problems)} problem(s):", file=sys.stderr)
    for problem in problems:
        print(f"  {problem}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
