#!/usr/bin/env python3
"""Build and synchronize static HTML pages from Jinja2 templates.

Template sources: site/_templates/
Target outputs:
  site/index.html
  site/install/index.html
  site/verify/index.html
  site/404.html

Usage:
  python tools/build_site.py            # render and write all pages
  python tools/build_site.py --check    # exit 1 if rendered output differs from disk
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

import jinja2

REPO = Path(__file__).resolve().parents[1]
TEMPLATES_DIR = REPO / "templates" / "site"
SITE_DIR = REPO / "site"
CONFIG_FILE = REPO / "s0_config.json"


def get_version() -> str:
    if CONFIG_FILE.is_file():
        try:
            data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            return str(data.get("version", "3.0.0"))
        except Exception:
            pass
    return "3.0.0"


PAGES = [
    {
        "template": "index.html",
        "output": SITE_DIR / "index.html",
        "context": {
            "page_id": "home",
            "title": "s0 — Unified Forensic Data Sanitization, Acquisition & Carving Suite",
            "description": "s0 (Sector Zero) is an open-source digital forensic and media sanitization suite. Aligned with NIST SP 800-88 Rev. 2, with Ed25519-signed attestation records.",
            "canonical": "https://sector0.pages.dev/",
            "rel_prefix": "",
        },
    },
    {
        "template": "install.html",
        "output": SITE_DIR / "install" / "index.html",
        "context": {
            "page_id": "install",
            "title": "s0 — Installation & Deployment Guide",
            "description": "Forensic-grade drive sanitization, deleted-file recovery, and Ed25519-signed verification. Deploy across Linux, macOS, and Windows.",
            "canonical": "https://sector0.pages.dev/install/",
            "rel_prefix": "",
        },
    },
    {
        "template": "verify.html",
        "output": SITE_DIR / "verify" / "index.html",
        "context": {
            "page_id": "verify",
            "title": "s0 — Cryptographic Certificate Verification",
            "description": "Verify s0 cryptographic sanitization certificates offline using pure WebCrypto. 100% client-side zero-trust verification.",
            "canonical": "https://sector0.pages.dev/verify/",
            "rel_prefix": "",
        },
    },
]


def render_all(env: jinja2.Environment, version: str) -> dict[Path, str]:
    rendered = {}
    for page in PAGES:
        ctx = dict(page["context"])
        ctx["version"] = version
        tmpl = env.get_template(page["template"])
        content = tmpl.render(**ctx)
        # Ensure trailing newline
        if not content.endswith("\n"):
            content += "\n"
        rendered[page["output"]] = content
    return rendered


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify rendered output matches disk")
    args = parser.parse_args()

    if not TEMPLATES_DIR.is_dir():
        print(f"error: templates directory not found: {TEMPLATES_DIR}", file=sys.stderr)
        return 2

    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=jinja2.select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )

    version = get_version()
    rendered = render_all(env, version)

    stale: list[str] = []
    for out_path, content in rendered.items():
        rel = out_path.relative_to(REPO)
        if args.check:
            if not out_path.is_file():
                stale.append(f"{rel} (missing on disk)")
            else:
                on_disk = out_path.read_text(encoding="utf-8")
                if on_disk != content:
                    stale.append(f"{rel} (content differs from template)")
        else:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(content, encoding="utf-8")
            print(f"  rendered {rel}")

    if args.check:
        if stale:
            print("error: rendered HTML files out of date with templates:", file=sys.stderr)
            for s in stale:
                print(f"  {s}", file=sys.stderr)
            print("\nRun: python tools/build_site.py", file=sys.stderr)
            return 1
        print(f"site templates in sync across {len(rendered)} pages (v{version})")
        return 0

    # If wrote pages, automatically sync CSP hashes
    sync_csp_script = REPO / "tools" / "sync_csp.py"
    if sync_csp_script.is_file():
        subprocess.run([sys.executable, str(sync_csp_script), "--write"], check=True, cwd=str(REPO))

    return 0


if __name__ == "__main__":
    sys.exit(main())
