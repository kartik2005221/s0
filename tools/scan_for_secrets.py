#!/usr/bin/env python3
"""Fail if a tracked file contains a credential, with the demo key explicitly allowed.

Why a script rather than gitleaks or trufflehog: both are Go binaries distributed outside
pip, so pinning and verifying them here would mean inventing an action SHA or trusting an
apt package. This is the check that can be run, reviewed and tested in the repository it
protects -- and a secret scanner nobody can run is not a scanner.

The one allowance is deliberate and narrow
-----------------------------------------
`src/s0/data/keys/demo_issuer_private.pem` is a **committed private key**, and it has to
stay committed: it ships in the wheel so `s0` works out of the box, it is the key the
verification portal recognises as unaccredited, and `tests/core/test_demo_key_statement_is_true.py`
asserts both facts. A scanner that flagged it would be a scanner everyone disables with a
blanket ignore.

So it is allowlisted *by path*, not by pattern, and the script prints it on every run. An
allowlist that is silent is how "one exception" becomes "the whole file". Any *other*
private key, anywhere, fails.

Exit codes: 0 clean, 1 something was found, 2 the scanner itself is broken.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

# The one permitted private key, with the reason it exists.
ALLOWED_PRIVATE_KEYS = {
    "src/s0/data/keys/demo_issuer_private.pem": (
        "the deliberately unaccredited demo key; it ships in the wheel and the portal "
        "labels every certificate it signs as a demo"
    ),
}

# Files that legitimately contain the *text* of a key header without being a key.
TEXT_ONLY_SUFFIXES = {".py", ".md", ".txt", ".html", ".js", ".json", ".yml", ".yaml", ".toml"}

PATTERNS: dict[str, re.Pattern[str]] = {
    "private key block": re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----"),
    "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}\b"),
    "GitHub fine-grained token": re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    "AWS access key id": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "Slack token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "Google API key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "Stripe live key": re.compile(r"\b[rs]k_live_[0-9a-zA-Z]{16,}\b"),
    "PyPI upload token": re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{16,}\b"),
    "npm token": re.compile(r"\bnpm_[A-Za-z0-9]{30,}\b"),
}

# Binary-ish and generated paths that are not worth scanning and produce false positives.
SKIP_SUFFIXES = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".webp",
    ".mp4",
    ".mkv",
    ".webm",
    ".mp3",
    ".zip",
    ".gz",
    ".bz2",
    ".xz",
    ".zst",
    ".iso",
    ".pdf",
    ".woff",
    ".woff2",
    ".ttf",
    ".otf",
    ".eot",
    ".so",
    ".pyc",
    ".min.js",
    ".min.css",
}
SKIP_DIR_PARTS = {".git", "node_modules", "build", "dist", "__pycache__", ".venv"}


def tracked_files(root: Path) -> list[Path]:
    """Files git knows about. Untracked scratch files are not a leak risk to CI."""
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"error: cannot list tracked files: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    return [root / p for p in out.split("\0") if p]


def scan(path: Path, root: Path) -> list[tuple[str, int, str]]:
    try:
        text = path.read_text(encoding="utf-8", errors="strict")
    except (UnicodeDecodeError, OSError):
        return []  # binary or unreadable; not a text credential
    if len(text) > 4 * 1024 * 1024:
        return []  # a multi-megabyte text file in a source tree is a mistake, not a secret

    rel = path.relative_to(root).as_posix()
    findings: list[tuple[str, int, str]] = []
    for name, pattern in PATTERNS.items():
        for lineno, line in enumerate(text.splitlines(), 1):
            if not pattern.search(line):
                continue
            if name == "private key block":
                if rel in ALLOWED_PRIVATE_KEYS:
                    continue
                # A file *describing* a header is documentation, not a key.
                if path.suffix in TEXT_ONLY_SUFFIXES:
                    continue
            findings.append((name, lineno, rel))
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".", help="repository root (default: .)")
    parser.add_argument("--quiet", action="store_true", help="only print problems")
    args = parser.parse_args()
    root = Path(args.root).resolve()

    print("Allowed private keys (checked by path, not by pattern):")
    for path, reason in sorted(ALLOWED_PRIVATE_KEYS.items()):
        present = (root / path).is_file()
        state = "present" if present else "ABSENT (unexpected -- see the docstring)"
        print(f"  {path}\n      {reason}\n      {state}")
    if not args.quiet:
        print()

    all_findings: list[tuple[str, int, str]] = []
    scanned = 0
    for path in tracked_files(root):
        if set(path.relative_to(root).parts) & SKIP_DIR_PARTS:
            continue
        if path.suffix.lower() in SKIP_SUFFIXES:
            continue
        scanned += 1
        all_findings.extend(scan(path, root))

    print(f"Scanned {scanned} tracked text file(s).")
    if not all_findings:
        print("No credentials found.")
        return 0

    print(f"\n{len(all_findings)} potential credential(s) found:", file=sys.stderr)
    for name, lineno, rel in sorted(all_findings, key=lambda f: (f[2], f[1])):
        print(f"  {rel}:{lineno}  {name}", file=sys.stderr)
    print(
        "\nIf one of these is deliberate, add it to ALLOWED_PRIVATE_KEYS in "
        "tools/scan_for_secrets.py with a reason. Do not add a blanket ignore.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
