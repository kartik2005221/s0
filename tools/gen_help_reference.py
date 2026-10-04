#!/usr/bin/env python3
"""Regenerate the `Help Screen` blocks in docs/guides/cli-reference.md.

Why this exists
---------------
Those ten blocks were pasted from `--help` by hand, so they drifted: every one was
missing the global output flags, `s0 image` was missing `--force`, `s0 audit` was
missing `--key`, and the sample outputs predated a reformat of the verify output. A
pasted transcript is a snapshot that decays; the drift is invisible because nothing
compares it to the parser.

The check mode is the point. `--check` exits non-zero if the file on disk differs
from what the live parser would produce, which turns "are the docs current?" from a
manual read into a CI gate. Nothing runs the commands -- `--help` output only, so
there is no way for this to touch a device.

Usage:
    tools/gen_help_reference.py            # rewrite the blocks in place
    tools/gen_help_reference.py --check    # exit 1 if they are stale (for CI)
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DOC = REPO_ROOT / "docs" / "guides" / "cli-reference.md"

#: The command whose help each `Help Screen` tab documents.
COMMANDS = [
    "list",
    "plan",
    "wipe",
    "image",
    "clone",
    "carve",
    "verify",
    "audit",
    "keygen",
    "live",
]

TAB = re.compile(r'(?P<head>\{% tab title="Help Screen" %\}\n)(?P<body>.*?)(?P<tail>\{% endtab %\})', re.S)


def help_for(command: str) -> str:
    """Run `<entry point> <command> --help` and return it, or a note."""
    entry = REPO_ROOT / ".venv" / "bin" / "s0"
    if not entry.is_file():
        sys.path.insert(0, str(REPO_ROOT / "src"))
        try:
            from s0.cli.main import build_parser
        except ImportError as exc:  # pragma: no cover
            return f"(could not import the parser: {exc})\n"
        parser = build_parser()
        try:
            help_text = parser.parse_args([command, "--help"])
        except SystemExit:
            help_text = None
        if help_text is None:
            return f"(no --help for `{command}`)\n"
        return _normalise(parser.format_help())

    # COLUMNS pins argparse's wrap width; without it the output depends on the
    # terminal, and a docs check that fails cosmetically gets ignored.
    proc = subprocess.run(
        [str(entry), command, "--help"],
        capture_output=True,
        text=True,
        timeout=60,
        env={**os.environ, "COLUMNS": "100"},
    )
    if proc.returncode != 0:
        return f"(no --help for `{command}`)\n"
    return _normalise(proc.stdout)


def _normalise(text: str) -> str:
    """Normalise line endings and trailing whitespace.

    Width is pinned by the caller via COLUMNS in the subprocess environment; argparse
    wraps its output to the terminal width, so without that the same command renders
    differently in CI and in a terminal and `--check` would fail for cosmetic reasons.
    """
    lines = [line.rstrip() for line in text.replace("\r\n", "\n").split("\n")]
    while lines and not lines[-1]:
        lines.pop()
    return "\n".join(lines) + "\n"


def rewrite(text: str, blocks: list[str]) -> str:
    """Replace each Help Screen body with the freshly generated help."""
    index = iter(blocks)

    def replace(match: re.Match[str]) -> str:
        try:
            block = next(index)
        except StopIteration:
            return match.group(0)
        return f"{match.group('head')}\n```\n{block}```\n{match.group('tail')}"

    return TAB.sub(replace, text)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true", help="exit 1 if the file on disk is stale")
    args = ap.parse_args()

    if not DOC.is_file():
        print(f"{DOC} not found", file=sys.stderr)
        return 2

    blocks = [help_for(command) for command in COMMANDS]
    original = DOC.read_text()
    updated = rewrite(original, blocks)

    if args.check:
        if updated != original:
            print(
                f"{DOC.relative_to(REPO_ROOT)} is stale: its Help Screen blocks no "
                f"longer match `--help`. Run tools/gen_help_reference.py.",
                file=sys.stderr,
            )
            return 1
        print("help reference is current")
        return 0

    if updated == original:
        print("already current; no change")
        return 0
    DOC.write_text(updated)
    print(f"rewrote {len(blocks)} Help Screen blocks in {DOC.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
