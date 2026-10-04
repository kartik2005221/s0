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

#: A `Help Screen` tab's command is derived from the markdown heading it sits
#: under, so blocks cannot drift out of their section. This list is gone: keeping
#: one meant the generator filled tabs in *document* order, so the ten tabs in
#: cli-reference.md received help for a different set of ten commands. Five blocks
#: landed in the wrong section and `s0 upgrade` -- which does have a heading -- was
#: given no help at all. `--check` could not catch it, because it compares each
#: block to the generator's own output and the generator is what misplaced them.
HEADING = re.compile(r"^#{2,4}\s+s0\s+(?P<cmd>.+?)\s*$")


def command_for_heading(heading: str) -> str | None:
    """`## s0 wipe (Files & Folders)` -> `wipe`; `## s0 audit list` -> `audit list`."""
    m = HEADING.match(heading)
    if not m:
        return None
    cmd = re.sub(r"\s*\(.*?\)\s*$", "", m.group("cmd")).strip()
    return cmd or None


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
            help_text = parser.parse_args([*command.split(), "--help"])
        except SystemExit:
            help_text = None
        if help_text is None:
            return f"(no --help for `{command}`)\n"
        return _normalise(parser.format_help())

    # COLUMNS pins argparse's wrap width; without it the output depends on the
    # terminal, and a docs check that fails cosmetically gets ignored.
    proc = subprocess.run(
        # `command` can name a nested command ("audit list"), so split it: passing
        # it as one argv element asks s0 for a subcommand literally named
        # "audit list", which does not exist.
        [str(entry), *command.split(), "--help"],
        capture_output=True,
        text=True,
        timeout=60,
        env={**os.environ, "COLUMNS": "100"},
    )
    if proc.returncode != 0:
        return f"(no --help for `{command}`)\n"
    return _normalise(proc.stdout)


#: argparse's *layout* is Python-version dependent; its *content* is not.
#:
#: 3.11 prints an option that has both forms as `--passes PASSES, -p PASSES`; 3.13+
#: prints `--passes, -p PASSES`. The longer pre-3.13 invocation also pushes argparse's
#: help column further right, so where the description starts, and whether it starts
#: on the same line at all, both move. The committed blocks were generated on one
#: interpreter while CI's `--check` ran on 3.10 through 3.13, so the gate failed on
#: every version but one -- over a comma and some padding.
#:
#: So the gate compares content, not layout: `_skeleton` reduces a help screen to
#: (option invocation, description) pairs with whitespace collapsed, which is
#: identical on every supported version. The committed block stays pretty, exactly
#: as argparse rendered it for whoever generated it.
HELP_LINE = re.compile(r"^(?P<indent>\s+)(?P<invocation>\S.*?)(?:\s{2,}(?P<help>\S.*))?$")
OLD_STYLE_OPTION = re.compile(
    r"^(?P<long>--[A-Za-z0-9-]+)\s+(?P<meta>.+?),\s+(?P<short>-[A-Za-z])\s+(?P<meta2>.+)$"
)
SECTION_HEADING = re.compile(r"^[A-Za-z][A-Za-z ]*:$")


def canonical_invocation(invocation: str) -> str:
    """`--passes PASSES, -p PASSES` and `--passes, -p PASSES` -> the latter."""
    m = OLD_STYLE_OPTION.match(invocation)
    if not m or m.group("meta").strip() != m.group("meta2").strip():
        return " ".join(invocation.split())
    return " ".join(f"{m.group('long')}, {m.group('short')} {m.group('meta2')}".split())


def _skeleton(text: str) -> list[str]:
    """Reduce a help screen to comparable content, ignoring layout.

    Wrapped description lines are folded back onto the option they belong to, since
    argparse moves a description to its own line once the invocation is long enough
    to exhaust the help column -- which is exactly what the 3.11 spelling does.
    """
    entries: list[str] = []
    current: list[str] | None = None
    for raw in text.replace("\r\n", "\n").split("\n"):
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped:
            current = None
            continue
        if SECTION_HEADING.match(stripped) or stripped.startswith(("usage:", "usage ", "positional")):
            current = None
            entries.append(" ".join(stripped.split()))
            continue
        m = HELP_LINE.match(line)
        if m and m.group("invocation").startswith("-"):
            inv = canonical_invocation(m.group("invocation"))
            help_text = " ".join((m.group("help") or "").split())
            current = [f"{inv} | {help_text}"]
            entries.append(" ".join(current))
            continue
        if current is not None:
            # A continuation of the previous option's description.
            entries[-1] = f"{entries[-1]} {stripped}"
            continue
        entries.append(" ".join(stripped.split()))
    return entries


def _normalise(text: str) -> str:
    """Trim trailing whitespace and trailing blank lines from a rendered help screen."""
    lines = [line.rstrip() for line in text.replace("\r\n", "\n").split("\n")]
    while lines and not lines[-1]:
        lines.pop()
    return "\n".join(lines) + "\n"


def tab_commands(text: str) -> list[str]:
    """The command each Help Screen tab documents, in document order.

    A tab's command is taken from the nearest markdown heading above it, so the
    only way a block can be wrong is if its heading is wrong.
    """
    headings: list[tuple[int, str]] = []
    offset = 0
    for line in text.splitlines(keepends=True):
        if line.startswith("#"):
            headings.append((offset, line.strip()))
        offset += len(line)

    out: list[str] = []
    for m in TAB.finditer(text):
        earlier = [h for h in headings if h[0] < m.start()]
        heading = earlier[-1][1] if earlier else ""
        cmd = command_for_heading(heading)
        if cmd is None:
            raise SystemExit(
                f"a Help Screen tab sits under {heading!r}, which does not name an s0 "
                f"command, so its help cannot be generated. Move the tab under a "
                f"heading like `## s0 wipe`."
            )
        out.append(cmd)
    return out


def rewrite(text: str, help_of) -> str:
    """Replace each Help Screen body with the help for the command it documents."""
    pieces: list[str] = []
    cursor = 0
    for cmd in tab_commands(text):
        m = TAB.search(text, cursor)
        if m is None:  # pragma: no cover - tab_commands and TAB disagree
            raise SystemExit("internal error: tab scan and tab regex disagree")
        block = help_of(cmd)
        pieces.append(text[cursor : m.start("body")])
        pieces.append(f"\n```\n{block}```\n")
        cursor = m.end("body")
    pieces.append(text[cursor:])
    return "".join(pieces)


def _first_difference(on_disk: str, generated: str) -> str | None:
    """A description of the first Help Screen block whose content differs.

    Compares content rather than text. argparse's layout changes between Python
    versions (see `_skeleton`), so an exact comparison reports a stale document
    whenever the check runs on a different interpreter than the one that generated
    it, and a gate that cries wolf gets ignored.
    """
    disk_tabs = list(TAB.finditer(on_disk))
    gen_tabs = list(TAB.finditer(generated))
    if len(disk_tabs) != len(gen_tabs):
        return f"{len(disk_tabs)} Help Screen tabs on disk, {len(gen_tabs)} generated"
    for n, (d, g) in enumerate(zip(disk_tabs, gen_tabs, strict=False), start=1):
        want, have = _skeleton(g.group("body")), _skeleton(d.group("body"))
        if want == have:
            continue
        for line_want, line_have in zip(want, have, strict=False):
            if line_want != line_have:
                return f"block {n}: on disk {line_have!r}, generated {line_want!r}"
        return f"block {n}: on disk has {len(have)} content lines, generated has {len(want)}"
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true", help="exit 1 if the file on disk is stale")
    args = ap.parse_args()

    if not DOC.is_file():
        print(f"{DOC} not found", file=sys.stderr)
        return 2

    original = DOC.read_text()
    cache: dict[str, str] = {}

    def help_of(command: str) -> str:
        if command not in cache:
            cache[command] = help_for(command)
        return cache[command]

    updated = rewrite(original, help_of)
    blocks = sorted(cache)

    if args.check:
        stale = _first_difference(original, updated)
        if stale is not None:
            print(
                f"{DOC.relative_to(REPO_ROOT)} is stale: its Help Screen blocks no "
                f"longer match `--help`. Run tools/gen_help_reference.py.",
                file=sys.stderr,
            )
            print(f"  first difference: {stale}", file=sys.stderr)
            return 1
        print("help reference is current")
        return 0

    if _first_difference(original, updated) is None:
        print("already current; no change")
        return 0
    DOC.write_text(updated)
    print(
        f"rewrote {len(blocks)} Help Screen blocks in {DOC.relative_to(REPO_ROOT)} "
        f"(commands: {', '.join(blocks)})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
