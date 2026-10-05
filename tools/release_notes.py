#!/usr/bin/env python3
"""Extract the release notes for one version from the canonical changelog.

`.github/workflows/release.yml` used to do this inline, and used to fall back to
`Release <tag> of s0 (Sector Zero) forensic data sanitization suite.` when the
section was missing. That fallback is worse than no notes: it looks like a
successful extraction, so a v3 tag cut from a changelog that had stopped at 2.4.4
published generic text and nothing surfaced until the release page was public.

It also read only `docs/project/changelog.md`. That file is now a mirror; the
canonical changelog is `CHANGELOG.md` at the repository root, so notes were being
taken from the copy rather than from the source.

The extraction lives here so it can be tested. A release workflow's notes step is
the one place where a silent fallback is most expensive and least likely to be
exercised, which is exactly the combination that should not be the only test.

    python tools/release_notes.py 3.0.0
    python tools/release_notes.py --check 3.0.0

Exits non-zero, with the sections it did find, when the version has no entry.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

#: Canonical first, mirror second. Both are read so the workflow works whether or not
#: the mirror has been regenerated.
CANDIDATES: tuple[Path, ...] = (
    REPO_ROOT / "CHANGELOG.md",
    REPO_ROOT / "docs" / "project" / "changelog.md",
)

#: `## [3.0.0] - 2026-01-01` and `## [3.0.0]` both count. The section ends at the next
#: `## [` heading or a horizontal rule.
SECTION = r"##\s*\[(?P<ver>{ver})\][^\n]*\n(?P<body>.*?)(?=\n---\n|\n##\s*\[|\Z)"
LIST_VERSIONS = r"^##\s*\[([^\]]+)\]"


class MissingSection(SystemExit):
    """No entry for the requested version. Carries the versions that do exist."""


def versions_in(text: str) -> list[str]:
    return re.findall(LIST_VERSIONS, text, re.MULTILINE)


def extract(version: str, candidates: tuple[Path, ...] = CANDIDATES) -> tuple[str, Path]:
    """The notes for *version*, and the file they came from.

    *version* may be given with or without a leading `v`. Raises `MissingSection`
    when no changelog has an entry for it.
    """
    ver = version.lstrip("v")
    pattern = SECTION.format(ver=re.escape(ver))
    searched: list[str] = []
    found: list[str] = []
    for path in candidates:
        if not path.is_file():
            searched.append(str(path))
            continue
        text = path.read_text(encoding="utf-8")
        m = re.search(pattern, text, re.DOTALL)
        if m:
            body = m.group("body").strip()
            if body:
                return body, path
            found.append(f"{path}: the [{ver}] section is empty")
        else:
            found.append(f"{path}: no section for [{ver}] (has: {versions_in(text)})")
    raise MissingSection(
        "\n".join(
            [
                f"error: no release notes for version {ver!r}.",
                *found,
                *(f"missing file: {p}" for p in searched),
                "",
                "Add the entry to the canonical changelog (CHANGELOG.md at the",
                "repository root), run `python tools/sync_changelog.py --write`,",
                "commit, and re-cut the tag.",
            ]
        )
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("version", help="e.g. 3.0.0 or v3.0.0")
    ap.add_argument(
        "--check",
        action="store_true",
        help="report whether notes exist without printing them (exit 1 if not)",
    )
    args = ap.parse_args(argv)

    try:
        notes, source = extract(args.version)
    except MissingSection as exc:
        print(str(exc), file=sys.stderr)
        return 1

    if args.check:
        print(f"release notes for {args.version}: {len(notes)} characters in {source}")
        return 0
    print(notes)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
