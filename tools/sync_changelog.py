#!/usr/bin/env python3
"""Mirror the canonical changelog into the GitBook tree.

There were two changelogs. `CHANGELOG.md` at the repository root is where changes
were actually recorded; `docs/project/changelog.md` is what `.github/workflows/
release.yml` read, and it had stopped at 2.4.4. A v3 tag would therefore have been
released with generic notes while the real notes sat in a file the release workflow
never opened.

Rather than pick one and delete the other -- `docs/SUMMARY.md` links to the GitBook
copy, and GitBook only publishes pages in that summary -- the root file is canonical
and this script mirrors it. The GitBook page keeps working, the release workflow can
read either, and there is one place to edit.

    python tools/sync_changelog.py --write    # regenerate docs/project/changelog.md
    python tools/sync_changelog.py --check    # exit 1 if the mirror is stale

The banner is what makes the mirror obvious to a reader who lands on the GitBook
page first: it says where the canonical file is, so nobody edits the copy by mistake.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CANONICAL = REPO_ROOT / "CHANGELOG.md"
MIRROR = REPO_ROOT / "docs" / "project" / "changelog.md"

BANNER = """<!-- GENERATED FILE - DO NOT EDIT.

     Mirrored from /CHANGELOG.md at the repository root by
     `python tools/sync_changelog.py --write`, which is run by the docs check in CI.

     Edit the root file. Changes made here are overwritten.
-->

> **This page is a mirror.** The canonical changelog is
> [`CHANGELOG.md`](https://github.com/kartik2005221/s0/blob/master/CHANGELOG.md) at
> the repository root. It is mirrored here so the GitBook navigation keeps working;
> if the two ever disagree, the root file is right.

"""


def build() -> str:
    """The mirror's contents for the current canonical file."""
    if not CANONICAL.is_file():
        raise SystemExit(f"{CANONICAL.relative_to(REPO_ROOT)} is missing")
    body = CANONICAL.read_text(encoding="utf-8")
    # The mirror keeps its own title; the canonical file's H1 is dropped so the page
    # does not open with two competing headings.
    lines = body.split("\n")
    if lines and lines[0].startswith("# "):
        lines = lines[1:]
    return BANNER + "\n".join(lines).lstrip("\n")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--write", action="store_true", help="regenerate the mirror")
    ap.add_argument("--check", action="store_true", help="exit 1 if the mirror is stale")
    args = ap.parse_args(argv)

    if not (args.write or args.check):
        ap.error("pass --write or --check")

    wanted = build()
    current = MIRROR.read_text(encoding="utf-8") if MIRROR.is_file() else ""

    if args.check:
        if current != wanted:
            print(
                f"{MIRROR.relative_to(REPO_ROOT)} is stale: it does not match "
                f"{CANONICAL.relative_to(REPO_ROOT)}. Run tools/sync_changelog.py --write.",
                file=sys.stderr,
            )
            return 1
        print("docs changelog mirror is current")
        return 0

    if current == wanted:
        print("already current; no change")
        return 0
    MIRROR.parent.mkdir(parents=True, exist_ok=True)
    MIRROR.write_text(wanted, encoding="utf-8")
    print(f"mirrored {CANONICAL.relative_to(REPO_ROOT)} -> {MIRROR.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
