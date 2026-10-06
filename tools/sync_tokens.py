#!/usr/bin/env python3
"""Copy the canonical design tokens to every surface that needs them.

Each portal is a static site deployed from its own directory, so a shared
stylesheet at /shared/tokens.css would not resolve on Cloudflare Pages. A build
step would be a worse trade than three identical copies, so the copies are made
here and held identical by `tests/test_portal_consistency.py`.

    python tools/sync_tokens.py           # write the copies
    python tools/sync_tokens.py --check   # fail if any copy has drifted
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SOURCE = REPO / "shared" / "tokens.css"

TARGETS = [
    REPO / "site/css" / "tokens.css",
    REPO / "site/install" / "css" / "tokens.css",
    REPO / "site/verify" / "css" / "tokens.css",
    REPO / "src" / "s0" / "web" / "static" / "css" / "tokens.css",
]

BANNER = (
    "/* GENERATED FILE - do not edit.\n"
    "   Source: shared/tokens.css   Sync: python tools/sync_tokens.py\n"
    "   The single source of truth for every s0 surface's colour, type,\n"
    "   spacing, focus and motion tokens. */\n\n"
)


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()[:16]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true", help="verify the copies match the source; do not write")
    args = ap.parse_args()

    if not SOURCE.is_file():
        print(f"error: canonical token file missing: {SOURCE}", file=sys.stderr)
        return 2
    payload = (BANNER + SOURCE.read_text(encoding="utf-8")).encode("utf-8")
    want = hashlib.sha256(payload).hexdigest()[:16]

    stale = []
    for target in TARGETS:
        rel = target.relative_to(REPO)
        if args.check:
            if not target.is_file() or _digest(target) != want:
                stale.append(str(rel))
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
            print(f"  synced {rel} ({want})")

    if args.check:
        if stale:
            print("error: design-token copies are out of date:", file=sys.stderr)
            for path in stale:
                print(f"  {path}", file=sys.stderr)
            print("\nRun: python tools/sync_tokens.py", file=sys.stderr)
            return 1
        print(f"design tokens in sync across {len(TARGETS)} surfaces ({want})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
