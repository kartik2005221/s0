#!/usr/bin/env python3
"""Synchronize s0 canonical design assets across all web surfaces.

Source of truth: design/
Generated targets:
  - site/assets/
  - src/s0/web/static/assets/

Usage:
    python tools/sync_assets.py           # synchronize assets to all targets
    python tools/sync_assets.py --check   # fail if any target has drifted from design/
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SOURCE = REPO / "design"
TARGETS = [
    REPO / "site" / "assets",
    REPO / "src" / "s0" / "web" / "static" / "assets",
]


def _file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_drift() -> list[str]:
    """Return list of drift errors, empty if in sync."""
    problems: list[str] = []
    source_files = {p.relative_to(SOURCE): p for p in SOURCE.rglob("*") if p.is_file()}

    for target in TARGETS:
        rel_target = target.relative_to(REPO)
        if not target.is_dir():
            problems.append(f"{rel_target} directory is missing")
            continue

        target_files = {p.relative_to(target): p for p in target.rglob("*") if p.is_file()}

        # Check missing or modified files
        for rel_path, src_file in source_files.items():
            if rel_path not in target_files:
                problems.append(f"{rel_target}/{rel_path} is missing")
            elif _file_digest(src_file) != _file_digest(target_files[rel_path]):
                problems.append(f"{rel_target}/{rel_path} differs from design/{rel_path}")

        # Check unexpected extra files
        for rel_path in target_files:
            if rel_path not in source_files:
                problems.append(f"{rel_target}/{rel_path} is not in design/")

    return problems


def sync_assets() -> None:
    """Copy all assets from design/ to target directories."""
    for target in TARGETS:
        target.mkdir(parents=True, exist_ok=True)
        # Copy tree
        shutil.copytree(SOURCE, target, dirs_exist_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify targets match design/ without modifying")
    args = parser.parse_args()

    if not SOURCE.is_dir():
        print(f"error: canonical design directory missing: {SOURCE}", file=sys.stderr)
        return 2

    if args.check:
        problems = check_drift()
        if problems:
            print("Design asset drift detected:", file=sys.stderr)
            for p in problems:
                print(f"  - {p}", file=sys.stderr)
            print("Run 'python tools/sync_assets.py' to synchronize.", file=sys.stderr)
            return 1
        print("ok: all web surface assets match design/ exactly")
        return 0

    sync_assets()
    problems = check_drift()
    if problems:
        print(f"error: synchronization failed: {problems}", file=sys.stderr)
        return 1
    print(f"synced {SOURCE.relative_to(REPO)} -> {[str(t.relative_to(REPO)) for t in TARGETS]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
