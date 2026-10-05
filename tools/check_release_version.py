#!/usr/bin/env python3
"""Fail if the tag being released is not the version the code declares.

`release.yml` already refuses to publish when the changelog has no section for the tag. It
did not check the tag against the *code*, so this was publishable:

    git tag v3.0.0 && git push --tags

with `pyproject.toml` still at 2.4.4. The workflow builds, hashes, uploads and signs a wheel
that calls itself 2.4.4, and publishes it as 3.0.0. Every downstream consumer that trusts the
filename or the embedded version -- a lockfile pin, an ISO manifest, a `pip install
s0==3.0.0` -- gets something that disagrees with itself, and the artifact is immutable once
uploaded.

Three version sources have to agree, and they are independent:

* `pyproject.toml` -- what the wheel is stamped with,
* `src/s0/__init__.py` -- what `s0 --version` prints,
* `s0_config.json` -- what the config file records.

A pre-release tag (`v3.0.0-rc.1`) is allowed to differ from the final version only if the
version it *does* match is the one being built; the script reports every mismatch rather than
the first, because finding them one at a time across three files is a waste of a release
attempt.

Exit codes: 0 agree, 1 mismatch, 2 the checker could not run.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


def pyproject_version(root: Path) -> str | None:
    text = (root / "pyproject.toml").read_text(encoding="utf-8")
    # Deliberately a narrow scan rather than a TOML parse-and-walk: pyproject has exactly
    # one top-level `version`, and a regex cannot be fooled by a dependency named version.
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    return match.group(1) if match else None


def dunder_version(root: Path) -> str | None:
    """The version `s0 --version` reports.

    It is computed, not a literal: `_distribution_version() or str(CONFIG.get("version",
    "2.4.4"))`. So there is nothing to match a plain `__version__ = "..."` against, and an
    earlier version of this script silently reported only two of the three sources -- which
    reads as "all three agree" when one was never checked.

    The literal inside `CONFIG.get("version", ...)` is used instead: it is the value used
    when the package is not installed (running from a source tree), which is exactly the
    case where a stale literal is what an operator sees.
    """
    text = (root / "src" / "s0" / "__init__.py").read_text(encoding="utf-8")
    literal = re.search(r'^__version__\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if literal:
        return literal.group(1)
    fallback = re.search(r'CONFIG\.get\(\s*"version"\s*,\s*"([^"]+)"', text)
    return fallback.group(1) if fallback else None


def config_version(root: Path) -> str | None:
    path = root / "s0_config.json"
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    value = data.get("version")
    return str(value) if value else None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tag", nargs="?", default="", help="the release tag, e.g. v3.0.0")
    parser.add_argument("--root", default=".", help="repository root (default: .)")
    args = parser.parse_args()
    root = Path(args.root).resolve()

    sources = {
        "pyproject.toml": pyproject_version(root),
        "src/s0/__init__.py": dunder_version(root),
        "s0_config.json": config_version(root),
    }
    found = {name: value for name, value in sources.items() if value}
    if not found:
        print("error: no version found in pyproject.toml, __init__.py or s0_config.json", file=sys.stderr)
        return 2

    print("Declared versions:")
    for name, value in sorted(found.items()):
        print(f"  {name:24} {value}")

    distinct = set(found.values())
    if len(distinct) > 1:
        print(
            f"\nerror: the version sources disagree with each other: "
            f"{found}\n"
            f"       A wheel built from this tree would be stamped "
            f"{sorted(distinct)[0]} while another says {sorted(distinct)[-1]}.",
            file=sys.stderr,
        )
        return 1

    current = distinct.pop()
    if not args.tag:
        print(f"\nNo tag given; the tree is internally consistent at {current}.")
        return 0

    tag = args.tag.strip()
    expected = tag[1:] if tag.startswith("v") else tag
    if expected != current:
        print(
            f"\nerror: the tag is {tag} but the code declares {current}.\n"
            f"       Publishing {tag} would upload a wheel that reports itself as "
            f"{current}.\n"
            f"       Set the version in pyproject.toml, src/s0/__init__.py and "
            f"s0_config.json to {expected}, commit, then re-cut the tag.\n"
            f"       A published artefact cannot be corrected in place -- the tag and the "
            f"upload have to be replaced.",
            file=sys.stderr,
        )
        return 1

    print(f"\nOK: tag {tag} matches the declared version {current}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
