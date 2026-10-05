#!/usr/bin/env python3
"""Set the default git ref that every installer and `s0 upgrade` resolves to.

The default ref was written out by hand in six places: `site/install/install.sh`,
`site/install/upgrade.sh`, `site/install/upgrade.cmd`, `site/install/install.ps1`,
`site/install/upgrade.ps1`, and twice in `src/s0/cli/main.py` (the two `s0 upgrade`
fallbacks). Nothing kept them in step, so after this branch is merged and deleted,
every install and every `s0 upgrade` on a machine without an explicit `S0_INSTALL_REF`
would try to fetch a branch that no longer exists.

Run this instead of editing six places by hand:

    python tools/set_install_ref.py master        # immediately after merging to master
    python tools/set_install_ref.py v3.0.0        # at release time

Both are needed. `master` is what a fresh install should follow between releases;
the tag is what a reproducible install should pin, and it is what the installer
documentation already tells operators to set.

The value is left at `agent/harness` on this branch, which is correct today: it is
the branch that is installable, and `master` is not.

Accepted values:

* `master`
* a release tag: `v3.0.0`, or a pre-release `v3.0.0-rc.1`
* the current branch, `agent/harness`, so the pre-merge state stays expressible

Anything else is refused. A typo like `v3.0.0.` or `mastre` would otherwise be
written into six places and only discovered when an operator's install failed.

`--check` reports where the files disagree and exits non-zero; `--show` lists every
place the default is written and the value in each.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
MAIN_PY = REPO_ROOT / "src" / "s0" / "cli" / "main.py"

#: `install.sh` and `upgrade.sh`: the default sits inside a nested parameter default.
SHELL_PATTERN = re.compile(
    r'(?P<prefix>S0_REF="\$\{S0_INSTALL_REF:-\$\{S0_BRANCH:-)(?P<ref>[^}]+)(?P<suffix>\}\}")'
)
#: `upgrade.cmd`: an `if` that assigns the default when the override is unset.
CMD_PATTERN = re.compile(r'(?P<prefix>if "%S0_INSTALL_REF%"=="" \(set "S0_REF=)(?P<ref>[^"]+)(?P<suffix>")')
#: `install.ps1` and `upgrade.ps1`: the default sits inside the $S0Ref fallback block.
PS1_PATTERN = re.compile(
    r'(?P<prefix>\$S0Ref\s*=\s*if\s*\([^)]+\)\s*\{[^}]+\}\s*elseif\s*\([^)]+\)\s*\{[^}]+\}\s*else\s*\{\s*")'
    r'(?P<ref>[^"]+)'
    r'(?P<suffix>"\s*\})',
    re.DOTALL,
)

SCRIPT_TARGETS: tuple[tuple[Path, re.Pattern[str]], ...] = (
    (REPO_ROOT / "site" / "install" / "install.sh", SHELL_PATTERN),
    (REPO_ROOT / "site" / "install" / "upgrade.sh", SHELL_PATTERN),
    (REPO_ROOT / "site" / "install" / "upgrade.cmd", CMD_PATTERN),
    (REPO_ROOT / "site" / "install" / "install.ps1", PS1_PATTERN),
    (REPO_ROOT / "site" / "install" / "upgrade.ps1", PS1_PATTERN),
)

VALID_TAG = re.compile(r"^v\d+\.\d+\.\d+(-rc\.\d+)?$")
CURRENT_BRANCH = "agent/harness"
ALLOWED = ("master", CURRENT_BRANCH)

#: A ref fallback returns a git ref at either indent. Narrow on purpose: the envelope
#: builder also returns quoted strings at 8 spaces, and matching those would find two
#: extra "candidates" that are not refs.
REF_RETURN = re.compile(r'^ {4,8}return "(?P<ref>[A-Za-z0-9][A-Za-z0-9._/-]*)"$')

#: The marker that distinguishes the *first* upgrade fallback from any other quoted
#: return. Only the marker is matched; the comment body is rebuilt from the template so
#: it cannot contradict the value two lines below it.
PY_COMMENT_MARKER = "installer pins a ref precisely"
#: Why the fallback is pinned rather than inherited. `{ref}` is the value in force.
#: Written for a branch; the wording for a tag is different, because a tag *is* the
#: installable ref and "not installable" would be false.
PY_COMMENT_BRANCH = (
    '        # Deliberately NOT "{ref}". This branch\'s installer pins a ref precisely\n'
    "        # because {ref} is not installable, so falling back to it re-introduces the\n"
    "        # bug the installer fix removed."
)
PY_COMMENT_TAG = (
    "        # Pinned to the released tag, not to the remote's default branch: this\n"
    "        # installer pins a ref precisely so a fresh install is reproducible, and\n"
    '        # "{ref}" is the artefact it was verified against. Falling back to whatever\n'
    "        # the remote points at would re-introduce the bug this removed."
)


def _fail(message: str) -> None:
    raise SystemExit(
        f"{MAIN_PY.relative_to(REPO_ROOT)}: {message}\n"
        f"  Fix the anchors in {Path(__file__).name} rather than leaving the ref unset."
    )


def current_branch() -> str:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
            timeout=15,
        )
        return out.stdout.strip() or CURRENT_BRANCH
    except (OSError, subprocess.SubprocessError):
        return CURRENT_BRANCH


def validate(ref: str, branch: str) -> str | None:
    """An error message, or None if *ref* is acceptable."""
    if ref in ALLOWED or ref == branch:
        return None
    if VALID_TAG.match(ref):
        return None
    return (
        f"{ref!r} is not an acceptable install ref.\n"
        f"  accepted: master, {branch}, or a release tag like v3.0.0 / v3.0.0-rc.1"
    )


def _comment_above(lines: list[str], index: int) -> bool:
    """True when the marker comment sits in the block directly above *index*."""
    at = index
    while at > 0 and lines[at - 1].lstrip().startswith("#"):
        if PY_COMMENT_MARKER in lines[at - 1]:
            return True
        at -= 1
    return False


def _main_py_ref_lines(lines: list[str]) -> list[int]:
    """Indices of the two `s0 upgrade` ref fallbacks.

    Structural, not a pattern over the whole file: `main.py` has three
    `return "<ref>"` statements at that indent and only two are the fallback. The
    first is the one carrying the explanatory comment; the second is the last such
    return before `cmd_upgrade` is defined.
    """
    candidates = [i for i, line in enumerate(lines) if REF_RETURN.fullmatch(line)]
    if not candidates:
        _fail('found no `return "<ref>"` statement to anchor on.')

    first = next((i for i in candidates if _comment_above(lines, i)), None)
    if first is None:
        _fail(
            "the first `s0 upgrade` fallback is no longer preceded by its explanatory "
            f"comment ({PY_COMMENT_MARKER!r})."
        )
    second = next((i for i in reversed(candidates) if i > first), None)
    if second is None:
        _fail(f"expected two `s0 upgrade` ref fallbacks, found one (at line {first + 1}).")
    return [first, second]


def read_refs() -> dict[Path, list[str]]:
    """Every default ref currently written, keyed by file."""
    found: dict[Path, list[str]] = {}
    for path, pattern in SCRIPT_TARGETS:
        if not path.is_file():
            raise SystemExit(f"{path.relative_to(REPO_ROOT)} is missing")
        text = path.read_text(encoding="utf-8")
        found[path] = [m.group("ref") for m in pattern.finditer(text)]

    if not MAIN_PY.is_file():
        raise SystemExit(f"{MAIN_PY.relative_to(REPO_ROOT)} is missing")
    lines = MAIN_PY.read_text(encoding="utf-8").split("\n")
    found[MAIN_PY] = [
        REF_RETURN.match(lines[i]).group(1)  # type: ignore[union-attr]
        for i in _main_py_ref_lines(lines)
    ]
    return found


def _rewrite_scripts(new_ref: str) -> None:
    for path, pattern in SCRIPT_TARGETS:
        text = path.read_text(encoding="utf-8")
        updated, count = pattern.subn(lambda m: f"{m.group('prefix')}{new_ref}{m.group('suffix')}", text)
        if count == 0:
            raise SystemExit(
                f"{path.relative_to(REPO_ROOT)}: no default ref matched. The pattern in "
                f"{Path(__file__).name} no longer fits the source; fix it rather than "
                f"leaving the ref unset."
            )
        if path.suffix == ".ps1":
            non_ascii = [ch for ch in updated if ord(ch) > 127]
            if non_ascii:
                raise SystemExit(
                    f"{path.relative_to(REPO_ROOT)} contains non-ASCII characters: {set(non_ascii)}"
                )
        path.write_text(updated, encoding="utf-8")


def _rewrite_main_py(new_ref: str) -> None:
    lines = MAIN_PY.read_text(encoding="utf-8").split("\n")
    first, second = _main_py_ref_lines(lines)

    # Replace the comment block above the first fallback, then both values.
    comment_start = first
    while comment_start > 0 and lines[comment_start - 1].lstrip().startswith("#"):
        comment_start -= 1
    if comment_start == first:
        _fail("found no comment block above the first `s0 upgrade` fallback.")
    # The branch template is only truthful for a branch. Naming a *tag* as the ref
    # makes "not installable" false, and naming a branch as a released artefact is
    # equally wrong -- a branch is not an artefact anything was verified against. So
    # the branch template is reused only when the ref really is a branch.
    template = (
        PY_COMMENT_BRANCH if new_ref == "master" or VALID_TAG.match(new_ref) is None else PY_COMMENT_TAG
    )
    lines[comment_start:first] = template.format(ref=new_ref).split("\n")

    # The comment replacement can change the line count, so re-locate rather than
    # trusting the earlier indices.
    first, second = _main_py_ref_lines(lines)
    for index in (first, second):
        indent = " " * (len(lines[index]) - len(lines[index].lstrip()))
        lines[index] = f'{indent}return "{new_ref}"'

    MAIN_PY.write_text("\n".join(lines), encoding="utf-8")


def _report(found: dict[Path, list[str]], before: dict[Path, list[str]] | None = None) -> None:
    width = max(len(str(p.relative_to(REPO_ROOT))) for p in found)
    for path, refs in sorted(found.items()):
        label = str(path.relative_to(REPO_ROOT)).ljust(width)
        shown = ", ".join(refs) if refs else "(none found)"
        marker = ""
        if before is not None and refs != before[path]:
            marker = f"  (was {', '.join(before[path])})"
        print(f"  {label}  {shown}{marker}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("ref", nargs="?", help="master, the current branch, or a tag like v3.0.0")
    ap.add_argument(
        "--check",
        action="store_true",
        help="exit 1 if the files disagree about the default ref; changes nothing",
    )
    ap.add_argument("--show", action="store_true", help="print every place the default ref is written")
    args = ap.parse_args(argv)

    if args.ref is None and not (args.show or args.check):
        ap.error("a ref is required (or use --show / --check)")

    branch = current_branch()

    if args.show:
        _report(read_refs())
        return 0

    if args.check:
        found = read_refs()
        empty = [p for p, refs in found.items() if not refs]
        distinct = {ref for refs in found.values() for ref in refs}
        if len(distinct) > 1 or empty or not distinct:
            if len(distinct) > 1:
                print(
                    "The installers and `s0 upgrade` disagree about the default ref:",
                    file=sys.stderr,
                )
            for path in empty:
                print(f"MISSING  {path.relative_to(REPO_ROOT)}: no default ref", file=sys.stderr)
            _report(found)
            print(f"\nFix with: python {Path(__file__).name} <ref>", file=sys.stderr)
            return 1
        print(f"all {len(found)} files agree: {distinct.pop()}")
        return 0

    error = validate(args.ref, branch)
    if error:
        print(error, file=sys.stderr)
        return 2

    before = read_refs()
    _rewrite_scripts(args.ref)
    _rewrite_main_py(args.ref)

    print(f"set the default install ref to {args.ref}")
    _report(read_refs(), before)
    if args.ref == "master":
        print(
            "\nAfter this, `s0 upgrade` and every installer fetch master. Confirm the\n"
            "merge to master has landed before shipping it."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
