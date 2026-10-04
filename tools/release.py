#!/usr/bin/env python3
"""S0 (Sector Zero) — Automated Release & Version Synchronization Script.

================================================================================
HOW TO USE THIS SCRIPT
================================================================================

This script unifies version management across the entire repository. You can
either:

Method A (Recommended — Edit s0_config.json directly):
    1. Edit "version" in `s0_config.json` (e.g. "2.5.0").
    2. Add release notes under `## [2.5.0] — YYYY-MM-DD` in `docs/project/changelog.md`.
    3. Run:
         python tools/release.py --commit --tag
       or with automatic push:
         python tools/release.py --commit --tag --push

Method B (Command-line one-liner):
    1. Run:
         python tools/release.py 2.5.0 --commit --tag --push
       This will bump `s0_config.json` and all dependent files, ensure changelog
       has a stub, run the test suite, create the commit & tag, and push.

Other Useful Flags:
    --check         Verify whether all repository files are synchronized with s0_config.json.
    --dry-run       Preview all file diffs and actions without modifying disk.
    --skip-tests    Skip executing pytest before tagging/releasing.
    --commit        Automatically run `git commit` for modified files.
    --tag           Create annotated git tag `v<version>`.
    --push          Push the commit and tag to origin.

================================================================================
FILES SYNCHRONIZED BY THIS SCRIPT
================================================================================
1.  s0_config.json                          (Primary Single Source of Truth)
2.  pyproject.toml              (s0-core Python package metadata)
3.  src/s0/pyproject.toml                (s0-cli Python package metadata)
4.  src/s0/config.py           (DEFAULT_CONFIG fallback)
5.  src/s0/__init__.py         (__version__ export)
6.  src/s0/__init__.py            (__version__ export)
7.  src/s0/imager.py              (tool_version fallback)
8.  src/s0/cli/file_eraser.py         (tool_version fallback)
9.  src/s0/carve/engine.py       (tool_version fallback)
10. src/s0/live_manager.py        (User-Agent header & tag_synth versions)
11. src/s0/platform/macos/s0_eraser.py       (macOS CLI version string & tool_version)
12. src/s0/platform/windows/s0_eraser.py     (Windows CLI version string & tool_version)
13. tools/benchmark_perf.py               (Benchmark tool_version)
14. site/install/install.sh               (Web/sh installer fallback echo)
15. README.md                               (Release badge link)
16. PLAN.md                                 (Roadmap status line)
17. docs/project/evaluator-guide.md         (Software release metadata)
18. docs/project/README.md                  (Release notes table link)
19. docs/getting-started/quickstart.md      (CLI output & config JSON examples)
20. docs/architecture/certificate-spec.md   (Certificate JSON spec example)
21. docs/architecture/system-architecture.md(System architecture certificate spec)
22. docs/architecture/performance.md        (Performance benchmark evaluation date)
23. docs/guides/cli-reference.md            (CLI upgrade sample & download flag)
24. docs/guides/live-iso.md                 (Live ISO downloads, filenames, checksums)
25. docs/project/changelog.md               (Release header verification & stubbing)
================================================================================
"""

from __future__ import annotations

import argparse
import datetime
import json
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def get_current_config_version() -> str:
    """Read version currently defined in s0_config.json."""
    cfg_path = REPO_ROOT / "s0_config.json"
    if not cfg_path.is_file():
        raise FileNotFoundError(f"Configuration file not found: {cfg_path}")
    with open(cfg_path, encoding="utf-8") as f:
        data = json.load(f)
    version = data.get("version")
    if not version:
        raise ValueError(f"No 'version' field in {cfg_path}")
    return str(version).strip()


def validate_version(ver: str) -> None:
    """Ensure version string is semver-compliant (e.g., 2.4.2 or 2.5.0-rc1)."""
    pattern = r"^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$"
    if not re.match(pattern, ver):
        raise ValueError(f"Invalid semver version format: '{ver}'. Expected format: X.Y.Z or X.Y.Z-rc1")


def update_file_regex(
    file_path: Path,
    pattern: str,
    replacement: str,
    dry_run: bool = False,
) -> bool:
    """Read a file, apply regex replacement, and write back if changed. Return True if modified."""
    if not file_path.is_file():
        return False
    content = file_path.read_text(encoding="utf-8")
    new_content, count = re.subn(pattern, replacement, content)
    if count > 0 and new_content != content:
        if not dry_run:
            file_path.write_text(new_content, encoding="utf-8")
        return True
    return False


def sync_all_files(target_version: str, dry_run: bool = False) -> list[Path]:
    """Synchronize target_version across all repository files."""
    modified_files: list[Path] = []

    # 1. s0_config.json
    cfg_path = REPO_ROOT / "s0_config.json"
    if cfg_path.is_file():
        content = cfg_path.read_text(encoding="utf-8")
        new_content, count = re.subn(
            r'("version"\s*:\s*)"[^"]+"',
            f'\\g<1>"{target_version}"',
            content,
            count=1,
        )
        if count > 0 and new_content != content:
            if not dry_run:
                cfg_path.write_text(new_content, encoding="utf-8")
            modified_files.append(cfg_path)

    # 2. Distribution metadata. This is the only packaging site for the
    #    version: s0.__version__ reads it back through importlib.metadata.
    # Anchored to the start of a line so it cannot match `requires-python`.
    p = REPO_ROOT / "pyproject.toml"
    if update_file_regex(p, r'(?m)^(version\s*=\s*)"[^"]+"', f'\\g<1>"{target_version}"', dry_run):
        modified_files.append(p)

    # 3. DEFAULT_CONFIG fallback in the package config.
    p = REPO_ROOT / "src" / "s0" / "config.py"
    if update_file_regex(p, r'("version"\s*:\s*)"[^"]+"', f'\\g<1>"{target_version}"', dry_run):
        modified_files.append(p)

    # 4. Every remaining Python fallback literal.
    #
    #    This is a table, not a sequence of hand-written blocks, because the
    #    previous hand-written list silently stopped matching when the package
    #    moved out of src and src/s0 -- the release check then
    #    reported a failure against a file that no longer existed. A missing
    #    entry is now a hard error instead of a silent skip.
    for rel in (
        "src/s0/__init__.py",
        "src/s0/image/imager.py",
        "src/s0/cli/file_eraser.py",
        "src/s0/carve/engine.py",
        "src/s0/live/live_manager.py",
        "src/s0/platform/macos/s0_eraser.py",
        "src/s0/platform/windows/s0_eraser.py",
        "tools/benchmark_perf.py",
    ):
        p = REPO_ROOT / rel
        if not p.is_file():
            raise FileNotFoundError(
                f"version-synced file is missing from the tree: {rel}. "
                "Update the version-source table in tools/release.py."
            )
        content = p.read_text(encoding="utf-8")
        c1, n1 = re.subn(
            r"CONFIG\.get\('version',\s*'[^']+'\)",
            f"CONFIG.get('version', '{target_version}')",
            content,
        )
        c2, n2 = re.subn(
            r'CONFIG\.get\("version",\s*"[^"]+"\)',
            f'CONFIG.get("version", "{target_version}")',
            c1,
        )
        if (n1 > 0 or n2 > 0) and c2 != content:
            if not dry_run:
                p.write_text(c2, encoding="utf-8")
            modified_files.append(p)

    # 13. site/install/install.sh (and tools/install.sh if not symlink)
    p = REPO_ROOT / "site/install" / "install.sh"
    if update_file_regex(p, r'(\|\|\s*echo\s*)"[^"]+"(\))', f'\\g<1>"{target_version}"\\g<2>', dry_run):
        modified_files.append(p)

    # 14. README.md (Release badge)
    p = REPO_ROOT / "README.md"
    if update_file_regex(p, r'badge/Release-v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?-blue\.svg', f'badge/Release-v{target_version}-blue.svg', dry_run):
        modified_files.append(p)

    # 15. PLAN.md
    p = REPO_ROOT / "PLAN.md"
    if update_file_regex(p, r'Production Release \(v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?\)', f'Production Release (v{target_version})', dry_run):
        modified_files.append(p)

    # 16. docs/project/evaluator-guide.md
    p = REPO_ROOT / "docs" / "project" / "evaluator-guide.md"
    if update_file_regex(p, r'(\*\*Software Release:\*\*\s*v)[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?', f'\\g<1>{target_version}', dry_run):
        modified_files.append(p)

    # 17. docs/project/README.md
    p = REPO_ROOT / "docs" / "project" / "README.md"
    if update_file_regex(p, r'(current\s*v)[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?(\s*release)', f'\\g<1>{target_version}\\g<3>', dry_run):
        modified_files.append(p)

    # 18. docs/getting-started/quickstart.md (CLI output & config JSON samples)
    p = REPO_ROOT / "docs" / "getting-started" / "quickstart.md"
    if p.is_file():
        content = p.read_text(encoding="utf-8")
        c1, n1 = re.subn(r'("version"\s*:\s*)"[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?",', f'\\g<1>"{target_version}",', content)
        c2, n2 = re.subn(r'(\n\s*s0\s+)[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?(\s*\n)', f'\\g<1>{target_version}\\g<3>', c1)
        if (n1 > 0 or n2 > 0) and c2 != content:
            if not dry_run:
                p.write_text(c2, encoding="utf-8")
            modified_files.append(p)

    # 19. docs/architecture/certificate-spec.md (tool version in JSON sample)
    p = REPO_ROOT / "docs" / "architecture" / "certificate-spec.md"
    if update_file_regex(p, r'("name":\s*"s0",\s*\n\s*"version":\s*)"[^"]+"', f'\\g<1>"{target_version}"', dry_run):
        modified_files.append(p)

    # 20. docs/architecture/system-architecture.md (tool_version in JSON sample)
    p = REPO_ROOT / "docs" / "architecture" / "system-architecture.md"
    if update_file_regex(p, r'("tool_version":\s*)"[^"]+"', f'\\g<1>"{target_version}"', dry_run):
        modified_files.append(p)

    # 21. docs/architecture/performance.md (benchmark evaluation version)
    p = REPO_ROOT / "docs" / "architecture" / "performance.md"
    if update_file_regex(p, r'(\(\s*v)[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?(\s*\))', f'\\g<1>{target_version}\\g<3>', dry_run):
        modified_files.append(p)

    # 22. docs/guides/cli-reference.md (upgrade notice & version parameter)
    p = REPO_ROOT / "docs" / "guides" / "cli-reference.md"
    if p.is_file():
        content = p.read_text(encoding="utf-8")
        c1, n1 = re.subn(r'(S0 upgraded successfully to\s+)[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?', f'\\g<1>{target_version}', content)
        c2, n2 = re.subn(r'(\(e\.g\.,\s*`v)[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?(`\))', f'\\g<1>{target_version}\\g<3>', c1)
        if (n1 > 0 or n2 > 0) and c2 != content:
            if not dry_run:
                p.write_text(c2, encoding="utf-8")
            modified_files.append(p)

    # 23. docs/guides/live-iso.md (hybrid ISO filenames & download URLs)
    p = REPO_ROOT / "docs" / "guides" / "live-iso.md"
    if p.is_file():
        content = p.read_text(encoding="utf-8")
        c1, n1 = re.subn(r's0-live-v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?-amd64', f's0-live-v{target_version}-amd64', content)
        c2, n2 = re.subn(r'download/v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?/', f'download/v{target_version}/', c1)
        c3, n3 = re.subn(r'(download\s+v)[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?(\s+-R)', f'\\g<1>{target_version}\\g<3>', c2)
        if (n1 > 0 or n2 > 0 or n3 > 0) and c3 != content:
            if not dry_run:
                p.write_text(c3, encoding="utf-8")
            modified_files.append(p)

    return modified_files


def ensure_changelog_entry(target_version: str, dry_run: bool = False) -> bool:
    """Ensure docs/project/changelog.md contains ## [target_version].

    If missing, prepends a template entry above the latest version section.
    Returns True if changelog was updated or already has the section.
    """
    changelog_path = REPO_ROOT / "docs" / "project" / "changelog.md"
    if not changelog_path.is_file():
        print(f"[-] Warning: {changelog_path} does not exist.")
        return False

    content = changelog_path.read_text(encoding="utf-8")
    escaped_ver = re.escape(target_version)
    pattern = rf"##\s*\[{escaped_ver}\]"

    if re.search(pattern, content):
        print(f"[+] Changelog entry for [{target_version}] verified.")
        return False

    # Section is missing; stub a new entry
    today_str = datetime.date.today().isoformat()
    stub = (
        f"## [{target_version}] — {today_str}\n\n"
        f"### Changed\n"
        f"- Release v{target_version}.\n\n"
        f"---\n\n"
    )

    # Find the first existing release header e.g. ## [2.4.2]
    first_header = re.search(r"(##\s*\[[0-9]+\.[0-9]+\.[0-9]+)", content)
    if first_header:
        idx = first_header.start()
        new_content = content[:idx] + stub + content[idx:]
    else:
        new_content = content + "\n\n" + stub

    if not dry_run:
        changelog_path.write_text(new_content, encoding="utf-8")
        print(f"[+] Created release notes stub in docs/project/changelog.md for [{target_version}].")
    else:
        print(f"[dry-run] Would prepend release notes stub in docs/project/changelog.md for [{target_version}].")
    return True


def check_sync_status() -> int:
    """Check if all versioned files match s0_config.json."""
    current_ver = get_current_config_version()
    print(f"[*] Checking version synchronization against s0_config.json (v{current_ver})...")
    modified = sync_all_files(current_ver, dry_run=True)
    if modified:
        print(f"[-] Out-of-sync files detected ({len(modified)} files):")
        for m in modified:
            print(f"    - {m.relative_to(REPO_ROOT)}")
        print(f"[*] Run 'python tools/release.py' to synchronize all files to v{current_ver}.")
        return 1
    print(f"[+] All files are in sync with v{current_ver}.")
    return 0


def run_command(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    """Execute a subprocess command printing output."""
    print(f"[*] Running: {' '.join(cmd)}")
    res = subprocess.run(cmd, cwd=str(REPO_ROOT), text=True)
    if check and res.returncode != 0:
        print(f"[-] Command failed with exit code {res.returncode}: {' '.join(cmd)}", file=sys.stderr)
        sys.exit(res.returncode)
    return res


def main() -> int:
    parser = argparse.ArgumentParser(
        description="S0 (Sector Zero) Automated Release & Version Synchronization Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "version",
        nargs="?",
        default=None,
        help="Target release version (e.g. 2.5.0). If omitted, reads 'version' from s0_config.json.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check if all repository files are synchronized with s0_config.json.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate the release process without modifying files or git state.",
    )
    parser.add_argument(
        "--skip-tests",
        action="store_true",
        help="Skip executing pytest before committing and tagging.",
    )
    parser.add_argument(
        "--commit",
        action="store_true",
        help="Automatically create git commit for all modified version files.",
    )
    parser.add_argument(
        "--tag",
        action="store_true",
        help="Create annotated git tag v<version>.",
    )
    parser.add_argument(
        "--push",
        action="store_true",
        help="Push git commit and tag to origin master.",
    )
    args = parser.parse_args()

    if args.check:
        return check_sync_status()

    # Determine target version
    if args.version:
        target_version = args.version.lstrip("v")
    else:
        target_version = get_current_config_version()

    validate_version(target_version)
    tag_name = f"v{target_version}"
    print(f"[*] S0 Release Automation — Target Version: {target_version} ({tag_name})")

    # Synchronize all files
    modified = sync_all_files(target_version, dry_run=args.dry_run)
    if modified:
        print(f"[+] Synchronized {len(modified)} files to v{target_version}:")
        for m in modified:
            print(f"    • {m.relative_to(REPO_ROOT)}")
    else:
        print(f"[+] All files already match target version v{target_version}.")

    # Ensure changelog section exists
    changelog_updated = ensure_changelog_entry(target_version, dry_run=args.dry_run)
    if changelog_updated and not args.dry_run:
        modified.append(REPO_ROOT / "docs" / "project" / "changelog.md")

    # Run tests if requested and not dry run
    if not args.skip_tests and (args.commit or args.tag or args.push):
        print("[*] Verifying test suite before release...")
        pytest_bin = REPO_ROOT / ".venv" / "bin" / "pytest"
        if pytest_bin.is_file():
            run_command([str(pytest_bin), "-q", "--tb=short"])
        else:
            run_command(["pytest", "-q", "--tb=short"])
        print("[+] Test suite passed successfully.")

    if args.dry_run:
        print("[*] Dry run complete. No git commands executed.")
        return 0

    # Git operations
    if args.commit:
        # Check if working tree has changes
        status = subprocess.check_output(["git", "status", "--porcelain"], cwd=str(REPO_ROOT), text=True)
        if status.strip():
            run_command(["git", "add", "-A"])
            commit_msg = f"chore(release): bump version to {target_version} and update documentation"
            run_command(["git", "commit", "-m", commit_msg])
            print(f"[+] Created release commit: {commit_msg}")
        else:
            print("[*] Working tree clean; no changes to commit.")

    if args.tag:
        # Check if tag already exists
        tags = subprocess.check_output(["git", "tag", "-l", tag_name], cwd=str(REPO_ROOT), text=True).strip()
        if tags:
            print(f"[*] Tag {tag_name} already exists.")
        else:
            tag_msg = f"Release {tag_name}"
            run_command(["git", "tag", "-a", tag_name, "-m", tag_msg])
            print(f"[+] Created git tag: {tag_name}")

    if args.push:
        print(f"[*] Pushing master branch and tag {tag_name} to origin...")
        run_command(["git", "push", "origin", "master"])
        if args.tag:
            run_command(["git", "push", "origin", tag_name])
        print(f"[+] Successfully pushed release {tag_name} to origin.")

    print(f"\n✅ Release process for v{target_version} completed successfully!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
