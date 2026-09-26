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
         python scripts/release.py --commit --tag
       or with automatic push:
         python scripts/release.py --commit --tag --push

Method B (Command-line one-liner):
    1. Run:
         python scripts/release.py 2.5.0 --commit --tag --push
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
2.  core/python/pyproject.toml              (s0-core Python package metadata)
3.  linux/cli/pyproject.toml                (s0-cli Python package metadata)
4.  core/python/s0_core/config.py           (DEFAULT_CONFIG fallback)
5.  linux/cli/s0_cli/__init__.py            (__version__ export)
6.  linux/cli/s0_cli/imager.py              (tool_version fallback)
7.  linux/cli/s0_cli/live_manager.py        (User-Agent header version)
8.  macos/cli/s0_eraser.py                  (macOS CLI version string)
9.  windows/cli/s0_eraser.py                (Windows CLI version string)
10. install-portal/install.sh               (Web/sh installer fallback echo)
11. README.md                               (Release badge link)
12. PLAN.md                                 (Roadmap status line)
13. docs/project/evaluator-guide.md         (Software release metadata)
14. docs/project/README.md                  (Release notes table link)
15. docs/getting-started/quickstart.md      (Config JSON example)
16. docs/architecture/certificate-spec.md   (Certificate JSON spec example)
17. docs/project/changelog.md               (Release header verification & stubbing)
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
from typing import Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]


def get_current_config_version() -> str:
    """Read version currently defined in s0_config.json."""
    cfg_path = REPO_ROOT / "s0_config.json"
    if not cfg_path.is_file():
        raise FileNotFoundError(f"Configuration file not found: {cfg_path}")
    with open(cfg_path, "r", encoding="utf-8") as f:
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


def sync_all_files(target_version: str, dry_run: bool = False) -> List[Path]:
    """Synchronize target_version across all repository files."""
    modified_files: List[Path] = []

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

    # 2. core/python/pyproject.toml
    p = REPO_ROOT / "core" / "python" / "pyproject.toml"
    if update_file_regex(p, r'(version\s*=\s*)"[^"]+"', f'\\g<1>"{target_version}"', dry_run):
        modified_files.append(p)

    # 3. linux/cli/pyproject.toml
    p = REPO_ROOT / "linux" / "cli" / "pyproject.toml"
    if update_file_regex(p, r'(version\s*=\s*)"[^"]+"', f'\\g<1>"{target_version}"', dry_run):
        modified_files.append(p)

    # 4. core/python/s0_core/config.py
    p = REPO_ROOT / "core" / "python" / "s0_core" / "config.py"
    if update_file_regex(p, r'("version"\s*:\s*)"[^"]+"', f'\\g<1>"{target_version}"', dry_run):
        modified_files.append(p)

    # 4b. core/python/s0_core/__init__.py
    p = REPO_ROOT / "core" / "python" / "s0_core" / "__init__.py"
    if update_file_regex(p, r'CONFIG\.get\("version",\s*"[^"]+"\)', f'CONFIG.get("version", "{target_version}")', dry_run):
        modified_files.append(p)

    # 5. linux/cli/s0_cli/__init__.py
    p = REPO_ROOT / "linux" / "cli" / "s0_cli" / "__init__.py"
    if p.is_file():
        content = p.read_text(encoding="utf-8")
        c1, n1 = re.subn(r'CONFIG\.get\("version",\s*"[^"]+"\)', f'CONFIG.get("version", "{target_version}")', content)
        c2, n2 = re.subn(r'__version__\s*=\s*"[^"]+"', f'__version__ = "{target_version}"', c1)
        if (n1 > 0 or n2 > 0) and c2 != content:
            if not dry_run:
                p.write_text(c2, encoding="utf-8")
            modified_files.append(p)

    # 6. linux/cli/s0_cli/imager.py
    p = REPO_ROOT / "linux" / "cli" / "s0_cli" / "imager.py"
    if update_file_regex(p, r'CONFIG\.get\("version",\s*"[^"]+"\)', f'CONFIG.get("version", "{target_version}")', dry_run):
        modified_files.append(p)

    # 7. linux/cli/s0_cli/live_manager.py
    p = REPO_ROOT / "linux" / "cli" / "s0_cli" / "live_manager.py"
    if update_file_regex(p, r'CONFIG\.get\(\'version\',\s*\'[^\']+\'\)', f"CONFIG.get('version', '{target_version}')", dry_run):
        modified_files.append(p)

    # 8. macos/cli/s0_eraser.py
    p = REPO_ROOT / "macos" / "cli" / "s0_eraser.py"
    if update_file_regex(p, r'CONFIG\.get\(\'version\',\s*\'[^\']+\'\)', f"CONFIG.get('version', '{target_version}')", dry_run):
        modified_files.append(p)

    # 9. windows/cli/s0_eraser.py
    p = REPO_ROOT / "windows" / "cli" / "s0_eraser.py"
    if update_file_regex(p, r'CONFIG\.get\(\'version\',\s*\'[^\']+\'\)', f"CONFIG.get('version', '{target_version}')", dry_run):
        modified_files.append(p)

    # 10. install-portal/install.sh (and scripts/install.sh if not symlink)
    p = REPO_ROOT / "install-portal" / "install.sh"
    if update_file_regex(p, r'(\|\|\s*echo\s*)"[^"]+"(\))', f'\\g<1>"{target_version}"\\g<2>', dry_run):
        modified_files.append(p)

    # 11. README.md (Release badge)
    p = REPO_ROOT / "README.md"
    if update_file_regex(p, r'badge/Release-v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?-blue\.svg', f'badge/Release-v{target_version}-blue.svg', dry_run):
        modified_files.append(p)

    # 12. PLAN.md
    p = REPO_ROOT / "PLAN.md"
    if update_file_regex(p, r'Production Release \(v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?\)', f'Production Release (v{target_version})', dry_run):
        modified_files.append(p)

    # 13. docs/project/evaluator-guide.md
    p = REPO_ROOT / "docs" / "project" / "evaluator-guide.md"
    if update_file_regex(p, r'(\*\*Software Release:\*\*\s*v)[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?', f'\\g<1>{target_version}', dry_run):
        modified_files.append(p)

    # 14. docs/project/README.md
    p = REPO_ROOT / "docs" / "project" / "README.md"
    if update_file_regex(p, r'(current\s*v)[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?(\s*release)', f'\\g<1>{target_version}\\g<3>', dry_run):
        modified_files.append(p)

    # 15. docs/getting-started/quickstart.md (config sample)
    p = REPO_ROOT / "docs" / "getting-started" / "quickstart.md"
    if update_file_regex(p, r'("version"\s*:\s*)"[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?",', f'\\g<1>"{target_version}",', dry_run):
        modified_files.append(p)

    # 16. docs/architecture/certificate-spec.md (tool version in JSON sample)
    p = REPO_ROOT / "docs" / "architecture" / "certificate-spec.md"
    if update_file_regex(p, r'("name":\s*"s0",\s*\n\s*"version":\s*)"[^"]+"', f'\\g<1>"{target_version}"', dry_run):
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
        print(f"[*] Run 'python scripts/release.py' to synchronize all files to v{current_ver}.")
        return 1
    print(f"[+] All files are in sync with v{current_ver}.")
    return 0


def run_command(cmd: List[str], check: bool = True) -> subprocess.CompletedProcess:
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
