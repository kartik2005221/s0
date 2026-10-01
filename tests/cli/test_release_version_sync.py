"""Every module with a version fallback must be in the release tool's table.

`tools/release.py` keeps a hardcoded list of files carrying
`CONFIG.get('version', '...')` literals, and raises if a listed file is missing.
That guard only works in one direction: a file that *gains* such a literal and is
never added to the table silently keeps a stale version in the certificate.

The eight modules added during the carving and sanitization phases are libraries
with no entry point, so none of them need an entry -- and that is worth
asserting rather than leaving to whoever reads the table next.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
LITERAL = re.compile(r"CONFIG\.get\(\s*'version'\s*,\s*'[^']+'\s*\)")


def _release_table() -> set[str]:
    text = (REPO / "tools" / "release.py").read_text(encoding="utf-8")
    start = text.index("# 4. Every remaining Python fallback literal")
    body = text[start:text.index("):", start)]
    return set(re.findall(r'"([^"]+\.py)"', body))


def test_release_check_passes():
    r = subprocess.run(
        [sys.executable, "tools/release.py", "--check", "--dry-run", "--skip-tests"],
        capture_output=True, text=True, cwd=REPO)
    assert r.returncode == 0, r.stdout[-800:] + r.stderr[-800:]


def test_every_file_with_a_version_literal_is_in_the_table():
    table = _release_table()
    unlisted = []
    for path in sorted(REPO.rglob("*.py")):
        rel = path.relative_to(REPO).as_posix()
        if any(part in {".venv", ".git", "build", "dist", "__pycache__",
                        "tests", "tools"}
               for part in path.parts):
            # `tests/` and `tools/` are not shipped, and both this file and
            # release.py contain the pattern as a literal string, so including
            # them makes the check match itself.
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if LITERAL.search(text) and rel not in table:
            unlisted.append(rel)
    assert not unlisted, (
        f"these files carry a version fallback but are not in release.py's table, "
        f"so a release would leave a stale version in them: {unlisted}")


def test_every_table_entry_exists():
    """The guard release.py already has, checked here too so the failure names
    the file rather than a release failure."""
    missing = [rel for rel in sorted(_release_table())
               if not (REPO / rel).is_file()]
    assert not missing, f"release.py lists files that do not exist: {missing}"


def test_the_new_library_modules_need_no_entry():
    """Documenting *why* the table is short, so nobody adds empty entries."""
    for rel in ("src/s0/carve/matroska.py", "src/s0/carve/reassembly.py",
                "src/s0/carve/containers.py", "src/s0/carve/suppression.py",
                "src/s0/carve/bodyfile.py", "src/s0/carve/provenance.py",
                "src/s0/carve/session.py", "src/s0/wipe/attest.py"):
        text = (REPO / rel).read_text(encoding="utf-8")
        assert not LITERAL.search(text), f"{rel} unexpectedly has a version literal"
        assert rel not in _release_table()
