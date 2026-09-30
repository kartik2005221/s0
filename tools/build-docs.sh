#!/usr/bin/env bash
set -euo pipefail

# s0 Documentation Validator (GitBook)
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
echo "==> Validating GitBook documentation suite at ${REPO_ROOT}/docs"

[ -f "${REPO_ROOT}/gitbook-docs.yaml" ] || { echo "ERROR: Missing gitbook-docs.yaml"; exit 1; }
[ -f "${REPO_ROOT}/docs/SUMMARY.md" ] || { echo "ERROR: Missing docs/SUMMARY.md"; exit 1; }
[ -f "${REPO_ROOT}/docs/README.md" ] || { echo "ERROR: Missing docs/README.md"; exit 1; }

python3 - << 'PYEOF'
import os, glob, re, sys

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
root = os.path.join(repo_root, "docs")
broken = 0
for f in glob.glob(root + "/**/*.md", recursive=True):
    with open(f) as fp:
        text = fp.read()
    for l in re.findall(r"\]\(([^)]+)\)", text):
        if l.startswith("http") or l.startswith("#") or l.startswith("mailto:"):
            continue
        clean = l.split("#")[0]
        if not clean:
            continue
        target = os.path.normpath(os.path.join(os.path.dirname(f), clean))
        if not os.path.exists(target):
            print(f"BROKEN LINK in {os.path.relpath(f, root)}: {l}")
            broken += 1

if broken > 0:
    sys.exit(1)
print("All internal GitBook documentation links verified successfully (0 broken links).")
PYEOF

echo "==> Documentation validation passed: s0 documentation ready for GitBook Site Sync."
