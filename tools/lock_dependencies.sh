#!/usr/bin/env bash
# Regenerate requirements.lock -- the hash-pinned resolution of every direct
# dependency, transitively.
#
# Why this exists
# ---------------
# pyproject.toml declares lower bounds only (`cryptography>=42`). That is right for
# a library: it does not constrain anyone who installs s0. It is wrong for the
# things this project *builds*: the ISO image, the container, the release tarball.
# Those resolve "whatever is newest at build time", so two builds of the same
# commit can contain different code, and a compromised or broken transitive release
# lands in an artefact that was signed off without anyone reviewing it.
#
# So the library stays loosely bounded and the builds pin exactly. This file is the
# pinned side, and `pip install --require-hashes -r requirements.lock` refuses to
# install anything whose artefact hash is not listed.
#
# Only the direct dependencies are declared here; pip-compile resolves the rest and
# records the whole graph, so adding a dependency means adding it to BOTH pyproject
# and requirements.in (a test asserts they agree).
#
# Usage:  tools/lock_dependencies.sh
# Verify: pip install --require-hashes --dry-run -r requirements.lock
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

PY="${PYTHON:-python3}"
LOCK_IN="requirements.in"
LOCK_OUT="requirements.lock"

if ! "$PY" -m piptools --version >/dev/null 2>&1 && ! command -v pip-compile >/dev/null 2>&1; then
    printf 'pip-tools is not installed. Install it with:\n  %s -m pip install pip-tools\n' "$PY" >&2
    exit 1
fi

printf 'Resolving %s -> %s\n' "$LOCK_IN" "$LOCK_OUT"
"$PY" -m piptools compile \
    --generate-hashes \
    --strip-extras \
    --allow-unsafe \
    --output-file "$LOCK_OUT" \
    "$LOCK_IN"

printf '\nVerifying the lock installs with hash checking enforced...\n'
"$PY" -m pip install --require-hashes --dry-run --quiet -r "$LOCK_OUT"
printf 'OK: every artefact in %s is hash-pinned and resolvable.\n' "$LOCK_OUT"
