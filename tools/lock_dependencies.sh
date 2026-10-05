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

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

PY="${PYTHON:-python3}"
LOCK_IN="requirements.in"
LOCK_OUT="requirements.lock"

# `python -m piptools --version` is not a valid invocation -- piptools is a command
# group and exits 2 with a usage message. So this check reported "not installed" on an
# environment where pip-tools was installed and working, and the script refused to run
# there. Probe the module itself, and fall back to the console script.
if ! "$PY" -c "import piptools" >/dev/null 2>&1 && ! command -v pip-compile >/dev/null 2>&1; then
    printf 'pip-tools is not installed. Install it with:\n  %s -m pip install pip-tools\n' "$PY" >&2
    exit 1
fi

# `--no-emit-index-url` / `--no-emit-trusted-host` keep the generated header free of
# whatever index happened to be configured. `--quiet` and the relative paths matter for
# the same reason: pip-compile records its own invocation in the header, so an absolute
# path or a scratch directory leaks into a committed file. The previous lock carried
# `/tmp/opencode/...` in ten places for exactly this reason.
printf 'Resolving %s -> %s\n' "$LOCK_IN" "$LOCK_OUT"
( cd "$REPO_ROOT" && "$PY" -m piptools compile \
    --generate-hashes \
    --strip-extras \
    --allow-unsafe \
    --no-emit-index-url \
    --no-emit-trusted-host \
    --quiet \
    --output-file "$LOCK_OUT" \
    "$LOCK_IN" )

printf '\nVerifying the lock installs with hash checking enforced...\n'
"$PY" -m pip install --require-hashes --dry-run --quiet -r "$LOCK_OUT"
printf 'OK: every artefact in %s is hash-pinned and resolvable.\n' "$LOCK_OUT"
