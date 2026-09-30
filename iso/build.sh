#!/bin/bash
# s0 Live ISO Build Entrypoint Wrapper
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$DIR/.." && pwd)"

if ! command -v lb >/dev/null 2>&1; then
    echo "==> 'live-build' (lb) not found natively."
    echo "    Switching to universal cross-platform builder (Podman / Docker / distro checks)..."
    exec "$REPO_ROOT/tools/build_iso.sh" "$@"
fi

exec "$DIR/auto/build.sh" "$@"
