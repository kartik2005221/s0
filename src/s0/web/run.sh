#!/usr/bin/env bash
# Launch the s0 local Web Dashboard. Binds 127.0.0.1 only — never expose it.
#
# For an installed s0, prefer the `s0 web` command: it wires authentication,
# spawns uvicorn and opens the browser. This script is for source checkouts,
# where the venv lives at the repo root (two levels up from this directory —
# it used to look one level up, at src/s0/.venv, which does not exist).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
REPO="$(cd ../.. && pwd)"
PORT="${S0_PORT:-8669}"
if [ -x "$REPO/.venv/bin/python" ]; then
    exec "$REPO/.venv/bin/python" -m uvicorn s0.web.app:app --host 127.0.0.1 --port "$PORT"
fi
# No checkout venv: fall back to the installed package.
exec python3 -m uvicorn s0.web.app:app --host 127.0.0.1 --port "$PORT"
