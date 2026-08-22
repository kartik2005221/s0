#!/usr/bin/env bash
# Launch the TrustWipe local GUI. Binds 127.0.0.1 only — never expose it.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
REPO="$(cd ../.. && pwd)"
exec "$REPO/.venv/bin/python" -m uvicorn app:app --host 127.0.0.1 --port "${TRUSTWIPE_PORT:-8080}"
