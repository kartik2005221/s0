#!/usr/bin/env bash
# Helper script to launch the static Verification Portal locally

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
PORT="${1:-8080}"
PORTAL_DIR="$REPO/verification-portal"

echo "================================================================="
echo " TrustWipe Verification Portal (Pure Client-Side Zero-Trust Web)"
echo "================================================================="
echo "Serving directory: $PORTAL_DIR"
echo "URL: http://127.0.0.1:$PORT"
echo "Press Ctrl+C to stop."
echo "================================================================="

cd "$PORTAL_DIR"
"$REPO/.venv/bin/python" -m http.server "$PORT"
