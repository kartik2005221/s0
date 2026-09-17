#!/usr/bin/env bash
# S0 (Sector Zero) macOS Unified Forensic Sanitization & Recovery CLI
set -e
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$DIR/cli/s0_eraser.py" "$@"
