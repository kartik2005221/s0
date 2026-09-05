#!/usr/bin/env bash
# TrustWipe macOS Secure File & Folder Eraser Launcher
# Smart India Hackathon 2026 (SIH26149) - NTRO

if [ -z "$1" ]; then
    echo "Usage: ./trustwipe-eraser.sh <target_file_or_folder> [passes] [pattern]"
    echo "Example: ./trustwipe-eraser.sh ~/Documents/classified.pdf 1 zero"
    exit 1
fi

TARGET="$1"
PASSES="${2:-1}"
PATTERN="${3:-zero}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python3 "${SCRIPT_DIR}/trustwipe_eraser.py" --targets "${TARGET}" --passes "${PASSES}" --pattern "${PATTERN}"
