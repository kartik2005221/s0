#!/usr/bin/env bash
# TrustWipe macOS Secure Sanitization Platform Launcher (Files, Partitions, USB Drives)
# Smart India Hackathon 2026 (SIH26149) - NTRO

if [ -z "${1:-}" ]; then
    echo "Usage:"
    echo "  File/Folder Erasure: ./trustwipe-eraser.sh <target_file_or_folder> [passes] [pattern]"
    echo "  Secondary Partition: ./trustwipe-eraser.sh --wipe-partition /dev/rdisk2s1 --yes"
    echo "  USB / Pen Drive:     ./trustwipe-eraser.sh --wipe-drive /dev/rdisk2 --yes"
    echo
    echo "Example:"
    echo "  ./trustwipe-eraser.sh ~/Documents/classified.pdf 1 zero"
    echo "  ./trustwipe-eraser.sh --wipe-drive /dev/rdisk2 --pattern zero --yes"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "$1" == --* ]]; then
    exec python3 "${SCRIPT_DIR}/trustwipe_eraser.py" "$@"
fi

TARGET="$1"
PASSES="${2:-1}"
PATTERN="${3:-zero}"

exec python3 "${SCRIPT_DIR}/trustwipe_eraser.py" --targets "${TARGET}" --passes "${PASSES}" --pattern "${PATTERN}"
