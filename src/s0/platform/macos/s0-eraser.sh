#!/usr/bin/env bash
# s0 macOS Secure Sanitization Platform Launcher (Files, Partitions, USB Drives)

if [ -z "${1:-}" ]; then
    echo "Usage:"
    echo "  File/Folder Erasure: ./s0-eraser.sh <target_file_or_folder> [passes] [pattern]"
    echo "  Secondary Partition: ./s0-eraser.sh --wipe-partition /dev/rdisk2s1 --yes"
    echo "  USB / Pen Drive:     ./s0-eraser.sh --wipe-drive /dev/rdisk2 --yes"
    echo
    echo "Example:"
    echo "  ./s0-eraser.sh ~/Documents/classified.pdf 1 zero"
    echo "  ./s0-eraser.sh --wipe-drive /dev/rdisk2 --pattern zero --yes"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "$1" == --* ]]; then
    exec python3 "${SCRIPT_DIR}/s0_eraser.py" "$@"
fi

TARGET="$1"
PASSES="${2:-1}"
PATTERN="${3:-zero}"

exec python3 "${SCRIPT_DIR}/s0_eraser.py" --targets "${TARGET}" --passes "${PASSES}" --pattern "${PATTERN}"
