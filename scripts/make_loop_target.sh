#!/usr/bin/env bash
# Helper script to create and attach a sparse loop block device target for testing
# Requires root / sudo privileges to run losetup.

set -euo pipefail

IMG_PATH="${1:-/tmp/trustwipe_loop_test.img}"
SIZE_MIB="${2:-256}"

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Attaching loop devices requires root / sudo."
    echo "Usage: sudo $0 [image_path] [size_in_mib]"
    exit 1
fi

echo "==> Creating sparse image: $IMG_PATH ($SIZE_MIB MiB)..."
truncate -s "${SIZE_MIB}M" "$IMG_PATH"

echo "==> Attaching to next available loop device..."
LOOP_DEV=$(losetup --find --show "$IMG_PATH")

echo "==> Attached: $LOOP_DEV -> $IMG_PATH"
echo "==> You can now run S0 against this block device:"
echo "    sudo s0 plan --target $LOOP_DEV"
echo "    sudo s0 wipe --target $LOOP_DEV --yes"
echo
echo "==> To detach later:"
echo "    sudo losetup -d $LOOP_DEV"
echo "    rm -f $IMG_PATH"
