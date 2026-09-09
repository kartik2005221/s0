#!/bin/bash
# Build the s0 live ISO with Debian live-build.
#
# REQUIRES: sudo (or root), live-build, xorriso. NOT runnable in this repo's
# development environment — see README.md. scripts/build_all.sh skips it and
# says why.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

REPO_ROOT="$(cd ../.. && pwd)"
STAGING_DIR="$(pwd)/config/includes.chroot/root/repo-snapshot"

echo "==> staging repo snapshot ($REPO_ROOT) -> $STAGING_DIR"
mkdir -p "$STAGING_DIR"
trap 'rm -rf "$STAGING_DIR"' EXIT INT TERM
cp -r "$REPO_ROOT/core" "$REPO_ROOT/linux" "$REPO_ROOT/gui" "$STAGING_DIR/"

echo "==> configuring live-build (debian bookworm amd64, minimal + chromium)"
lb config noauto \
    --architecture amd64 \
    --distribution bookworm \
    --archive-areas "main contrib" \
    --mode debian \
    --binary-images iso-hybrid \
    --bootappend-live "boot=live components quiet splash hostname=s0" \
    --debian-installer false \
    --iso-volume "S0" \
    "${@}"

echo "==> building (this downloads ~1GB of packages on first run)"
sudo lb build

echo "==> done: $(pwd)/live-image-amd64.hybrid.iso"
echo "    smoke-test it headless: ./qemu-test.sh live-image-amd64.hybrid.iso"
