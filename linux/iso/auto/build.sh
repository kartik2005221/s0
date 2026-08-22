#!/bin/bash
# Build the TrustWipe live ISO with Debian live-build.
#
# REQUIRES: sudo (or root), live-build, xorriso. NOT runnable in this repo's
# development environment — see README.md. scripts/build_all.sh skips it and
# says why.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

REPO_ROOT="$(cd ../.. && pwd)"
SNAPSHOT="$(mktemp -d)/repo-snapshot"

echo "==> snapshotting $REPO_ROOT -> $SNAPSHOT"
mkdir -p "$SNAPSHOT"
cp -r "$REPO_ROOT/core" "$REPO_ROOT/linux" "$SNAPSHOT/"

echo "==> configuring live-build (debian bookworm amd64, minimal + chromium)"
lb config noauto \
    --architecture amd64 \
    --distribution bookworm \
    --archive-areas "main contrib" \
    --mode debian \
    --binary-images iso-hybrid \
    --bootappend-live "boot=live components quiet splash hostname=trustwipe" \
    --packages-lists "trustwipe" \
    --debian-installer false \
    --iso-volume "TRUSTWIPE" \
    "${@}"

echo "==> building (this downloads ~1GB of packages on first run)"
sudo lb build

echo "==> done: $(pwd)/live-image-amd64.hybrid.iso"
echo "    smoke-test it headless: ./qemu-test.sh live-image-amd64.hybrid.iso"
