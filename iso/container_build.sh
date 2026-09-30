#!/bin/bash
set -euo pipefail

echo "==> Preparing clean build directory inside container..."
mkdir -p /build

# Workaround for Docker overlayfs mounted with nodev:
# debootstrap requires mknod capability. If nodev prevents mknod, mount a loopback ext4 volume.
if ! mknod /build/test-nodev c 1 3 2>/dev/null; then
    echo "==> Docker filesystem has nodev; creating ext4 loopback volume on /build with dev,exec..."
    truncate -s 8G /tmp_build.img
    mkfs.ext4 -F -q /tmp_build.img
    mount -o loop,dev,exec /tmp_build.img /build
fi
rm -f /build/test-nodev 2>/dev/null || true

mkdir -p /build/s0
rsync -a --exclude='.git' --exclude='node_modules' --exclude='.venv' --exclude='demo-out' /workspace/ /build/s0/


cd /build/s0/iso
chmod +x build.sh auto/build.sh

echo "==> Running live-build pipeline inside container..."
./build.sh

if [ -f live-image-amd64.hybrid.iso ]; then
    echo "==> Copying s0-live-amd64.hybrid.iso to host workspace..."
    cp live-image-amd64.hybrid.iso /workspace/s0-live-amd64.hybrid.iso
    chmod 664 /workspace/s0-live-amd64.hybrid.iso 2>/dev/null || true
    echo "==> Build complete: s0-live-amd64.hybrid.iso ready."
else
    echo "==> Error: live-image-amd64.hybrid.iso was not produced."
    exit 1
fi
