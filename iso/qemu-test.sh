#!/bin/bash
# Headless QEMU smoke test for the s0 ISO.
#
# Boots the ISO, waits, captures a VNC screenshot, and greps the serial console
# log for boot success/failure markers. A HUMAN still looks at the screenshot —
# this script proves "boots and reaches userspace", not "the UI is correct".
#
# REQUIRES qemu-system-x86_64 (sudo apt install) — unavailable in this repo's
# dev environment; see README.md.
set -euo pipefail

ISO="${1:-live-image-amd64.hybrid.iso}"
OUT="${2:-qemu-test-out}"
SECONDS_WAIT="${SECONDS_WAIT:-45}"

[ -f "$ISO" ] || { echo "usage: $0 <iso> [outdir]"; exit 2; }
command -v qemu-system-x86_64 >/dev/null || {
    echo "qemu-system-x86_64 not installed — cannot test. See README.md."; exit 3;
}

mkdir -p "$OUT"
echo "==> booting $ISO headless (serial log -> $OUT/serial.log)"
# The monitor socket powers the screendump below; the ISO's bootappend-live
# carries console=ttyS0 (see auto/build.sh), which is what makes serial.log
# contain the systemd markers this script greps for.
qemu-system-x86_64 \
    -m 2048 -smp 2 \
    -cdrom "$ISO" \
    -boot d \
    -display none \
    -vnc 127.0.0.1:5977 \
    -serial "file:$OUT/serial.log" \
    -monitor unix:"$OUT/monitor.sock",server,nowait \
    -daemonize -pidfile "$OUT/qemu.pid"

trap 'kill "$(cat "$OUT/qemu.pid")" 2>/dev/null || true' EXIT

echo "==> waiting ${SECONDS_WAIT}s for boot..."
sleep "$SECONDS_WAIT"

if grep -qiE "systemd.*(welcome|running)" "$OUT/serial.log" && \
   ! grep -qiE "Kernel panic" "$OUT/serial.log"; then
    echo "==> PASS: kernel booted, systemd reached userspace (no panic)"
else
    echo "==> FAIL: inspect $OUT/serial.log"
    tail -40 "$OUT/serial.log"
    exit 1
fi

# Screenshot via the QEMU monitor if socat is available (optional visual check
# for the human; a VNC viewer can also attach to :5977 during the run).
if command -v socat >/dev/null; then
    echo "screendump $OUT/screen.ppm" | socat - UNIX-CONNECT:"$OUT/monitor.sock" >/dev/null 2>&1 || true
    sleep 2
    [ -s "$OUT/screen.ppm" ] && echo "==> screen capture: $OUT/screen.ppm"
fi
echo "==> artifacts in $OUT/"
