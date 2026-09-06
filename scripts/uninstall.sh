#!/usr/bin/env bash
# S0 (Sector Zero) — Uninstaller for Linux & macOS
# Usage: curl -sSL https://raw.githubusercontent.com/kartik2005221/s0/master/scripts/uninstall.sh | bash
set -euo pipefail

INSTALL_DIR="${S0_INSTALL_DIR:-$HOME/.s0}"
BIN_DIR="${HOME}/.local/bin"

echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║      S0 (Sector Zero) — Uninstaller                             ║"
echo "╚══════════════════════════════════════════════════════════════════╝"

# Move out of install directory if inside
cd "$HOME"

# 1. Remove executable symlink
if [ -L "$BIN_DIR/s0" ] || [ -f "$BIN_DIR/s0" ]; then
    echo "==> Removing executable symlink $BIN_DIR/s0..."
    rm -f "$BIN_DIR/s0"
fi

# 2. Remove installation directory
if [ -d "$INSTALL_DIR" ]; then
    echo "==> Removing installation directory $INSTALL_DIR..."
    rm -rf "$INSTALL_DIR"
fi

echo ""
echo "✅ S0 has been completely uninstalled from your system."
echo ""
