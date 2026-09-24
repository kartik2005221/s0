#!/usr/bin/env bash
# S0 (Sector Zero) — Resilient Uninstaller for Linux & macOS
# Usage: curl -fsSL https://s0-install.pages.dev/uninstall-sh | bash
set -euo pipefail

INSTALL_DIR="${S0_INSTALL_DIR:-$HOME/.s0}"
BIN_DIR="${HOME}/.local/bin"

echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║      S0 (Sector Zero) — Uninstaller                             ║"
echo "╚══════════════════════════════════════════════════════════════════╝"

# Move out of install directory if inside
cd "$HOME"

# Check if anything is installed
if [ ! -d "$INSTALL_DIR" ] && [ ! -L "$BIN_DIR/s0" ] && [ ! -f "$BIN_DIR/s0" ]; then
    echo "S0 is not installed on this system."
    exit 0
fi

# Confirmation prompt
if [ "${1:-}" != "-y" ] && [ "${S0_UNINSTALL_YES:-}" != "1" ]; then
    printf "Are you sure you want to completely remove s0 from %s? [y/N]: " "$INSTALL_DIR"
    ans=""
    if [ -t 0 ]; then
        read -r ans
    elif [ -c /dev/tty ]; then
        read -r ans </dev/tty || ans="n"
    fi
    ans=$(echo "$ans" | tr '[:upper:]' '[:lower:]')
    if [ "$ans" != "y" ] && [ "$ans" != "yes" ]; then
        echo "Uninstallation aborted."
        exit 0
    fi
fi

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
