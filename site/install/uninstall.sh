#!/usr/bin/env bash
# S0 (Sector Zero) — Resilient Uninstaller for Linux/MacOS
# Usage: curl -fsSL https://sector-zero.pages.dev/uninstall-sh | bash
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
    # Security validation: ensure directory is an s0 install before recursive delete
    REAL_INSTALL_DIR="$(cd "$INSTALL_DIR" 2>/dev/null && pwd -P || echo "$INSTALL_DIR")"
    DEFAULT_DIR="$(cd "$HOME" 2>/dev/null && pwd -P || echo "$HOME")/.s0"
    if [ "$REAL_INSTALL_DIR" != "$DEFAULT_DIR" ] && [ ! -f "$INSTALL_DIR/.s0_install_marker" ] && [ ! -f "$INSTALL_DIR/s0_config.json" ]; then
        echo "ERROR: Refusing to delete $INSTALL_DIR — directory does not appear to be an S0 installation." >&2
        echo "  (Missing .s0_install_marker or s0_config.json)" >&2
        exit 1
    fi

    # Preserve forensic audit ledger by default
    if [ -f "$INSTALL_DIR/s0_audit.db" ]; then
        if [ "${1:-}" = "--purge-all" ] || [ "${1:-}" = "--purge" ] || [ "${S0_PURGE_ALL:-}" = "1" ]; then
            echo "==> Purging audit ledger as requested..."
        else
            BAK_FILE="$HOME/s0_audit.db.bak.$(date +%Y%m%d_%H%M%S)"
            cp -p "$INSTALL_DIR/s0_audit.db" "$BAK_FILE" 2>/dev/null || true
            echo "==> Audit ledger safely preserved at: $BAK_FILE"
            echo "    (Pass --purge-all if you intentionally wish to destroy audit history)"
        fi
    fi

    echo "==> Removing installation directory $INSTALL_DIR..."
    rm -rf "$INSTALL_DIR"
fi

echo ""
echo "✅ S0 has been completely uninstalled from your system."
echo ""
