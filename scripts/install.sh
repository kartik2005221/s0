#!/usr/bin/env bash
# S0 (Sector Zero) — One-Line Installer for Linux & macOS
# Usage: curl -sSL https://raw.githubusercontent.com/kartik2005221/s0/master/scripts/install.sh | bash
set -euo pipefail

REPO="https://github.com/kartik2005221/s0.git"
INSTALL_DIR="${S0_INSTALL_DIR:-$HOME/.s0}"

echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║      S0 (Sector Zero) — Digital Forensic & Sanitization Suite   ║"
echo "╚══════════════════════════════════════════════════════════════════╝"

command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 is required."; exit 1; }
command -v git >/dev/null 2>&1 || { echo "ERROR: git is required."; exit 1; }

echo "==> Deploying S0 to $INSTALL_DIR..."
if [ -d "$INSTALL_DIR" ]; then
    cd "$INSTALL_DIR" && git pull --ff-only || true
else
    git clone --depth 1 "$REPO" "$INSTALL_DIR"
fi
cd "$INSTALL_DIR"

echo "==> Configuring Python environment..."
python3 -m venv .venv
.venv/bin/python3 -m pip install --upgrade pip -q
.venv/bin/python3 -m pip install -e core/python -e linux/cli -q
.venv/bin/python3 -m pip install reportlab qrcode pillow -q

# Create local symlink
BIN_DIR="${HOME}/.local/bin"
mkdir -p "$BIN_DIR"
ln -sf "$INSTALL_DIR/.venv/bin/s0" "$BIN_DIR/s0"

echo ""
echo "✅ S0 installed successfully!"
echo "   Executable: $BIN_DIR/s0"
echo "   Run:        s0 --version"
echo ""
if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    echo "   NOTE: Add $BIN_DIR to your PATH by adding this to ~/.bashrc or ~/.zshrc:"
    echo "     export PATH=\"\$HOME/.local/bin:\$PATH\""
fi
