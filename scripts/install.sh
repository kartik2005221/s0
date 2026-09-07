#!/usr/bin/env bash
# S0 (Sector Zero) — One-Line Installer for Linux & macOS
# Usage: curl -sSL https://raw.githubusercontent.com/kartik2005221/s0/master/scripts/install.sh | bash
set -euo pipefail

REPO="https://github.com/kartik2005221/s0.git"
INSTALL_DIR="${S0_INSTALL_DIR:-$HOME/.s0}"
TOTAL_STEPS=6
STEP=0

# ── helpers ────────────────────────────────────────────────────────────────
_cyan='\033[0;36m'
_green='\033[0;32m'
_yellow='\033[1;33m'
_red='\033[0;31m'
_reset='\033[0m'
_bold='\033[1m'

step() {
    STEP=$((STEP + 1))
    printf "\n${_cyan}[%d/%d]${_reset} %s... " "$STEP" "$TOTAL_STEPS" "$1"
}
ok()   { printf "${_green}✓ done${_reset}\n"; }
info() { printf "\n    ${_yellow}→${_reset} %s\n" "$1"; }

# ── banner ─────────────────────────────────────────────────────────────────
echo ""
printf "${_bold}${_cyan}╔══════════════════════════════════════════════════════════════════╗${_reset}\n"
printf "${_bold}${_cyan}║      S0 (Sector Zero) — Digital Forensic & Sanitization Suite   ║${_reset}\n"
printf "${_bold}${_cyan}╚══════════════════════════════════════════════════════════════════╝${_reset}\n"
echo ""

# ── step 1: prerequisites ──────────────────────────────────────────────────
step "Checking prerequisites"
command -v python3 >/dev/null 2>&1 || { printf "\n${_red}ERROR: python3 is required.${_reset}\n"; exit 1; }
command -v git     >/dev/null 2>&1 || { printf "\n${_red}ERROR: git is required.${_reset}\n";     exit 1; }
PYTHON_VER=$(python3 -c "import sys; print('%d.%d' % sys.version_info[:2])")
ok; info "python3 ${PYTHON_VER}, git $(git --version | awk '{print $3}')"

# ── step 2: clone / update ─────────────────────────────────────────────────
step "Deploying S0 to ${INSTALL_DIR}"
if [ -d "$INSTALL_DIR" ]; then
    cd "$INSTALL_DIR" && git pull --ff-only -q 2>/dev/null || true
    ok; info "existing install updated"
else
    git clone --depth 1 -q "$REPO" "$INSTALL_DIR"
    ok; info "cloned from ${REPO}"
fi
cd "$INSTALL_DIR"

# ── step 3: virtual environment ────────────────────────────────────────────
step "Creating Python virtual environment"
python3 -m venv .venv
ok

# ── step 4: pip upgrade ────────────────────────────────────────────────────
step "Upgrading pip"
.venv/bin/python3 -m pip install --upgrade pip -q
ok

# ── step 5: install s0 packages ────────────────────────────────────────────
step "Installing S0 packages"
info "core cryptographic library..."
.venv/bin/python3 -m pip install -e core/python -q
info "CLI and dependencies..."
.venv/bin/python3 -m pip install -e linux/cli -q
info "PDF / QR generation..."
.venv/bin/python3 -m pip install reportlab qrcode pillow -q
ok

# ── step 6: symlink into PATH ──────────────────────────────────────────────
step "Installing s0 command"
BIN_DIR="${HOME}/.local/bin"
mkdir -p "$BIN_DIR"
ln -sf "$INSTALL_DIR/.venv/bin/s0" "$BIN_DIR/s0"
ok; info "symlink: ${BIN_DIR}/s0 → ${INSTALL_DIR}/.venv/bin/s0"

# ── summary ────────────────────────────────────────────────────────────────
echo ""
printf "${_bold}${_green}✅ S0 installed successfully!${_reset}\n"
printf "   Executable : ${BIN_DIR}/s0\n"
printf "   Run        : s0 --version\n"
echo ""

if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    printf "${_yellow}NOTE:${_reset} Add ~/.local/bin to your PATH by adding this to ~/.bashrc or ~/.zshrc:\n"
    printf "       export PATH=\"\$HOME/.local/bin:\$PATH\"\n"
    echo ""
fi
