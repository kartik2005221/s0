#!/usr/bin/env bash
# S0 (Sector Zero) — One-Line Upgrader for Linux & macOS
# Usage: curl -sSL https://raw.githubusercontent.com/kartik2005221/s0/master/scripts/upgrade.sh | bash
set -euo pipefail

INSTALL_DIR="${S0_INSTALL_DIR:-$HOME/.s0}"
BIN_DIR="${HOME}/.local/bin"
TOTAL_STEPS=5
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
info() { printf "    ${_yellow}→${_reset} %s\n" "$1"; }

# ── banner ─────────────────────────────────────────────────────────────────
echo ""
printf "${_bold}${_cyan}╔══════════════════════════════════════════════════════════════════╗${_reset}\n"
printf "${_bold}${_cyan}║      S0 (Sector Zero) — Suite Upgrade & Maintenance Tool         ║${_reset}\n"
printf "${_bold}${_cyan}╚══════════════════════════════════════════════════════════════════╝${_reset}\n"
echo ""

# ── step 1: check existing install ─────────────────────────────────────────
step "Checking existing installation"
if [ ! -d "$INSTALL_DIR" ]; then
    printf "\n${_yellow}WARNING: S0 is not installed at ${INSTALL_DIR}.${_reset}\n"
    printf "To install S0 from scratch, run:\n"
    printf "  curl -sSL https://raw.githubusercontent.com/kartik2005221/s0/master/scripts/install.sh | bash\n\n"
    exit 1
fi
if [ ! -d "$INSTALL_DIR/.git" ]; then
    printf "\n${_red}ERROR: ${INSTALL_DIR} is not a git repository.${_reset}\n"
    exit 1
fi
cd "$INSTALL_DIR"
CURRENT_HASH=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
ok; info "found S0 at ${INSTALL_DIR} (current commit: ${CURRENT_HASH})"

# ── step 2: pull latest source ─────────────────────────────────────────────
step "Pulling latest updates from GitHub"
git fetch origin master -q
LATEST_HASH=$(git rev-parse --short origin/master 2>/dev/null || echo "unknown")
if [ "$CURRENT_HASH" = "$LATEST_HASH" ]; then
    info "already up-to-date at commit ${CURRENT_HASH}"
else
    git pull --ff-only origin master -q
    info "updated: ${CURRENT_HASH} → ${LATEST_HASH}"
fi
ok

# ── step 3: upgrade pip & dependencies ─────────────────────────────────────
step "Updating virtual environment packages"
if [ ! -f ".venv/bin/python3" ]; then
    python3 -m venv .venv
fi
.venv/bin/python3 -m pip install --upgrade pip -q
.venv/bin/python3 -m pip install -e core/python -q
.venv/bin/python3 -m pip install -e linux/cli -q
.venv/bin/python3 -m pip install reportlab qrcode pillow -q
ok; info "dependencies refreshed"

# ── step 4: refresh PATH symlink ───────────────────────────────────────────
step "Verifying s0 command symlink"
mkdir -p "$BIN_DIR"
ln -sf "$INSTALL_DIR/.venv/bin/s0" "$BIN_DIR/s0"
ok; info "symlink: ${BIN_DIR}/s0 → ${INSTALL_DIR}/.venv/bin/s0"

# ── step 5: verify installation ────────────────────────────────────────────
step "Verifying upgraded version"
S0_VER=$("$INSTALL_DIR/.venv/bin/s0" --version 2>&1 || echo "unknown")
ok; info "active version: ${S0_VER}"

# ── summary ────────────────────────────────────────────────────────────────
echo ""
printf "${_bold}${_green}✅ S0 upgraded successfully!${_reset}\n"
printf "   Version    : %s\n" "${S0_VER}"
printf "   Commit     : %s\n" "${LATEST_HASH}"
printf "   Executable : %s/s0\n" "${BIN_DIR}"
echo ""
