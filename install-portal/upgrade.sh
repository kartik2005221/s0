#!/usr/bin/env bash
# S0 (Sector Zero) — Resilient Upgrader for Linux & macOS
# Usage: curl -fsSL https://s0-install.pages.dev/upgrade-sh | bash
set -euo pipefail

INSTALL_DIR="${S0_INSTALL_DIR:-$HOME/.s0}"
BIN_DIR="${HOME}/.local/bin"
TOTAL_STEPS=5
STEP=0

# ── helpers ────────────────────────────────────────────────────────────────
if [ -t 1 ]; then
    _cyan='\033[0;36m'
    _green='\033[0;32m'
    _yellow='\033[1;33m'
    _red='\033[0;31m'
    _reset='\033[0m'
    _bold='\033[1m'
else
    _cyan=''
    _green=''
    _yellow=''
    _red=''
    _reset=''
    _bold=''
fi

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
    printf "  curl -fsSL https://s0-install.pages.dev/sh | bash\n\n"
    exit 1
fi
if [ ! -d "$INSTALL_DIR/.git" ]; then
    printf "\n${_red}ERROR: ${INSTALL_DIR} is not a git repository.${_reset}\n"
    exit 1
fi
cd "$INSTALL_DIR"
CURRENT_HASH=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
ok; info "found S0 at ${INSTALL_DIR} (current commit: ${CURRENT_HASH})"

# ── step 2: pull latest source with backup fallback ────────────────────────
step "Pulling latest updates from GitHub"
git fetch origin master -q 2>/dev/null || {
    info "fetch failed, checking remote connection..."
    git fetch origin master
}
LATEST_HASH=$(git rev-parse --short origin/master 2>/dev/null || echo "unknown")

if [ "$CURRENT_HASH" = "$LATEST_HASH" ]; then
    info "already up-to-date at commit ${CURRENT_HASH}"
else
    if ! git pull --ff-only origin master -q 2>/dev/null; then
        # Fast-forward failed (e.g. local modifications). Create a safe backup before reset.
        BACKUP_DIR="${INSTALL_DIR}/backups"
        mkdir -p "$BACKUP_DIR"
        BACKUP_FILE="${BACKUP_DIR}/s0_backup_$(date +%Y%m%d_%H%M%S).tar.gz"
        info "local modifications detected, creating safety backup at ${BACKUP_FILE}..."
        tar -czf "$BACKUP_FILE" --exclude=".git" --exclude=".venv" -C "$INSTALL_DIR" . 2>/dev/null || true
        git reset --hard origin/master -q
        info "reset cleanly to latest release ${LATEST_HASH}"
    else
        info "updated: ${CURRENT_HASH} → ${LATEST_HASH}"
    fi
fi
ok

# ── step 3: upgrade pip & dependencies with retries ─────────────────────────
step "Updating virtual environment packages"
if [ ! -f ".venv/bin/python3" ]; then
    info "virtual environment missing or corrupt, rebuilding..."
    rm -rf .venv
    python3 -m venv .venv
fi

pip_retry() {
    local n=0
    until [ "$n" -ge 3 ]; do
        .venv/bin/python3 -m pip install "$@" -q && break
        n=$((n+1))
        info "retry $n/3..."
        sleep 2
    done
}

pip_retry --upgrade pip
pip_retry -e core/python
pip_retry -e linux/cli
pip_retry reportlab qrcode pillow fastapi "uvicorn[standard]"
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
