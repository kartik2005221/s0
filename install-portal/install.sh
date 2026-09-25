#!/usr/bin/env bash
# S0 (Sector Zero) — Resilient One-Line Installer for Linux & macOS
# Usage: curl -fsSL https://s0-install.pages.dev/sh | bash
set -euo pipefail

REPO="https://github.com/kartik2005221/s0.git"
INSTALL_DIR="${S0_INSTALL_DIR:-$HOME/.s0}"
TOTAL_STEPS=6
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
info() { printf "\n    ${_yellow}→${_reset} %s\n" "$1"; }

# ── sudo safety guard ──────────────────────────────────────────────────────
# S0 installs into user home directory ($HOME/.s0). Running under sudo from a
# regular user shell installs into /root/.s0 and leaves binaries unusable by the user.
if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ] && [ -z "${S0_INSTALL_ALLOW_SUDO:-}" ]; then
    printf "${_red}Error: Do not run this installer with sudo.${_reset}\n\n" >&2
    printf "S0 installs into your user home directory (%s/.s0) and does not need root privileges.\n" "$HOME" >&2
    printf "With sudo, files would belong to root and the 's0' command would not work in your regular shell.\n\n" >&2
    printf "Please re-run without sudo, e.g.:\n" >&2
    printf "    curl -fsSL https://s0-install.pages.dev/sh | bash\n\n" >&2
    printf "If you intentionally wish to install for the root user, set S0_INSTALL_ALLOW_SUDO=1, e.g.:\n" >&2
    printf "    curl -fsSL https://s0-install.pages.dev/sh | sudo S0_INSTALL_ALLOW_SUDO=1 bash\n" >&2
    exit 1
fi

# ── package manager detection ──────────────────────────────────────────────
detect_pkg_manager() {
    if command -v brew >/dev/null 2>&1; then
        echo "brew"
    elif command -v apt-get >/dev/null 2>&1; then
        echo "apt"
    elif command -v dnf >/dev/null 2>&1; then
        echo "dnf"
    elif command -v pacman >/dev/null 2>&1; then
        echo "pacman"
    elif command -v zypper >/dev/null 2>&1; then
        echo "zypper"
    elif command -v apk >/dev/null 2>&1; then
        echo "apk"
    else
        echo "unknown"
    fi
}

install_system_dep() {
    local dep="$1"
    local mgr
    mgr=$(detect_pkg_manager)

    printf "\n${_yellow}[!] Missing dependency: '%s'.${_reset}\n" "$dep"
    printf "Would you like s0 installer to install it via system package manager (%s)? [Y/n]: " "$mgr"
    
    local ans=""
    if [ -t 0 ]; then
        read -r ans
    else
        # When piped through curl | bash, stdin is the script itself. Read from /dev/tty if available.
        if [ -c /dev/tty ]; then
            read -r ans </dev/tty || ans="y"
        else
            ans="y"
        fi
    fi
    ans=$(echo "$ans" | tr '[:upper:]' '[:lower:]')

    if [ "$ans" = "" ] || [ "$ans" = "y" ] || [ "$ans" = "yes" ]; then
        printf "Installing %s...\n" "$dep"
        case "$mgr" in
            apt)
                if [ "$dep" = "python3" ]; then
                    sudo apt-get update -qq && sudo apt-get install -y python3 python3-venv python3-pip
                elif [ "$dep" = "git" ]; then
                    sudo apt-get update -qq && sudo apt-get install -y git
                fi
                ;;
            brew)
                brew install "$dep"
                ;;
            dnf)
                if [ "$dep" = "python3" ]; then
                    sudo dnf install -y python3 python3-pip
                else
                    sudo dnf install -y "$dep"
                fi
                ;;
            pacman)
                if [ "$dep" = "python3" ]; then
                    sudo pacman -Sy --noconfirm python python-pip
                else
                    sudo pacman -Sy --noconfirm "$dep"
                fi
                ;;
            zypper)
                sudo zypper install -y "$dep"
                ;;
            apk)
                sudo apk add --no-cache "$dep" py3-pip
                ;;
            *)
                printf "${_red}ERROR: Unknown package manager. Please install %s manually.${_reset}\n" "$dep" >&2
                exit 1
                ;;
        esac
    else
        printf "${_red}ERROR: %s is required to continue installation.${_reset}\n" "$dep" >&2
        exit 1
    fi
}

# ── banner ─────────────────────────────────────────────────────────────────
echo ""
printf "${_bold}${_cyan}╔══════════════════════════════════════════════════════════════════╗${_reset}\n"
printf "${_bold}${_cyan}║      S0 (Sector Zero) — Digital Forensic & Sanitization Suite   ║${_reset}\n"
printf "${_bold}${_cyan}╚══════════════════════════════════════════════════════════════════╝${_reset}\n"
echo ""

# ── step 1: prerequisites ──────────────────────────────────────────────────
step "Checking prerequisites"
if ! command -v python3 >/dev/null 2>&1; then
    install_system_dep "python3"
fi
if ! command -v git >/dev/null 2>&1; then
    install_system_dep "git"
fi

PYTHON_VER=$(python3 -c "import sys; print('%d.%d' % sys.version_info[:2])")
GIT_VER=$(git --version | awk '{print $3}')
ok; info "python3 ${PYTHON_VER}, git ${GIT_VER}"

# ── step 2: clone / update ─────────────────────────────────────────────────
step "Deploying S0 to ${INSTALL_DIR}"
if [ -d "$INSTALL_DIR/.git" ]; then
    cd "$INSTALL_DIR" && git pull --ff-only -q 2>/dev/null || true
    ok; info "existing install updated"
else
    # Try shallow clone first, fallback to standard clone if depth fails
    if ! git clone --depth 1 -q "$REPO" "$INSTALL_DIR" 2>/dev/null; then
        info "shallow clone failed, falling back to full clone..."
        git clone -q "$REPO" "$INSTALL_DIR"
    fi
    ok; info "cloned from ${REPO}"
fi
cd "$INSTALL_DIR"

# ── step 3: virtual environment ────────────────────────────────────────────
step "Configuring Python virtual environment"
if [ ! -d ".venv" ] || [ ! -f ".venv/bin/python3" ]; then
    rm -rf .venv 2>/dev/null || true
    if ! python3 -m venv .venv 2>/dev/null; then
        # Debian/Ubuntu systems often separate python3-venv
        info "standard venv creation failed, installing python3-venv..."
        install_system_dep "python3"
        python3 -m venv .venv
    fi
fi
ok

# ── step 4: pip upgrade with retries ───────────────────────────────────────
step "Upgrading pip and package managers"
pip_retry() {
    local n=0
    until [ "$n" -ge 3 ]; do
        .venv/bin/python3 -m pip install "$@" -q && break
        n=$((n+1))
        info "network retry $n/3..."
        sleep 2
    done
    if [ "$n" -ge 3 ]; then
        printf "\n${_red}ERROR: pip installation failed after 3 attempts.${_reset}\n" >&2
        exit 1
    fi
}
pip_retry --upgrade pip
ok

# ── step 5: install s0 packages ────────────────────────────────────────────
step "Installing S0 packages and cryptographic modules"
info "core cryptographic library..."
pip_retry -e core/python
info "CLI and forensic engines..."
pip_retry -e linux/cli
info "PDF, QR code generation and web dashboard..."
pip_retry reportlab qrcode pillow fastapi "uvicorn[standard]"
ok

# ── step 6: symlink into PATH ──────────────────────────────────────────────
step "Installing s0 command into user bin"
BIN_DIR="${HOME}/.local/bin"
mkdir -p "$BIN_DIR"
ln -sf "$INSTALL_DIR/.venv/bin/s0" "$BIN_DIR/s0"
touch "$INSTALL_DIR/.s0_install_marker"
ok; info "symlink: ${BIN_DIR}/s0 → ${INSTALL_DIR}/.venv/bin/s0"

# ── summary ────────────────────────────────────────────────────────────────
echo ""
printf "${_bold}${_green}✅ S0 installed successfully!${_reset}\n"
printf "   Executable : %s/s0\n" "${BIN_DIR}"
printf "   Version    : %s\n" "$("${BIN_DIR}/s0" --version 2>/dev/null || echo "2.4.1")"
printf "   Web Console: sudo s0 web\n"
echo ""

# ── legal & authorized use notice ──────────────────────────────────────────
printf "${_yellow}⚖  LEGAL & RESPONSIBLE USE NOTICE:${_reset}\n"
printf "   s0 is a certified digital forensic and media sanitization suite.\n"
printf "   Only operate on storage devices and files you legally own or have explicit\n"
printf "   documented authorization to process. Unauthorized use may violate computer\n"
printf "   crime laws (e.g., CFAA, Computer Misuse Act, IT Act 2000).\n"
printf "   Documentation & Legal FAQ: https://s0-docs.gitbook.io/faq\n\n"

if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    printf "${_yellow}NOTE:${_reset} Add ~/.local/bin to your PATH by adding this to ~/.bashrc or ~/.zshrc:\n"
    printf "       export PATH=\"\$HOME/.local/bin:\$PATH\"\n"
    echo ""
fi
