#!/usr/bin/env bash
# S0 (Sector Zero) — Universal Live ISO Build Orchestrator
# Builds the bare-metal Debian live ISO on Fedora, Debian, Ubuntu, Arch, or macOS
# via Podman, Docker, or native live-build.
#
# Usage: ./scripts/build_iso.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# ── ANSI helpers ────────────────────────────────────────────────────────────
_cyan='\033[0;36m'; _green='\033[0;32m'; _yellow='\033[1;33m'
_red='\033[0;31m'; _gray='\033[0;37m'; _bold='\033[1m'; _reset='\033[0m'

printf "\n"
printf "${_bold}${_cyan}╔══════════════════════════════════════════════════════════════════╗${_reset}\n"
printf "${_bold}${_cyan}║      S0 (Sector Zero) — Live ISO Build Orchestrator              ║${_reset}\n"
printf "${_bold}${_cyan}╚══════════════════════════════════════════════════════════════════╝${_reset}\n"
printf "\n"

# ── Detect Host OS ─────────────────────────────────────────────────────────
HOST_DISTRO="unknown"
if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    HOST_DISTRO="${ID:-unknown}"
    printf "  Host System : %s (%s)\n" "${PRETTY_NAME:-$HOST_DISTRO}" "$(uname -m)"
else
    printf "  Host System : %s (%s)\n" "$(uname -s)" "$(uname -m)"
fi
printf "  Repository  : %s\n\n" "$REPO_ROOT"

# ── Strategy 1: Podman (Native on Fedora, RHEL, CentOS) ────────────────────
if command -v podman >/dev/null 2>&1; then
    printf "${_cyan}[1/3] Checking Podman (Preferred on Fedora / RHEL)...${_reset} ${_green}found!${_reset}\n"
    printf "${_yellow}==> Building S0 Live Builder container image via Podman...${_reset}\n"
    
    podman build -t s0-live-builder -f linux/iso/Dockerfile linux/iso
    
    printf "\n${_yellow}==> Running Debian live-build inside privileged Podman container...${_reset}\n"
    printf "${_gray}    (SELinux volume label :z applied for Fedora security compatibility)${_reset}\n"
    
    podman run --rm --privileged -v "${REPO_ROOT}":/workspace:z s0-live-builder

# ── Strategy 2: Docker (Universal Linux / macOS) ───────────────────────────
elif command -v docker >/dev/null 2>&1; then
    printf "${_cyan}[1/3] Podman not found. Checking Docker...${_reset} ${_green}found!${_reset}\n"
    printf "${_yellow}==> Building S0 Live Builder container image via Docker...${_reset}\n"
    
    docker build -t s0-live-builder -f linux/iso/Dockerfile linux/iso
    
    printf "\n${_yellow}==> Running Debian live-build inside privileged Docker container...${_reset}\n"
    docker run --rm --privileged -v "${REPO_ROOT}":/workspace s0-live-builder

# ── Strategy 3: Native live-build (Debian / Ubuntu Native) ──────────────────
elif command -v lb >/dev/null 2>&1 && command -v xorriso >/dev/null 2>&1; then
    printf "${_cyan}[1/3] Checking native Debian live-build toolchain...${_reset} ${_green}found!${_reset}\n"
    printf "${_yellow}==> Executing native Debian live-build pipeline...${_reset}\n"
    
    cd "$REPO_ROOT/linux/iso"
    if [ "$(id -u)" -eq 0 ]; then
        ./build.sh
    else
        sudo ./build.sh
    fi
    cd "$REPO_ROOT"

# ── Fallback: Distro-specific guidance ──────────────────────────────────────
else
    printf "${_red}[ERROR] No supported ISO build engine found.${_reset}\n\n"
    printf "Debian Live ISO generation requires Linux kernel subsystems:\n"
    printf "  • debootstrap & chroot (POSIX root isolation & device node creation)\n"
    printf "  • loopback block device driver (losetup for SquashFS compression)\n"
    printf "  • xorriso with hybrid MBR/GPT UEFI boot catalogs\n\n"
    
    case "$HOST_DISTRO" in
        fedora|rhel|centos|rocky|alma)
            printf "${_bold}${_yellow}Recommended for Fedora / RHEL:${_reset}\n"
            printf "Install Podman to build the ISO in an isolated container without modifying your system:\n\n"
            printf "    ${_cyan}sudo dnf install -y podman${_reset}\n"
            printf "    ${_cyan}./scripts/build_iso.sh${_reset}\n\n"
            ;;
        debian|ubuntu|pop|linuxmint)
            printf "${_bold}${_yellow}Recommended for Debian / Ubuntu:${_reset}\n"
            printf "Install native live-build tools or Docker/Podman:\n\n"
            printf "    ${_cyan}sudo apt-get update && sudo apt-get install -y live-build xorriso debootstrap squashfs-tools${_reset}\n"
            printf "    ${_cyan}./scripts/build_iso.sh${_reset}\n\n"
            ;;
        arch|manjaro)
            printf "${_bold}${_yellow}Recommended for Arch Linux:${_reset}\n"
            printf "Install Podman:\n\n"
            printf "    ${_cyan}sudo pacman -S podman${_reset}\n"
            printf "    ${_cyan}./scripts/build_iso.sh${_reset}\n\n"
            ;;
        *)
            printf "Please install ${_bold}podman${_reset} or ${_bold}docker${_reset} on your system, then re-run:\n"
            printf "    ${_cyan}./scripts/build_iso.sh${_reset}\n\n"
            ;;
    esac
    exit 1
fi

# ── Post-Build Validation & Output ──────────────────────────────────────────
TARGET_ISO="$REPO_ROOT/s0-live-amd64.hybrid.iso"
SRC_ISO="$REPO_ROOT/linux/iso/live-image-amd64.hybrid.iso"

if [ ! -f "$TARGET_ISO" ] && [ -f "$SRC_ISO" ]; then
    cp "$SRC_ISO" "$TARGET_ISO"
fi

if [ -f "$TARGET_ISO" ]; then
    printf "\n${_bold}${_green}✅ SUCCESS! Bootable ISO generated at:${_reset}\n"
    printf "   %s\n" "$TARGET_ISO"
    
    if command -v sha256sum >/dev/null 2>&1; then
        printf "   SHA-256: %s\n\n" "$(sha256sum "$TARGET_ISO" | awk '{print $1}')"
    fi
    
    printf "${_bold}${_cyan}Next Steps:${_reset}\n"
    printf "  1. ${_bold}Test in QEMU (Virtual Machine):${_reset}\n"
    case "$HOST_DISTRO" in
        fedora|rhel|centos)
            printf "     Install QEMU : ${_cyan}sudo dnf install -y qemu-system-x86 qemu-img${_reset}\n"
            ;;
        debian|ubuntu)
            printf "     Install QEMU : ${_cyan}sudo apt-get install -y qemu-system-x86 qemu-utils${_reset}\n"
            ;;
        *)
            printf "     Install QEMU via your package manager\n"
            ;;
    esac
    printf "     Create dummy drive: ${_cyan}qemu-img create -f raw test_drive.img 1G${_reset}\n"
    printf "     Launch VM         : ${_cyan}qemu-system-x86_64 -enable-kvm -m 2048 -smp 2 -cdrom s0-live-amd64.hybrid.iso -drive file=test_drive.img,format=raw,if=virtio -vga virtio -usb -device usb-tablet${_reset}\n\n"
    
    printf "  2. ${_bold}Flash to Physical USB:${_reset}\n"
    printf "     Linux (Fedora/Debian): ${_cyan}sudo dd if=s0-live-amd64.hybrid.iso of=/dev/sdX bs=4M status=progress oflag=sync${_reset}\n"
    printf "     Windows              : Use Rufus in ${_bold}DD Image Mode${_reset} (https://rufus.ie/)\n"
    echo ""
else
    printf "\n${_red}[ERROR] ISO build finished but target ISO was not found.${_reset}\n"
    exit 1
fi
