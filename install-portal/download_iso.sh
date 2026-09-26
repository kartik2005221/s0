#!/usr/bin/env bash
# ==============================================================================
# S0 (Sector Zero) — Download Pre-Built Live ISO for Linux & macOS
# Usage:
#   curl -fsSL https://s0-install.pages.dev/download-iso-sh | bash
# ==============================================================================
set -euo pipefail

REPO="kartik2005221/s0"
API_URL="https://api.github.com/repos/${REPO}/releases/latest"

# Destination directory: $HOME/Downloads if it exists, otherwise current directory
if [ -n "${HOME:-}" ] && [ -d "${HOME}/Downloads" ]; then
    OUT_DIR="${HOME}/Downloads"
else
    OUT_DIR="."
fi
OUT_FILE="${OUT_DIR}/s0-live-amd64.hybrid.iso"

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "\n${CYAN}╔══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║      S0 (Sector Zero) — Live ISO Downloader & Verifier           ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${NC}\n"

echo -e "${CYAN}==> Checking latest releases on GitHub (${REPO})...${NC}"

# Check for curl or wget
if command -v curl >/dev/null 2>&1; then
    FETCH_CMD="curl -sSL -H 'User-Agent: s0-iso-downloader'"
elif command -v wget >/dev/null 2>&1; then
    FETCH_CMD="wget -qO- --user-agent='s0-iso-downloader'"
else
    echo -e "${RED}[ERROR] Neither curl nor wget was found on this system.${NC}"
    exit 1
fi

RELEASE_JSON=$(eval "$FETCH_CMD \"$API_URL\"" 2>/dev/null || echo "")

if [ -z "$RELEASE_JSON" ]; then
    echo -e "${RED}[ERROR] Failed to query releases from GitHub API.${NC}"
    exit 1
fi

# Extract ISO browser download URL
ISO_URL=""
if command -v python3 >/dev/null 2>&1; then
    ISO_URL=$(python3 -c "import sys, json; data=json.loads(sys.stdin.read()); assets=data.get('assets', []); print(next((a['browser_download_url'] for a in assets if a.get('name', '').endswith('.iso')), ''))" <<< "$RELEASE_JSON" 2>/dev/null || echo "")
fi

if [ -z "$ISO_URL" ] && command -v jq >/dev/null 2>&1; then
    ISO_URL=$(echo "$RELEASE_JSON" | jq -r '.assets[] | select(.name | endswith(".iso")) | .browser_download_url' 2>/dev/null | head -n 1 || echo "")
fi

if [ -z "$ISO_URL" ] || [ "$ISO_URL" = "null" ]; then
    # Fallback to grep regex parsing
    ISO_URL=$(echo "$RELEASE_JSON" | grep -o 'https://[^"]*\.iso' | head -n 1 || echo "")
fi

if [ -z "$ISO_URL" ] || [ "$ISO_URL" = "null" ]; then
    echo -e "${YELLOW}[INFO] No release asset .iso attached yet on GitHub.${NC}"
    echo -e "       You can build the ISO locally using Docker or live-build:"
    echo -e "         ${CYAN}./scripts/build_iso.sh${NC}"
    echo -e "       Or trigger the automated GitHub Actions workflow: '.github/workflows/build-iso.yml'"
    exit 0
fi

TAG_NAME=$(echo "$RELEASE_JSON" | grep -m1 '"tag_name":' | cut -d '"' -f 4 || echo "latest")

echo -e "${GREEN}==> Found release: ${TAG_NAME}${NC}"
echo -e "${CYAN}==> Downloading to: ${OUT_FILE}...${NC}"

if command -v curl >/dev/null 2>&1; then
    curl -fL --progress-bar "$ISO_URL" -o "$OUT_FILE"
else
    wget --show-progress -O "$OUT_FILE" "$ISO_URL"
fi

echo -e "\n${GREEN}✅ Download complete!${NC}"
echo -e "   Path: ${OUT_FILE}"

echo -e "${CYAN}==> Computing SHA-256 Checksum...${NC}"
if command -v sha256sum >/dev/null 2>&1; then
    HASH=$(sha256sum "$OUT_FILE" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
    HASH=$(shasum -a 256 "$OUT_FILE" | awk '{print $1}')
else
    HASH="sha256sum not found"
fi
echo -e "   ${YELLOW}SHA-256: ${HASH}${NC}"

echo -e "\n${CYAN}==> Flashing to USB Drive on Linux / macOS:${NC}"
echo -e "   1. Insert a USB flash drive (>= 4 GB)."
echo -e "   2. Identify the target drive: ${CYAN}lsblk${NC} (Linux) or ${CYAN}diskutil list${NC} (macOS)"
echo -e "   3. Write image to USB (replace /dev/sdX with target drive):"
echo -e "      ${CYAN}sudo dd if=\"${OUT_FILE}\" of=/dev/sdX bs=4M status=progress conv=fsync${NC}"
echo -e "      or use Ventoy / BalenaEtcher / Raspberry Pi Imager."
