#!/usr/bin/env bash
# ==============================================================================
# S0 (Sector Zero) — Download Pre-Built Live ISO for Linux/MacOS
# Usage:
#   curl -fsSL https://sector0.pages.dev/download-iso-sh | bash
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

fetch_url() {
    local target_url="$1"
    if command -v curl >/dev/null 2>&1; then
        curl -sSL -H "User-Agent: s0-iso-downloader" "$target_url"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- --user-agent="s0-iso-downloader" "$target_url"
    fi
}

if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
    echo -e "${RED}[ERROR] Neither curl nor wget was found on this system.${NC}"
    exit 1
fi

RELEASE_JSON=$(fetch_url "$API_URL" 2>/dev/null || echo "")

if [ -z "$RELEASE_JSON" ]; then
    echo -e "${RED}[ERROR] Failed to query releases from GitHub API.${NC}"
    exit 1
fi

# Extract ISO browser download URL and Checksum URL
ISO_URL=""
ISO_NAME=""
CHECKSUM_URL=""
if command -v python3 >/dev/null 2>&1; then
    read -r ISO_URL ISO_NAME CHECKSUM_URL <<< "$(python3 -c '
import sys, json
data = json.loads(sys.stdin.read())
assets = data.get("assets", [])
iso = next((a for a in assets if a.get("name", "").endswith(".iso")), None)
if not iso:
    print("   ")
    sys.exit(0)
iso_url = iso.get("browser_download_url", "")
iso_name = iso.get("name", "")
chk = next((a for a in assets if a.get("name") == f"{iso_name}.sha256"), None)
if not chk:
    chk = next((a for a in assets if a.get("name") == "SHA256SUMS.txt"), None)
if not chk:
    chk = next((a for a in assets if a.get("name", "").endswith(".sha256")), None)
chk_url = chk.get("browser_download_url", "") if chk else ""
print(f"{iso_url} {iso_name} {chk_url}")
' <<< "$RELEASE_JSON" 2>/dev/null || echo "")"
fi

if [ -z "$ISO_URL" ] && command -v jq >/dev/null 2>&1; then
    ISO_URL=$(echo "$RELEASE_JSON" | jq -r '.assets[] | select(.name | endswith(".iso")) | .browser_download_url' 2>/dev/null | head -n 1 || echo "")
    ISO_NAME=$(echo "$RELEASE_JSON" | jq -r '.assets[] | select(.name | endswith(".iso")) | .name' 2>/dev/null | head -n 1 || echo "")
    CHECKSUM_URL=$(echo "$RELEASE_JSON" | jq -r --arg n "$ISO_NAME" '.assets[] | select(.name == ($n + ".sha256") or .name == "SHA256SUMS.txt" or (.name | endswith(".sha256"))) | .browser_download_url' 2>/dev/null | head -n 1 || echo "")
fi

if [ -z "$ISO_URL" ] || [ "$ISO_URL" = "null" ]; then
    # Fallback to grep regex parsing
    ISO_URL=$(echo "$RELEASE_JSON" | grep -o 'https://[^"]*\.iso' | head -n 1 || echo "")
    ISO_NAME=$(basename "$ISO_URL")
    CHECKSUM_URL=$(echo "$RELEASE_JSON" | grep -o 'https://[^"]*\.sha256' | head -n 1 || echo "")
    if [ -z "$CHECKSUM_URL" ]; then
        CHECKSUM_URL=$(echo "$RELEASE_JSON" | grep -o 'https://[^"]*SHA256SUMS\.txt' | head -n 1 || echo "")
    fi
fi

if [ -z "$ISO_URL" ] || [ "$ISO_URL" = "null" ]; then
    echo -e "${YELLOW}[INFO] No release asset .iso attached yet on GitHub.${NC}"
    echo -e "       You can build the ISO locally using Docker or live-build:"
    echo -e "         ${CYAN}./tools/build_iso.sh${NC}"
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
    echo -e "${RED}[ERROR] Neither sha256sum nor shasum was found on this system.${NC}"
    rm -f "$OUT_FILE"
    exit 1
fi
echo -e "   ${YELLOW}Computed SHA-256: ${HASH}${NC}"

EXPECTED_HASH=""
if [ -n "$CHECKSUM_URL" ] && [ "$CHECKSUM_URL" != "null" ]; then
    echo -e "${CYAN}==> Fetching official release checksum...${NC}"
    CHECKSUM_CONTENT=$(fetch_url "$CHECKSUM_URL" 2>/dev/null || echo "")
    if [ -n "$CHECKSUM_CONTENT" ]; then
        if command -v python3 >/dev/null 2>&1; then
            EXPECTED_HASH=$(python3 -c '
import sys, re
content = sys.stdin.read()
iso_name = sys.argv[1] if len(sys.argv) > 1 else ""
matched = ""
for line in content.splitlines():
    if iso_name and iso_name in line:
        m = re.search(r"([0-9a-fA-F]{64})", line)
        if m:
            matched = m.group(1)
            break
if not matched:
    m = re.search(r"([0-9a-fA-F]{64})", content)
    if m:
        matched = m.group(1)
print(matched.lower())
' "$ISO_NAME" <<< "$CHECKSUM_CONTENT" 2>/dev/null || echo "")
        else
            if echo "$CHECKSUM_CONTENT" | grep -F "$ISO_NAME" >/dev/null 2>&1; then
                EXPECTED_HASH=$(echo "$CHECKSUM_CONTENT" | grep -F "$ISO_NAME" | grep -oE '[0-9a-fA-F]{64}' | head -n 1 || echo "")
            else
                EXPECTED_HASH=$(echo "$CHECKSUM_CONTENT" | grep -oE '[0-9a-fA-F]{64}' | head -n 1 || echo "")
            fi
        fi
    fi
fi

if [ -n "${EXPECTED_HASH:-}" ]; then
    EXPECTED_HASH=$(echo "$EXPECTED_HASH" | tr '[:upper:]' '[:lower:]')
    HASH_LOWER=$(echo "$HASH" | tr '[:upper:]' '[:lower:]')
    echo -e "   ${YELLOW}Official SHA-256: ${EXPECTED_HASH}${NC}"
    if [ "$HASH_LOWER" = "$EXPECTED_HASH" ]; then
        echo -e "${GREEN}✅ SHA-256 checksum VERIFIED against official release!${NC}"
    else
        echo -e "${RED}❌ [CRITICAL SECURITY ERROR] SHA-256 checksum MISMATCH!${NC}"
        echo -e "${RED}   Expected: ${EXPECTED_HASH}${NC}"
        echo -e "${RED}   Computed: ${HASH_LOWER}${NC}"
        echo -e "${RED}   Removing compromised/corrupted download: ${OUT_FILE}${NC}"
        rm -f "$OUT_FILE"
        exit 1
    fi
else
    echo -e "${RED}❌ [CRITICAL SECURITY ERROR] Official release checksum not found. Cannot verify ISO integrity.${NC}"
    echo -e "   Removing unverified download: ${OUT_FILE}"
    rm -f "$OUT_FILE"
    exit 1
fi

echo -e "\n${CYAN}==> Flashing to USB Drive on Linux/MacOS:${NC}"
echo -e "   1. Insert a USB flash drive (>= 4 GB)."
echo -e "   2. Identify the target drive: ${CYAN}lsblk${NC} (Linux) or ${CYAN}diskutil list${NC} (macOS)"
echo -e "   3. Write image to USB (replace /dev/sdX with target drive):"
echo -e "      ${CYAN}sudo dd if=\"${OUT_FILE}\" of=/dev/sdX bs=4M status=progress conv=fsync${NC}"
echo -e "      or use Ventoy / BalenaEtcher / Raspberry Pi Imager."
