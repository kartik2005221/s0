#!/usr/bin/env bash
set -euo pipefail

# s0 GitBook Theme Applicator
# Applies the Pitch-Black (#000000) & Electric Orange (#FF6500) theme to GitBook via REST API.

if [ -z "${GITBOOK_TOKEN:-}" ]; then
    echo "ERROR: GITBOOK_TOKEN environment variable is not set."
    echo "Create a personal access token at https://app.gitbook.com/account/developer"
    echo "Usage: GITBOOK_TOKEN=<token> ORG_ID=<org_id> SITE_ID=<site_id> ./tools/apply-gitbook-theme.sh"
    exit 1
fi

if [ -z "${ORG_ID:-}" ] || [ -z "${SITE_ID:-}" ]; then
    echo "ERROR: ORG_ID and SITE_ID must be specified."
    echo "Usage: GITBOOK_TOKEN=<token> ORG_ID=<org_id> SITE_ID=<site_id> ./tools/apply-gitbook-theme.sh"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CUSTOMIZATION_FILE="${SCRIPT_DIR}/../docs/.gitbook/customization.json"

if [ ! -f "$CUSTOMIZATION_FILE" ]; then
    echo "ERROR: Customization file not found at $CUSTOMIZATION_FILE"
    exit 1
fi

echo "==> Fetching current GitBook site customization..."
CURRENT=$(curl -sSf -H "Authorization: Bearer $GITBOOK_TOKEN" \
    "https://api.gitbook.com/v1/orgs/${ORG_ID}/sites/${SITE_ID}/customization" 2>/dev/null || echo "{}")
echo "    Current configuration: ${#CURRENT} bytes fetched."

echo "==> Applying s0 standard portal theme (Pitch-Black & Electric Orange)..."
curl -sSf -X PUT \
    -H "Authorization: Bearer $GITBOOK_TOKEN" \
    -H "Content-Type: application/json" \
    -d @"$CUSTOMIZATION_FILE" \
    "https://api.gitbook.com/v1/orgs/${ORG_ID}/sites/${SITE_ID}/customization"

echo "==> Success! GitBook site theme updated to s0 standard palette."
