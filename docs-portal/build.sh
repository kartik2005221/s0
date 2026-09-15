#!/bin/bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

echo "========================================="
echo "==> Building s0 Documentation for Vercel"
echo "========================================="

# 1. Ensure PATH includes user local bin where uv installs
export PATH="${HOME}/.local/bin:${PATH}"
export UV_LINK_MODE=copy

# 2. Install uv if not already available
if ! command -v uv >/dev/null 2>&1; then
  echo "==> Installing uv (Astral standalone package runner)..."
  curl -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="${HOME}/.local/bin:${PATH}"
fi

echo "==> uv version: $(uv --version)"

# 3. Build MkDocs documentation using uv
echo "==> Compiling MkDocs documentation to public/..."
uv run --with "mkdocs-material>=9.5.0" mkdocs build -d public

# 4. Sanity verification
if [ -f "public/index.html" ]; then
  PAGE_COUNT=$(find public -name '*.html' | wc -l)
  echo "========================================="
  echo "✅ Documentation build successful!"
  echo "   Generated ${PAGE_COUNT} HTML pages in public/"
  echo "========================================="
else
  echo "❌ Error: public/index.html was not generated!"
  exit 1
fi
