# Deploying s0 Portals to Cloudflare Pages

This guide outlines how to deploy the three static portals of **s0** to **Cloudflare Pages** for zero-maintenance, global edge CDN distribution with SSL.

---

## Portals Overview

| Portal | Source Directory | Framework / Build | Output Directory | Notes |
|---|---|---|---|---|
| **Verification Portal** | `verification-portal/` | Static HTML / JS | `.` | Completely client-side offline Ed25519 & PDF verification |
| **Documentation Portal** | `docs-portal/` | MkDocs Material | `public/` | Compiles markdown documentation via `uv` |
| **Installation Portal** | `install-portal/` | Static HTML / Scripts | `.` | Serves `install.sh`, `install.ps1`, `install.cmd` with clean URLs |

---

## 1. Deploying the Verification Portal

The Verification Portal (`verification-portal/`) is a standalone, client-side zero-backend web app. It performs cryptographic verification of s0 sanitization certificates using WebAssembly/pure JavaScript with zero network calls.

### Cloudflare Pages Settings:
- **Project Name:** `s0-verify` (or custom name)
- **Framework Preset:** `None`
- **Root Directory:** `verification-portal`
- **Build Command:** *(Leave empty)*
- **Build Output Directory:** `.`

### Headers & Security:
`verification-portal/_headers` is automatically detected by Cloudflare Pages to configure:
- Strict CSP allowing Web Workers for PDF.js and camera access for optical QR scanning.
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: SAMEORIGIN`

---

## 2. Deploying the Documentation Portal

The Documentation Portal (`docs-portal/`) generates the comprehensive offline/online technical documentation using MkDocs Material.

### Cloudflare Pages Settings:
- **Project Name:** `s0-docs`
- **Framework Preset:** `None`
- **Root Directory:** `docs-portal`
- **Build Command:** `bash build.sh`
- **Build Output Directory:** `public`
- **Environment Variables:**
  - `PYTHON_VERSION`: `3.11` (or modern Python)

The `build.sh` script automatically installs Astral's `uv`, compiles the documentation, and copies `_headers` into `public/_headers`.

---

## 3. Deploying the Installation Portal

The Installation Portal (`install-portal/`) serves one-line installer scripts for Linux/macOS (`install.sh`), Windows PowerShell (`install.ps1`), and Windows Command Prompt (`install.cmd`).

### Cloudflare Pages Settings:
- **Project Name:** `s0-install`
- **Framework Preset:** `None`
- **Root Directory:** `install-portal`
- **Build Command:** *(Leave empty)*
- **Build Output Directory:** `.`

### URL Routing & Headers:
Cloudflare Pages uses two configuration files included in `install-portal/`:
- `_redirects`: Maps clean endpoints like `/sh`, `/ps1`, `/cmd`, `/upgrade`, `/uninstall` to their respective shell scripts with status 200 rewrites.
- `_headers`: Enforces `Content-Type: text/plain; charset=utf-8` and `Cache-Control: public, max-age=0, must-revalidate` so `curl -sSfL ... | bash` executes immediately without caching stale releases.

---

## 4. Local Preview with Wrangler

You can preview any portal locally using the Cloudflare Wrangler CLI:

```bash
# Preview Verification Portal
npx wrangler pages dev verification-portal/

# Preview Docs Portal (after build)
cd docs-portal && bash build.sh
npx wrangler pages dev public/

# Preview Install Portal
npx wrangler pages dev install-portal/
```
