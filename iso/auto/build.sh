#!/bin/bash
# Build the s0 live ISO with Debian live-build.
#
# REQUIRES: sudo (or root), live-build, xorriso. NOT runnable in this repo's
# development environment — see README.md. tools/build_all.sh skips it and
# says why.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

REPO_ROOT="$(cd .. && pwd)"
STAGING_DIR="$(pwd)/config/includes.chroot/root/repo-snapshot"

echo "==> staging repo snapshot ($REPO_ROOT) -> $STAGING_DIR"
mkdir -p "$STAGING_DIR"
trap 'rm -rf "$STAGING_DIR"' EXIT INT TERM
# src/s0/data/keys/README.md states the private signing key "never lives in
  # this repository and is never shipped inside any application bundle. Not the
  # Linux ISO". Copying src/ wholesale put the demo private key into every ISO,
  # and the ISO config pointed default_key_path at it, so the appliance signed
  # certificates with a key anyone can read. Stage src/ without private keys.
  cp -r "$REPO_ROOT/src" "$STAGING_DIR/"
  find "$STAGING_DIR/src" -type f \( -name '*private*.pem' -o -name '*private*.key' \) -delete
  find "$STAGING_DIR/src" -type d -name '__pycache__' -prune -exec rm -rf {} +
# The air-gapped verifier only. site/ also holds the landing page and the web
# installer, neither of which belongs on a bare-metal sanitization appliance.
# The site/ prefix is preserved so PORTAL_DIR (repo_root / "site/verify")
# resolves the same way here as it does in a working tree.
if [ -d "$REPO_ROOT/site/verify" ]; then
    mkdir -p "$STAGING_DIR/site"
    cp -r "$REPO_ROOT/site/verify" "$STAGING_DIR/site/"
fi
if [ -d "$REPO_ROOT/vendor" ]; then
    cp -r "$REPO_ROOT/vendor" "$STAGING_DIR/"
fi
if [ -f "$REPO_ROOT/pyproject.toml" ]; then
    cp "$REPO_ROOT/pyproject.toml" "$STAGING_DIR/"
fi
if [ -f "$REPO_ROOT/s0_config.json" ]; then
    cp "$REPO_ROOT/s0_config.json" "$STAGING_DIR/"
fi


  # One privilege prefix for every live-build call. `lb config` used to run
  # unsudoed while `lb build` ran under `sudo`, and sudo does not inherit
  # LB_DIR -- so the build came from /root/.live-build with none of the options
  # below applied: not --binary-images iso-hybrid, not --distribution bookworm.
  if [ "$(id -u)" -eq 0 ]; then
      SUDO=""
  else
      SUDO="sudo"
  fi

  echo "==> configuring live-build (debian bookworm amd64, minimal + chromium)"
  # Not silenced: a failed purge leaves the previous config in place and the
  # build would continue against stale, mixed state.
  $SUDO lb clean --purge || echo "WARN: 'lb clean --purge' failed; continuing with existing config" >&2
  $SUDO lb config noauto \
    --architecture amd64 \
    --distribution bookworm \
    --archive-areas "main contrib security" \
    --mode debian \
    --mirror-bootstrap "http://deb.debian.org/debian" \
    --mirror-chroot "http://deb.debian.org/debian" \
    --mirror-binary "http://deb.debian.org/debian" \
    --security true \
    --mirror-chroot-security "http://security.debian.org/debian-security" \
    --mirror-binary-security "http://security.debian.org/debian-security" \
    --apt-indices false \
    --binary-images iso-hybrid \
    --bootappend-live "boot=live components quiet splash hostname=s0" \
    --debian-installer false \
    --iso-volume "S0" \
    "${@}"


  $SUDO lb build

  # `lb build` returning 0 was the only success check, and the script then
  # printed a path that need not exist. iso/container_build.sh already does this.
  ISO="live-image-amd64.hybrid.iso"
  if [ ! -s "$ISO" ]; then
      echo "ERROR: 'lb build' reported success but produced no $ISO" >&2
      echo "       Run 'lb build' by hand to see the failure." >&2
      exit 1
  fi

  echo "==> done: $(pwd)/$ISO"
echo "    smoke-test it headless: ./qemu-test.sh live-image-amd64.hybrid.iso"
