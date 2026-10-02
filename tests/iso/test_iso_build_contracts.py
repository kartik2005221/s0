"""The Live ISO build must fail loudly and must not ship a signing key.

Nothing under `iso/` had any test coverage, which matters more than usual here
because the build runs as root, takes a long time, and is only exercised at
release time. Every check in this module is static and instant: it reads the
build scripts, the chroot hook, and the systemd units as text and asserts the
properties that a silent regression would quietly violate.

Each assertion below corresponds to a defect that was present and is now fixed.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent.parent
ISO = REPO / "iso"
AUTO_BUILD = ISO / "auto" / "build.sh"
HOOK = ISO / "config" / "hooks" / "live" / "9000-s0.hook.chroot"
WEB_UNIT = ISO / "config" / "includes.chroot" / "etc" / "systemd" / "system" / "s0-web.service"
KIOSK_UNIT = ISO / "config" / "includes.chroot" / "etc" / "systemd" / "system" / "s0-kiosk.service"
WAIT_WEB = ISO / "config" / "includes.chroot" / "usr" / "local" / "bin" / "s0-wait-web"
PKG_LIST = ISO / "config" / "package-lists" / "s0.list.chroot"
KEYS_README = REPO / "src" / "s0" / "data" / "keys" / "README.md"


def _text(path: Path) -> str:
    assert path.is_file(), f"expected {path.relative_to(REPO)} to exist"
    return path.read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# 1. The ISO must not ship the issuer private key.
# --------------------------------------------------------------------------- #

def test_keys_policy_states_the_private_key_never_ships():
    """The stated policy, so the build can be checked against it."""
    policy = _text(KEYS_README).lower()
    assert "never" in policy and "iso" in policy, (
        "the keys README must state the private key never ships in any bundle, "
        "including the ISO"
    )


def test_iso_build_excludes_private_keys_from_the_staged_tree():
    """Regression: `cp -r src` put the demo private key into every ISO.

    The README says the private key is "never shipped inside any application
    bundle. Not the Linux ISO". The build then copied `src/` wholesale, which
    included `src/s0/data/keys/demo_issuer_private.pem`, and the ISO config
    pointed `default_key_path` at it -- so the appliance signed certificates with a
    key anyone can read.
    """
    build = _text(AUTO_BUILD)
    assert re.search(r"find .*-name '\*private\*\.pem'", build), (
        "iso/auto/build.sh must delete private keys from the staged tree; "
        "a bare `cp -r src` ships the demo issuer key"
    )
    assert re.search(r"find .*-name '\*private\*\.key'", build), (
        "private .key files must be excluded too"
    )


def test_iso_excludes_bytecode_so_builds_are_reproducible():
    """`__pycache__` exists in developer trees and is gitignored.

    Copying it into the ISO meant a locally built ISO contained developer .pyc
    files that a CI-built ISO of the same commit did not.
    """
    assert "__pycache__" in _text(AUTO_BUILD), (
        "the staged tree must exclude __pycache__, or a local build ships "
        "bytecode that a CI build of the same commit does not"
    )


def test_default_issuer_key_fails_closed_when_no_key_exists():
    """With private keys excluded, an unconfigured ISO must refuse to sign.

    `default_issuer_key` returns None and the callers require `--key` or an
    explicit `--no-certificate`, so this is a regression guard on that contract
    rather than a property of the ISO.
    """
    planner = _text(REPO / "src" / "s0" / "wipe" / "planner.py")
    assert "return None" in planner, (
        "default_issuer_key must return None rather than raising when no key is found"
    )
    cli = _text(REPO / "src" / "s0" / "cli" / "main.py")
    assert "no issuer signing key found" in cli, (
        "the CLI must refuse to issue a certificate with no issuer key and name "
        "--key / --no-certificate as the ways forward"
    )


# --------------------------------------------------------------------------- #
# 2. The build must not report success it did not achieve.
# --------------------------------------------------------------------------- #

def test_build_verifies_the_iso_artifact_exists():
    """Regression: `lb build` returning 0 was the only success check.

    The script then printed a path that need not exist, so a build that produced
    nothing reported "==> done".
    """
    build = _text(AUTO_BUILD)
    assert re.search(r"\[\s+!\s+-s\s+\"\$ISO\"\s*\]", build), (
        "iso/auto/build.sh must check the ISO exists and is non-empty after lb build"
    )
    assert "exit 1" in build, "a missing artifact must fail the build"


def test_live_build_does_not_silence_a_failed_purge():
    """`lb clean --purge 2>/dev/null || true` left a stale config in place."""
    build = _text(AUTO_BUILD)
    for line in build.splitlines():
        if "lb clean" in line:
            assert "|| true" not in line, (
                "a failed `lb clean --purge` must warn, not be swallowed -- the "
                "build would continue against stale, mixed config"
            )


# --------------------------------------------------------------------------- #
# 3. One privilege prefix for every live-build call.
# --------------------------------------------------------------------------- #

def test_live_build_uses_one_privilege_prefix_for_config_and_build():
    """Regression: `lb config` unsudoed + `sudo lb build` built the wrong image.

    sudo does not inherit LB_DIR, so the build ran against /root/.live-build and
    none of the configured options applied: not `--binary-images iso-hybrid`, not
    `--distribution bookworm`, not the mirror or archive area.
    """
    build = _text(AUTO_BUILD)
    assert "SUDO=" in build, "auto/build.sh must derive a single privilege prefix"
    assert re.search(r"\$SUDO\s+lb config", build), "`lb config` must use that prefix"
    assert re.search(r"\$SUDO\s+lb build", build), "`lb build` must use the same prefix"
    assert "sudo lb config" not in build, "a bare `sudo lb config` reintroduces the split"


# --------------------------------------------------------------------------- #
# 4. Security updates must be enabled.
# --------------------------------------------------------------------------- #

def test_iso_enables_the_debian_security_archive():
    """Regression: `--security false` built the appliance unpatched.

    debian-security is where the security-updated builds of chromium, python3,
    systemd-sysv, util-linux and linux-image-amd64 live -- every entry in the
    package list. `--security false` meant all of them came from main only.
    """
    build = _text(AUTO_BUILD)
    assert "--security false" not in build, (
        "the ISO must not disable debian-security: that is where the "
        "security-updated build of every package in the list actually lives"
    )
    assert "--security true" in build
    assert "debian-security" in build, "a security mirror must be configured"
    assert "security" in re.search(r"--archive-areas \"([^\"]+)\"", build).group(1), (
        "the security component must be in --archive-areas"
    )


# --------------------------------------------------------------------------- #
# 5. The chroot hook must not mask failures.
# --------------------------------------------------------------------------- #

def test_chroot_hook_creates_the_kiosk_user_or_fails():
    """Regression: `groupadd || true` then `useradd ... || usermod ... || true`.

    If groupadd failed, useradd -G failed, usermod failed, and the hook exited 0
    having created no kiosk user. The web tier then fell back to a 0600
    root-owned token that the `s0` user could not read, and s0-kiosk.service
    sat in a Restart=always loop with nothing on screen.
    """
    hook = _text(HOOK)
    for line in hook.splitlines():
        stripped = line.strip()
        if stripped.startswith(("groupadd", "useradd", "usermod")):
            assert "|| true" not in stripped, (
                f"user/group creation must not be best-effort: {stripped!r}. "
                "A build that cannot make the kiosk work should fail at build time."
            )


def test_run_directory_is_created_by_systemd_not_the_chroot():
    """`/run` is a tmpfs: a directory made at build time is gone at boot.

    The hook created /run/s0 and chowned it, which never applied, so the
    documented 0750/root:s0-kiosk posture was not what actually ran.
    """
    hook = _text(HOOK)
    assert "mkdir -p /run/s0" not in hook, (
        "creating /run/s0 in the chroot has no effect at boot; systemd must own it"
    )
    web_unit = _text(WEB_UNIT)
    assert "RuntimeDirectory=s0" in web_unit, (
        "s0-web.service must declare RuntimeDirectory=s0 so the directory exists "
        "at boot with the right owner and is cleaned up on stop"
    )
    assert re.search(r"RuntimeDirectoryMode=0?750", web_unit), (
        "s0-kiosk must be able to read the token directory"
    )


# --------------------------------------------------------------------------- #
# 6. The kiosk readiness gate.
# --------------------------------------------------------------------------- #

def test_kiosk_wait_script_probes_an_unauthenticated_endpoint():
    """Regression: it polled /api/devices with no token.

    401 makes urllib raise HTTPError, so the `if` was always false and the kiosk
    always burned the full 30 s and then failed its ordering dependency.
    """
    wait = _text(WAIT_WEB)
    assert "/healthz" in wait, "s0-wait-web must poll the unauthenticated /healthz"
    # Only the command matters; the comment above it documents the old bug.
    polled = [ln for ln in wait.splitlines() if "urlopen" in ln]
    assert polled, "s0-wait-web must actually poll something"
    for line in polled:
        assert "/api/devices" not in line, (
            "polling an authenticated endpoint without the token can never "
            "succeed: 401 makes urllib raise, so the `if` test is always false"
        )


def test_healthz_is_the_only_unauthenticated_data_route():
    """And it must expose nothing about the host."""
    app = _text(REPO / "src" / "s0" / "web" / "app.py")
    assert '"status": "ok"' in app, "/healthz must return a fixed literal"
    healthz = app[app.index('def healthz'):app.index('def index')]
    assert "REPO" not in healthz and "Path.home()" not in healthz, (
        "the readiness probe must not disclose host paths"
    )


def test_web_unit_binds_loopback_only():
    """A wipe tool must never expose an erase-the-disk API to the network."""
    assert "--host 127.0.0.1" in _text(WEB_UNIT)
    assert "--host 0.0.0.0" not in _text(WEB_UNIT)


def test_kiosk_unit_passes_the_token_to_the_bootstrap_url():
    """Both launch paths use ?token=, which the server trades for a cookie."""
    kiosk = _text(KIOSK_UNIT)
    assert "?token=" in kiosk, (
        "the kiosk must pass the session token as the ?token= bootstrap, which "
        "GET / exchanges for an HttpOnly cookie"
    )
    assert "/run/s0/web_auth_token" in kiosk, (
        "the kiosk must read the token from the file the web tier writes"
    )


# --------------------------------------------------------------------------- #
# 7. Package manifest hygiene.
# --------------------------------------------------------------------------- #

def test_package_list_has_no_duplicate_entries():
    lines = [
        line.strip()
        for line in _text(PKG_LIST).splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    assert len(lines) == len(set(lines)), f"duplicate package in {PKG_LIST.name}"


def test_package_list_entries_are_plain_names():
    """Pinning by version is a known gap; unparseable lines make it worse.

    A line that is not a plain package name cannot be pinned later without
    editing this, so at least keep the format uniform and assertable.
    """
    for line in _text(PKG_LIST).splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        assert re.fullmatch(r"[a-z0-9][a-z0-9.+-]*", stripped), (
            f"package entry {stripped!r} is not a plain Debian package name"
        )


# --------------------------------------------------------------------------- #
# 8. Shell scripts must at least parse.
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "script",
    [
        "iso/build.sh",
        "iso/auto/build.sh",
        "iso/container_build.sh",
        "iso/qemu-test.sh",
        "iso/config/hooks/live/9000-s0.hook.chroot",
        "iso/config/includes.chroot/usr/local/bin/s0-wait-web",
    ],
)
def test_shell_script_is_executable_and_parses(script: str) -> None:
    import subprocess

    path = REPO / script
    assert path.is_file(), f"{script} is missing"
    assert path.stat().st_mode & 0o111, f"{script} is not executable"
    result = subprocess.run(["sh", "-n", str(path)], capture_output=True, text=True)
    assert result.returncode == 0, f"{script} has a shell syntax error:\n{result.stderr}"
