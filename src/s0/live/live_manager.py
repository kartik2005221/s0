"""s0 Live ISO & Bootable Media Manager (s0 live).

Subcommands:
  - s0 live download [--version TAG] [--out-dir DIR]
  - s0 live devices [--json]
  - s0 live flash --target DEVICE [--iso PATH] [-y|--yes]
  - s0 live build [--out-dir DIR]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from s0.config import CONFIG
from s0.progress import ProgressBar

GITHUB_REPO = "kartik2005221/s0"


def _format_size(size_bytes: int) -> str:
    """Format bytes to human-readable string."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(size_bytes) < 1024.0 or unit == "TB":
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} TB"


# ---------------------------------------------------------------------------
# 1. Device Enumeration (Cross-Platform Removable USBs)
# ---------------------------------------------------------------------------


def get_removable_usb_devices() -> list[dict[str, Any]]:
    """Enumerate removable USB drives safely across Linux, macOS, and Windows."""
    devices: list[dict[str, Any]] = []

    if sys.platform == "linux":
        sys_block = Path("/sys/block")
        if not sys_block.is_dir():
            return devices

        # Determine root / boot disk to protect it
        system_disks = set()
        try:
            with open("/proc/mounts", encoding="utf-8") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2 and parts[1] in ("/", "/boot", "/boot/efi", "/home"):
                        m = re.match(r"^/dev/([a-z]+|nvme\d+n\d+)", parts[0])
                        if m:
                            system_disks.add(m.group(1))
        except Exception as exc:
            print(
                f"[s0 live]  WARN : Cannot read /proc/mounts to identify system disks: {exc}", file=sys.stderr
            )
            print("    Device listing refused for safety (cannot exclude system disk).", file=sys.stderr)
            return []

        for entry in sorted(sys_block.iterdir()):
            name = entry.name
            if name.startswith(("loop", "ram", "dm-", "sr", "zram")):
                continue
            if name in system_disks:
                continue

            # Check if removable or on USB bus
            is_removable = False
            removable_path = entry / "removable"
            if removable_path.is_file():
                try:
                    is_removable = removable_path.read_text(encoding="utf-8").strip() == "1"
                except Exception:
                    pass

            # Check subsystem path for 'usb'
            try:
                resolved_link = (sys_block / name).resolve()
                if "usb" in str(resolved_link).lower():
                    is_removable = True
            except Exception:
                pass

            if not is_removable:
                continue

            size_path = entry / "size"
            size_bytes = 0
            if size_path.is_file():
                try:
                    size_bytes = int(size_path.read_text(encoding="utf-8").strip()) * 512
                except Exception:
                    pass

            if size_bytes <= 0:
                continue

            model = "USB Removable Drive"
            model_path = entry / "device" / "model"
            if model_path.is_file():
                try:
                    model = model_path.read_text(encoding="utf-8").strip()
                except Exception:
                    pass

            vendor_path = entry / "device" / "vendor"
            if vendor_path.is_file():
                try:
                    v = vendor_path.read_text(encoding="utf-8").strip()
                    if v:
                        model = f"{v} {model}".strip()
                except Exception:
                    pass

            devices.append(
                {
                    "path": f"/dev/{name}",
                    "model": model,
                    "size_bytes": size_bytes,
                    "size_human": _format_size(size_bytes),
                    "platform": "linux",
                }
            )

    elif sys.platform == "darwin":
        try:
            cmd = ["diskutil", "list", "-plist", "external", "physical"]
            res = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if res.returncode == 0:
                import plistlib

                data = plistlib.loads(res.stdout.encode("utf-8"))
                for disk_id in data.get("AllDisks", []):
                    # Query info for this disk
                    info_cmd = ["diskutil", "info", "-plist", disk_id]
                    info_res = subprocess.run(info_cmd, capture_output=True, text=True, check=False)
                    if info_res.returncode == 0:
                        info = plistlib.loads(info_res.stdout.encode("utf-8"))
                        if info.get("Internal", True) is False or info.get("RemovableMedia", False):
                            sz = info.get("TotalSize", 0)
                            devices.append(
                                {
                                    "path": f"/dev/{disk_id}",
                                    "raw_path": f"/dev/r{disk_id}",
                                    "model": info.get("MediaName", "External USB Drive"),
                                    "size_bytes": sz,
                                    "size_human": _format_size(sz),
                                    "platform": "darwin",
                                }
                            )
        except Exception:
            pass

    elif sys.platform == "win32":
        try:
            ps_cmd = (
                "Get-Disk | Where-Object { $_.BusType -eq 'USB' } | "
                "Select-Object Number, FriendlyName, Size, BusType | ConvertTo-Json"
            )
            res = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd], capture_output=True, text=True, check=False
            )
            if res.returncode == 0 and res.stdout.strip():
                data = json.loads(res.stdout.strip())
                if isinstance(data, dict):
                    data = [data]
                for item in data:
                    num = item.get("Number")
                    sz = item.get("Size", 0)
                    devices.append(
                        {
                            "path": f"\\\\.\\PhysicalDrive{num}",
                            "disk_number": str(num),
                            "model": item.get("FriendlyName", f"USB Disk {num}"),
                            "size_bytes": sz,
                            "size_human": _format_size(sz),
                            "platform": "win32",
                        }
                    )
        except Exception:
            pass

    return devices


# ---------------------------------------------------------------------------
# 2. Command: s0 live devices
# ---------------------------------------------------------------------------

#: sysex(3) exit codes. Imported from neither `sysex` (absent from minimal and
#: Windows Python builds) nor `os` (POSIX-only), so they are spelled out. The
#: values are fixed by sysex.h.
#:
#: * `EX_NOINPUT` (66) - an input device does not exist. `s0 live devices`
#:   finding no removable USB used to return 0, so `s0 live devices &&
#:   s0 live flash -t /dev/sdb` chained into a flash against a path that was
#:   never enumerated.
#: * `EX_TEMPFAIL` (75) - a temporary failure such as the operator declining an
#:   irreversible action. `s0 live flash` used to return 0 on abort, so
#:   `s0 live flash ... && echo "USB ready"` printed "USB ready" after a refusal.
EX_NOINPUT = 66
EX_TEMPFAIL = 75


def cmd_live_devices(args: argparse.Namespace) -> int:
    """List available removable USB drives safely.

    This wrote the whole table to stdout with bare ``print()``, which broke the
    contract every other command keeps and that every `--help` screen states: human
    text goes to stderr and stdout stays empty so it can carry only machine-readable
    output. A user running `s0 live devices > drives.txt` got a text table on stdout
    and nothing on stderr, so `2>/dev/null` did not silence it and a script reading
    stdout got prose.

    It also read `args.json` directly, so `--format json` was ignored here and
    `--json` emitted a bare list where every other command emits the `s0.*` envelope.
    Both are fixed by routing through the resolved policy.
    """
    from s0.cli.ui import UI

    ui = getattr(args, "ui", None) or UI(
        getattr(args, "policy", None) or _fallback_policy(args), "live devices"
    )
    devs = get_removable_usb_devices()

    if ui.policy.fmt in ("json", "csv"):
        # `ui.finish` emits the same `s0.*` envelope every other command emits. This
        # used to `print(json.dumps(devs))`, a bare list with no schema, no status and
        # no timestamp -- the one command whose machine output a caller could not
        # parse the same way as the rest.
        ui.finish(result={"devices": devs, "count": len(devs)})
        # Same rule in machine-readable mode: an empty list is a failure to find a
        # target, not a successful listing. Returning 0 here while the text path
        # returned EX_NOINPUT made `--json` the odd one out for scripts.
        return EX_NOINPUT if not devs else 0

    ui.note("[s0 live]  Detected Removable USB Target Drives:")
    ui.note("━" * 68)
    if not devs:
        ui.note("  (No removable USB drives detected)")
        ui.note("")
        ui.note("  Tip: Insert a USB pendrive and ensure it is recognized by your OS.")
        # Non-zero: "found no target" is a failure to do the job asked for.
        # Returning 0 meant `s0 live devices && s0 live flash -t /dev/sdb`
        # chained straight into a flash against a path never enumerated.
        return EX_NOINPUT

    ui.note(f"  {'#':<3} {'Target Device':<24} {'Capacity':<14} {'Model / Description'}")
    ui.note(f"  {'-' * 3} {'-' * 24} {'-' * 14} {'-' * 22}")
    for idx, d in enumerate(devs):
        ui.note(f"  [{idx}] {d['path']:<24} {d['size_human']:<14} {d['model']}")
    ui.note("━" * 68)
    ui.note("  Use 's0 live flash --target <device>' to create bootable live media.")
    return 0


def _fallback_policy(args: argparse.Namespace):
    """The output policy for a `live` invocation dispatched without one attached."""
    from s0.cli.ui import policy_from_args

    return policy_from_args(args)


# ---------------------------------------------------------------------------
# 3. Command: s0 live download
# ---------------------------------------------------------------------------

_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")


def _parse_sha256_document(text: str, iso_name: str) -> str | None:
    """Extract the SHA-256 for *iso_name* from a checksum file, strictly.

    Three ways the previous parsing could pick the wrong value, all of which end in
    a *false mismatch* and the good ISO being deleted:

    * ``text.split()[0]`` on the dedicated ``.sha256`` asset takes the first
      whitespace-separated token of the whole body. An HTML error page -- which is
      what a rate-limited or redirected request returns -- yields ``<html>`` or a
      doctype fragment as the "expected hash".
    * ``SHA256SUMS.txt`` was scanned for the first line merely *containing*
      ``iso_name`` or ``live-amd64``. With several artefacts in the file, a
      substring match hits the wrong line -- ``s0-live-amd64.iso.sha256`` matches
      before ``s0-live-amd64.iso`` does, and the wrong file's hash is then used to
      condemn a correct download.
    * Neither checked that the result was a hash at all.

    So the format is now parsed as the format it is: one line per artefact,
    ``<64 hex> <two spaces or *><name>``. The name must match exactly (after the
    ``./`` prefix some tools emit), and the digest must be 64 hex characters.
    Anything else is not a checksum for this file, and returns None so the caller
    fails closed with "no checksum" rather than "checksum mismatch".

    A body that is *only* a digest is accepted directly, since that is what the
    dedicated `.sha256` asset usually contains. Deciding that here rather than at
    each call site means one place decides what counts as a hash.

    This is integrity, not authenticity. The digest is fetched from the same host as
    the ISO, so anyone who can replace the artefact can replace its checksum. A
    correct parser makes "this file is internally consistent" reliable; it cannot
    make the publisher trustworthy, and nothing here should be read as doing so.
    """
    stripped = text.strip()
    if _SHA256_HEX.match(stripped.lower()):
        return stripped.lower()

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Accept both `sha256sum` output forms: "<hash>  <name>" and "<hash> *<name>".
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        digest, name = parts[0].strip().lower(), parts[1].strip()
        if name.startswith("*"):
            name = name[1:]
        if name.startswith("./"):
            name = name[2:]
        # Some tools append a mode or size column; the basename is what identifies
        # the artefact, and matching the basename is what a reader expects.
        if os.path.basename(name) != iso_name:
            continue
        if _SHA256_HEX.match(digest):
            return digest
    return None


def _parse_sha256_sums(text: str, iso_name: str) -> str | None:
    """Find the ISO's digest in a multi-entry SHA256SUMS.txt.

    Separate from _parse_sha256_document because a sums file lists many artefacts,
    so a line for a *different* file must be skipped rather than accepted -- which
    is exactly the case the substring match got wrong.
    """
    return _parse_sha256_document(text, iso_name)


def _https_only(url: str, what: str = "URL") -> str:
    """Refuse anything that is not an https:// URL.

    The asset URL comes from a GitHub API response, so it is data rather than a
    literal, and it is then written straight to a file. A `file://` or plain
    `http://` value there would turn a release download into a local file read
    or an unencrypted fetch, and the API response is exactly the thing an
    attacker would try to influence. Every other download in this module builds
    its URL from a literal `https://` prefix, so this check is free there and
    load-bearing here.
    """
    if not isinstance(url, str) or not url.lower().startswith("https://"):
        raise ValueError(
            f"{what} is not an https:// URL: {url!r}. Refusing to fetch it, "
            f"because the value came from a network response and would be "
            f"written straight to disk."
        )
    return url


def _get_auth_token() -> str | None:
    """Retrieve GitHub token from environment or gh CLI if available."""
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        return token.strip()
    if shutil.which("gh"):
        try:
            res = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, check=False)
            if res.returncode == 0 and res.stdout.strip():
                return res.stdout.strip()
        except Exception:
            pass
    return None


def _fetch_github_release(repo: str, version: str) -> dict[str, Any]:
    """Fetch GitHub Release metadata via public API or gh CLI."""
    if version.lower() == "latest":
        url = f"https://api.github.com/repos/{repo}/releases/latest"
    else:
        tag = version if version.startswith("v") else f"v{version}"
        url = f"https://api.github.com/repos/{repo}/releases/tags/{tag}"

    headers = {
        "User-Agent": f"s0-cli/{CONFIG.get('version', '2.4.4')} (LiveDownloader)",
        "Accept": "application/vnd.github.v3+json",
    }
    token = _get_auth_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as resp:  # nosec B310 - literal https:// above
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        # Fallback to gh release view if gh is installed
        if shutil.which("gh"):
            try:
                tag_arg = (
                    "latest"
                    if version.lower() == "latest"
                    else (version if version.startswith("v") else f"v{version}")
                )
                gh_cmd = ["gh", "release", "view", tag_arg, "-R", repo, "--json", "tagName,assets"]
                res = subprocess.run(gh_cmd, capture_output=True, text=True, check=False)
                if res.returncode == 0 and res.stdout.strip():
                    data = json.loads(res.stdout.strip())
                    return {
                        "tag_name": data.get("tagName", version),
                        "assets": [
                            {
                                "name": a.get("name"),
                                "size": a.get("size", 0),
                                "browser_download_url": a.get("url"),
                                "url": a.get("apiUrl", a.get("url")),
                            }
                            for a in data.get("assets", [])
                        ],
                    }
            except Exception:
                pass

        # Fallback to direct asset download URLs without GitHub API (e.g. rate limit HTTP 403)
        tag_synth = CONFIG.get("version", "2.4.4")
        if not tag_synth.startswith("v"):
            tag_synth = f"v{tag_synth}"
        if version.lower() != "latest" and version.strip():
            tag_synth = version if version.startswith("v") else f"v{version}"
        iso_name = f"s0-live-{tag_synth}-amd64.hybrid.iso"
        base_dl = f"https://github.com/{repo}/releases/download/{tag_synth}"
        return {
            "tag_name": tag_synth,
            "assets": [
                {
                    "name": iso_name,
                    "size": 0,
                    "browser_download_url": f"{base_dl}/{iso_name}",
                    "url": f"{base_dl}/{iso_name}",
                },
                {
                    "name": f"{iso_name}.sha256",
                    "size": 0,
                    "browser_download_url": f"{base_dl}/{iso_name}.sha256",
                    "url": f"{base_dl}/{iso_name}.sha256",
                },
            ],
        }


def cmd_live_download(args: argparse.Namespace) -> int:
    """Download official s0 Live ISO and verify SHA-256 checksum."""
    repo = GITHUB_REPO
    ver_input = getattr(args, "version", "latest") or "latest"
    out_dir = Path(getattr(args, "out_dir", ".") or ".").resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"[s0 live]  Querying GitHub Releases for {repo} ({ver_input})...")
    try:
        rel = _fetch_github_release(repo, ver_input)
    except Exception as e:
        print(f"[s0 live]  ERROR : Failed to fetch release metadata from GitHub: {e}", file=sys.stderr)
        return 1

    tag_name = rel.get("tag_name", ver_input)
    assets = rel.get("assets", [])

    # Find ISO asset: preference for versioned name s0-live-*.hybrid.iso, fallback to s0-live-amd64.hybrid.iso
    iso_asset = None
    sha_asset = None
    sha_sums_asset = None

    for a in assets:
        name = a.get("name", "")
        if name.endswith(".hybrid.iso"):
            iso_asset = a
        elif name.endswith(".hybrid.iso.sha256"):
            sha_asset = a
        elif name == "SHA256SUMS.txt":
            sha_sums_asset = a

    if not iso_asset:
        target_tag = tag_name
        print(
            f"\n[s0 live]  WARN : Release {target_tag} does not contain a bootable Live ISO asset.",
            file=sys.stderr,
        )
        print("[s0 live]  Checking for the latest available Live ISO from older releases...", file=sys.stderr)

        fallback_rel = None
        fallback_iso = None
        fallback_tag = None
        fallback_assets = []

        headers = {
            "User-Agent": f"s0-cli/{CONFIG.get('version', '2.4.4')} (LiveDownloader)",
            "Accept": "application/vnd.github.v3+json",
        }
        token = _get_auth_token()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        try:
            url = f"https://api.github.com/repos/{repo}/releases?per_page=10"
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=15) as resp:  # nosec B310 - literal https:// above
                all_releases = json.loads(resp.read().decode("utf-8"))
            for cand_rel in all_releases:
                if cand_rel.get("tag_name") == target_tag:
                    continue
                cand_assets = cand_rel.get("assets", [])
                for a in cand_assets:
                    if a.get("name", "").endswith(".hybrid.iso"):
                        fallback_rel = cand_rel
                        fallback_tag = cand_rel.get("tag_name", "")
                        fallback_assets = cand_assets
                        fallback_iso = a
                        break
                if fallback_iso:
                    break
        except Exception:
            pass

        if not fallback_iso and shutil.which("gh"):
            try:
                gh_cmd = ["gh", "release", "list", "-R", repo, "--limit", "10", "--json", "tagName"]
                gh_res = subprocess.run(gh_cmd, capture_output=True, text=True, check=False)
                if gh_res.returncode == 0 and gh_res.stdout.strip():
                    items = json.loads(gh_res.stdout.strip())
                    for item in items:
                        t = item.get("tagName")
                        if not t or t == target_tag:
                            continue
                        try:
                            cand_rel = _fetch_github_release(repo, t)
                            cand_assets = cand_rel.get("assets", [])
                            for a in cand_assets:
                                if a.get("name", "").endswith(".hybrid.iso"):
                                    fallback_rel = cand_rel
                                    fallback_tag = t
                                    fallback_assets = cand_assets
                                    fallback_iso = a
                                    break
                            if fallback_iso:
                                break
                        except Exception:
                            continue
            except Exception:
                pass

        if fallback_iso:
            print(
                f"[s0 live]  Fallback release identified: {fallback_tag} containing '{fallback_iso['name']}' ({_format_size(fallback_iso.get('size', 0))})"
            )
            accept_redirect = False
            allow_older = getattr(args, "allow_older", False)

            if not sys.stdin.isatty():
                if not allow_older:
                    print(
                        f"[s0 live]  ERROR : Target release {target_tag} has no Live ISO and environment is non-interactive.\n"
                        f"    Pass --allow-older to automatically download Live ISO from fallback release {fallback_tag}.",
                        file=sys.stderr,
                    )
                    return 1
                print(
                    f"[s0 live]  Non-interactive mode: proceeding with fallback release {fallback_tag} (--allow-older specified)."
                )
                accept_redirect = True
            else:
                if allow_older:
                    print(
                        f"[s0 live]  Proceeding with fallback release {fallback_tag} (--allow-older specified)."
                    )
                    accept_redirect = True
                else:
                    try:
                        ans = (
                            input(
                                f"[s0 live]  Would you like to redirect and download the Live ISO from older release {fallback_tag}? [y/N]: "
                            )
                            .strip()
                            .lower()
                        )
                    except (KeyboardInterrupt, EOFError):
                        print("\n[s0 live]  Download cancelled.")
                        return 130
                    if ans in ("y", "yes"):
                        accept_redirect = True
                    else:
                        print(f"[s0 live]  Download cancelled by user (declined fallback to {fallback_tag}).")
                        return 1

            if accept_redirect:
                print(f"[s0 live]  Redirecting download to release {fallback_tag}...")
                rel = fallback_rel
                tag_name = fallback_tag
                assets = fallback_assets
                iso_asset = fallback_iso
                sha_asset = None
                sha_sums_asset = None
                for a in assets:
                    name = a.get("name", "")
                    if name.endswith(".hybrid.iso.sha256"):
                        sha_asset = a
                    elif name == "SHA256SUMS.txt":
                        sha_sums_asset = a
        else:
            print(
                f"[s0 live]  ERROR : No Live ISO asset (.hybrid.iso) found in release {target_tag} or any older release.",
                file=sys.stderr,
            )
            return 1

    iso_name = iso_asset["name"]
    iso_url = _https_only(iso_asset["browser_download_url"], "ISO download URL")
    iso_size = iso_asset["size"]
    target_iso = out_dir / iso_name

    print(f"[s0 live]  Found Live ISO: {iso_name} ({_format_size(iso_size)})")

    # Download with progress bar
    print(f"[s0 live]  Downloading {iso_name} to {target_iso}...")
    bar = ProgressBar(iso_size, operation="s0 live download")
    downloaded = 0
    # Use bare headers without Authorization to avoid leaking tokens across redirects to storage CDNs
    dl_headers = {"User-Agent": "s0-cli"}

    try:
        req = urllib.request.Request(iso_url, headers=dl_headers)
        with urllib.request.urlopen(req, timeout=60) as response, open(target_iso, "wb") as out_f:  # nosec B310 - checked by _https_only above
            while True:
                chunk = response.read(65536)
                if not chunk:
                    break
                out_f.write(chunk)
                downloaded += len(chunk)
                bar.update(downloaded)
        bar.finish()
    except KeyboardInterrupt:
        bar.close()
        if target_iso.exists():
            try:
                target_iso.unlink()
            except OSError:
                pass
        print("\n⚠  Download cancelled by user (Ctrl+C).", file=sys.stderr)
        return 130
    except Exception as e:
        bar.close()
        if shutil.which("gh"):
            try:
                print("[s0 live]  Fetching release asset via GitHub CLI...")
                cmd = [
                    "gh",
                    "release",
                    "download",
                    tag_name,
                    "-R",
                    repo,
                    "-p",
                    iso_name,
                    "--dir",
                    str(out_dir),
                    "--clobber",
                ]
                res = subprocess.run(cmd, check=False)
                if res.returncode != 0 or not target_iso.is_file():
                    raise e
            except Exception:
                if target_iso.exists():
                    target_iso.unlink()
                print(f"[s0 live]  ERROR : Download failed: {e}", file=sys.stderr)
                return 1
        else:
            if target_iso.exists():
                target_iso.unlink()
            print(f"[s0 live]  ERROR : Download failed: {e}", file=sys.stderr)
            return 1

    # Verify Checksum
    expected_sha: str | None = None
    if sha_asset:
        try:
            req = urllib.request.Request(sha_asset["browser_download_url"], headers=dl_headers)
            with urllib.request.urlopen(req, timeout=15) as resp:  # nosec B310 - literal https:// above
                text = resp.read().decode("utf-8").strip()
                expected_sha = _parse_sha256_document(text, iso_name)
        except Exception:
            if shutil.which("gh"):
                try:
                    res = subprocess.run(
                        [
                            "gh",
                            "release",
                            "download",
                            tag_name,
                            "-R",
                            repo,
                            "-p",
                            sha_asset["name"],
                            "--dir",
                            str(out_dir),
                            "--clobber",
                        ],
                        capture_output=True,
                        check=False,
                    )
                    local_sha = out_dir / sha_asset["name"]
                    if local_sha.is_file():
                        expected_sha = _parse_sha256_document(local_sha.read_text(encoding="utf-8"), iso_name)
                except Exception:
                    pass

    if not expected_sha and sha_sums_asset:
        try:
            req = urllib.request.Request(sha_sums_asset["browser_download_url"], headers=dl_headers)
            with urllib.request.urlopen(req, timeout=15) as resp:  # nosec B310 - literal https:// above
                text = resp.read().decode("utf-8")
                expected_sha = _parse_sha256_sums(text, iso_name)
        except Exception:
            if shutil.which("gh"):
                try:
                    res = subprocess.run(
                        [
                            "gh",
                            "release",
                            "download",
                            tag_name,
                            "-R",
                            repo,
                            "-p",
                            "SHA256SUMS.txt",
                            "--dir",
                            str(out_dir),
                            "--clobber",
                        ],
                        capture_output=True,
                        check=False,
                    )
                    local_sums = out_dir / "SHA256SUMS.txt"
                    if local_sums.is_file():
                        text = local_sums.read_text(encoding="utf-8")
                        expected_sha = _parse_sha256_sums(text, iso_name)
                except Exception:
                    pass

    print("[s0 live]  Verifying cryptographic integrity (SHA-256)...")
    hasher = hashlib.sha256()
    with open(target_iso, "rb") as f:
        while True:
            chunk = f.read(1048576)
            if not chunk:
                break
            hasher.update(chunk)
    actual_sha = hasher.hexdigest().lower()

    if expected_sha:
        if actual_sha == expected_sha:
            print(
                f"[s0 live]  OK : Integrity Verified: SHA-256 matches official release ({actual_sha[:16]}...)"
            )
        else:
            print("[s0 live]  ERROR : Integrity Error: Checksum mismatch!", file=sys.stderr)
            print(f"    Expected: {expected_sha}", file=sys.stderr)
            print(f"    Actual:   {actual_sha}", file=sys.stderr)
            try:
                target_iso.unlink()
            except OSError:
                pass
            return 1
    else:
        print(
            "[s0 live]  ERROR : No official checksum found to verify against. Cannot verify ISO integrity.",
            file=sys.stderr,
        )
        try:
            target_iso.unlink()
        except OSError:
            pass
        return 1

    # Write local .sha256 file
    sha_file = out_dir / f"{iso_name}.sha256"
    sha_file.write_text(f"{actual_sha}  {iso_name}\n", encoding="utf-8")

    print()
    print(f"[s0 live]  OK : Download complete: {target_iso}")
    print(f"[s0 live]    To write to USB: s0 live flash --target <device> --iso {target_iso}")
    return 0


# ---------------------------------------------------------------------------
# 4. Command: s0 live flash
# ---------------------------------------------------------------------------


def _still_mounted(target: str) -> list[str]:
    """Mount points still backed by *target* or one of its partitions.

    Reads /proc/mounts rather than trusting `umount`'s exit status, because
    `umount -f` on a busy filesystem returns non-zero in some configurations and zero in
    others, and `check=False` meant nobody was looking either way.
    """
    base = os.path.basename(target.rstrip("/"))
    if not base:
        return []
    holders: list[str] = []
    try:
        with open("/proc/mounts", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) < 2:
                    continue
                dev = parts[0].removeprefix("/dev/").removesuffix("*")
                # The whole device, or any partition of it (sda1 for sda).
                if dev == base or dev.startswith(base) and dev[len(base) : len(base) + 1].isdigit():
                    holders.append(f"{parts[1]} ({dev})")
    except OSError:
        return []
    return holders


def _unmount_partitions(target: str) -> bool:
    """Unmount active partitions on target. Returns True only if nothing is left mounted.

    The Linux branch used to return `True` unconditionally: it ran `umount -f` with
    `check=False` and never looked at the result. So when the unmount failed -- a busy
    filesystem, which is the normal case for a USB stick someone is still using -- the
    caller was told it had succeeded and wrote the ISO over a *mounted* filesystem,
    reporting "Successfully flashed". `wipe` and `clone` both refuse a mounted target;
    `live flash` did not.
    """
    if sys.platform == "linux":
        try:
            base = os.path.basename(target)
            sys_block = Path(f"/sys/block/{base}")
            if sys_block.is_dir():
                for p in sorted(sys_block.iterdir()):
                    if p.name.startswith(base):
                        subprocess.run(["umount", f"/dev/{p.name}"], capture_output=True, check=False)
            subprocess.run(["umount", target], capture_output=True, check=False)
        except Exception:
            return False
        # Ask the kernel, not umount.
        return not _still_mounted(target)
    elif sys.platform == "darwin":
        try:
            disk_target = target.replace("/dev/rdisk", "/dev/disk")
            res = subprocess.run(
                ["diskutil", "unmountDisk", disk_target], capture_output=True, text=True, check=False
            )
            return res.returncode == 0
        except Exception:
            return False
    elif sys.platform == "win32":
        return True
    return True


def validate_iso_image(iso_path: Path) -> tuple[bool, str]:
    """Check that this file is a bootable hybrid ISO, not just a large file.

    The only test was `size >= 100 MiB`, so any sufficiently large file passed: a
    video, a disk image, a tarball. Flashing one produces an unbootable USB stick and,
    more importantly, destroys whatever device it was aimed at -- the failure is
    discovered after the write, on hardware that may have held the only copy of
    something.

    Four cheap structural checks, all from the first and last few KiB, so this costs
    nothing on a multi-hundred-megabyte image:

    * a Hybrid ISO is an ISO 9660 image, so it starts with ``CD001`` at offset
      0x8001 (32769) -- the standard 32 KiB system area;
    * it carries an El Torito boot record, whose magic is ``EL TORITO SPEC`` (also
      at 0x8821, inside the system area);
    * the volume descriptor must actually say the image is bootable, via the
      ``boot record`` identifier at offset 7 of the primary descriptor;
    * a PDF or a tarball must not be accepted, which the magic checks rule out.

    A refusal names what was found, because "not a valid ISO" with no detail sends
    the operator to the wrong problem.
    """
    try:
        size = iso_path.stat().st_size
    except OSError as exc:
        return False, f"cannot stat the ISO: {exc}"

    # The system area lives at 0x8000..0x9000 and must be inside the file.
    if size < 0x9000:
        return False, (f"only {size} bytes; an ISO 9660 system area needs at least {0x9000} (36864)")

    try:
        with open(iso_path, "rb") as fh:
            fh.seek(0x8000)
            system_area = fh.read(0x1000)
    except OSError as exc:
        return False, f"cannot read the ISO system area: {exc}"

    if b"CD001" not in system_area:
        head = _describe_leading_bytes(iso_path)
        return False, (
            f"no ISO 9660 signature ('CD001') in the 32 KiB system area, so this is "
            f"not an ISO image at all. It starts with {head}."
        )

    descriptor = system_area[1:6]
    if descriptor != b"CD001":
        return False, (
            f"expected the primary volume descriptor at offset 0x8001, found "
            f"{descriptor!r}. This is not a standard-layout ISO."
        )

    boot_type = system_area[7]
    if boot_type not in (0x00, 0x88):
        return False, (
            f"the primary volume descriptor does not indicate a boot record "
            f"(type byte {boot_type:#04x}, expected 0x00 'no boot' or 0x88 "
            f"'El Torito'). This ISO will not produce a bootable USB stick."
        )

    if b"EL TORITO SPEC" not in system_area:
        # Not fatal on its own -- some images boot via a partition-table hybrid
        # header rather than El Torito -- so reported as a warning by the caller.
        return True, (
            "ISO 9660 structure verified, but no El Torito boot record was found. "
            "This may be a hybrid image that boots via the partition table, or it "
            "may not be bootable at all."
        )

    return True, "ISO 9660 structure and El Torito boot record verified."


def _describe_leading_bytes(path: Path, count: int = 8) -> str:
    """Best-effort identification of a file we are about to refuse."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(count)
    except OSError:
        return "unreadable"
    if not head:
        return "empty"
    printable = all(32 <= b < 127 for b in head)
    if printable:
        return f"ASCII text {head.decode('ascii', 'replace')!r}"
    if head[:4] == b"\x7fELF":
        return "an ELF executable"
    if head[:2] == b"PK":
        return "a ZIP archive"
    if head[:5] == b"%PDF-":
        return "a PDF document"
    if head[257:262] == b"ustar":
        return "a tar archive"
    return f"binary data starting {head[:4].hex()}"


def cmd_live_flash(args: argparse.Namespace) -> int:
    """Flash a bootable s0 Live ISO to a removable USB flash drive."""
    target_arg = getattr(args, "target", None)
    if not target_arg:
        print("[s0 live]  ERROR : Missing required argument '--target'.", file=sys.stderr)
        print("    Run 's0 live devices' to see connected USB flash drives.", file=sys.stderr)
        return 2

    # `--dry-run` is attached to every s0 subcommand with the help text "plan
    # only; never write to the target", and `cmd_live_flash` never read it. So the
    # documented way to preview a flash -- `s0 live flash --dry-run` -- wrote the
    # ISO to the device. Honour it before anything is touched.
    dry_run = bool(getattr(args, "dry_run", False))

    # Resolve ISO
    iso_path: Path | None = None
    if getattr(args, "iso", None):
        iso_path = Path(args.iso).resolve()
    else:
        candidates = list(Path(".").glob("s0-live-*.iso")) + list(Path.home().glob(".s0/iso/s0-live-*.iso"))
        if candidates:
            iso_path = sorted(candidates, key=lambda p: p.stat().st_mtime, reverse=True)[0]

    if not iso_path or not iso_path.is_file():
        print("[s0 live]  ERROR : Could not find s0 Live ISO file to flash.", file=sys.stderr)
        print("    Specify an ISO via: s0 live flash --target <device> --iso <path-to-iso>", file=sys.stderr)
        print("    Or download one via: s0 live download", file=sys.stderr)
        return 2

    iso_size = iso_path.stat().st_size
    if iso_size < 100 * 1024 * 1024:
        print(
            f"[s0 live]  ERROR : Selected file {iso_path.name} is too small ({_format_size(iso_size)}) to be a valid Live ISO.",
            file=sys.stderr,
        )
        return 2

    ok, detail = validate_iso_image(iso_path)
    if not ok:
        print(f"[s0 live]  ERROR : {iso_path.name} is not a usable Live ISO.", file=sys.stderr)
        print(f"            {detail}", file=sys.stderr)
        print(
            "            Refusing to flash it: the write would destroy the target "
            "device and the stick would not boot, so the loss is discovered only "
            "afterwards.",
            file=sys.stderr,
        )
        return 2
    print(f"[s0 live]  Image check: {detail}", file=sys.stderr)

    if dry_run:
        print("[s0 live]  Dry run: no writes will be performed.")
        print("━" * 68)
        print(f"  Source ISO:       {iso_path.name} ({_format_size(iso_size)})")
        print(f"  Target Device:    {target_arg}")
        verified = any(d["path"].lower() == target_arg.lower() for d in get_removable_usb_devices())
        print(f"  Verified USB:     {'yes' if verified else 'no (--force would be required)'}")
        print()
        print("[s0 live]  Planned action: write the ISO to the target device.")
        print("    Re-run without --dry-run, and answer the FLASH confirmation, to proceed.")
        return 0

    # Check root privileges
    if sys.platform in ("linux", "darwin") and hasattr(os, "geteuid") and os.geteuid() != 0:
        print(
            "[s0 live]  ERROR : 's0 live flash' requires root/administrator privileges to write directly to block devices.",
            file=sys.stderr,
        )
        print(f"    Run: sudo s0 live flash --target {target_arg} --iso {iso_path}", file=sys.stderr)
        return 1

    # Match target device against removable USB devices
    devs = get_removable_usb_devices()
    matched_device = None

    for d in devs:
        if d["path"].lower() == target_arg.lower():
            matched_device = d
            break
        if sys.platform == "win32" and d.get("disk_number") == str(target_arg).strip():
            matched_device = d
            break
        if sys.platform == "darwin" and d.get("raw_path", "").lower() == target_arg.lower():
            matched_device = d
            break

    if not matched_device:
        print(
            f"[s0 live]  WARN : Device '{target_arg}' was not verified as a removable USB drive.",
            file=sys.stderr,
        )
        print("    Available removable USB devices:", file=sys.stderr)
        for d in devs:
            print(f"      - {d['path']} ({d['model']}, {d['size_human']})", file=sys.stderr)
        print()
        if not getattr(args, "force", False):
            print(
                "[s0 live]  ERROR : Refusing to write to unverified or potentially internal disk for safety.",
                file=sys.stderr,
            )
            print("    If you are certain, pass '--force' alongside confirmation.", file=sys.stderr)
            return 2
        # `--force` waives the removable-USB check, not basic existence. Without
        # this, a typo like `--target sdb` created a regular file called `sdb` in
        # the working directory via `open(target, "wb")` and reported success.
        forced = Path(target_arg)
        if not forced.exists():
            print(f"[s0 live]  ERROR : Target '{target_arg}' does not exist.", file=sys.stderr)
            print("    Check the path from 's0 live devices'.", file=sys.stderr)
            return 2
        if not stat.S_ISBLK(os.stat(forced).st_mode):
            print(
                f"[s0 live]  ERROR : Target '{target_arg}' is not a block device.",
                file=sys.stderr,
            )
            print("    Refusing to write an ISO to a regular file or directory.", file=sys.stderr)
            return 2
        try:
            forced_size = os.stat(forced).st_size
        except OSError:
            forced_size = 0
        matched_device = {
            "path": target_arg,
            "model": "Manual Target (unverified)",
            "size_human": _format_size(forced_size),
            "size_bytes": forced_size,
            "platform": sys.platform,
        }

    target_capacity = matched_device.get("size_bytes", 0)
    if target_capacity and target_capacity < iso_size:
        print(
            f"[s0 live]  ERROR : Target USB drive is too small ({matched_device['size_human']}) to hold ISO ({_format_size(iso_size)}).",
            file=sys.stderr,
        )
        return 2

    print("[s0 live]  USB Flash Confirmation :")
    print("━" * 68)
    print(f"  Source ISO:       {iso_path.name} ({_format_size(iso_size)})")
    print(f"  Target Device:    {matched_device['path']}")
    print(f"  Device Model:     {matched_device.get('model', 'USB Device')}")
    print(f"  Device Capacity:  {matched_device.get('size_human', 'Unknown')}")
    print("━" * 68)
    print("  ⚠ CAUTION: ALL DATA ON THE TARGET DEVICE WILL BE PERMANENTLY DESTROYED!")
    print("━" * 68)

    if not getattr(args, "yes", False):
        try:
            confirm = input("Type 'FLASH' to proceed with writing to USB: ").strip()
            if confirm != "FLASH":
                # Non-zero: `s0 live flash ... && echo "USB ready"` printed
                # "USB ready" after the operator declined to flash.
                print("[s0 live]  Aborted: Confirmation did not match 'FLASH'.")
                return EX_TEMPFAIL
        except (KeyboardInterrupt, EOFError):
            print("\n[s0 live]  Aborted by user.")
            return EX_TEMPFAIL

    print("[s0 live]  Unmounting existing filesystems on target drive...")
    if not _unmount_partitions(matched_device["path"]):
        still = _still_mounted(matched_device["path"])
        print(
            "[s0 live]  ERROR : the target still has mounted filesystems, so writing to "
            "it would corrupt the mounted data rather than replace the device.",
            file=sys.stderr,
        )
        for entry in still:
            print(f"[s0 live]          still mounted: {entry}", file=sys.stderr)
        print(
            "[s0 live]          unmount them and retry, or stop anything using them "
            "(a shell cwd, a file manager, a backup agent).",
            file=sys.stderr,
        )
        # Refusing is the whole point. Proceeding wrote the ISO over live data and
        # reported success; `--force` does not override this, because there is no
        # version of "overwrite a mounted filesystem" that is what the operator meant.
        return EX_TEMPFAIL

    write_target = (
        matched_device.get("raw_path")
        if (sys.platform == "darwin" and matched_device.get("raw_path"))
        else matched_device["path"]
    )

    print(f"[s0 live]  Writing {iso_path.name} to {write_target}...")
    bar = ProgressBar(iso_size, operation="s0 live flash")
    written = 0
    chunk_size = 4 * 1024 * 1024  # 4MB buffer

    try:
        if sys.platform == "win32":
            from s0.platform.windows.s0_eraser import win32_flush_buffers, win32_open_drive_or_partition

            f_out = win32_open_drive_or_partition(write_target, write=True)
            with open(iso_path, "rb") as f_in:
                while True:
                    chunk = f_in.read(chunk_size)
                    if not chunk:
                        break
                    f_out.write(chunk)
                    written += len(chunk)
                    bar.update(written)
                f_out.flush()
                win32_flush_buffers(f_out)
                f_out.close()
        else:
            with open(iso_path, "rb") as f_in, open(write_target, "wb") as f_out:
                while True:
                    chunk = f_in.read(chunk_size)
                    if not chunk:
                        break
                    f_out.write(chunk)
                    written += len(chunk)
                    bar.update(written)
                f_out.flush()
                os.fsync(f_out.fileno())

        bar.finish()
    except KeyboardInterrupt:
        bar.close()
        print(
            "\n⚠  Flashing interrupted by user (Ctrl+C). USB drive is in an incomplete/unbootable state.",
            file=sys.stderr,
        )
        return 130
    except Exception as e:
        bar.close()
        print(f"[s0 live]  ERROR : Flash failed: {e}", file=sys.stderr)
        return 1

    print()
    print("[s0 live]  OK : Successfully flashed s0 Live ISO to USB drive!")
    print()
    print("How to boot:")
    print("  1. Insert the USB into the target computer.")
    print("  2. Turn on the machine and repeatedly press the Boot Menu key (F12, F11, F9, or Option on Mac).")
    print("  3. Select the UEFI USB boot entry to launch the s0 Live Kiosk.")
    return 0


# ---------------------------------------------------------------------------
# 5. Command: s0 live build
# ---------------------------------------------------------------------------


def cmd_live_build(args: argparse.Namespace) -> int:
    """Build s0 bare-metal Live ISO from source."""
    if sys.platform != "linux":
        print(
            "[s0 live]  ERROR : 's0 live build' natively requires the Linux kernel and Debian live-build toolchain.",
            file=sys.stderr,
        )
        print(f"    Current platform: {sys.platform}", file=sys.stderr)
        print()
        print("Tips:")
        print("  - To run s0 from a pendrive without compiling, use 's0 live download' and 's0 live flash'.")
        print("  - On macOS/Windows, you can build inside Docker or WSL2:")
        print("      docker run --privileged -v $(pwd):/s0 -w /s0 debian:bookworm bash -c 'iso/build.sh'")
        return 1

    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print(
            "[s0 live]  ERROR : 's0 live build' requires root privileges to mount loop devices and configure chroot.",
            file=sys.stderr,
        )
        print("    Run: sudo s0 live build", file=sys.stderr)
        return 1

    # `_root` was never defined here, so every `s0 live build` run that reached
    # this line raised NameError rather than reporting where it looked. The
    # install tree is found the same way the rest of the package finds it.
    from s0.resources import repo_root

    _root = repo_root()
    build_script = _root / "iso" / "build.sh" if _root is not None else Path("iso/build.sh")
    if not build_script.is_file():
        print("[s0 live]  ERROR : build.sh not found in the s0 installation tree.", file=sys.stderr)
        print(f"    Expected location: {build_script}", file=sys.stderr)
        return 1

    print(f"[s0 live]  Launching s0 Live ISO build pipeline: {build_script}")
    print("━" * 68)

    cmd = ["bash", str(build_script)]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        if proc.stdout:
            for line in iter(proc.stdout.readline, ""):
                sys.stdout.write(line)
                sys.stdout.flush()
        proc.wait()
        if proc.returncode == 0:
            print("━" * 68)
            print("[s0 live]  OK : Live ISO build completed successfully!")
            return 0
        else:
            print("━" * 68)
            print(
                f"[s0 live]  ERROR : Live ISO build failed with exit code {proc.returncode}.", file=sys.stderr
            )
            return proc.returncode
    except Exception as e:
        print(f"[s0 live]  ERROR : Error executing build: {e}", file=sys.stderr)
        return 1


# ---------------------------------------------------------------------------
# 6. Argument Parser Registration
# ---------------------------------------------------------------------------


def register_live_parser(subparsers: argparse._SubParsersAction) -> None:
    """Register 'live' subparser."""
    p = subparsers.add_parser("live", help="download, inspect, and flash bootable s0 Live ISO to USB")
    sub = p.add_subparsers(dest="live_action", required=True)

    # download
    d_p = sub.add_parser("download", help="download official s0 Live ISO with SHA-256 validation")
    d_p.add_argument(
        "--version", default="latest", help="release tag to download (default: latest, or e.g. v2.4.0)"
    )
    d_p.add_argument("--out-dir", default=".", help="directory to save ISO (default: current directory)")
    d_p.add_argument(
        "--allow-older",
        action="store_true",
        help="allow downloading Live ISO from older release if target release lacks an ISO",
    )
    d_p.set_defaults(func=cmd_live_download)

    # devices
    dev_p = sub.add_parser("devices", help="safely list connected removable USB flash drives")
    dev_p.add_argument("--json", action="store_true", help="output JSON array")
    dev_p.set_defaults(func=cmd_live_devices)

    # flash
    f_p = sub.add_parser("flash", help="write s0 Live ISO to removable USB drive")
    f_p.add_argument("--target", "-t", required=True, help="target device path (from 's0 live devices')")
    f_p.add_argument(
        "--iso", help="path to custom or downloaded ISO (defaults to auto-detecting in current dir)"
    )
    f_p.add_argument("--yes", "-y", action="store_true", help="skip interactive confirmation")
    f_p.add_argument(
        "--force", action="store_true", help="allow flashing even if drive removable flag is unconfirmed"
    )
    f_p.set_defaults(func=cmd_live_flash)

    # build
    b_p = sub.add_parser("build", help="build s0 Live ISO from source (Linux native or Docker/WSL2)")
    b_p.add_argument("--out-dir", default="iso", help="output destination directory")
    b_p.set_defaults(func=cmd_live_build)
