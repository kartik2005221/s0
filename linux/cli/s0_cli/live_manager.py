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
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from s0_core.config import CONFIG
from s0_core.progress import ProgressBar


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

def get_removable_usb_devices() -> List[Dict[str, Any]]:
    """Enumerate removable USB drives safely across Linux, macOS, and Windows."""
    devices: List[Dict[str, Any]] = []

    if sys.platform == "linux":
        sys_block = Path("/sys/block")
        if not sys_block.is_dir():
            return devices

        # Determine root / boot disk to protect it
        system_disks = set()
        try:
            with open("/proc/mounts", "r", encoding="utf-8") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2 and parts[1] in ("/", "/boot", "/boot/efi", "/home"):
                        m = re.match(r"^/dev/([a-z]+|nvme\d+n\d+)", parts[0])
                        if m:
                            system_disks.add(m.group(1))
        except Exception as exc:
            print(f"[s0 live]  WARN : Cannot read /proc/mounts to identify system disks: {exc}", file=sys.stderr)
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

            devices.append({
                "path": f"/dev/{name}",
                "model": model,
                "size_bytes": size_bytes,
                "size_human": _format_size(size_bytes),
                "platform": "linux",
            })

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
                            devices.append({
                                "path": f"/dev/{disk_id}",
                                "raw_path": f"/dev/r{disk_id}",
                                "model": info.get("MediaName", "External USB Drive"),
                                "size_bytes": sz,
                                "size_human": _format_size(sz),
                                "platform": "darwin",
                            })
        except Exception:
            pass

    elif sys.platform == "win32":
        try:
            ps_cmd = (
                "Get-Disk | Where-Object { $_.BusType -eq 'USB' } | "
                "Select-Object Number, FriendlyName, Size, BusType | ConvertTo-Json"
            )
            res = subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd], capture_output=True, text=True, check=False)
            if res.returncode == 0 and res.stdout.strip():
                data = json.loads(res.stdout.strip())
                if isinstance(data, dict):
                    data = [data]
                for item in data:
                    num = item.get("Number")
                    sz = item.get("Size", 0)
                    devices.append({
                        "path": f"\\\\.\\PhysicalDrive{num}",
                        "disk_number": str(num),
                        "model": item.get("FriendlyName", f"USB Disk {num}"),
                        "size_bytes": sz,
                        "size_human": _format_size(sz),
                        "platform": "win32",
                    })
        except Exception:
            pass

    return devices


# ---------------------------------------------------------------------------
# 2. Command: s0 live devices
# ---------------------------------------------------------------------------

def cmd_live_devices(args: argparse.Namespace) -> int:
    """List available removable USB drives safely."""
    devs = get_removable_usb_devices()

    if getattr(args, "json", False):
        print(json.dumps(devs, indent=2))
        return 0

    print("[s0 live]  Detected Removable USB Target Drives:")
    print("━" * 68)
    if not devs:
        print("  (No removable USB drives detected)")
        print()
        print("  Tip: Insert a USB pendrive and ensure it is recognized by your OS.")
        return 0

    print(f"  {'#':<3} {'Target Device':<24} {'Capacity':<14} {'Model / Description'}")
    print(f"  {'-'*3} {'-'*24} {'-'*14} {'-'*22}")
    for idx, d in enumerate(devs):
        print(f"  [{idx}] {d['path']:<24} {d['size_human']:<14} {d['model']}")
    print("━" * 68)
    print("  Use 's0 live flash --target <device>' to create bootable live media.")
    return 0


# ---------------------------------------------------------------------------
# 3. Command: s0 live download
# ---------------------------------------------------------------------------

def _get_auth_token() -> Optional[str]:
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


def _fetch_github_release(repo: str, version: str) -> Dict[str, Any]:
    """Fetch GitHub Release metadata via public API or gh CLI."""
    if version.lower() == "latest":
        url = f"https://api.github.com/repos/{repo}/releases/latest"
    else:
        tag = version if version.startswith("v") else f"v{version}"
        url = f"https://api.github.com/repos/{repo}/releases/tags/{tag}"

    headers = {
        "User-Agent": f"s0-cli/{CONFIG.get('version', '2.4.3')} (LiveDownloader)",
        "Accept": "application/vnd.github.v3+json",
    }
    token = _get_auth_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        # Fallback to gh release view if gh is installed
        if shutil.which("gh"):
            try:
                tag_arg = "latest" if version.lower() == "latest" else (version if version.startswith("v") else f"v{version}")
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
        raise


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
        print(f"\n[s0 live]  WARN : Release {target_tag} does not contain a bootable Live ISO asset.", file=sys.stderr)
        print("[s0 live]  Checking for the latest available Live ISO from older releases...", file=sys.stderr)

        fallback_rel = None
        fallback_iso = None
        fallback_tag = None
        fallback_assets = []

        headers = {
            "User-Agent": f"s0-cli/{CONFIG.get('version', '2.4.3')} (LiveDownloader)",
            "Accept": "application/vnd.github.v3+json",
        }
        token = _get_auth_token()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        try:
            url = f"https://api.github.com/repos/{repo}/releases?per_page=10"
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=15) as resp:
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
            print(f"[s0 live]  Fallback release identified: {fallback_tag} containing '{fallback_iso['name']}' ({_format_size(fallback_iso.get('size', 0))})")
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
                print(f"[s0 live]  Non-interactive mode: proceeding with fallback release {fallback_tag} (--allow-older specified).")
                accept_redirect = True
            else:
                if allow_older:
                    print(f"[s0 live]  Proceeding with fallback release {fallback_tag} (--allow-older specified).")
                    accept_redirect = True
                else:
                    try:
                        ans = input(f"[s0 live]  Would you like to redirect and download the Live ISO from older release {fallback_tag}? [y/N]: ").strip().lower()
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
            print(f"[s0 live]  ERROR : No Live ISO asset (.hybrid.iso) found in release {target_tag} or any older release.", file=sys.stderr)
            return 1

    iso_name = iso_asset["name"]
    iso_url = iso_asset["browser_download_url"]
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
        with urllib.request.urlopen(req, timeout=60) as response, open(target_iso, "wb") as out_f:
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
                cmd = ["gh", "release", "download", tag_name, "-R", repo, "-p", iso_name, "--dir", str(out_dir), "--clobber"]
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
    expected_sha: Optional[str] = None
    if sha_asset:
        try:
            req = urllib.request.Request(sha_asset["browser_download_url"], headers=dl_headers)
            with urllib.request.urlopen(req, timeout=15) as resp:
                text = resp.read().decode("utf-8").strip()
                expected_sha = text.split()[0].lower()
        except Exception:
            if shutil.which("gh"):
                try:
                    res = subprocess.run(
                        ["gh", "release", "download", tag_name, "-R", repo, "-p", sha_asset["name"], "--dir", str(out_dir), "--clobber"],
                        capture_output=True, check=False
                    )
                    local_sha = out_dir / sha_asset["name"]
                    if local_sha.is_file():
                        expected_sha = local_sha.read_text(encoding="utf-8").strip().split()[0].lower()
                except Exception:
                    pass

    if not expected_sha and sha_sums_asset:
        try:
            req = urllib.request.Request(sha_sums_asset["browser_download_url"], headers=dl_headers)
            with urllib.request.urlopen(req, timeout=15) as resp:
                text = resp.read().decode("utf-8")
                for line in text.splitlines():
                    if iso_name in line or "live-amd64" in line:
                        expected_sha = line.split()[0].lower()
                        break
        except Exception:
            if shutil.which("gh"):
                try:
                    res = subprocess.run(
                        ["gh", "release", "download", tag_name, "-R", repo, "-p", "SHA256SUMS.txt", "--dir", str(out_dir), "--clobber"],
                        capture_output=True, check=False
                    )
                    local_sums = out_dir / "SHA256SUMS.txt"
                    if local_sums.is_file():
                        text = local_sums.read_text(encoding="utf-8")
                        for line in text.splitlines():
                            if iso_name in line or "live-amd64" in line:
                                expected_sha = line.split()[0].lower()
                                break
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
            print(f"[s0 live]  OK : Integrity Verified: SHA-256 matches official release ({actual_sha[:16]}...)")
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
        print("[s0 live]  ERROR : No official checksum found to verify against. Cannot verify ISO integrity.", file=sys.stderr)
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

def _unmount_partitions(target: str) -> bool:
    """Unmount active partitions on target drive across platforms."""
    if sys.platform == "linux":
        try:
            # Look up partitions of target
            base = os.path.basename(target)
            sys_block = Path(f"/sys/block/{base}")
            if sys_block.is_dir():
                for p in sys_block.iterdir():
                    if p.name.startswith(base):
                        part_dev = f"/dev/{p.name}"
                        subprocess.run(["umount", "-f", part_dev], capture_output=True, check=False)
            subprocess.run(["umount", "-f", target], capture_output=True, check=False)
            return True
        except Exception:
            return False
    elif sys.platform == "darwin":
        try:
            disk_target = target.replace("/dev/rdisk", "/dev/disk")
            res = subprocess.run(["diskutil", "unmountDisk", disk_target], capture_output=True, text=True, check=False)
            return res.returncode == 0
        except Exception:
            return False
    elif sys.platform == "win32":
        return True
    return True


def cmd_live_flash(args: argparse.Namespace) -> int:
    """Flash a bootable s0 Live ISO to a removable USB flash drive."""
    target_arg = getattr(args, "target", None)
    if not target_arg:
        print("[s0 live]  ERROR : Missing required argument '--target'.", file=sys.stderr)
        print("    Run 's0 live devices' to see connected USB flash drives.", file=sys.stderr)
        return 2

    # Resolve ISO
    iso_path: Optional[Path] = None
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
        print(f"[s0 live]  ERROR : Selected file {iso_path.name} is too small ({_format_size(iso_size)}) to be a valid Live ISO.", file=sys.stderr)
        return 2

    # Check root privileges
    if sys.platform in ("linux", "darwin") and hasattr(os, "geteuid") and os.geteuid() != 0:
        print("[s0 live]  ERROR : 's0 live flash' requires root/administrator privileges to write directly to block devices.", file=sys.stderr)
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
        print(f"[s0 live]  WARN : Device '{target_arg}' was not verified as a removable USB drive.", file=sys.stderr)
        print("    Available removable USB devices:", file=sys.stderr)
        for d in devs:
            print(f"      - {d['path']} ({d['model']}, {d['size_human']})", file=sys.stderr)
        print()
        if not getattr(args, "force", False):
            print("[s0 live]  ERROR : Refusing to write to unverified or potentially internal disk for safety.", file=sys.stderr)
            print("    If you are certain, pass '--force' alongside confirmation.", file=sys.stderr)
            return 2
        matched_device = {"path": target_arg, "model": "Manual Target", "size_human": "Unknown", "platform": sys.platform}

    target_capacity = matched_device.get("size_bytes", 0)
    if target_capacity and target_capacity < iso_size:
        print(f"[s0 live]  ERROR : Target USB drive is too small ({matched_device['size_human']}) to hold ISO ({_format_size(iso_size)}).", file=sys.stderr)
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
                print("[s0 live]  Aborted: Confirmation did not match 'FLASH'.")
                return 0
        except (KeyboardInterrupt, EOFError):
            print("\n[s0 live]  Aborted by user.")
            return 0

    print("[s0 live]  Unmounting existing filesystems on target drive...")
    _unmount_partitions(matched_device["path"])

    write_target = matched_device.get("raw_path") if (sys.platform == "darwin" and matched_device.get("raw_path")) else matched_device["path"]

    print(f"[s0 live]  Writing {iso_path.name} to {write_target}...")
    bar = ProgressBar(iso_size, operation="s0 live flash")
    written = 0
    chunk_size = 4 * 1024 * 1024  # 4MB buffer

    try:
        if sys.platform == "win32":
            from windows.cli.s0_eraser import win32_open_drive_or_partition, win32_flush_buffers
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
        print("\n⚠  Flashing interrupted by user (Ctrl+C). USB drive is in an incomplete/unbootable state.", file=sys.stderr)
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
        print(f"[s0 live]  ERROR : 's0 live build' natively requires the Linux kernel and Debian live-build toolchain.", file=sys.stderr)
        print(f"    Current platform: {sys.platform}", file=sys.stderr)
        print()
        print("Tips:")
        print("  - To run s0 from a pendrive without compiling, use 's0 live download' and 's0 live flash'.")
        print("  - On macOS/Windows, you can build inside Docker or WSL2:")
        print("      docker run --privileged -v $(pwd):/s0 -w /s0 debian:bookworm bash -c 'linux/iso/build.sh'")
        return 1

    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("[s0 live]  ERROR : 's0 live build' requires root privileges to mount loop devices and configure chroot.", file=sys.stderr)
        print("    Run: sudo s0 live build", file=sys.stderr)
        return 1

    build_script = Path(__file__).resolve().parents[3] / "linux" / "iso" / "build.sh"
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
            print(f"[s0 live]  ERROR : Live ISO build failed with exit code {proc.returncode}.", file=sys.stderr)
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
    d_p.add_argument("--version", default="latest", help="release tag to download (default: latest, or e.g. v2.4.0)")
    d_p.add_argument("--out-dir", default=".", help="directory to save ISO (default: current directory)")
    d_p.add_argument("--allow-older", action="store_true", help="allow downloading Live ISO from older release if target release lacks an ISO")
    d_p.set_defaults(func=cmd_live_download)

    # devices
    dev_p = sub.add_parser("devices", help="safely list connected removable USB flash drives")
    dev_p.add_argument("--json", action="store_true", help="output JSON array")
    dev_p.set_defaults(func=cmd_live_devices)

    # flash
    f_p = sub.add_parser("flash", help="write s0 Live ISO to removable USB drive")
    f_p.add_argument("--target", "-t", required=True, help="target device path (from 's0 live devices')")
    f_p.add_argument("--iso", help="path to custom or downloaded ISO (defaults to auto-detecting in current dir)")
    f_p.add_argument("--yes", "-y", action="store_true", help="skip interactive confirmation")
    f_p.add_argument("--force", action="store_true", help="allow flashing even if drive removable flag is unconfirmed")
    f_p.set_defaults(func=cmd_live_flash)

    # build
    b_p = sub.add_parser("build", help="build s0 Live ISO from source (Linux native or Docker/WSL2)")
    b_p.add_argument("--out-dir", default="linux/iso", help="output destination directory")
    b_p.set_defaults(func=cmd_live_build)
