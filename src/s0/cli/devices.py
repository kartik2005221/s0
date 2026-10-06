"""Device inventory: lsblk + /sys probing, image-file targets, safety checks."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from s0.safety import evaluate_path_safety
from s0.wipe.methods.base import Target

logger = logging.getLogger("s0.devices")


class SafetyError(RuntimeError):
    """Refusal to proceed — target looks system-critical or is mounted."""


def _lsblk() -> list[dict]:
    if not shutil.which("lsblk"):
        return []
    try:
        out = subprocess.run(
            ["lsblk", "-J", "-b", "-o", "NAME,PATH,TYPE,SIZE,SERIAL,MODEL,RM,ROTA,MOUNTPOINTS"],
            capture_output=True,
            text=True,
            check=False,
        )
        if out.returncode != 0:
            return []
        return json.loads(out.stdout).get("blockdevices", [])
    except Exception:
        return []


def _sys_int(device_name: str, rel: str) -> int | None:
    p = Path("/sys/block") / device_name / rel
    try:
        return int(p.read_text().strip())
    except (OSError, ValueError):
        return None


def _unescape_mount_field(s: str) -> str:
    """Decode kernel octal escapes in /proc/mounts (\\040=space, \\011=tab, \\012=newline, \\134=backslash, etc.)."""
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), s)


def _mounted_paths() -> set[str]:
    mounts = set()
    try:
        with open("/proc/mounts", encoding="utf-8") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    dev = _unescape_mount_field(parts[0])
                    mounts.add(dev)
                    try:
                        mounts.add(os.path.realpath(dev))
                    except OSError:
                        pass
    except OSError:
        pass

    if not mounts and sys.platform in ("darwin", "freebsd"):
        try:
            res = subprocess.run(["mount"], capture_output=True, text=True, check=False)
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 3 and parts[1] == "on":
                        mounts.add(parts[0])
                        rdev = parts[0].replace("/dev/disk", "/dev/rdisk")
                        mounts.add(rdev)
        except Exception:
            pass

    return mounts


def _storage_type(name: str, rotational: int | None) -> str:
    if name.startswith("nvme"):
        return "NVMe"
    if name.startswith("mmcblk"):
        return "eMMC"
    if rotational == 1:
        return "HDD"
    if rotational == 0:
        return "SSD"
    return "UNKNOWN"


def get_block_device_size(device_path: str | Path) -> int:
    """Determine capacity in bytes of any Linux block special device using ioctl, sysfs, or blockdev."""
    norm_dev = os.path.normpath(str(device_path).strip())
    if "\x00" in norm_dev or ".." in norm_dev.split(os.sep):
        return 0
    p = Path(norm_dev)
    dev_name = p.name

    # 1. Try ioctl BLKGETSIZE64
    if norm_dev.startswith("/dev/"):
        try:
            import fcntl
            import struct

            BLKGETSIZE64 = 0x80081272
            with open(norm_dev, "rb") as f:
                buf = fcntl.ioctl(f.fileno(), BLKGETSIZE64, struct.pack("Q", 0))
                sz = struct.unpack("Q", buf)[0]
                if sz > 0:
                    return sz
        except Exception:
            pass

    # 2. Try sysfs /sys/class/block/<dev>/size (sectors * 512)
    try:
        safe_dev = os.path.basename(dev_name)
        if safe_dev and ".." not in safe_dev and re.match(r"^[A-Za-z0-9_.-]+$", safe_dev):
            norm_sys = os.path.normpath(f"/sys/class/block/{safe_dev}/size")
            if norm_sys.startswith("/sys/class/block/"):
                sys_size = Path(norm_sys)
                if sys_size.exists():
                    sectors = int(sys_size.read_text().strip())
                    if sectors > 0:
                        return sectors * 512
    except Exception:
        pass

    # 3. Try blockdev --getsize64
    if shutil.which("blockdev"):
        try:
            res = subprocess.run(
                ["blockdev", "--getsize64", str(p)], capture_output=True, text=True, check=True
            )
            sz = int(res.stdout.strip())
            if sz > 0:
                return sz
        except Exception:
            pass

    # 4. Try lsblk
    if shutil.which("lsblk"):
        try:
            res = subprocess.run(
                ["lsblk", "-b", "-d", "-n", "-o", "SIZE", str(p)], capture_output=True, text=True, check=True
            )
            sz = int(res.stdout.strip())
            if sz > 0:
                return sz
        except Exception:
            pass

    clean_p = str(p).replace("\r", "").replace("\n", "")
    message = (
        f"Could not determine size of block device {clean_p} — all detection methods "
        f"failed; falling back to 0 bytes"
    )
    logger.debug(message)
    # Also recorded for the machine-readable envelope. A warning that only reaches
    # stderr means `s0 list --json` reports `"warnings": []` while the operator's
    # terminal scrolls three complaints about the same device -- so the one output
    # meant for automation is the one that looks clean. `drain_detection_warnings`
    # is called by the command handlers that surface devices.
    _DETECTION_WARNINGS.append(message)
    return 0


#: Human-readable detection problems, drained into the envelope by the handlers.
_DETECTION_WARNINGS: list[str] = []


def drain_detection_warnings() -> list[str]:
    """Return and clear the detection warnings recorded since the last drain."""
    out = list(_DETECTION_WARNINGS)
    _DETECTION_WARNINGS.clear()
    return out


def _flatten_devs(devs: list[dict]) -> list[dict]:
    flat = []
    for d in devs:
        flat.append(d)
        if d.get("children"):
            flat.extend(_flatten_devs(d["children"]))
    return flat


def _windows_disk_targets() -> list[Target]:
    targets = []
    import string

    for letter in string.ascii_uppercase:
        drive_path = f"{letter}:"
        try:
            if Path(f"{letter}:\\").exists():
                sz = 0
                try:
                    from s0.platform.windows.s0_eraser import get_windows_target_size

                    sz = get_windows_target_size(drive_path)
                except Exception as exc:
                    logger.warning(
                        "Could not determine size of Windows volume %s: %s; falling back to 0 bytes",
                        drive_path,
                        exc,
                    )
                targets.append(
                    Target(
                        path=drive_path,
                        kind="block",
                        capacity_bytes=sz,
                        storage_type="UNKNOWN",
                        model=f"Windows Volume {drive_path}",
                    )
                )
        except Exception:
            pass
    return targets


def _macos_disk_targets() -> list[Target]:
    targets = []
    if not shutil.which("diskutil"):
        return []
    try:
        proc = subprocess.run(["diskutil", "list"], capture_output=True, text=True, check=False)
        if proc.returncode == 0:
            for line in proc.stdout.splitlines():
                line_str = line.strip()
                if line_str.startswith("/dev/disk"):
                    parts = line_str.split()
                    dev = parts[0]
                    rdev = dev.replace("/dev/disk", "/dev/rdisk")
                    sz = 0
                    try:
                        from s0.platform.macos.s0_eraser import get_macos_target_size

                        sz = get_macos_target_size(dev)
                    except Exception as exc:
                        logger.warning(
                            "Could not determine size of macOS disk %s: %s; falling back to 0 bytes", dev, exc
                        )
                    targets.append(
                        Target(
                            path=rdev,
                            kind="block",
                            capacity_bytes=sz,
                            storage_type="UNKNOWN",
                            model="macOS Disk",
                        )
                    )
    except Exception:
        pass
    return targets


def list_block_targets() -> list[Target]:
    """All block devices and partitions (disks, partitions, loop, LVM, crypt)."""
    if sys.platform == "win32":
        return _windows_disk_targets()
    if sys.platform == "darwin":
        return _macos_disk_targets()

    targets: list[Target] = []
    raw_devs = _lsblk()
    flat_devs = _flatten_devs(raw_devs)

    for dev in flat_devs:
        dev_type = dev.get("type")
        if dev_type not in ("disk", "part", "loop", "lvm", "crypt", "dm", "mpath"):
            continue
        name = dev["name"]
        target_path = dev.get("path") or f"/dev/{name}"
        rotational = _sys_int(name, "queue/rotational")
        size = int(dev.get("size") or 0)
        if size <= 0:
            size = get_block_device_size(target_path)

        targets.append(
            Target(
                path=target_path,
                kind="block",
                capacity_bytes=size,
                sector_size=_sys_int(name, "queue/logical_block_size") or 512,
                storage_type=_storage_type(name, rotational),
                model=(dev.get("model") or "").strip() or None,
                serial=(dev.get("serial") or "").strip() or None,
                removable=bool(_sys_int(name, "removable")),
            )
        )
    return targets


def image_target(path: str) -> Target:
    """Wrap a regular file as a wipe target (the root-free test medium)."""
    s_path = str(path).strip()
    if not s_path or "\x00" in s_path:
        raise ValueError(f"invalid image path: {path}")
    norm = os.path.normpath(s_path)
    if ".." in norm.split(os.sep):
        raise ValueError(f"path traversal not permitted: {path}")
    p = Path(os.path.realpath(norm))
    if p.is_dir():
        files = [f for f in p.rglob("*") if f.is_file()]
        total_size = sum(f.stat().st_size for f in files)
        return Target(
            path=str(p),
            kind="directory",
            capacity_bytes=total_size if total_size > 0 else 4096,
            sector_size=512,
            storage_type="DIRECTORY",
            model=p.name,
        )
    if not p.is_file():
        raise FileNotFoundError(f"not a regular file or directory: {path}")
    return Target(
        path=str(p),
        kind="image",
        capacity_bytes=p.stat().st_size,
        sector_size=512,
        storage_type="IMAGE_FILE",
        model=p.name,
    )


def device_id_for(target: Target) -> str:
    """Best stable identifier available; the cert records which one it used."""
    if target.serial:
        return target.serial
    if target.kind == "block":
        wwn = Path("/sys/block") / Path(target.path).name / "wwid"
        try:
            return wwn.read_text().strip()
        except OSError:
            pass
    # Last resort: content-independent identifier of the target path.
    return "sha256:" + hashlib.sha256(target.path.encode()).hexdigest()


def _is_partition(dev_name: str) -> bool:
    """Return True if dev_name is a partition rather than a whole disk."""
    if re.search(r"(?<=\d)p\d+$", dev_name):
        return True
    if re.match(r"^(?:sd[a-z]+|hd[a-z]+|vd[a-z]+|xvd[a-z]+)\d+$", dev_name):
        return True
    return False


def _is_dev_or_subpartition(parent_path: str, candidate_mount: str) -> bool:
    """Check if candidate_mount is parent_path or a sub-partition of parent_path."""
    parent_real = os.path.realpath(parent_path)
    cand_real = os.path.realpath(candidate_mount)
    if parent_real == cand_real:
        return True

    # If parent_real is already a partition, only exact match applies
    # (e.g. /dev/sda1 must not match /dev/sda10)
    p_name = Path(parent_real).name
    if _is_partition(p_name):
        return False

    # Parent is a whole drive (e.g. /dev/sda, /dev/nvme0n1, /dev/loop0)
    parent_esc = re.escape(parent_real)
    pattern = rf"^{parent_esc}(?:p)?[0-9]+$"
    return bool(re.match(pattern, cand_real))


def evaluate_safety(
    target: Target, force: bool = False, *, force_honoured: bool = True
) -> tuple[list[str], str | None]:
    """Evaluate system-critical target safety without raising an exception.

    Returns (warnings, refusal_reason).
    """
    warnings: list[str] = []

    warnings_path, refusal = evaluate_path_safety(target.path, force=force)
    warnings.extend(warnings_path)
    if refusal is not None:
        return warnings, refusal

    if target.kind == "image":
        return warnings, None

    mounted = _mounted_paths()
    hits = sorted(m for m in mounted if _is_dev_or_subpartition(target.path, m))
    if hits:
        if not force:
            hint = (
                "Unmount them first, or pass --force if you truly mean it."
                if force_honoured
                else (
                    "Unmount them first. Cloning onto a mounted filesystem would corrupt "
                    "the mounted data, so --force does not bypass this -- unmount, or "
                    "choose a different destination."
                )
            )
            return warnings, f"{target.path} has mounted filesystems ({', '.join(hits)}). {hint}"
        warnings.append(f"proceeding WITH MOUNTED FILESYSTEMS: {', '.join(hits)}")

    root_src = _get_root_mount_source()
    if root_src:
        target_real = os.path.realpath(target.path)
        if is_os_device(target_real):
            if not force:
                return warnings, (
                    f"{target.path} hosts the running ROOT filesystem. The tool refuses "
                    f"this without --force; if you mean it, boot the s0 ISO instead."
                )
            warnings.append(
                "proceeding AGAINST THE RUNNING ROOT FILESYSTEM — this will destroy the running system"
            )
    else:
        if not force:
            return warnings, (
                f"Cannot verify whether {target.path} hosts the running ROOT filesystem "
                f"(findmnt unavailable and /proc/mounts could not be verified). "
                f"Refusing to proceed without --force."
            )
        warnings.append("WARNING: could not verify whether target hosts the root filesystem")

    return warnings, None


def check_safety(target: Target, force: bool = False, *, force_honoured: bool = True) -> list[str]:
    """Refuse system-critical targets unless --force. Returns warnings.

    `force_honoured` says whether the caller will actually act on a `--force`.
    `wipe` does; `clone` does not, because its `--force` means "overwrite an existing
    image file" and nothing more. It only changes the wording of the refusal, never
    whether the refusal happens.
    """
    warnings, refusal = evaluate_safety(target, force=force, force_honoured=force_honoured)
    if refusal is not None:
        raise SafetyError(refusal)
    return warnings


def _get_root_mount_source() -> str | None:
    """Resolve the real backing device path for the running root filesystem (/),
    attempting findmnt first with direct /proc/mounts parsing as fallback.
    """
    try:
        res = subprocess.run(
            ["findmnt", "-n", "-o", "SOURCE", "/"], capture_output=True, text=True, check=True
        )
        src = res.stdout.strip()
        if src:
            return os.path.realpath(src)
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    try:
        with open("/proc/mounts", encoding="utf-8") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and _unescape_mount_field(parts[1]) == "/":
                    src = _unescape_mount_field(parts[0])
                    if src.startswith("/"):
                        return os.path.realpath(src)
    except Exception:
        pass

    if sys.platform == "darwin":
        try:
            res = subprocess.run(["stat", "-f", "%Sd", "/"], capture_output=True, text=True, check=False)
            if res.returncode == 0 and res.stdout.strip():
                dev_name = res.stdout.strip()
                return f"/dev/{dev_name}"
        except Exception:
            pass
        try:
            res = subprocess.run(["mount"], capture_output=True, text=True, check=False)
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 3 and parts[1] == "on" and parts[2] == "/":
                        return parts[0]
        except Exception:
            pass

    return None


def _get_underlying_devices(dev_path: str) -> set[str]:
    """Recursively find all underlying physical/slave devices for a block device (e.g. LUKS/dm-crypt/LVM)."""
    found: set[str] = set()
    to_visit = [os.path.realpath(dev_path)]
    visited: set[str] = set()

    while to_visit:
        curr = to_visit.pop()
        if curr in visited:
            continue
        visited.add(curr)
        found.add(curr)

        bname = os.path.basename(curr)
        slaves_dir = f"/sys/class/block/{bname}/slaves"
        if os.path.isdir(slaves_dir):
            try:
                for slave in os.listdir(slaves_dir):
                    slave_path = os.path.realpath(f"/dev/{slave}")
                    if slave_path not in visited:
                        to_visit.append(slave_path)
            except OSError:
                pass

        try:
            res = subprocess.run(
                ["lsblk", "-s", "-n", "-o", "KNAME", curr], capture_output=True, text=True, check=False
            )
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    kname = line.strip()
                    if kname:
                        kpath = os.path.realpath(f"/dev/{kname}")
                        if kpath not in visited:
                            to_visit.append(kpath)
        except Exception:
            pass

    return found


def is_os_device(device_path: str) -> bool:
    """Return True if device_path hosts the running root/OS filesystem or is a parent/child of it."""
    if not device_path:
        return False
    if sys.platform == "win32" and not device_path.startswith("/dev/"):
        sys_drive = os.environ.get("SystemDrive", "C:").upper()
        norm = device_path.replace("\\", "/").rstrip("/")
        if norm.upper().startswith(sys_drive) or norm.upper() == sys_drive:
            return True
        return False
    root_src = _get_root_mount_source()
    if not root_src:
        return False
    try:
        dev_real = os.path.realpath(device_path)
        underlying_devs = _get_underlying_devices(root_src)
        for u_dev in underlying_devs:
            if dev_real == u_dev:
                return True
            if _is_dev_or_subpartition(dev_real, u_dev):
                return True
            if _is_dev_or_subpartition(u_dev, dev_real):
                return True
        if sys.platform == "darwin":
            d_clean = dev_real.replace("/dev/rdisk", "/dev/disk")
            r_clean = root_src.replace("/dev/rdisk", "/dev/disk")
            if d_clean == r_clean or _is_dev_or_subpartition(d_clean, r_clean):
                return True
            m_d = re.match(r"^/dev/disk\d+", d_clean)
            m_r = re.match(r"^/dev/disk\d+", r_clean)
            if m_d and m_r and m_d.group(0) == m_r.group(0):
                return True
        return False
    except Exception:
        return False
