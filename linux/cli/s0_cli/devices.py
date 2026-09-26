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
from dataclasses import dataclass
from pathlib import Path

from .methods.base import Target

logger = logging.getLogger("s0.devices")


class SafetyError(RuntimeError):
    """Refusal to proceed — target looks system-critical or is mounted."""


def _lsblk() -> list[dict]:
    if not shutil.which("lsblk"):
        return []
    try:
        out = subprocess.run(
            ["lsblk", "-J", "-b", "-o",
             "NAME,PATH,TYPE,SIZE,SERIAL,MODEL,RM,ROTA,MOUNTPOINTS"],
            capture_output=True, text=True, check=False,
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


def _mounted_paths() -> set[str]:
    mounts = set()
    try:
        with open("/proc/mounts") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    mounts.add(parts[0])
                    try:
                        mounts.add(os.path.realpath(parts[0]))
                    except OSError:
                        pass
    except OSError:
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
    p = Path(device_path)
    dev_name = p.name

    # 1. Try ioctl BLKGETSIZE64
    try:
        import fcntl
        import struct
        BLKGETSIZE64 = 0x80081272
        with open(p, "rb") as f:
            buf = fcntl.ioctl(f.fileno(), BLKGETSIZE64, struct.pack("Q", 0))
            sz = struct.unpack("Q", buf)[0]
            if sz > 0:
                return sz
    except Exception:
        pass

    # 2. Try sysfs /sys/class/block/<dev>/size (sectors * 512)
    try:
        sys_size = Path("/sys/class/block") / dev_name / "size"
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
                ["blockdev", "--getsize64", str(p)],
                capture_output=True, text=True, check=True
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
                ["lsblk", "-b", "-d", "-n", "-o", "SIZE", str(p)],
                capture_output=True, text=True, check=True
            )
            sz = int(res.stdout.strip())
            if sz > 0:
                return sz
        except Exception:
            pass

    logger.warning("Could not determine size of block device %s — all detection methods failed; falling back to 0 bytes", p)
    return 0


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
                    from windows.cli.s0_eraser import get_windows_target_size
                    sz = get_windows_target_size(drive_path)
                except Exception as exc:
                    logger.warning("Could not determine size of Windows volume %s: %s; falling back to 0 bytes", drive_path, exc)
                targets.append(Target(
                    path=drive_path,
                    kind="block",
                    capacity_bytes=sz,
                    storage_type="UNKNOWN",
                    model=f"Windows Volume {drive_path}",
                ))
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
                        from macos.cli.s0_eraser import get_macos_target_size
                        sz = get_macos_target_size(dev)
                    except Exception as exc:
                        logger.warning("Could not determine size of macOS disk %s: %s; falling back to 0 bytes", dev, exc)
                    targets.append(Target(
                        path=rdev,
                        kind="block",
                        capacity_bytes=sz,
                        storage_type="UNKNOWN",
                        model="macOS Disk",
                    ))
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

        targets.append(Target(
            path=target_path,
            kind="block",
            capacity_bytes=size,
            sector_size=_sys_int(name, "queue/logical_block_size") or 512,
            storage_type=_storage_type(name, rotational),
            model=(dev.get("model") or "").strip() or None,
            serial=(dev.get("serial") or "").strip() or None,
            removable=bool(_sys_int(name, "removable")),
        ))
    return targets


def image_target(path: str) -> Target:
    """Wrap a regular file as a wipe target (the root-free test medium)."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"not a regular file: {path}")
    return Target(
        path=str(p.resolve()),
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


def _is_dev_or_subpartition(parent_path: str, candidate_mount: str) -> bool:
    """Check if candidate_mount is parent_path or a sub-partition of parent_path."""
    parent_real = os.path.realpath(parent_path)
    cand_real = os.path.realpath(candidate_mount)
    if parent_real == cand_real:
        return True

    # If parent_real is already a partition (ends in digit), only exact match applies
    # (e.g. /dev/sda1 must not match /dev/sda10)
    p_name = Path(parent_real).name
    if re.search(r"\d+$", p_name) and not (p_name.startswith("loop") and not re.search(r"p\d+$", p_name)):
        return False

    # Parent is a whole drive (e.g. /dev/sda, /dev/nvme0n1, /dev/loop0)
    parent_esc = re.escape(parent_real)
    pattern = rf"^{parent_esc}(?:p)?[0-9]+$"
    return bool(re.match(pattern, cand_real))


def check_safety(target: Target, force: bool = False) -> list[str]:
    """Refuse system-critical targets unless --force. Returns warnings."""
    warnings: list[str] = []
    if target.kind == "image":
        return warnings

    mounted = _mounted_paths()
    hits = sorted(m for m in mounted if _is_dev_or_subpartition(target.path, m))
    if hits:
        if not force:
            raise SafetyError(
                f"{target.path} has mounted filesystems ({', '.join(hits)}). "
                f"Unmount them first, or pass --force if you truly mean it."
            )
        warnings.append(f"proceeding WITH MOUNTED FILESYSTEMS: {', '.join(hits)}")

    root_src = _get_root_mount_source()
    if root_src:
        target_real = os.path.realpath(target.path)
        if target_real == root_src or root_src.startswith(target_real):
            if not force:
                raise SafetyError(
                    f"{target.path} hosts the running ROOT filesystem. The tool refuses "
                    f"this without --force; if you mean it, boot the s0 ISO instead."
                )
            warnings.append("proceeding AGAINST THE RUNNING ROOT FILESYSTEM — this "
                            "will destroy the running system")
    else:
        if not force:
            raise SafetyError(
                f"Cannot verify whether {target.path} hosts the running ROOT filesystem "
                f"(findmnt unavailable and /proc/mounts could not be verified). "
                f"Refusing to proceed without --force."
            )
        warnings.append("WARNING: could not verify whether target hosts the root filesystem")

    return warnings


def _get_root_mount_source() -> Optional[str]:
    """Resolve the real backing device path for the running root filesystem (/),
    attempting findmnt first with direct /proc/mounts parsing as fallback.
    """
    try:
        res = subprocess.run(
            ["findmnt", "-n", "-o", "SOURCE", "/"],
            capture_output=True, text=True, check=True
        )
        src = res.stdout.strip()
        if src:
            return os.path.realpath(src)
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    try:
        with open("/proc/mounts", "r", encoding="utf-8") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[1] == "/":
                    src = parts[0]
                    if src.startswith("/"):
                        return os.path.realpath(src)
    except Exception:
        pass

    return None

