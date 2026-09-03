"""Device inventory: lsblk + /sys probing, image-file targets, safety checks."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .methods.base import Target


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


def list_block_targets() -> list[Target]:
    """All top-level disk-class block devices with type detection."""
    targets: list[Target] = []
    for dev in _lsblk():
        if dev.get("type") != "disk":
            continue
        name = dev["name"]
        rotational = _sys_int(name, "queue/rotational")
        size = int(dev.get("size") or 0)
        targets.append(Target(
            path=dev.get("path") or f"/dev/{name}",
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
    # For image files this is honest (the file IS the target); for block
    # devices lacking serial+wwid it is recorded as a fallback in notes.
    return "sha256:" + hashlib.sha256(target.path.encode()).hexdigest()


def check_safety(target: Target, force: bool = False) -> list[str]:
    """Refuse system-critical targets unless --force. Returns warnings.

    This is the tool's most important function after the wipe itself: the
    difference between a demo and an outage.
    """
    warnings: list[str] = []
    if target.kind == "image":
        return warnings

    mounted = _mounted_paths()
    hits = sorted(m for m in mounted if m.startswith(target.path))
    if hits:
        if not force:
            raise SafetyError(
                f"{target.path} has mounted filesystems ({', '.join(hits)}). "
                f"Unmount them first, or pass --force if you truly mean it."
            )
        warnings.append(f"proceeding WITH MOUNTED FILESYSTEMS: {', '.join(hits)}")

    try:
        root_src = os.path.realpath(
            subprocess.run(["findmnt", "-n", "-o", "SOURCE", "/"],
                           capture_output=True, text=True, check=True).stdout.strip()
        )
        target_real = os.path.realpath(target.path)
        if target_real == root_src or root_src.startswith(target_real):
            if not force:
                raise SafetyError(
                    f"{target.path} hosts the running ROOT filesystem. The tool refuses "
                    f"this without --force; if you mean it, boot the TrustWipe ISO instead."
                )
            warnings.append("proceeding AGAINST THE RUNNING ROOT FILESYSTEM — this "
                            "will destroy the running system")
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass  # no findmnt / no root mount — nothing to protect against here
    return warnings
