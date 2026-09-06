"""Cross-platform opportunistic drive temperature reader for S0.

Probes non-destructive telemetry across Linux, Windows, and macOS:
 - Linux:   sysfs hwmon, nvme-cli smart-log, smartctl
 - Windows: PowerShell Get-PhysicalDisk / WMI MSStorageDriver, smartctl
 - macOS:   smartctl

Returns temperature in °C as integer, or None if unsupported or unavailable.
Never raises an exception.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional


def read_temperature(device_path: str) -> Optional[int]:
    """Best-effort temperature read in Celsius. Returns None if unsupported."""
    if not device_path:
        return None

    try:
        if sys.platform.startswith("linux"):
            return _read_linux_temp(device_path)
        elif sys.platform == "win32":
            return _read_windows_temp(device_path)
        elif sys.platform == "darwin":
            return _read_macos_temp(device_path)
        else:
            return _try_smartctl(device_path)
    except Exception:
        return None


def _read_linux_temp(device_path: str) -> Optional[int]:
    p = Path(device_path)
    dev_name = p.name

    # 1. Sysfs hwmon
    t = _try_linux_hwmon(dev_name)
    if t is not None:
        return t

    # 2. NVMe CLI
    if "nvme" in dev_name:
        t = _try_nvme_smart(device_path)
        if t is not None:
            return t

    # 3. smartctl
    return _try_smartctl(device_path)


def _try_linux_hwmon(dev_name: str) -> Optional[int]:
    base = Path(f"/sys/class/block/{dev_name}/device")
    if not base.exists():
        parent = re.sub(r"\d+$", "", dev_name)
        if parent != dev_name:
            base = Path(f"/sys/class/block/{parent}/device")
        if not base.exists():
            return None

    hwmon_dirs = sorted(base.glob("hwmon/hwmon*")) + sorted(base.glob("hwmon*"))
    for hw in hwmon_dirs:
        for tf in sorted(hw.glob("temp*_input")):
            try:
                milli = int(tf.read_text().strip())
                deg = milli // 1000
                if 0 < deg < 125:
                    return deg
            except Exception:
                continue
    return None


def _try_nvme_smart(device_path: str) -> Optional[int]:
    if not shutil.which("nvme"):
        return None
    try:
        proc = subprocess.run(
            ["nvme", "smart-log", device_path, "-o", "normal"],
            capture_output=True,
            text=True,
            timeout=2,
        )
        if proc.returncode == 0:
            for line in proc.stdout.splitlines():
                if "temperature" in line.lower() and "warning" not in line.lower():
                    m = re.search(r"(\d+)\s*°?C", line, re.IGNORECASE)
                    if m:
                        deg = int(m.group(1))
                        if 0 < deg < 125:
                            return deg
    except Exception:
        pass
    return None


def _read_windows_temp(device_path: str) -> Optional[int]:
    # 1. Try smartctl on Windows
    t = _try_smartctl(device_path)
    if t is not None:
        return t

    # 2. Try PowerShell Storage Cmdlet
    if shutil.which("powershell"):
        try:
            ps_cmd = (
                "Get-PhysicalDisk | Select-Object -ExpandProperty OperationalStatus -ErrorAction SilentlyContinue; "
                "Get-StorageReliabilityCounter -PhysicalDisk (Get-PhysicalDisk | Select-Object -First 1) "
                "| Select-Object -ExpandProperty Temperature -ErrorAction SilentlyContinue"
            )
            proc = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=3,
            )
            for line in proc.stdout.splitlines():
                line = line.strip()
                if line.isdigit():
                    val = int(line)
                    if 0 < val < 125:
                        return val
        except Exception:
            pass
    return None


def _read_macos_temp(device_path: str) -> Optional[int]:
    return _try_smartctl(device_path)


def _try_smartctl(device_path: str) -> Optional[int]:
    if not shutil.which("smartctl"):
        return None
    try:
        proc = subprocess.run(
            ["smartctl", "-A", device_path],
            capture_output=True,
            text=True,
            timeout=3,
        )
        if proc.returncode in (0, 4):
            for line in proc.stdout.splitlines():
                if re.search(r"^\s*(194|190)\s+", line):
                    parts = line.split()
                    if len(parts) >= 10:
                        try:
                            raw = int(parts[9])
                            if 0 < raw < 125:
                                return raw
                        except ValueError:
                            pass
    except Exception:
        pass
    return None
