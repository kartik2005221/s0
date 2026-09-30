"""Platform primitives that are genuinely shared, and were genuinely duplicated.

Scope note. This module deliberately does **not** wrap the ~60 ``sys.platform ==
"darwin"`` conditionals scattered through :mod:`s0.cli.main`,
:mod:`s0.cli.file_eraser`, :mod:`s0.image.imager` and :mod:`s0.live.live_manager`
behind a per-OS interface. Those branches are small, local, and each one is the
simplest correct thing at its site; behind an abstraction they would gain a
lookup and lose their context. That was the original Phase 7 proposal and it is
the wrong call, so this module holds only the rules that were copy-pasted
between modules and had already started to drift:

* :func:`is_block_device` appeared seven times. On Linux it is a block special
  file; on macOS block devices are *character* devices (``/dev/disk2``), so the
  check has to be platform-dependent or macOS targets are invisible.
* :func:`is_windows_volume_path` appeared three times with subtly different
  spellings, one of which accepted ``//./`` and two of which did not.
* :func:`platform_name` was written inline in two places, and one of them
  reported *any* non-Linux non-Windows platform as ``macos`` -- correct for
  FreeBSD only by accident.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

__all__ = [
    "current",
    "is_block_device",
    "is_windows_volume_path",
    "looks_like_windows_volume_letter",
    "darwin_raw_device_path",
]

#: Prefixes Windows uses for raw volume and physical-disk paths.
_WINDOWS_RAW_PREFIXES = ("\\\\.\\", "//./")


def current() -> str:
    """Return ``linux``, ``windows``, ``macos``, or the raw ``sys.platform``.

    Use this for display and for certificate metadata. It never guesses: an
    unrecognised platform is reported as-is rather than being folded into
    another platform's bucket.
    """
    p = sys.platform
    if p.startswith("linux"):
        return "linux"
    if p == "win32":
        return "windows"
    if p == "darwin":
        return "macos"
    return p


def is_windows_volume_path(value: str) -> bool:
    """True if ``value`` names a Windows raw volume or physical disk.

    Covers ``\\\\.\\PhysicalDrive0``, ``//./PHYSICALDRIVE0`` and the
    case-insensitive ``physicaldrive`` spelling.
    """
    low = value.strip().lower()
    if low.startswith(_WINDOWS_RAW_PREFIXES):
        return True
    return "physicaldrive" in low


def looks_like_windows_volume_letter(value: str) -> bool:
    """True for a bare drive letter such as ``E:`` or ``E:\\\\``.

    Used to reject a drive letter early: a single-letter path is never a real
    imaging target on POSIX, and on Windows it means "the whole volume", which
    the operator must confirm by name.
    """
    v = value.strip()
    return ":" in v and len(v) <= 3


def is_block_device(path: Path) -> bool:
    """True if ``path`` refers to a whole block device on any supported platform.

    Linux and Windows expose block devices as block special files. macOS does
    not: ``/dev/disk2`` is a character device, so a plain ``is_block_device()``
    check finds nothing on a Mac and the operator is told no targets exist.
    Windows additionally needs the raw-path spellings, which do not exist on
    disk at all.
    """
    try:
        if path.is_block_device():
            return True
        if sys.platform == "darwin" and path.is_char_device():
            return True
    except OSError:
        # Permission and I/O errors mean "not something we can open", not
        # "definitely not a device". Callers surface their own error.
        return False
    if sys.platform == "win32" and is_windows_volume_path(str(path)):
        return True
    return False


def darwin_raw_device_path(value: str) -> Optional[str]:
    """Map a macOS ``/dev/rdiskN`` path to its buffered ``/dev/diskN`` form.

    The raw device bypasses the disk-arbiter cache, which is what imaging wants
    for speed but what ``is_block_device`` and ``get_block_device_size`` do not
    recognise. Returns ``None`` when the path is not a raw device.
    """
    v = value.strip()
    if not v.startswith("/dev/rdisk"):
        return None
    return "/dev/disk" + v[len("/dev/rdisk"):]
