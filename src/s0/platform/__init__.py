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

import os
import sys
import tempfile
from pathlib import Path

__all__ = [
    "current",
    "is_block_device",
    "is_windows_volume_path",
    "looks_like_windows_volume_letter",
    "darwin_raw_device_path",
    "safe_home",
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
    s_path = str(path).strip()
    if not s_path or "\x00" in s_path:
        return False
    if sys.platform == "win32":
        if is_windows_volume_path(s_path):
            return True
        if s_path.startswith(("\\\\.\\", "\\\\?\\")):
            try:
                return path.is_block_device()
            except OSError:
                return False
        return False

    norm = os.path.normpath(s_path)
    if ".." in norm.split(os.sep) or not norm.startswith("/dev/"):
        return False

    try:
        dev_p = Path(norm)
        if dev_p.is_block_device():
            return True
        if sys.platform == "darwin" and dev_p.is_char_device():
            return True
    except OSError:
        # Permission and I/O errors mean "not something we can open", not
        # "definitely not a device". Callers surface their own error.
        return False
    return False


def darwin_raw_device_path(value: str) -> str | None:
    """Map a macOS ``/dev/rdiskN`` path to its buffered ``/dev/diskN`` form.

    The raw device bypasses the disk-arbiter cache, which is what imaging wants
    for speed but what ``is_block_device`` and ``get_block_device_size`` do not
    recognise. Returns ``None`` when the path is not a raw device.
    """
    v = value.strip()
    if not v.startswith("/dev/rdisk"):
        return None
    return "/dev/disk" + v[len("/dev/rdisk") :]


def safe_home() -> Path:
    """Return the user's home directory safely, falling back if not configured."""
    try:
        return Path.home()
    except (RuntimeError, OSError):
        raw = os.environ.get("USERPROFILE") or os.environ.get("HOME") or tempfile.gettempdir()
        return Path(raw)


# --------------------------------------------------------------------------- #
# Platform wipe engines
# --------------------------------------------------------------------------- #
# ``s0.platform.windows`` and ``s0.platform.macos`` hold the native drive-wipe
# engines. They used to be top-level ``windows`` and ``macos`` packages at the
# repository root, imported as ``windows.cli.s0_eraser``. The wheel only ever
# contained ``s0*``, so for anyone who installed s0 rather than running it from a
# checkout, both engines were simply absent -- the imports are lazy, so the
# failure did not surface as an ImportError but as drive wipes reporting a zero or
# unreadable capacity. Shipping a top-level package named ``windows`` or ``macos``
# in site-packages would also collide with any other distribution using those
# names.
#
# They live under this package so ``pip install s0`` carries them, and the import
# is ``s0.platform.windows.s0_eraser``.
