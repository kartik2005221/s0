"""Test isolation. Read at collection time, before any s0 module is imported.

## Why this file exists at all

Running the test suite created `~/.s0/` on the developer's machine, containing
audit blocks signed by `op-forensic`, `op-e2e-test` and `op-cert-test`, plus
keypairs and a web auth token. `s0 audit verify` then failed with

    UNVERIFIABLE - SIGNING KEY NOT IN THE TRUST SET

On an examiner's workstation this is not untidy, it is damaging: the tool's
chain-of-custody ledger is the record of every operation already performed, and a
test run appends blocks to it signed by keys that are not in any trust set. The
ledger then no longer verifies, and there is no supported way to tell those blocks
apart from real evidence.

## Why it is module level and not a fixture

`s0.audit.db` evaluates `DEFAULT_AUDIT_DB = get_default_audit_db()` at *import*
time, and `s0.config` resolves `~/.s0/s0_config.json` the same way. A fixture
runs after collection, by which point those modules are already imported and the
real paths are baked in. Setting `HOME` here, at conftest import, happens before
pytest imports any test module, so the constants come out pointing at the
temporary tree.

`homedir` is redirected too, because `pathlib.Path.home()` consults it on POSIX
and a process that has already cached the real home would otherwise keep writing
there.
"""

from __future__ import annotations

import atexit
import os
import shutil
import tempfile
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
_src = str(_REPO_ROOT / "src")
if _src not in os.environ.get("PYTHONPATH", ""):
    os.environ["PYTHONPATH"] = f"{_src}:{os.environ.get('PYTHONPATH', '')}".rstrip(":")

# A per-run temporary home. `prefix` keeps it out of $TMPDIR's immediate listing
# noise and makes it obvious in a `ls /tmp` what the directory is.
_SANDBOX_HOME = tempfile.mkdtemp(prefix="s0-test-home-")

os.environ["HOME"] = _SANDBOX_HOME
os.environ["USERPROFILE"] = _SANDBOX_HOME  # Windows
os.environ["homedir"] = _SANDBOX_HOME  # consulted by Path.home() on some builds
_drive, _rest = os.path.splitdrive(_SANDBOX_HOME)
os.environ["HOMEDRIVE"] = _drive or "C:"
os.environ["HOMEPATH"] = _rest or _SANDBOX_HOME

# Point the audit ledger at the sandbox explicitly as well, so isolation holds even
# if a future refactor reintroduces a direct path that does not consult HOME.
#
# S0_CONFIG_PATH is deliberately NOT set. Pointing it at a missing file makes every
# command emit a "no such config" warning (which is correct behaviour, and was
# briefly introduced here), and HOME redirection already excludes a developer's own
# ~/.s0/s0_config.json -- which is the only thing that variable would be used to
# defeat.
os.environ["S0_AUDIT_DB"] = os.path.join(_SANDBOX_HOME, ".s0", "s0_audit.db")

atexit.register(shutil.rmtree, _SANDBOX_HOME, True)


def pytest_report_header(config) -> list[str]:
    """Make the sandbox visible in the run header.

    A test suite that silently redirects HOME is the kind of thing that looks like
    a bug the next time somebody reads the output, so it is stated outright.
    """
    return [f"s0: HOME redirected to {_SANDBOX_HOME} for the duration of the run"]


def test_home_is_redirected_for_the_whole_run() -> None:
    """The isolation is load-bearing, so assert it rather than trust it.

    If a future refactor reintroduces a direct `Path.home()` write, this is the
    test that notices -- and it is a test in the suite rather than a comment,
    because the whole point of the finding was that a comment would not have
    helped.
    """
    from pathlib import Path

    real = Path(os.environ["HOME"])
    assert str(real).startswith(tempfile.gettempdir()), (
        f"HOME is {real}, not inside the temporary directory; the test suite is "
        "writing to the developer's real home directory"
    )
    assert real.name.startswith("s0-test-home-")

    # The ledger s0 itself resolved must also be inside the sandbox.
    from s0.audit.db import get_default_audit_db
    from s0.config import CONFIG  # noqa: F401  (import proves load order)

    db = get_default_audit_db()
    assert str(db).startswith(str(real)), f"audit ledger resolves to {db}, outside the sandbox"


# --------------------------------------------------------------------------- #
# No real block devices, ever.
# --------------------------------------------------------------------------- #
#
# The suite once tested the live-flash unmount gate by picking whatever block devices the
# machine had mounted and running a real `umount -f` against them. Unprivileged that failed
# with EPERM, which is what made the assertion pass -- so the test was safe *because of the
# permissions it happened to run with*. Hand the same job to a root CI container, or to a
# developer who runs the suite with sudo because something else needed it, and it becomes a
# test that unmounts or overwrites the build machine's disks.
#
# "Be careful" is not a control, and neither is a comment. This is: an autouse fixture that
# makes the two ways a test can reach real hardware -- running a device-destructive
# command, or opening a device node for writing -- raise instead. A test that needs to
# exercise that code path asserts on the *refusal*, the way
# tests/cli/test_live_flash_and_keygen_safety.py does with a patched `subprocess.run`.

import re as _re

# Programs that alter or destroy a block device, matched on argv[0]'s basename.
#
# `format` is deliberately absent: it is a Windows program and this guard does not run
# there, while `format` is an extremely common word in an s0 command line
# (`--format json`) and including it blocked 284 tests.
_DEVICE_COMMANDS = frozenset(
    {
        "blkdiscard",
        "cfdisk",
        "dd",
        "diskpart",
        "diskutil",
        "fdisk",
        "hdparm",
        "mkfs",
        "mke2fs",
        "newfs",
        "nvme",
        "parted",
        "sgdisk",
        "sfdisk",
        "umount",
        "wipefs",
    }
)

# Whether the program is destructive matters less than what it is pointed at, so the
# rule below is target-based. That means no per-command read/write tables are needed:
# `hdparm -I /dev/sda` is harmless in itself and still blocked, because the suite has no
# business contacting the build machine's disks -- in CI there is no such device, and
# locally it is the same class of accident this guard exists to prevent. A read-only probe
# that names no disk (`hdparm --version`, `blkdiscard --help`) is allowed, because that is
# how s0 discovers which tools exist.

# mkfs.ext4, mkfs.vfat, mkdosfs, ...
_MKFS_LIKE = _re.compile(r"^(mkfs|mke2fs|newfs|mkdosfs)(\.[a-z0-9]+)?$")

# A whole disk or partition. Not /dev/null, /dev/urandom, /dev/shm/*.
# Written out per family rather than factored, because the numbering differs: `sda`,
# `sda1`, `sda12`; `nvme0n1`, `nvme0n1p2`; `mmcblk0`, `mmcblk0p1`. A shared suffix group
# cannot express both `\d+` and `p\d+`, and an earlier attempt at one missed `/dev/sda1`
# entirely -- which is the case that matters.
_DEVICE_NODE = _re.compile(
    r"^("
    r"/dev/(?:"
    r"(?:sd|hd|vd|xvd)[a-z]+\d*"  # sda, sda1, sda12, hdb, xvdf2
    r"|nvme\d+(?:n\d+(?:p\d+)?)?"  # nvme0 (controller), nvme0n1 (namespace), nvme0n1p2 (partition)
    r"|mmcblk\d+(?:p\d+)?"  # mmcblk0, mmcblk0p1
    r"|loop\d+(?:p\d+)?"  # loop0, loop0p1
    r"|dm-\d+"  # dm-0
    r"|md\d+"  # md0
    r"|mapper/[A-Za-z0-9_.-]+"  # /dev/mapper/vg0-lv1
    r"|r?disk\d+(?:s\d+)*"  # macOS: disk0, rdisk2, disk2s1
    r")"
    r"|(?i:\\\\\.\\PhysicalDrive\d+)"  # Windows: \\.\PhysicalDrive0
    r")$"
)

_SB = "/sys/block"


def _argv_text(argv) -> str:
    if isinstance(argv, (list, tuple)):
        return " ".join(str(a) for a in argv)
    return str(argv)


def _is_device_command(argv) -> bool:
    """True if *argv* would alter or destroy a block device.

    Three shapes are checked, because there are three ways to hide the program:

    * it is argv[0] -- `["umount", "/dev/sda1"]`, `["/usr/bin/mkfs.ext4", ...]`. Only
      argv[0], not every element: an earlier version scanned the whole argv and blocked
      `["s0", "image", "--out-dir", "dd"]`, because a directory the caller named `dd` is
      not the `dd` utility. The question is which program is being executed, and that is
      argv[0];
    * it is a word inside a shell string -- `["sh", "-c", "wipefs -a /dev/sdd"]`;
    * it is `dd`, which is destructive through its arguments rather than its name.

    And one argument pattern, because `dd` is destructive through `of=`:

    * `of=/dev/sda`, whether standalone or inside a shell string.

    Never a bare mention of a device node. An earlier version matched `/dev/sd[a-z]`
    anywhere, which blocked `ls /dev/sda` -- a read. A guard that blocks reads gets
    disabled, and a disabled guard protects nothing.
    """
    elements = [str(a) for a in argv] if isinstance(argv, (list, tuple)) else []

    def names_a_disk() -> bool:
        return any(_DEVICE_NODE.match(a) for a in elements)

    if elements:
        program = os.path.basename(elements[0])
        is_device_tool = _MKFS_LIKE.match(program) or program in _DEVICE_COMMANDS
        if is_device_tool:
            # The tool name alone is not the hazard. `mke2fs` on a regular file under
            # /tmp is how the ext4 tests build a fixture filesystem, and `hdparm
            # --sanitize-status /dev/sdX` is how the capability tests check a code path
            # against a placeholder that does not exist. Blocking on the program name
            # alone broke five legitimate tests.
            #
            # What matters is whether the *target* is a disk. So: block when a realistic
            # device path is named, allow when the target is a regular file or a
            # placeholder like /dev/sdX that the pattern does not match. A `dd` writing
            # to a device is handled separately, since its target is an argument, not an
            # element.
            if names_a_disk():
                return True

    text = _argv_text(argv)
    if _re.search(r"\bof=/dev/", text):
        return True

    # Shell indirection: only then look for a device command as a bare word, because that
    # is the only way the real program is a word rather than an argv element. Without this
    # restriction any command line containing e.g. "dd" in a path would be blocked.
    if not _re.search(r"(^|\s)(/bin/|/usr/bin/)?(sh|bash|dash|zsh|ksh)\s+-c", text):
        return False
    words = set(_re.findall(r"[A-Za-z0-9_.-]+", text))
    is_device_tool = any(_MKFS_LIKE.match(w) for w in words) or bool(words & _DEVICE_COMMANDS)
    if not is_device_tool:
        return False
    return any(_DEVICE_NODE.match(a) for a in elements) or bool(
        _re.findall(
            r"/dev/(?:sd[a-z]+|hd[a-z]+|vd[a-z]+|xvd[a-z]+)\d*|"
            r"/dev/(?:nvme\d+(?:n\d+(?:p\d+)?)?|mmcblk\d+(?:p\d+)?|loop\d+(?:p\d+)?)|"
            r"/dev/(?:dm-\d+|md\d+|mapper/[A-Za-z0-9_.-]+|r?disk\d+(?:s\d+)*)|"
            r"(?i:\\\\\.\\PhysicalDrive\d+)",
            text,
        )
    )


def _is_device_node_write(path, mode) -> bool:
    """True if opening *path* in *mode* would write to a whole disk or partition.

    Pure, so the guard's own behaviour can be asserted without standing up a fixture.
    `/dev/null`, `/dev/urandom` and `/dev/shm/*` are character devices or tmpfs, not
    disks, and are not matched.
    """
    if not isinstance(path, (str, bytes, os.PathLike)):
        return False
    if not _DEVICE_NODE.match(os.fsdecode(path)):
        return False
    return bool(mode) and any(flag in mode for flag in ("w", "a", "x", "+"))


def _refuse(request, what: str, detail: str) -> None:
    raise AssertionError(
        f"{request.node.nodeid} tried to {what}: {detail}. "
        "The test suite must not touch real devices -- use a regular file, or a loopback "
        "device the test created itself."
    )


@pytest.fixture(autouse=True)
def _no_real_block_devices(monkeypatch, request):
    """Fail any test that tries to reach real block-device hardware.

    Opt out with `@pytest.mark.real_device` on a test that genuinely needs it, so the
    exception is deliberate and greppable rather than something an edit removes by
    accident.
    """
    if request.node.get_closest_marker("real_device") or os.name == "nt":
        return

    import subprocess as _subprocess

    def check(argv):
        if _is_device_command(argv):
            _refuse(request, "run a device-destructive command", _argv_text(argv)[:200])

    real_popen = _subprocess.Popen
    # Captured before patching. `run` and friends call the module-global `Popen`, so they
    # are wrapped around the originals, not around each other.
    real_run, real_check_call, real_check_output = (
        _subprocess.run,
        _subprocess.check_call,
        _subprocess.check_output,
    )

    class GuardedPopen(real_popen):  # type: ignore[misc, valid-type]
        """A real Popen, so the context-manager and iterator protocols still work.

        A delegating proxy was the first attempt and broke `with subprocess.Popen(...)`,
        which 284 tests use. Subclassing keeps every behaviour and only adds the check.
        """

        def __init__(self, argv, *a, **kw):
            check(argv)
            super().__init__(argv, *a, **kw)

    monkeypatch.setattr(_subprocess, "Popen", GuardedPopen)

    def guard_run(fn):
        def wrapper(argv, *a, **kw):
            check(argv)
            return fn(argv, *a, **kw)

        return wrapper

    monkeypatch.setattr(_subprocess, "run", guard_run(real_run))
    monkeypatch.setattr(_subprocess, "check_call", guard_run(real_check_call))
    monkeypatch.setattr(_subprocess, "check_output", guard_run(real_check_output))

    import builtins as _builtins

    real_open = _builtins.open

    def guarded_open(file, mode="r", *a, **kw):
        if _is_device_node_write(file, mode):
            _refuse(request, "open a block device for writing", os.fsdecode(file))
        return real_open(file, mode, *a, **kw)

    monkeypatch.setattr(_builtins, "open", guarded_open)

    if os.path.isdir(_SB):
        real_os_open = os.open

        def guarded_os_open(path, flags, *a, **kw):
            if flags & (os.O_WRONLY | os.O_RDWR) and os.fsdecode(path).startswith(_SB):
                _refuse(request, "write to a sysfs block device", os.fsdecode(path))
            return real_os_open(path, flags, *a, **kw)

        monkeypatch.setattr(os, "open", guarded_os_open)


def test_the_guard_itself_works() -> None:
    """Assert the guard, or it is decoration.

    The failure mode of an untested safety net is one that quietly stopped working: a
    refactor renamed the helper, the fixture stopped patching anything, and every test
    still passed while the guarantee was gone.
    """
    for argv, why in (
        (["umount", "/dev/sda1"], "umount by name"),
        (["mkfs.ext4", "/dev/sdb"], "mkfs with a .type suffix"),
        (["mke2fs", "/dev/sdb"], "mke2fs alias"),
        (["dd", "if=/dev/zero", "of=/dev/sdc"], "dd writing to a device node"),
        (["sh", "-c", "wipefs -a /dev/sdd"], "hidden behind sh -c"),
        (["/usr/bin/umount", "/dev/sde1"], "an absolute path to the binary"),
        (["bash", "-c", "mkfs.vfat /dev/sdf"], "hidden behind bash -c"),
        (["nvme", "format", "/dev/nvme0n1"], "an nvme write subcommand"),
        (["nvme", "sanitize", "/dev/nvme0"], "nvme sanitize controller node"),
        (["diskutil", "unmountDisk", "/dev/disk2"], "macOS diskutil on disk node"),
        (["diskpart", "/s", r"\\.\PhysicalDrive0"], "Windows diskpart on physical drive"),
        (["hdparm", "-I", "/dev/sda"], "a read-only command pointed at a real disk"),
        (
            ["hdparm", "--user-master", "u", "--security-set-pass", "x", "/dev/sdb"],
            "hdparm setting a password",
        ),
    ):
        assert _is_device_command(argv), f"the guard missed {why}: {argv}"

    # Must NOT be blocked. Each of these is something the suite legitimately does, and the
    # first version of this guard blocked all of them.
    for argv, why in (
        (["pytest", "-q"], "the test runner"),
        (["git", "status"], "git"),
        (["/bin/sh", "-c", "echo /dev/null"], "a shell mentioning /dev/null"),
        (["ls", "/dev/sda"], "reading a device node's existence"),
        (["s0", "wipe", "--format", "json", "--targets", "a.txt"], "s0's own --format flag"),
        (["s0", "image", "--target", "disk.img", "--out-dir", "dd"], "a path containing dd"),
        # Tool discovery: s0 runs these to find out which capabilities exist, and they
        # name no disk. Blocking them would break the suite for no safety gain.
        (["hdparm", "--version"], "hdparm --version"),
        (["blkdiscard", "--help"], "blkdiscard --help"),
        (["mke2fs", "-q", "-t", "ext4", "/tmp/fs.img"], "mkfs on a regular file"),
        (["hdparm", "--sanitize-status", "/dev/sdX"], "a placeholder device that does not exist"),
    ):
        assert not _is_device_command(argv), f"the guard would block {why}: {argv}"

    for path, why in (
        ("/dev/sda", "a whole disk"),
        ("/dev/sda1", "a partition"),
        ("/dev/nvme0", "an NVMe controller"),
        ("/dev/nvme0n1", "an NVMe namespace"),
        ("/dev/nvme0n1p2", "an NVMe partition"),
        ("/dev/disk0", "a macOS disk node"),
        ("/dev/rdisk2", "a macOS raw disk node"),
        ("/dev/disk2s1", "a macOS partition"),
        ("/dev/dm-0", "a device-mapper node"),
        ("/dev/md0", "a software RAID node"),
        ("/dev/mapper/vg0-lv1", "a device-mapper path"),
        (r"\\.\PhysicalDrive0", "a Windows physical drive"),
        ("/dev/loop0", "a loop device"),
    ):
        assert _is_device_node_write(path, "wb"), f"the guard missed {why}"
        assert _is_device_node_write(path, "r+b"), f"the guard missed {why} in append/update mode"

    # These must not be blocked: character devices and tmpfs, not disks.
    for path in ("/dev/null", "/dev/urandom", "/dev/shm/s0-test", "/dev", "/dev/sda.txt"):
        assert not _is_device_node_write(path, "wb"), f"the guard would block {path}"

    # Read modes are never a write, and an int fd has no path to judge.
    assert not _is_device_node_write("/dev/sda", "rb")
    assert not _is_device_node_write(3, "wb")
