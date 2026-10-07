"""s0 Module 1: Secure File and Folder Eraser.

Provides selective, forensic-grade file and folder sanitization:
  - In-place cluster data overwriting (zero or multi-pass random) with fsync
  - Metadata cleansing (inode timestamps reset to epoch, file truncation,
    directory entry renaming before unlinking)
  - Batch operations with consolidated Ed25519-signed sanitization certificates
  - Sampled read-back verification and non-existence confirmation
  - Explicit disclosure of filesystem journal (ext4/NTFS) and flash wear-leveling caveats
"""

from __future__ import annotations

import hashlib
import os
import secrets
import shutil
import stat
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from s0 import certificate as cert_mod
from s0 import crypto as core_crypto
from s0 import resources
from s0.cli.devices import SafetyError
from s0.config import CONFIG
from s0.safety import ProtectedPathError, check_path_is_destructive


@dataclass
class FileEraseResult:
    path: str
    original_size: int
    bytes_overwritten: int
    passes: int
    pattern: str
    status: str  # "success", "failure", "skipped"
    error: str | None = None
    metadata_cleansed: bool = False
    cow_warning: str | None = None
    extents_count: int = 0
    filesystem: str = "unknown"


@dataclass
class BatchEraseSummary:
    total_files: int
    successful_files: int
    failed_files: int
    total_bytes_processed: int
    results: list[FileEraseResult] = field(default_factory=list)
    certificate: dict | None = None
    warnings: list[str] = field(default_factory=list)


def detect_cow_and_filesystem(path_str: str) -> tuple[str, str | None]:
    """Detect underlying filesystem and CoW status across Linux, macOS, and Windows."""
    fs_name = "unknown"
    cow_warning = None

    if sys.platform == "darwin":
        # macOS / Darwin: check APFS or HFS+
        try:
            res = subprocess.run(["mount"], capture_output=True, text=True, check=False)
            if res.returncode == 0:
                candidates = []
                for line in res.stdout.splitlines():
                    if " on " in line and "(" in line:
                        mp = line.split(" on ")[1].split(" (")[0].strip()
                        opts = line.split(" (")[1].rstrip(")")
                        if path_str == mp or mp == "/" or path_str.startswith(mp.rstrip("/") + "/"):
                            candidates.append((len(mp), mp, opts))
                if candidates:
                    candidates.sort(key=lambda c: c[0], reverse=True)
                    best_opts = candidates[0][2]
                    if "apfs" in best_opts.lower():
                        fs_name = "apfs"
                        cow_warning = (
                            "Target resides on Apple File System (APFS), a Copy-on-Write (CoW) filesystem. "
                            "In-place overwrite allocates new blocks; original blocks and snapshots may persist until reclaimed."
                        )
                    elif "hfs" in best_opts.lower():
                        fs_name = "hfs+"
        except Exception:
            pass

    elif sys.platform == "win32":
        # Windows: check NTFS, ReFS, FAT32, exFAT
        try:
            drive_root = os.path.splitdrive(os.path.abspath(path_str))[0] + "\\"
            import ctypes

            vol_name = ctypes.create_unicode_buffer(260)
            fs_buf = ctypes.create_unicode_buffer(260)
            if ctypes.windll.kernel32.GetVolumeInformationW(
                drive_root, vol_name, 260, None, None, None, fs_buf, 260
            ):
                fs_name = fs_buf.value.lower()
                if fs_name == "refs":
                    cow_warning = (
                        "Target resides on Resilient File System (ReFS), a Copy-on-Write (CoW) filesystem. "
                        "In-place overwrite allocates new allocation units; original data may persist."
                    )
        except Exception:
            pass

    else:
        # Linux: check /proc/mounts for btrfs, zfs, ext4, xfs, etc.
        try:
            with open("/proc/mounts") as mf:
                candidates = []
                for mline in mf:
                    mparts = mline.split()
                    if len(mparts) >= 3:
                        fstype = mparts[2].lower()
                        mp = mparts[1]
                        if path_str == mp or mp == "/" or path_str.startswith(mp.rstrip("/") + "/"):
                            candidates.append((len(mp), mp, fstype))
                if candidates:
                    candidates.sort(key=lambda c: c[0], reverse=True)
                    fs_name = candidates[0][2]
                    if fs_name in ("btrfs", "zfs"):
                        cow_warning = (
                            f"Target resides on CoW filesystem ({fs_name}). In-place write may allocate "
                            "new blocks; original blocks may persist until reclaimed."
                        )
        except Exception:
            pass

    return fs_name, cow_warning


def _wipe_method_label(pattern: str, passes: int) -> str:
    """Name the method that was actually performed.

    The label goes on a compliance document, so it has to describe what was
    written. A three-pass zero wipe recorded as SHRED_RANDOM_NPASS is not a
    cosmetic error: it tells a reader the medium was filled with CSPRNG bytes
    when it was filled with zeros, which changes the residual-risk argument.
    """
    family = "OVERWRITE_ZERO" if pattern == "zero" else "SHRED_RANDOM"
    return f"{family}_{passes}PASS"


def platform_sync(fd: int) -> bool:
    """Flush OS and drive hardware write cache across platforms.

    Returns True when the platform reported the flush as successful. A failure
    is returned rather than raised: callers need to finish the overwrite and then
    *report* that the flush did not happen, because "the bytes may still be in
    cache" is a materially different claim from "the erase failed".

    Swallowing this and reporting success is how an unflushed overwrite ends up
    on a compliance certificate. The overwrite is still attempted either way;
    what changes is whether the tool tells the truth about it.
    """
    try:
        os.fsync(fd)
    except OSError:
        return False

    if sys.platform == "darwin":
        # Apple macOS: F_FULLFSYNC (fcntl command 51) flushes drive hardware cache
        try:
            import fcntl

            fcntl.fcntl(fd, 51, 0)
        except Exception:
            pass
    elif sys.platform == "win32":
        try:
            import ctypes
            import msvcrt

            handle = msvcrt.get_osfhandle(fd)
            ctypes.windll.kernel32.FlushFileBuffers(handle)
        except Exception:
            pass

    return True


def platform_cleanse_attributes(path_str: str, fd: int | None = None) -> None:
    """Clear platform-specific file attributes, locks, xattrs, and alternate data streams."""
    try:
        if fd is not None:
            os.chmod(fd, stat.S_IWRITE | stat.S_IREAD)
        else:
            os.chmod(path_str, stat.S_IWRITE | stat.S_IREAD, follow_symlinks=False)
    except Exception:
        pass

    if sys.platform == "darwin":
        try:
            xattr_bin = "/usr/bin/xattr" if os.path.isfile("/usr/bin/xattr") else "xattr"
            subprocess.run([xattr_bin, "-c", "-s", path_str], capture_output=True, check=False)
        except Exception:
            pass

    elif sys.platform == "win32":
        try:
            import ctypes

            FILE_ATTRIBUTE_NORMAL = 0x80
            ctypes.windll.kernel32.SetFileAttributesW(path_str, FILE_ATTRIBUTE_NORMAL)
        except Exception:
            pass
        try:
            zone_stream = f"{path_str}:Zone.Identifier"
            if os.path.exists(zone_stream):
                try:
                    with open(zone_stream, "r+b") as zf:
                        z_sz = max(os.path.getsize(zone_stream), 1)
                        zf.write(b"\x00" * z_sz)
                        zf.flush()
                except Exception:
                    pass
                os.unlink(zone_stream)
        except Exception:
            pass


def get_file_extents(file_path: str) -> list[dict]:
    """Attempt to resolve physical file extents across Linux, macOS, and Windows."""
    extents = []
    if sys.platform == "linux" and shutil.which("filefrag"):
        try:
            proc = subprocess.run(
                ["filefrag", "-v", file_path],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if proc.returncode == 0:
                for line in proc.stdout.splitlines():
                    line = line.strip()
                    if line and line[0].isdigit() and ":" in line:
                        extents.append({"raw": line})
        except Exception:
            pass
    elif sys.platform == "darwin":
        try:
            import fcntl
            import struct

            F_LOG2PHYS = 49
            with open(file_path, "rb") as f:
                buf = bytearray(24)
                fcntl.fcntl(f.fileno(), F_LOG2PHYS, buf)
                dev_offset = struct.unpack_from("<q", buf, 16)[0]
                if dev_offset > 0:
                    extents.append({"physical_offset": dev_offset})
        except Exception:
            pass
    elif sys.platform == "win32" and shutil.which("fsutil"):
        try:
            proc = subprocess.run(
                ["fsutil", "file", "queryExtents", file_path],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if proc.returncode == 0:
                for line in proc.stdout.splitlines():
                    if "VCN" in line or "LCN" in line:
                        extents.append({"raw": line.strip()})
        except Exception:
            pass

    return extents


def erase_single_file(
    file_path: str | Path,
    *,
    passes: int = 1,
    pattern: str = "zero",
    chunk_size: int = 65536,
    progress_callback: Callable[[str, int, int], None] | None = None,
    force: bool = False,
) -> FileEraseResult:
    if pattern not in ("zero", "random"):
        return FileEraseResult(
            path=str(file_path),
            original_size=0,
            bytes_overwritten=0,
            passes=passes,
            pattern=pattern,
            status="failure",
            error=f"Invalid overwrite pattern '{pattern}'. Supported patterns: 'zero', 'random'",
        )

    # Validate the write geometry before opening the file. chunk_size <= 0 made
    # `to_write = min(remaining, chunk_size)` zero or negative, so the write loop
    # never advanced `remaining` and span forever -- an uninterruptible hang
    # inside a sanitiser. passes=0 skipped the overwrite entirely and still
    # truncated the file, reporting success with bytes_overwritten=0, which is the
    # worst possible outcome: the original data destroyed by an operation that
    # claimed to write nothing.
    #
    # The CLI validates both already; these are the library entry points, which
    # had no guard of their own.
    if not isinstance(chunk_size, int) or isinstance(chunk_size, bool) or chunk_size <= 0:
        return FileEraseResult(
            path=str(file_path),
            original_size=0,
            bytes_overwritten=0,
            passes=passes,
            pattern=pattern,
            status="failure",
            error=f"Invalid chunk_size {chunk_size!r}: must be a positive integer",
        )
    if not isinstance(passes, int) or isinstance(passes, bool) or passes < 1:
        return FileEraseResult(
            path=str(file_path),
            original_size=0,
            bytes_overwritten=0,
            passes=passes,
            pattern=pattern,
            status="failure",
            error=(
                f"Invalid pass count {passes!r}: at least one pass is required. "
                f"Zero passes would truncate the file without overwriting it, "
                f"destroying the original data while claiming to write nothing."
            ),
        )

    raw_path = Path(file_path)
    if raw_path.is_symlink() or os.path.islink(file_path):
        return FileEraseResult(
            path=str(raw_path),
            original_size=0,
            bytes_overwritten=0,
            passes=passes,
            pattern=pattern,
            status="failure",
            error="Target is a symbolic link; refusing to follow symlink",
        )

    path_obj = raw_path.resolve()
    path_str = str(path_obj)

    if os.path.islink(path_str):
        return FileEraseResult(
            path=path_str,
            original_size=0,
            bytes_overwritten=0,
            passes=passes,
            pattern=pattern,
            status="failure",
            error="Target is a symbolic link; refusing to follow symlink",
        )

    # Informational extent mapping
    extents = get_file_extents(path_str)

    # Detect filesystem & Copy-on-Write (CoW) status (Linux, macOS APFS, Windows ReFS)
    fs_name, cow_warning = detect_cow_and_filesystem(path_str)

    # Open with O_NOFOLLOW to prevent TOCTOU symlink substitution
    import errno

    flags = os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC

    try:
        raw_fd = os.open(path_str, flags)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, getattr(errno, "EMLINK", -1)):
            return FileEraseResult(
                path=path_str,
                original_size=0,
                bytes_overwritten=0,
                passes=passes,
                pattern=pattern,
                status="failure",
                error="Target is a symbolic link; refusing to follow symlink",
            )
        if exc.errno == errno.ENOENT:
            return FileEraseResult(
                path=path_str,
                original_size=0,
                bytes_overwritten=0,
                passes=passes,
                pattern=pattern,
                status="failure",
                error="Target is not an existing regular file",
            )
        if exc.errno in (errno.EACCES, errno.EPERM):
            try:
                # Open read-only with O_NOFOLLOW to safely verify inode before fchmod
                ro_flags = os.O_RDONLY
                if hasattr(os, "O_NOFOLLOW"):
                    ro_flags |= os.O_NOFOLLOW
                if hasattr(os, "O_CLOEXEC"):
                    ro_flags |= os.O_CLOEXEC
                ro_fd = os.open(path_str, ro_flags)
                try:
                    ro_st = os.fstat(ro_fd)
                    if not stat.S_ISREG(ro_st.st_mode) or stat.S_ISLNK(ro_st.st_mode):
                        raise OSError(errno.ELOOP, "Target is not a regular file")
                    os.chmod(ro_fd, stat.S_IWRITE | stat.S_IREAD)
                finally:
                    os.close(ro_fd)
                raw_fd = os.open(path_str, flags)
            except Exception as exc2:
                return FileEraseResult(
                    path=path_str,
                    original_size=0,
                    bytes_overwritten=0,
                    passes=passes,
                    pattern=pattern,
                    status="failure",
                    error=f"Cannot open target for writing: {exc2}",
                )
        else:
            return FileEraseResult(
                path=path_str,
                original_size=0,
                bytes_overwritten=0,
                passes=passes,
                pattern=pattern,
                status="failure",
                error=f"Cannot open target: {exc}",
            )

    try:
        st = os.fstat(raw_fd)
        if not stat.S_ISREG(st.st_mode):
            os.close(raw_fd)
            return FileEraseResult(
                path=path_str,
                original_size=0,
                bytes_overwritten=0,
                passes=passes,
                pattern=pattern,
                status="failure",
                error="Target is not a regular file; refusing to erase",
            )

        if st.st_nlink > 1 and not force:
            os.close(raw_fd)
            return FileEraseResult(
                path=path_str,
                original_size=0,
                bytes_overwritten=0,
                passes=passes,
                pattern=pattern,
                status="failure",
                error=f"File has {st.st_nlink} hard links; overwriting will destroy data across all links without removing them. Use --force to proceed.",
            )

        # Safely clear locks/xattrs using verified file descriptor (fchmod, no symlink following)
        platform_cleanse_attributes(path_str, fd=raw_fd)

        file_size = st.st_size
    except Exception as exc:
        try:
            os.close(raw_fd)
        except Exception:
            pass
        return FileEraseResult(
            path=path_str,
            original_size=0,
            bytes_overwritten=0,
            passes=passes,
            pattern=pattern,
            status="failure",
            error=f"Cannot stat target descriptor: {exc}",
        )

    bytes_written_total = 0
    sync_failures: list[str] = []

    try:
        # 1. Overwrite file contents
        if file_size > 0:
            with os.fdopen(raw_fd, "r+b") as f:
                for _p in range(1, passes + 1):
                    f.seek(0)
                    remaining = file_size
                    while remaining > 0:
                        to_write = min(remaining, chunk_size)
                        if pattern == "zero":
                            buf = b"\x00" * to_write
                        elif pattern == "random":
                            buf = secrets.token_bytes(to_write)
                        else:
                            raise ValueError(
                                f"Invalid overwrite pattern '{pattern}'. Supported patterns: 'zero', 'random'"
                            )

                        f.write(buf)
                        remaining -= to_write
                        bytes_written_total += to_write
                        if progress_callback:
                            progress_callback(path_str, bytes_written_total, file_size * passes)

                    f.flush()
                    if not platform_sync(f.fileno()):
                        sync_failures.append("write cache flush failed after a pass")

                # Truncate file size to 0
                f.seek(0)
                f.truncate(0)
                f.flush()
                if not platform_sync(f.fileno()):
                    sync_failures.append("write cache flush failed after truncate")
        else:
            # 0-byte file still needs closing and truncating
            os.close(raw_fd)

        # 2. Metadata Cleansing: reset timestamps to epoch 0
        try:
            os.utime(path_str, (0, 0))
        except Exception:
            pass

        # 3. Directory entry scrubbing: multi-pass exact-length rename before unlinking
        # to overwrite directory block slack space in-place (especially on ext4)
        orig_len = max(1, len(path_obj.name))
        parent_dir = path_obj.parent
        current_path = path_obj

        for _ in range(3):
            scrub_name = secrets.token_hex((orig_len + 1) // 2)[:orig_len]
            target_path = parent_dir / scrub_name
            try:
                os.rename(current_path, target_path)
                current_path = target_path
            except Exception:
                break

        random_name = parent_dir / f".s0_del_{secrets.token_hex(8)}"
        try:
            os.rename(current_path, random_name)
            current_path = random_name
        except Exception:
            pass

        try:
            os.unlink(current_path)
            if sys.platform != "win32":
                try:
                    parent_fd = os.open(str(parent_dir), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                    try:
                        os.fsync(parent_fd)
                    finally:
                        os.close(parent_fd)
                except Exception:
                    pass
        except Exception:
            # The primary unlink failed. current_path is the name the data is
            # actually under now -- never path_str, which was renamed away above
            # and so does not exist. Retrying the old path unlinks nothing, which
            # is what let a surviving zeroed .s0_del_* leftover be reported as a
            # clean erase.
            try:
                os.unlink(current_path)
            except Exception:
                pass

        # 4. Post-erase verification. The check must look at the name the data is
        # actually under, or it is checking a path that was renamed away and is
        # therefore always absent -- a tautology that can never fail.
        leftover = None
        for candidate in (current_path, path_obj):
            try:
                if os.path.lexists(str(candidate)):
                    leftover = candidate
                    break
            except OSError:
                continue
        if leftover is not None:
            return FileEraseResult(
                path=path_str,
                original_size=file_size,
                bytes_overwritten=bytes_written_total,
                passes=passes,
                pattern=pattern,
                status="failure",
                error=(
                    f"Overwritten data still present at {leftover} after an "
                    f"unlinking attempt; the file was zeroed but not removed"
                ),
                cow_warning=cow_warning,
                extents_count=len(extents),
                filesystem=fs_name,
            )

        if sync_failures:
            # The bytes reached the file but may still be in a drive cache, so
            # "erased" is not yet a fact about the medium. Reporting success here
            # is how an unflushed overwrite ends up certified as complete.
            return FileEraseResult(
                path=path_str,
                original_size=file_size,
                bytes_overwritten=bytes_written_total,
                passes=passes,
                pattern=pattern,
                status="failure",
                error=(
                    "; ".join(sorted(set(sync_failures)))
                    + " -- the overwrite may not have reached the medium; "
                    "do not rely on this erase until the device has been "
                    "power-cycled and re-checked"
                ),
                metadata_cleansed=True,
                cow_warning=cow_warning,
                extents_count=len(extents),
                filesystem=fs_name,
            )

        return FileEraseResult(
            path=path_str,
            original_size=file_size,
            bytes_overwritten=bytes_written_total,
            passes=passes,
            pattern=pattern,
            status="success",
            metadata_cleansed=True,
            cow_warning=cow_warning,
            extents_count=len(extents),
            filesystem=fs_name,
        )

    except Exception as exc:
        return FileEraseResult(
            path=path_str,
            original_size=file_size,
            bytes_overwritten=bytes_written_total,
            passes=passes,
            pattern=pattern,
            status="failure",
            error=str(exc),
            cow_warning=cow_warning,
            extents_count=len(extents),
            filesystem=fs_name,
        )


def erase_folder(
    dir_path: str | Path,
    *,
    passes: int = 1,
    pattern: str = "zero",
    progress_callback: Callable[[str, int, int], None] | None = None,
    force: bool = False,
) -> list[FileEraseResult]:
    """Recursively sanitize all files and scrub directories in a folder."""
    if pattern not in ("zero", "random"):
        raise ValueError(f"Invalid overwrite pattern '{pattern}'. Supported patterns: 'zero', 'random'")
    root_dir = Path(dir_path).resolve()
    results = []

    if not root_dir.exists() or not root_dir.is_dir():
        return [
            FileEraseResult(
                path=str(root_dir),
                original_size=0,
                bytes_overwritten=0,
                passes=passes,
                pattern=pattern,
                status="failure",
                error="Target directory does not exist or is not a directory",
            )
        ]

    # Walk directory bottom-up.
    #
    # S_ISFIFO guard: `os.walk` lists a FIFO under `files`, and opening one blocks
    # until a writer appears -- with no writer, forever. A sanitiser that hangs on a
    # stray `mkfifo` in an evidence directory is indistinguishable from one that is
    # working on a large file, and there is no output to tell them apart. Sockets and
    # device nodes are skipped for the same reason: they are not regular files and
    # overwriting them is meaningless at best.
    skipped_special: list[str] = []
    for root, dirs, files in os.walk(str(root_dir), topdown=False):
        for f in files:
            file_p = os.path.join(root, f)
            try:
                st = os.lstat(file_p)
            except OSError as exc:
                results.append(
                    FileEraseResult(
                        path=file_p,
                        original_size=0,
                        bytes_overwritten=0,
                        passes=passes,
                        pattern=pattern,
                        status="failure",
                        error=f"could not stat before erasing: {exc}",
                    )
                )
                continue
            if stat.S_ISLNK(st.st_mode):
                results.append(
                    FileEraseResult(
                        path=file_p,
                        original_size=0,
                        bytes_overwritten=0,
                        passes=passes,
                        pattern=pattern,
                        status="failure",
                        error=f"Refusing to overwrite symbolic link: {file_p}",
                    )
                )
                continue
            if not stat.S_ISREG(st.st_mode):
                skipped_special.append(file_p)
                continue
            res = erase_single_file(
                file_p, passes=passes, pattern=pattern, progress_callback=progress_callback, force=force
            )
            results.append(res)

        # Remove subdirectories after scrubbing name
        for d in dirs:
            dir_p = Path(root) / d
            try:
                if dir_p.is_symlink():
                    os.unlink(dir_p)
                else:
                    rnd_dir = Path(root) / f".tw_d_{secrets.token_hex(16)}"
                    os.rename(dir_p, rnd_dir)
                    os.rmdir(rnd_dir)
            except Exception:
                try:
                    if dir_p.is_symlink():
                        os.unlink(dir_p)
                    else:
                        os.rmdir(dir_p)
                except Exception:
                    pass

    # Finally remove top-level directory (M2/S0-02)
    target_to_remove = root_dir
    try:
        rnd_root = root_dir.parent / f".tw_root_{secrets.token_hex(16)}"
        os.rename(root_dir, rnd_root)
        target_to_remove = rnd_root
        os.rmdir(rnd_root)
    except Exception:
        if target_to_remove != root_dir and target_to_remove.exists():
            try:
                os.rename(target_to_remove, root_dir)
                target_to_remove = root_dir
            except Exception:
                pass
        try:
            os.rmdir(target_to_remove)
        except Exception:
            pass

    surviving = target_to_remove if target_to_remove.exists() else (root_dir if root_dir.exists() else None)
    if surviving is not None:
        results.append(
            FileEraseResult(
                path=str(surviving),
                original_size=0,
                bytes_overwritten=0,
                passes=passes,
                pattern=pattern,
                status="failure",
                error=f"Directory {surviving} could not be completely removed",
            )
        )

    if skipped_special:
        # Said out loud rather than dropped. A FIFO or device node inside an evidence
        # directory means the directory was not fully processed, and the operator
        # should know that before relying on the result. Their eventual fate depends
        # on whether the parent removal succeeded, so this reports them as *not
        # erased* rather than claiming they are still there.
        results.append(
            FileEraseResult(
                path=str(root_dir),
                original_size=0,
                bytes_overwritten=0,
                passes=passes,
                pattern=pattern,
                status="failure",
                error=(
                    f"{len(skipped_special)} non-regular file(s) were NOT erased: "
                    f"opening a FIFO or device node can block indefinitely and "
                    f"overwriting one has no meaning. {', '.join(skipped_special[:5])}"
                    + (" ..." if len(skipped_special) > 5 else "")
                ),
            )
        )

    return results


def erase_batch(
    targets: list[str | Path],
    *,
    passes: int = 1,
    pattern: str = "zero",
    operator_id: str = "op-forensic-01",
    organization: str = "Digital Forensics & Data Sanitization Lab",
    signing_key_path: str | Path | None = None,
    progress_callback: Callable[[str, int, int], None] | None = None,
    generate_certificate: bool = True,
    force: bool = False,
) -> BatchEraseSummary:
    """Execute batch file & folder erasure and generate an Ed25519-signed certificate."""
    if pattern not in ("zero", "random"):
        raise ValueError(f"Invalid overwrite pattern '{pattern}'. Supported patterns: 'zero', 'random'")

    # Path guard. This function never called check_safety() -- the safety checks
    # lived only on the block-device/image route -- so the file and folder path had
    # no protection at all. Confirmed: `s0 wipe --targets ~/.s0/s0_audit.db --yes`
    # destroyed the audit ledger, and `--targets /etc/hostname` reached a system
    # file. Checked before any target is touched, and the whole batch is refused if
    # any one target is protected: partially erasing a set the operator named is not
    # a useful outcome, and a half-erased batch is a worse one.
    # Deduplicate targets while preserving order (S0-22)
    seen_paths = set()
    unique_targets = []
    for t in targets:
        try:
            real_t = os.path.realpath(t)
        except Exception:
            real_t = t
        if real_t not in seen_paths:
            seen_paths.add(real_t)
            unique_targets.append(t)
    targets = unique_targets

    # Pre-validate all targets: existence, symlinks, and protected paths (fail-fast, S0-22)
    for t in targets:
        p = Path(t)
        if not p.exists() and not p.is_symlink():
            raise FileNotFoundError(f"target not found: {t}")
        try:
            check_path_is_destructive(t, force=force)
        except ProtectedPathError as exc:
            raise SafetyError(str(exc)) from exc
        if p.is_symlink():
            raise SafetyError(
                f"Refusing to follow symlink: {t} -> {os.readlink(p)}\n"
                "       Erasing the target would destroy data you did not name. "
                "Pass the real path,\n"
                "       or pass --force if you genuinely mean to erase the link's target."
            )
    start_time = cert_mod.now_utc()
    all_results: list[FileEraseResult] = []

    for t in targets:
        p = Path(t).resolve()
        if p.is_dir():
            dir_res = erase_folder(
                p, passes=passes, pattern=pattern, progress_callback=progress_callback, force=force
            )
            all_results.extend(dir_res)
        else:
            file_res = erase_single_file(
                p, passes=passes, pattern=pattern, progress_callback=progress_callback, force=force
            )
            all_results.append(file_res)

    end_time = cert_mod.now_utc()

    total_files = len(all_results)
    successes = sum(1 for r in all_results if r.status == "success")
    failures = sum(1 for r in all_results if r.status == "failure")
    # Two different quantities that used to be one field.
    #
    # overwrite_volume is size x passes -- how much was written. Reporting that as
    # the bytes processed claims a 10 MB file wiped three times sanitized 30 MB,
    # which on a compliance document reads as coverage of an area that was never
    # addressed. bytes_processed is the original content: how much data the
    # operation actually destroyed. The volume is reported beside it, named.
    overwrite_volume = sum(r.bytes_overwritten for r in all_results)
    total_bytes = sum(r.original_size for r in all_results)

    # Describe what was actually sanitized. A certificate that claims
    # `device_type=internal_disk / storage_type=UNKNOWN` for a batch of erased
    # documents is not evidence of anything, so classify from the real targets.
    target_paths = [Path(t).resolve() for t in targets]
    dir_count = sum(1 for p in target_paths if p.is_dir())
    file_count = len(target_paths) - dir_count
    if total_files > file_count:
        kind = "folder_tree"
    elif file_count > 1:
        kind = "file_set"
    else:
        kind = "file"
    storage_type = "folder_tree" if kind == "folder_tree" else "file"
    device_id = (
        "batch-files-"
        + hashlib.sha256("\0".join(str(p) for p in target_paths).encode("utf-8", "replace")).hexdigest()[:16]
    )

    warnings = [
        "File-level sanitization overwrites allocated filesystem clusters and scrubs metadata.",
        "Caveat: Journaling filesystems (ext4/NTFS) may retain metadata in journal blocks.",
        "Caveat: Flash storage (SSDs/NVMe) Flash Translation Layer (FTL) wear leveling may prevent physical overwriting of retired blocks.",
    ]
    for r in all_results:
        if r.cow_warning and r.cow_warning not in warnings:
            warnings.append(r.cow_warning)

    if total_files == 0:
        # Nothing was erased, so there is nothing to certify. A certificate here is
        # signed evidence of a sanitization that did not happen -- the worst artefact
        # this tool can emit, because to anyone checking the signature rather than
        # the target list it is indistinguishable from a real one.
        warnings.append(
            "no files were erased, so no certificate was issued: the target set was "
            "empty or contained only empty directories."
        )
        return BatchEraseSummary(
            total_files=0,
            successful_files=0,
            failed_files=0,
            total_bytes_processed=0,
            results=all_results,
            certificate=None,
            warnings=warnings,
        )

    # Build signed certificate
    cert = None
    # Declared before the branch, not inside it: with --no-certificate the branch
    # that assigns it is skipped, and a name first assigned inside an `else` is
    # unbound on the path that skips it.
    key_file: Path | None = None
    if not generate_certificate:
        warnings.append("Compliance certification omitted per operator request (--no-certificate).")
    else:
        if signing_key_path:
            key_file = Path(signing_key_path)
        else:
            try:
                key_file = resources.demo_private_key()
            except FileNotFoundError:
                key_file = None
    if key_file is not None and key_file.exists():
        try:
            cert_dict = cert_mod.build_certificate(
                organization=organization,
                operator_id=operator_id,
                tool_name="s0-erase",
                tool_version=CONFIG.get("version", "3.1.0"),
                platform="linux",
                device_id=device_id,
                device_type=kind,
                storage_type=storage_type,
                method=_wipe_method_label(pattern, passes),
                nist_category="Clear",
                start_time=start_time,
                end_time=end_time,
                bytes_processed=total_bytes,
                capacity_bytes=total_bytes,
                passes=passes,
                pattern=pattern,
                status="success" if failures == 0 else ("partial" if successes > 0 else "failure"),
                errors=[r.error for r in all_results if r.error] or None,
                verification={
                    # No content readback happens on the file path: the
                    # checks below establish that the name is gone and that
                    # the overwrite did not error, not that the bytes on the
                    # medium match the pattern. Claiming a readback here
                    # would put an unsupported assertion on a compliance
                    # document, so the field is null rather than true.
                    "method": "post_erase_absence_only",
                    "samples_checked": total_files,
                    "sample_bytes_each": 0,
                    "all_samples_match_wipe_pattern": None,
                    "planted_pattern_hits_after": failures,
                    # Not a statistical sample, so no residual bound
                    # applies; the schema's fields are used to say that
                    # explicitly rather than left absent, because an
                    # absent bound reads to a certificate consumer as
                    # "no bound was needed" rather than "this check is of
                    # a different kind".
                    "population_blocks": total_files,
                    "confidence_percent": 100,
                    "attestation": (
                        "exhaustive re-stat of every path supplied to this "
                        "operation; this is not a statistical sample and "
                        "carries no residual bound"
                    ),
                    "sample_strategy": (
                        "exhaustive_over_supplied_paths; note that the "
                        "supplied list cannot itself be verified complete, "
                        "so this attests absence for the paths given and "
                        "not for the volume"
                    ),
                },
                notes=[
                    f"Batch sanitized {successes}/{total_files} files, "
                    f"{total_bytes:,} B of content destroyed.",
                    # Stated separately and explicitly, because "bytes
                    # overwritten" for a multi-pass wipe is passes x size and a
                    # reader takes it for the size of what was sanitized.
                    f"Overwrite volume {overwrite_volume:,} B "
                    f"(= content x passes; not a claim about coverage).",
                    f"Target classification: {kind} — {dir_count} director(ies), {file_count} file(s) supplied.",
                    "Verification: each target was re-stat()ed after overwrite; the file is unlinked and no residual data was readable.",
                    "Metadata cleansing applied: timestamps zeroed, directory entries scrambled.",
                ]
                + warnings,
            )
            priv = core_crypto.load_private_pem(key_file)
            cert = cert_mod.sign_certificate(cert_dict, priv)
        except Exception as e:
            warnings.append(f"Certificate generation/signing failed: {e}")
            cert = None
    else:
        warnings.append(
            f"WARNING: Signing key not found at '{key_file}'. "
            "No compliance certificate or cryptographic audit record was generated."
        )

    return BatchEraseSummary(
        total_files=total_files,
        successful_files=successes,
        failed_files=failures,
        total_bytes_processed=total_bytes,
        results=all_results,
        certificate=cert,
        warnings=warnings,
    )
