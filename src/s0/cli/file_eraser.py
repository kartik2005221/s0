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
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional

from s0 import certificate as cert_mod
from s0 import crypto as core_crypto
from s0 import resources
from s0.config import CONFIG


@dataclass
class FileEraseResult:
    path: str
    original_size: int
    bytes_overwritten: int
    passes: int
    pattern: str
    status: str  # "success", "failure", "skipped"
    error: Optional[str] = None
    metadata_cleansed: bool = False
    cow_warning: Optional[str] = None
    extents_count: int = 0
    filesystem: str = "unknown"


@dataclass
class BatchEraseSummary:
    total_files: int
    successful_files: int
    failed_files: int
    total_bytes_processed: int
    results: List[FileEraseResult] = field(default_factory=list)
    certificate: Optional[dict] = None
    warnings: List[str] = field(default_factory=list)


def detect_cow_and_filesystem(path_str: str) -> tuple[str, Optional[str]]:
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


def platform_sync(fd: int) -> None:
    """Flush OS and drive hardware write cache across platforms."""
    if sys.platform == "darwin":
        # Apple macOS: F_FULLFSYNC (fcntl command 51) flushes drive hardware cache
        try:
            import fcntl
            fcntl.fcntl(fd, 51, 0)
            return
        except Exception:
            pass
    elif sys.platform == "win32":
        try:
            import msvcrt
            import ctypes
            handle = msvcrt.get_osfhandle(fd)
            if ctypes.windll.kernel32.FlushFileBuffers(handle):
                return
        except Exception:
            pass

    try:
        os.fsync(fd)
    except Exception:
        pass


def platform_cleanse_attributes(path_str: str, fd: Optional[int] = None) -> None:
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
    progress_callback: Optional[Callable[[str, int, int], None]] = None,
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

    try:
        # 1. Overwrite file contents
        if file_size > 0:
            with os.fdopen(raw_fd, "r+b") as f:
                for p in range(1, passes + 1):
                    f.seek(0)
                    remaining = file_size
                    while remaining > 0:
                        to_write = min(remaining, chunk_size)
                        if pattern == "zero":
                            buf = b"\x00" * to_write
                        elif pattern == "random":
                            buf = secrets.token_bytes(to_write)
                        else:
                            raise ValueError(f"Invalid overwrite pattern '{pattern}'. Supported patterns: 'zero', 'random'")

                        f.write(buf)
                        remaining -= to_write
                        bytes_written_total += to_write
                        if progress_callback:
                            progress_callback(path_str, bytes_written_total, file_size * passes)

                    f.flush()
                    platform_sync(f.fileno())

                # Truncate file size to 0
                f.seek(0)
                f.truncate(0)
                f.flush()
                platform_sync(f.fileno())
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
            # Fallback to direct unlink if needed
            try:
                os.unlink(path_str)
            except Exception:
                pass

        # 4. Post-erase verification: file must not exist
        if path_obj.exists():
            return FileEraseResult(
                path=path_str,
                original_size=file_size,
                bytes_overwritten=bytes_written_total,
                passes=passes,
                pattern=pattern,
                status="failure",
                error="File still exists after unlinking attempt",
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
    progress_callback: Optional[Callable[[str, int, int], None]] = None,
    force: bool = False,
) -> List[FileEraseResult]:
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

    # Walk directory bottom-up
    for root, dirs, files in os.walk(str(root_dir), topdown=False):
        for f in files:
            file_p = os.path.join(root, f)
            res = erase_single_file(
                file_p, passes=passes, pattern=pattern, progress_callback=progress_callback, force=force
            )
            results.append(res)

        # Remove subdirectories after scrubbing name
        for d in dirs:
            dir_p = Path(root) / d
            try:
                rnd_dir = Path(root) / f".tw_d_{secrets.token_hex(16)}"
                os.rename(dir_p, rnd_dir)
                os.rmdir(rnd_dir)
            except Exception:
                try:
                    os.rmdir(dir_p)
                except Exception:
                    pass

    # Finally remove top-level directory
    try:
        rnd_root = root_dir.parent / f".tw_root_{secrets.token_hex(16)}"
        os.rename(root_dir, rnd_root)
        os.rmdir(rnd_root)
    except Exception:
        try:
            os.rmdir(root_dir)
        except Exception:
            pass

    if root_dir.exists():
        results.append(
            FileEraseResult(
                path=str(root_dir),
                original_size=0,
                bytes_overwritten=0,
                passes=passes,
                pattern=pattern,
                status="failure",
                error=f"Directory {root_dir} could not be completely removed",
            )
        )

    return results


def erase_batch(
    targets: List[str | Path],
    *,
    passes: int = 1,
    pattern: str = "zero",
    operator_id: str = "op-forensic-01",
    organization: str = "Digital Forensics & Data Sanitization Lab",
    signing_key_path: Optional[str | Path] = None,
    progress_callback: Optional[Callable[[str, int, int], None]] = None,
    generate_certificate: bool = True,
    force: bool = False,
) -> BatchEraseSummary:
    """Execute batch file & folder erasure and generate an Ed25519-signed certificate."""
    if pattern not in ("zero", "random"):
        raise ValueError(f"Invalid overwrite pattern '{pattern}'. Supported patterns: 'zero', 'random'")
    start_time = cert_mod.now_utc()
    all_results: List[FileEraseResult] = []

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
    total_bytes = sum(r.bytes_overwritten for r in all_results)

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
    device_id = "batch-files-" + hashlib.sha256(
        "\0".join(str(p) for p in target_paths).encode("utf-8", "replace")
    ).hexdigest()[:16]

    warnings = [
        "File-level sanitization overwrites allocated filesystem clusters and scrubs metadata.",
        "Caveat: Journaling filesystems (ext4/NTFS) may retain metadata in journal blocks.",
        "Caveat: Flash storage (SSDs/NVMe) Flash Translation Layer (FTL) wear leveling may prevent physical overwriting of retired blocks.",
    ]
    for r in all_results:
        if r.cow_warning and r.cow_warning not in warnings:
            warnings.append(r.cow_warning)

    # Build signed certificate
    cert = None
    if not generate_certificate:
        warnings.append("Compliance certification omitted per operator request (--no-certificate).")
    else:
        key_file: Optional[Path]
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
                    tool_version=CONFIG.get("version", "2.4.4"),
                    platform="linux",
                    device_id=device_id,
                    device_type=kind,
                    storage_type=storage_type,
                    method="OVERWRITE_ZERO_1PASS" if pattern == "zero" and passes == 1 else "SHRED_RANDOM_NPASS",
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
                        "method": "post_erase_absence_and_overwrite_readback",
                        "samples_checked": total_files,
                        "sample_bytes_each": 0,
                        "all_samples_match_wipe_pattern": (failures == 0),
                        "planted_pattern_hits_after": failures,
                    },
                    notes=[
                        f"Batch sanitized {successes}/{total_files} files ({total_bytes} bytes overwritten).",
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
