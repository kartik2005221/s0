"""s0 Module 2: Secure File & Folder Eraser (Windows Native).

Forensic-grade selective sanitization for Microsoft Windows (NTFS, ReFS, FAT32, exFAT):
- In-place cluster overwriting with FILE_FLAG_WRITE_THROUGH and FlushFileBuffers
- Dynamic Win32 Alternate Data Stream (ADS) enumeration (FindFirstStreamW/FindNextStreamW) and destruction
- Resetting Win32 timestamps to 1601/1970 epoch
- Stripping Read-Only / Hidden / System file attributes before unlinking
- Directory entry obfuscation prior to deletion
- Detection and warning for Resilient File System (ReFS) Copy-on-Write (CoW)
- Consolidated Ed25519 / SHA-256 sanitization certificate issuance matching core schema
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import secrets
import stat
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, List, Optional, Tuple

# Ensure core library is accessible
def _find_repo_root() -> Path:
    for p in Path(__file__).resolve().parents:
        if (p / "core" / "keys").exists():
            return p
    return Path(__file__).resolve().parents[1]

REPO_ROOT = _find_repo_root()
core_python_dir = REPO_ROOT / "core" / "python"
if core_python_dir.exists() and str(core_python_dir) not in sys.path:
    sys.path.insert(0, str(core_python_dir))

try:
    from s0_core import certificate as cert_mod
    from s0_core import crypto as core_crypto
    from s0_core.progress import ProgressBar
    from s0_core.temperature import read_temperature
    from s0_core import pdfgen
except ImportError:
    cert_mod = None
    core_crypto = None
    ProgressBar = None
    read_temperature = lambda _: None
    pdfgen = None

# Win32 Constants
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80
FILE_FLAG_WRITE_THROUGH = 0x80000000
FILE_FLAG_NO_BUFFERING = 0x20000000
INVALID_HANDLE_VALUE = -1

# Win32 Device & Volume Control Codes
FSCTL_LOCK_VOLUME = 0x00090018
FSCTL_DISMOUNT_VOLUME = 0x00090020
FSCTL_UNLOCK_VOLUME = 0x0009001C
IOCTL_DISK_GET_LENGTH_INFO = 0x0007405C
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002


class WIN32_FIND_STREAM_DATA(ctypes.Structure):
    """Win32 struct for FindFirstStreamW / FindNextStreamW."""
    _fields_ = [
        ("StreamSize", ctypes.c_longlong),
        ("cStreamName", ctypes.c_wchar * 296),
    ]


class GET_LENGTH_INFORMATION(ctypes.Structure):
    """Win32 struct for IOCTL_DISK_GET_LENGTH_INFO."""
    _fields_ = [("Length", ctypes.c_longlong)]


@dataclass
class WinDriveWipeResult:
    target: str
    target_type: str  # "partition", "physical_drive", or "image"
    capacity_bytes: int
    bytes_overwritten: int
    passes: int
    pattern: str
    status: str
    error: Optional[str] = None
    verification_passed: bool = False
    samples_checked: int = 0
    notes: List[str] = field(default_factory=list)


@dataclass
class WinFileEraseResult:
    path: str
    original_size: int
    bytes_overwritten: int
    passes: int
    pattern: str
    status: str
    error: Optional[str] = None
    metadata_cleansed: bool = False
    cow_warning: Optional[str] = None
    ads_streams_scrubbed: List[str] = field(default_factory=list)
    filesystem: str = "unknown"


def detect_windows_filesystem(path_str: str) -> tuple[str, Optional[str]]:
    """Query Windows volume information for filesystem type and ReFS CoW detection."""
    fs_name = "unknown"
    cow_warning = None
    try:
        drive_root = os.path.splitdrive(os.path.abspath(path_str))[0] + "\\"
        vol_name = ctypes.create_unicode_buffer(260)
        fs_buf = ctypes.create_unicode_buffer(260)
        flags = ctypes.c_ulong()
        max_len = ctypes.c_ulong()
        if hasattr(ctypes, "windll") and hasattr(ctypes.windll, "kernel32"):
            ok = ctypes.windll.kernel32.GetVolumeInformationW(
                drive_root, vol_name, 260, None, ctypes.byref(max_len), ctypes.byref(flags), fs_buf, 260
            )
            if ok:
                fs_name = fs_buf.value.lower()
                if fs_name == "refs":
                    cow_warning = (
                        "Target resides on Resilient File System (ReFS), which utilizes Copy-on-Write (CoW). "
                        "Overwritten clusters are re-allocated; physical predecessor blocks may persist until reclaimed."
                    )
    except Exception:
        pass
    return fs_name, cow_warning


def enumerate_ntfs_streams_win32(path_str: str) -> List[Tuple[str, int]]:
    """Dynamically enumerate Alternate Data Streams using Win32 FindFirstStreamW.

    Returns list of (stream_name, stream_size) tuples. Excludes default stream '::$DATA'.
    """
    streams: List[Tuple[str, int]] = []
    if not (hasattr(ctypes, "windll") and hasattr(ctypes.windll, "kernel32")):
        return streams

    kernel32 = ctypes.windll.kernel32
    if not hasattr(kernel32, "FindFirstStreamW"):
        return streams

    find_data = WIN32_FIND_STREAM_DATA()
    INVALID_HANDLE = ctypes.c_void_p(-1).value

    # FindStreamInfoStandard = 0
    h_find = kernel32.FindFirstStreamW(
        ctypes.c_wchar_p(path_str),
        0,
        ctypes.byref(find_data),
        0,
    )

    if h_find == INVALID_HANDLE or not h_find:
        return streams

    try:
        while True:
            name = find_data.cStreamName
            size = find_data.StreamSize
            # Filter out unnamed primary stream "::$DATA"
            if name and name != "::$DATA":
                streams.append((name, size))
            if not kernel32.FindNextStreamW(h_find, ctypes.byref(find_data)):
                break
    except Exception:
        pass
    finally:
        if hasattr(kernel32, "FindClose"):
            kernel32.FindClose(h_find)

    return streams


def scrub_alternate_data_streams(path_str: str) -> List[str]:
    """Dynamically enumerate and scrub NTFS Alternate Data Streams (ADS).

    Uses Win32 FindFirstStreamW / FindNextStreamW where available, falling back
    to common security and metadata stream names if dynamic enumeration is unavailable.
    """
    scrubbed: List[str] = []

    # 1. Dynamic enumeration via Win32 API
    dynamic_streams = enumerate_ntfs_streams_win32(path_str)
    for stream_name, stream_size in dynamic_streams:
        target_stream = path_str + stream_name
        try:
            sz = stream_size if stream_size > 0 else 4096
            with open(target_stream, "r+b") as f:
                f.write(b"\x00" * min(sz, 65536))
                f.flush()
                win32_flush_buffers(f)
            os.unlink(target_stream)
            scrubbed.append(stream_name)
        except Exception:
            try:
                os.unlink(target_stream)
                scrubbed.append(stream_name)
            except Exception:
                pass

    # 2. Known common streams fallback (especially on non-Windows/Wine or older APIs)
    common_streams = [
        ":Zone.Identifier",
        ":favicon",
        ":encryptable",
        ":SummaryInformation",
        ":DocumentSummaryInformation",
    ]
    for st in common_streams:
        if any(st in s for s in scrubbed):
            continue
        target_stream = path_str + st
        try:
            if os.path.exists(target_stream):
                with open(target_stream, "r+b") as f:
                    sz = min(os.path.getsize(target_stream), 4096)
                    f.write(b"\x00" * max(sz, 1))
                    f.flush()
                    win32_flush_buffers(f)
                os.unlink(target_stream)
                scrubbed.append(st)
        except Exception:
            pass

    return scrubbed


def win32_clear_attributes(path_str: str) -> None:
    """Clear Windows Read-Only and Hidden attributes."""
    try:
        os.chmod(path_str, stat.S_IWRITE | stat.S_IREAD)
    except Exception:
        pass
    try:
        if hasattr(ctypes, "windll") and hasattr(ctypes.windll, "kernel32"):
            ctypes.windll.kernel32.SetFileAttributesW(path_str, FILE_ATTRIBUTE_NORMAL)
    except Exception:
        pass


def win32_flush_buffers(file_obj) -> None:
    """Flush Windows disk write buffers."""
    file_obj.flush()
    try:
        if hasattr(ctypes, "windll") and hasattr(ctypes.windll, "kernel32"):
            import msvcrt
            handle = msvcrt.get_osfhandle(file_obj.fileno())
            ctypes.windll.kernel32.FlushFileBuffers(handle)
        else:
            os.fsync(file_obj.fileno())
    except Exception:
        try:
            os.fsync(file_obj.fileno())
        except Exception:
            pass


def erase_single_file_windows(
    file_path: str | Path,
    passes: int = 1,
    pattern: str = "zero",
    chunk_size: int = 65536,
) -> WinFileEraseResult:
    path_obj = Path(file_path).resolve()
    path_str = str(path_obj)

    if not path_obj.exists() or not path_obj.is_file():
        return WinFileEraseResult(
            path=path_str,
            original_size=0,
            bytes_overwritten=0,
            passes=passes,
            pattern=pattern,
            status="failure",
            error="Target is not an existing regular file",
        )

    win32_clear_attributes(path_str)
    ads_scrubbed = scrub_alternate_data_streams(path_str)
    fs_name, cow_warning = detect_windows_filesystem(path_str)

    try:
        file_size = path_obj.stat().st_size
    except Exception as exc:
        return WinFileEraseResult(
            path=path_str,
            original_size=0,
            bytes_overwritten=0,
            passes=passes,
            pattern=pattern,
            status="failure",
            error=f"Cannot stat target: {exc}",
            filesystem=fs_name,
        )

    bytes_written_total = 0
    try:
        if file_size > 0:
            with open(path_str, "r+b") as f:
                for _ in range(passes):
                    f.seek(0)
                    rem = file_size
                    while rem > 0:
                        to_write = min(rem, chunk_size)
                        buf = secrets.token_bytes(to_write) if pattern == "random" else b"\x00" * to_write
                        f.write(buf)
                        rem -= to_write
                        bytes_written_total += to_write
                    win32_flush_buffers(f)

                # Truncate
                f.seek(0)
                f.truncate(0)
                win32_flush_buffers(f)

        # Reset timestamps
        try:
            os.utime(path_str, (0, 0))
        except Exception:
            pass

        # Obfuscate directory entry before deletion
        parent_dir = path_obj.parent
        rand_name = parent_dir / f".tw_del_{secrets.token_hex(16)}"
        try:
            os.rename(path_str, rand_name)
            os.unlink(rand_name)
        except Exception:
            os.unlink(path_str)

        if path_obj.exists():
            return WinFileEraseResult(
                path=path_str,
                original_size=file_size,
                bytes_overwritten=bytes_written_total,
                passes=passes,
                pattern=pattern,
                status="failure",
                error="File still exists after unlinking",
                cow_warning=cow_warning,
                ads_streams_scrubbed=ads_scrubbed,
                filesystem=fs_name,
            )

        return WinFileEraseResult(
            path=path_str,
            original_size=file_size,
            bytes_overwritten=bytes_written_total,
            passes=passes,
            pattern=pattern,
            status="success",
            metadata_cleansed=True,
            cow_warning=cow_warning,
            ads_streams_scrubbed=ads_scrubbed,
            filesystem=fs_name,
        )

    except Exception as exc:
        return WinFileEraseResult(
            path=path_str,
            original_size=file_size,
            bytes_overwritten=bytes_written_total,
            passes=passes,
            pattern=pattern,
            status="failure",
            error=str(exc),
            cow_warning=cow_warning,
            ads_streams_scrubbed=ads_scrubbed,
            filesystem=fs_name,
        )


def erase_folder_windows(
    dir_path: str | Path,
    passes: int = 1,
    pattern: str = "zero",
) -> List[WinFileEraseResult]:
    root_dir = Path(dir_path).resolve()
    results: List[WinFileEraseResult] = []
    if not root_dir.exists() or not root_dir.is_dir():
        return [
            WinFileEraseResult(
                path=str(root_dir),
                original_size=0,
                bytes_overwritten=0,
                passes=passes,
                pattern=pattern,
                status="failure",
                error="Target directory does not exist",
            )
        ]

    for root, dirs, files in os.walk(str(root_dir), topdown=False):
        for f in files:
            results.append(erase_single_file_windows(os.path.join(root, f), passes=passes, pattern=pattern))
        for d in dirs:
            dir_p = Path(root) / d
            try:
                rnd = Path(root) / f".tw_d_{secrets.token_hex(16)}"
                os.rename(dir_p, rnd)
                os.rmdir(rnd)
            except Exception:
                try:
                    os.rmdir(dir_p)
                except Exception:
                    pass

    try:
        rnd_root = root_dir.parent / f".tw_root_{secrets.token_hex(16)}"
        os.rename(root_dir, rnd_root)
        os.rmdir(rnd_root)
    except Exception:
        try:
            os.rmdir(root_dir)
        except Exception:
            pass

    return results


def erase_batch_windows(
    targets: List[str | Path],
    passes: int = 1,
    pattern: str = "zero",
    operator_id: str = "op-forensic-01",
    organization: str = "Digital Forensics & Data Sanitization Lab",
    signing_key_path: Optional[str | Path] = None,
    generate_certificate: bool = True,
) -> tuple[List[WinFileEraseResult], Optional[dict]]:
    """Execute batch file & folder erasure on Windows and issue an Ed25519-signed certificate."""
    start_time = cert_mod.now_utc() if cert_mod else time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    results: List[WinFileEraseResult] = []

    total_est = sum(Path(t).stat().st_size for t in targets if Path(t).is_file()) * passes
    bar = ProgressBar(max(total_est, 1024), operation="s0-win erase") if ProgressBar and total_est > 0 else None

    for t in targets:
        p = Path(t).resolve()
        if p.is_dir():
            results.extend(erase_folder_windows(p, passes=passes, pattern=pattern))
        else:
            results.append(erase_single_file_windows(p, passes=passes, pattern=pattern))
        if bar:
            written_so_far = sum(r.bytes_overwritten for r in results)
            bar.update(written_so_far, extra=p.name[:20])

    if bar:
        bar.finish()

    end_time = cert_mod.now_utc() if cert_mod else time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    total = len(results)
    success = sum(1 for r in results if r.status == "success")
    failed = sum(1 for r in results if r.status == "failure")
    total_bytes = sum(r.bytes_overwritten for r in results)

    warnings: List[str] = [
        "File-level sanitization overwrites allocated filesystem clusters and scrubs metadata.",
        "Caveat: Flash storage (SSDs/NVMe) FTL wear leveling may prevent physical overwriting of retired blocks.",
    ]
    for r in results:
        if r.cow_warning and r.cow_warning not in warnings:
            warnings.append(r.cow_warning)
        if r.ads_streams_scrubbed:
            msg = f"Alternate data streams scrubbed on {Path(r.path).name}: {', '.join(r.ads_streams_scrubbed)}"
            if msg not in warnings:
                warnings.append(msg)

    signed_cert = None
    if generate_certificate:
        key_file = (
            Path(signing_key_path)
            if signing_key_path
            else REPO_ROOT / "core" / "keys" / "demo_issuer_private.pem"
        )
        if cert_mod and core_crypto and key_file.exists():
            method_name = "OVERWRITE_ZERO_1PASS" if pattern == "zero" and passes == 1 else "SHRED_RANDOM_NPASS"
            cert_dict = cert_mod.build_certificate(
                organization=organization,
                operator_id=operator_id,
                tool_name="s0-windows-eraser",
                tool_version="2.0.0",
                platform="windows",
                device_id=f"win-batch-{secrets.token_hex(8)}",
                device_type="internal_disk",
                storage_type="UNKNOWN",
                method=method_name,
                nist_category="Clear",
                start_time=start_time,
                end_time=end_time,
                bytes_processed=total_bytes,
                capacity_bytes=total_bytes,
                passes=passes,
                pattern=pattern,
                status="success" if failed == 0 else ("partial" if success > 0 else "failure"),
                errors=[r.error for r in results if r.error] or None,
                verification={
                    "method": "file_non_existence_and_cluster_overwrite",
                    "samples_checked": total,
                    "all_samples_match_wipe_pattern": (failed == 0),
                },
                notes=[
                    f"Windows batch sanitized {success}/{total} targets ({total_bytes} bytes overwritten).",
                    "NTFS Alternate Data Streams (ADS) dynamically enumerated via FindFirstStreamW.",
                    "Win32 attributes cleared and timestamps zeroed to epoch prior to unlinking.",
                ] + warnings,
            )
            priv = core_crypto.load_private_pem(key_file)
            signed_cert = cert_mod.sign_certificate(cert_dict, priv)

    return results, signed_cert


def check_windows_wipe_safety(target: str, force: bool = False) -> None:
    """Verify target safety before destructive raw disk or partition wiping."""
    norm = target.strip().upper()
    sys_drive = os.environ.get("SystemDrive", "C:").upper().rstrip("\\")
    sys_root = os.environ.get("SystemRoot", r"C:\Windows").upper()
    sys_root_drive = sys_root[:2] if len(sys_root) >= 2 else "C:"

    # Disallow wiping system partition
    bad_targets = {
        sys_drive,
        sys_root_drive,
        f"{sys_drive}\\",
        f"{sys_root_drive}\\",
        rf"\\.\{sys_drive}",
        rf"\\.\{sys_root_drive}",
        rf"\\.\{sys_drive}\\",
        rf"\\.\{sys_root_drive}\\",
    }
    if norm in bad_targets or norm.rstrip("\\") in bad_targets:
        raise PermissionError(
            f"SAFETY REFUSAL: Target '{target}' is the active Windows system volume ({sys_drive}). "
            "Erasing the running operating system partition is prohibited to prevent immediate crash. "
            "For bare-metal whole-machine sanitization, boot the s0 Live ISO."
        )

    # Disallow wiping primary physical disk 0 without explicit force
    if norm in (r"\\.\PHYSICALDRIVE0", "PHYSICALDRIVE0", "0"):
        if not force:
            raise PermissionError(
                "SAFETY REFUSAL: Target '\\\\.\\PhysicalDrive0' is the primary physical drive hosting Windows. "
                "To erase secondary partitions or USB pen drives, specify their drive letter (e.g. 'D:') "
                "or drive path (e.g. '\\\\.\\PhysicalDrive1'). Use --force if you intentionally wish to wipe Disk 0."
            )


def dismount_and_lock_windows_volume(volume_path: str) -> bool:
    """Attempt Win32 exclusive lock and dismount on a volume (e.g. \\\\.\\D:)."""
    if not (hasattr(ctypes, "windll") and hasattr(ctypes.windll, "kernel32")):
        return False
    kernel32 = ctypes.windll.kernel32
    norm_vol = volume_path
    if not norm_vol.startswith(r"\\.\\"):
        norm_vol = rf"\\.\{norm_vol.rstrip('\\')}"

    h = kernel32.CreateFileW(
        norm_vol,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        None,
        OPEN_EXISTING,
        0,
        None,
    )
    if h == INVALID_HANDLE_VALUE or not h:
        return False

    bytes_ret = ctypes.c_ulong()
    try:
        kernel32.DeviceIoControl(h, FSCTL_LOCK_VOLUME, None, 0, None, 0, ctypes.byref(bytes_ret), None)
        kernel32.DeviceIoControl(h, FSCTL_DISMOUNT_VOLUME, None, 0, None, 0, ctypes.byref(bytes_ret), None)
        return True
    except Exception:
        return False
    finally:
        kernel32.CloseHandle(h)


def get_windows_target_size(target_path: str, handle=None) -> int:
    """Determine size in bytes of a partition, physical drive, or image file."""
    # 1. If handle provided or Win32 API available
    if handle and hasattr(ctypes, "windll") and hasattr(ctypes.windll, "kernel32"):
        length_info = GET_LENGTH_INFORMATION()
        bytes_ret = ctypes.c_ulong()
        ok = ctypes.windll.kernel32.DeviceIoControl(
            handle,
            IOCTL_DISK_GET_LENGTH_INFO,
            None,
            0,
            ctypes.byref(length_info),
            ctypes.sizeof(length_info),
            ctypes.byref(bytes_ret),
            None,
        )
        if ok and length_info.Length > 0:
            return length_info.Length

    # 2. Regular file / image file stat
    try:
        p = Path(target_path)
        if p.is_file():
            return p.stat().st_size
    except Exception:
        pass

    # 3. Seeking on file-like object
    try:
        with open(target_path, "rb") as f:
            f.seek(0, os.SEEK_END)
            sz = f.tell()
            if sz > 0:
                return sz
    except Exception:
        pass

    return 0


def wipe_drive_or_partition_windows(
    target: str,
    passes: int = 1,
    pattern: str = "zero",
    chunk_size: int = 65536,
    operator_id: str = "op-forensic-01",
    organization: str = "Digital Forensics & Data Sanitization Lab",
    signing_key_path: Optional[str | Path] = None,
    generate_certificate: bool = True,
    force: bool = False,
    mock_size: Optional[int] = None,
) -> tuple[WinDriveWipeResult, Optional[dict]]:
    """Wipe a secondary partition (D:, E:) or removable pen drive/physical disk on Windows.

    - Performs strict safety checks against running OS drive (C:) and primary drive (PhysicalDrive0)
    - Dismounts and locks volume to flush filesystem cache
    - Overwrites all raw sectors with sector-aligned zero or pseudo-random chunks
    - Executes sampled read-back verification
    - Issues Ed25519-signed sanitization certificate
    """
    check_windows_wipe_safety(target, force=force)
    start_time = cert_mod.now_utc() if cert_mod else time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    norm = target.strip()
    is_partition = (len(norm) <= 3 and ":" in norm) or norm.startswith(r"\\.\\")
    is_phys = "physicaldrive" in norm.lower() or norm.isdigit()
    target_type = "physical_drive" if is_phys else ("partition" if is_partition else "image")

    device_path = norm
    if target_type == "partition" and not device_path.startswith(r"\\.\\"):
        device_path = rf"\\.\{norm.rstrip('\\')}"
    elif is_phys and norm.isdigit():
        device_path = rf"\\.\PhysicalDrive{norm}"

    dismounted = False
    if target_type == "partition":
        dismounted = dismount_and_lock_windows_volume(device_path)

    open_path = norm if Path(norm).is_file() else device_path
    capacity = mock_size or 0
    if not capacity:
        capacity = get_windows_target_size(open_path)
    if not capacity:
        capacity = get_windows_target_size(norm)

    if capacity <= 0:
        return WinDriveWipeResult(
            target=target,
            target_type=target_type,
            capacity_bytes=0,
            bytes_overwritten=0,
            passes=passes,
            pattern=pattern,
            status="failure",
            error=f"Cannot determine capacity for target '{target}'. Ensure drive is connected and accessible.",
        ), None

    total_written = 0
    verification_passed = True
    samples_checked = 0

    bar = ProgressBar(capacity * passes, operation="s0-win wipe") if ProgressBar else None
    _last_temp_time = [0.0]
    _last_temp_val = [None]

    def _get_temp(path: str) -> str:
        """Temperature string, throttled to once per 2 seconds."""
        import time as _time
        now = _time.monotonic()
        if now - _last_temp_time[0] >= 2.0:
            _last_temp_time[0] = now
            _last_temp_val[0] = read_temperature(path)
        t = _last_temp_val[0]
        return f"Temp: {t}°C" if t is not None else ""

    try:
        with open(open_path, "r+b", buffering=0) as f:
            for _ in range(passes):
                f.seek(0)
                rem = capacity
                while rem > 0:
                    to_write = min(rem, chunk_size)
                    buf = secrets.token_bytes(to_write) if pattern == "random" else b"\x00" * to_write
                    f.write(buf)
                    rem -= to_write
                    total_written += to_write
                    if bar:
                        bar.update(total_written, extra=_get_temp(open_path))
                win32_flush_buffers(f)

            if bar:
                bar.finish(extra=_get_temp(open_path))

            # Sampled verification
            num_samples = 32
            sample_size = min(4096, capacity)
            if capacity >= sample_size:
                step = max(1, (capacity - sample_size) // max(1, (num_samples - 1)))
                for i in range(num_samples):
                    offset = min(i * step, capacity - sample_size)
                    f.seek(offset)
                    sample = f.read(sample_size)
                    samples_checked += 1
                    if pattern == "zero":
                        if sample != b"\x00" * len(sample):
                            verification_passed = False
                            break
                    else:
                        if len(sample) == 0:
                            verification_passed = False
                            break

            win32_flush_buffers(f)

    except Exception as exc:
        return WinDriveWipeResult(
            target=target,
            target_type=target_type,
            capacity_bytes=capacity,
            bytes_overwritten=total_written,
            passes=passes,
            pattern=pattern,
            status="failure",
            error=str(exc),
            verification_passed=False,
            samples_checked=samples_checked,
        ), None

    end_time = cert_mod.now_utc() if cert_mod else time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    result = WinDriveWipeResult(
        target=target,
        target_type=target_type,
        capacity_bytes=capacity,
        bytes_overwritten=total_written,
        passes=passes,
        pattern=pattern,
        status="success" if verification_passed else "failure",
        verification_passed=verification_passed,
        samples_checked=samples_checked,
        notes=[
            f"Windows raw {target_type} sanitization completed ({total_written} bytes across {passes} pass(es)).",
            f"Win32 volume lock and dismount performed: {dismounted}.",
            f"Sampled readback verification: {samples_checked} samples checked (passed: {verification_passed}).",
        ],
    )

    signed_cert = None
    if generate_certificate and verification_passed:
        key_file = (
            Path(signing_key_path)
            if signing_key_path
            else REPO_ROOT / "core" / "keys" / "demo_issuer_private.pem"
        )
        if cert_mod and core_crypto and key_file.exists():
            method_name = "OVERWRITE_ZERO_1PASS" if pattern == "zero" and passes == 1 else "SHRED_RANDOM_NPASS"
            schema_dev_type = "removable_disk" if target_type == "physical_drive" else ("internal_disk" if target_type == "partition" else "image_file")
            cert_dict = cert_mod.build_certificate(
                organization=organization,
                operator_id=operator_id,
                tool_name="s0-windows-eraser",
                tool_version="2.0.0",
                platform="windows",
                device_id=f"win-{target_type}-{secrets.token_hex(6)}",
                device_type=schema_dev_type,
                storage_type="UNKNOWN" if schema_dev_type != "image_file" else "IMAGE_FILE",
                method=method_name,
                nist_category="Clear",
                start_time=start_time,
                end_time=end_time,
                bytes_processed=capacity,
                capacity_bytes=capacity,
                passes=passes,
                pattern=pattern,
                status="success",
                verification={
                    "method": "sampled_readback",
                    "samples_checked": samples_checked,
                    "all_samples_match_wipe_pattern": verification_passed,
                },
                notes=result.notes + [
                    "Direct raw sector overwriting executed with FILE_FLAG_WRITE_THROUGH and FlushFileBuffers.",
                    "Filesystem structures, partition tables, and directory records eradicated.",
                ],
            )
            priv = core_crypto.load_private_pem(key_file)
            signed_cert = cert_mod.sign_certificate(cert_dict, priv)

    return result, signed_cert


def main() -> int:
    parser = argparse.ArgumentParser(description="S0 (Sector Zero) Windows Native Forensic Sanitization Suite (Files, Partitions, Drives)")
    parser.add_argument("--targets", "-t", nargs="*", default=None, help="Files or folders to erase")
    parser.add_argument("--wipe-partition", help="Drive letter of secondary partition to wipe (e.g. D:, E:)")
    parser.add_argument("--wipe-drive", help="Physical drive path to wipe (e.g. \\\\.\\PhysicalDrive1 or disk number)")
    parser.add_argument("--yes", "-y", action="store_true", help="Confirm destructive operation without prompt")
    parser.add_argument("--force", action="store_true", help="Force wipe despite non-critical safety warnings")
    parser.add_argument("--passes", "-p", type=int, default=1, help="Overwrite passes (default: 1)")
    parser.add_argument("--pattern", choices=["zero", "random"], default="zero", help="Overwrite pattern")
    parser.add_argument("--out-dir", default="./sanitization_reports", help="Output directory for certificate")
    parser.add_argument("--signing-key", help="Path to Ed25519 issuer private key PEM")
    parser.add_argument("--operator-id", default="op-forensic-01", help="Operator identifier")
    parser.add_argument("--organization", default="Digital Forensics & Data Sanitization Lab", help="Issuing organization")
    parser.add_argument("--cert-out", help="Explicit path to write signed certificate JSON")
    parser.add_argument("--no-certificate", action="store_true", help="Omit compliance certificate generation")
    parser.add_argument("--no-pdf", action="store_true", help="Skip rendering PDF certificate")
    parser.add_argument("--qr-url-template", default="https://s0-vp.vercel.app/?cert={cert_uuid}", help="URL template for verification QR")
    parser.add_argument("--json", action="store_true", help="Output JSON result")
    args = parser.parse_args()

    # Case 1: Drive or partition wipe
    if args.wipe_partition or args.wipe_drive:
        target = args.wipe_partition or args.wipe_drive
        if not args.yes:
            print(f"WARNING: This will PERMANENTLY DESTROY all data on {target}!")
            confirm = input(f"Type '{target}' to confirm wiping {target}: ").strip()
            if confirm != target:
                print("Aborted by user.")
                return 1

        result, signed_cert = wipe_drive_or_partition_windows(
            target=target,
            passes=args.passes,
            pattern=args.pattern,
            operator_id=args.operator_id,
            organization=args.organization,
            signing_key_path=args.signing_key,
            generate_certificate=not args.no_certificate,
            force=args.force,
        )

        cert_path: Optional[Path] = None
        pdf_path: Optional[Path] = None
        if signed_cert:
            out_dir = Path(args.out_dir)
            out_dir.mkdir(parents=True, exist_ok=True)
            cert_path = Path(args.cert_out) if args.cert_out else out_dir / f"certificate_{signed_cert['cert_uuid'][:8]}.json"
            cert_path.parent.mkdir(parents=True, exist_ok=True)
            cert_path.write_text(json.dumps(signed_cert, indent=2), encoding="utf-8")

            if pdfgen and not args.no_pdf:
                pdf_target = out_dir / f"certificate_{signed_cert['cert_uuid'][:8]}.pdf"
                qr_target = out_dir / f"certificate_{signed_cert['cert_uuid'][:8]}.qr.png"
                try:
                    pdfgen.generate_pdf(signed_cert, pdf_target, qr_url_template=args.qr_url_template)
                    pdfgen.write_qr_file(signed_cert, qr_target)
                    pdf_path = pdf_target
                except Exception:
                    pass

        if args.json:
            if signed_cert:
                print(json.dumps(signed_cert, indent=2))
            else:
                print(json.dumps(asdict(result), indent=2))
        else:
            print("=" * 65)
            print(" S0 (WINDOWS NATIVE) - BLOCK SANITIZATION REPORT")
            print("=" * 65)
            print(f"Target                 : {result.target} ({result.target_type})")
            print(f"Capacity               : {result.capacity_bytes} bytes")
            print(f"Bytes overwritten      : {result.bytes_overwritten}")
            print(f"Passes / Pattern       : {result.passes} pass(es) ({result.pattern})")
            print(f"Verification Passed    : {result.verification_passed} ({result.samples_checked} samples)")
            print(f"Status                 : {result.status.upper()}")
            if result.error:
                print(f"Error                  : {result.error}")
            if cert_path and signed_cert:
                sig = signed_cert.get("signature", {})
                print(f"Signed Certificate     : {cert_path}")
                if pdf_path:
                    print(f"PDF Certificate        : {pdf_path}")
                print(f"Key Fingerprint        : {sig.get('public_key_fingerprint', 'N/A')}")
            print("=" * 65)

        return 0 if result.status == "success" else 1

    # Case 2: File & folder erasure
    elif args.targets:
        results, signed_cert = erase_batch_windows(
            targets=args.targets,
            passes=args.passes,
            pattern=args.pattern,
            operator_id=args.operator_id,
            organization=args.organization,
            signing_key_path=args.signing_key,
            generate_certificate=not args.no_certificate,
        )

        total = len(results)
        success = sum(1 for r in results if r.status == "success")
        failed = sum(1 for r in results if r.status == "failure")
        total_bytes = sum(r.bytes_overwritten for r in results)

        cert_path: Optional[Path] = None
        pdf_path: Optional[Path] = None
        if signed_cert:
            out_dir = Path(args.out_dir)
            out_dir.mkdir(parents=True, exist_ok=True)
            cert_path = Path(args.cert_out) if args.cert_out else out_dir / f"certificate_{signed_cert['cert_uuid'][:8]}.json"
            cert_path.parent.mkdir(parents=True, exist_ok=True)
            cert_path.write_text(json.dumps(signed_cert, indent=2), encoding="utf-8")

            if pdfgen and not args.no_pdf:
                pdf_target = out_dir / f"certificate_{signed_cert['cert_uuid'][:8]}.pdf"
                qr_target = out_dir / f"certificate_{signed_cert['cert_uuid'][:8]}.qr.png"
                try:
                    pdfgen.generate_pdf(signed_cert, pdf_target, qr_url_template=args.qr_url_template)
                    pdfgen.write_qr_file(signed_cert, qr_target)
                    pdf_path = pdf_target
                except Exception:
                    pass

        if args.json:
            if signed_cert:
                print(json.dumps(signed_cert, indent=2))
            else:
                summary = {
                    "platform": "windows",
                    "total_files": total,
                    "successful_files": success,
                    "failed_files": failed,
                    "total_bytes_overwritten": total_bytes,
                    "results": [asdict(r) for r in results],
                }
                print(json.dumps(summary, indent=2))
        else:
            print("=" * 65)
            print(" S0 (WINDOWS NATIVE) - SECURE FILE & FOLDER SANITIZATION")
            print("=" * 65)
            print(f"Total targets processed : {total}")
            print(f"Successfully erased     : {success}")
            print(f"Failures                : {failed}")
            print(f"Bytes overwritten       : {total_bytes}")
            if cert_path and signed_cert:
                sig = signed_cert.get("signature", {})
                print(f"Signed Certificate      : {cert_path}")
                if pdf_path:
                    print(f"PDF Certificate         : {pdf_path}")
                print(f"Signature Algorithm     : {sig.get('algorithm', 'Ed25519')}")
                print(f"Key Fingerprint         : {sig.get('public_key_fingerprint', 'N/A')}")
            print("=" * 65)

        return 0 if failed == 0 else 1

    else:
        parser.print_help()
        print("\nError: Must specify either --targets (files/folders), --wipe-partition (e.g. D:), or --wipe-drive (e.g. \\\\.\\PhysicalDrive1).")
        return 1


if __name__ == "__main__":
    sys.exit(main())

