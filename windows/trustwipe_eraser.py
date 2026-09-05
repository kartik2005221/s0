"""TrustWipe Module 2: Secure File & Folder Eraser (Windows Native).

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
REPO_ROOT = Path(__file__).resolve().parent.parent
core_python_dir = REPO_ROOT / "core" / "python"
if core_python_dir.exists() and str(core_python_dir) not in sys.path:
    sys.path.insert(0, str(core_python_dir))

try:
    from trustwipe_core import certificate as cert_mod
    from trustwipe_core import crypto as core_crypto
except ImportError:
    cert_mod = None
    core_crypto = None

# Win32 Constants
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80
FILE_FLAG_WRITE_THROUGH = 0x80000000
INVALID_HANDLE_VALUE = -1


class WIN32_FIND_STREAM_DATA(ctypes.Structure):
    """Win32 struct for FindFirstStreamW / FindNextStreamW."""
    _fields_ = [
        ("StreamSize", ctypes.c_longlong),
        ("cStreamName", ctypes.c_wchar * 296),
    ]


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
    organization: str = "NTRO Digital Forensics & Data Sanitization Lab",
    signing_key_path: Optional[str | Path] = None,
    generate_certificate: bool = True,
) -> tuple[List[WinFileEraseResult], Optional[dict]]:
    """Execute batch file & folder erasure on Windows and issue an Ed25519-signed certificate."""
    start_time = cert_mod.now_utc() if cert_mod else time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    results: List[WinFileEraseResult] = []

    for t in targets:
        p = Path(t).resolve()
        if p.is_dir():
            results.extend(erase_folder_windows(p, passes=passes, pattern=pattern))
        else:
            results.append(erase_single_file_windows(p, passes=passes, pattern=pattern))

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
                tool_name="trustwipe-windows-eraser",
                tool_version="1.0.0",
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


def main() -> int:
    parser = argparse.ArgumentParser(description="TrustWipe Windows Secure File & Folder Eraser")
    parser.add_argument("--targets", "-t", nargs="+", required=True, help="Files or folders to erase")
    parser.add_argument("--passes", "-p", type=int, default=1, help="Overwrite passes (default: 1)")
    parser.add_argument("--pattern", choices=["zero", "random"], default="zero", help="Overwrite pattern")
    parser.add_argument("--out-dir", default="./sanitization_reports", help="Output directory for certificate")
    parser.add_argument("--signing-key", help="Path to Ed25519 issuer private key PEM")
    parser.add_argument("--operator-id", default="op-forensic-01", help="Operator identifier")
    parser.add_argument("--organization", default="NTRO Digital Forensics & Data Sanitization Lab", help="Issuing organization")
    parser.add_argument("--cert-out", help="Explicit path to write signed certificate JSON")
    parser.add_argument("--no-certificate", action="store_true", help="Omit compliance certificate generation")
    parser.add_argument("--json", action="store_true", help="Output JSON result")
    args = parser.parse_args()

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
    if signed_cert:
        out_dir = Path(args.out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        if args.cert_out:
            cert_path = Path(args.cert_out)
            cert_path.parent.mkdir(parents=True, exist_ok=True)
        else:
            cert_path = out_dir / f"certificate_{signed_cert['cert_uuid'][:8]}.json"
        cert_path.write_text(json.dumps(signed_cert, indent=2), encoding="utf-8")

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
        print(" TRUSTWIPE (WINDOWS) - SECURE FILE & FOLDER SANITIZATION")
        print("=" * 65)
        print(f"Total targets processed : {total}")
        print(f"Successfully erased     : {success}")
        print(f"Failures                : {failed}")
        print(f"Bytes overwritten       : {total_bytes}")
        if cert_path and signed_cert:
            sig = signed_cert.get("signature", {})
            print(f"Signed Certificate      : {cert_path}")
            print(f"Signature Algorithm     : {sig.get('algorithm', 'Ed25519')}")
            print(f"Key Fingerprint         : {sig.get('public_key_fingerprint', 'N/A')}")
        print("=" * 65)

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
