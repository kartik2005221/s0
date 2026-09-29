"""S0 (Sector Zero) — Unified Forensic Sanitization & Recovery CLI.

Subcommands:
  1. Secure Sanitization (Unified Wipe):
     s0 list                       inventory of block devices
     s0 plan  --target PATH        dry-run: method, tier, warnings
     s0 wipe  --target PATH        sanitize drive, file, or folder, verify, issue certificate
              --targets PATH...    batch sanitize multiple files and folders

  2. Advanced File Carving & Recovery:
     s0 carve --target PATH --out-dir DIR   signature & structure recovery

  3. Hash-Chained Audit Ledger:
     s0 audit list                 display cryptographic audit blocks
     s0 audit verify               verify hash-chain integrity

  4. Offline Verification & Key Management:
     s0 verify CERT_JSON           verify signed certificate offline
     s0 keygen                     generate Ed25519 authority/operator keypair

  5. Lifecycle & Management:
     s0 upgrade                    upgrade s0 suite from GitHub
     s0 uninstall                  safely remove s0 from the system

  6. Forensic Imaging & Cloning:
     s0 image --source SRC --dest DST       forensic disk copy
     s0 clone --source SRC --dest DST       device-to-device clone

  7. Bootable Live Media (Live ISO & USB Station):
     s0 live download              download official s0 Live ISO with SHA-256 check
     s0 live devices               list removable USB flash drives safely
     s0 live flash --target DEV    flash bootable Live ISO to USB pendrive
     s0 live build                 build Live ISO from source
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import shutil
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

_interrupted = threading.Event()

def _sigint_handler(signum, frame):
    """Set interrupt flag on first Ctrl+C; force-exit on second."""
    if _interrupted.is_set():
        sys.stderr.write("\n\n⚠  Forced exit.\n")
        sys.stderr.flush()
        os._exit(130)
    _interrupted.set()
    raise KeyboardInterrupt

if threading.current_thread() is threading.main_thread():
    try:
        signal.signal(signal.SIGINT, _sigint_handler)
    except (ValueError, AttributeError):
        pass

from s0_core import certificate as cert_mod
from s0_core.config import CONFIG
from s0_core.progress import ProgressBar

from . import __version__
from .audit import init_audit_db, list_audit_blocks, record_audit_event, verify_audit_ledger
from .carver import carve_image, signature_from_dict
from .devices import (
    SafetyError,
    check_safety,
    get_block_device_size,
    image_target,
    is_os_device,
    list_block_targets,
)
from .devices import Target as DevTarget
from .file_eraser import erase_batch
from .methods.ata import AtaSecureEraseMethod, hpa_dco_report
from .methods.base import Plan
from .methods.overwrite import OverwriteMethod, plant_patterns
from .temperature import read_temperature
from .wipe import (
    default_issuer_key,
    make_certificate,
    select_method,
    take_pre_samples,
    verify_wipe,
)


from s0_core.crypto import is_demo_key


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _validate_portal_url(url: Optional[str]) -> Optional[str]:
    if not url:
        return url
    import urllib.parse
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("https", "http"):
        sys.stderr.write(f"\n❌ Error: Invalid portal URL scheme '{parsed.scheme}': must be http or https\n")
        sys.exit(1)
    if parsed.scheme == "http" and parsed.hostname not in ("localhost", "127.0.0.1"):
        sys.stderr.write("\n❌ Error: Plaintext HTTP portal URL is restricted to localhost/127.0.0.1; use HTTPS for remote hosts\n")
        sys.exit(1)
    if parsed.username or parsed.password:
        sys.stderr.write("\n❌ Error: Portal URL must not contain embedded user credentials (@)\n")
        sys.exit(1)
    if any(c in url for c in '<>"\'`\\| '):
        sys.stderr.write("\n❌ Error: Portal URL contains disallowed characters\n")
        sys.exit(1)
    return url



def _warn_if_demo_key(key_path: Path | None) -> None:
    if key_path is not None and is_demo_key(key_path):
        sys.stderr.write(
            "\n\033[33m[!] NOTICE: Operation signed with unaccredited demonstration key (demo_issuer_private.pem).\n"
            "    DO NOT use this certificate for legal chain-of-custody or regulatory compliance.\033[0m\n\n"
        )


def _validate_cli_metadata(args) -> bool:
    """Validate operator and organization metadata arguments. Returns False on validation error."""
    from s0_core.validation import validate_metadata_str
    for attr, max_len in (("operator", 64), ("operator_id", 64), ("organization", 128)):
        val = getattr(args, attr, None)
        if val is not None:
            try:
                cleaned = validate_metadata_str(attr, val, max_len=max_len)
                setattr(args, attr, cleaned)
            except ValueError as exc:
                print(f"error: invalid --{attr.replace('_', '-')}: {exc}", file=sys.stderr)
                return False
    return True


_S0_ASCII = r"""
            /$$$$$$ 
           /$$$_  $$
  /$$$$$$$| $$$$\ $$
 /$$_____/| $$ $$ $$
|  $$$$$$ | $$\ $$$$
 \____  $$| $$ \ $$$
 /$$$$$$$/|  $$$$$$/
|_______/  \______/  
"""


def _print_banner() -> None:
    """Show ASCII banner only on interactive TTY, bare s0, or s0 --help."""
    if not sys.stdout.isatty():
        return
    cyan = "\033[1;36m"
    bold = "\033[1m"
    dim = "\033[2m"
    link = "\033[4;36m"
    reset = "\033[0m"
    for line in _S0_ASCII.strip("\n").split("\n"):
        print(f"{cyan}{line}{reset}")
    ver = CONFIG.get("version", __version__)
    print(f"{bold}  Sector Zero (s0){reset} v{ver}")
    print(f"  {dim}@kartik2005221{reset}  {link}https://github.com/kartik2005221/s0{reset}\n")


_LEGAL_NOTICE = (
    "\n\033[1;33m⚖  LEGAL & RESPONSIBLE USE NOTICE:\033[0m\n"
    "\033[33m   Only operate on storage media you own or have explicit written authorization\n"
    "   to process. Unauthorized wiping, erasure, or forensic recovery may violate\n"
    "   computer crime legislation (e.g., CFAA 18 U.S.C. § 1030, Computer Misuse Act,\n"
    "   IT Act 2000 §§ 43/66). s0 is a digital forensic sanitization and recovery tool.\033[0m\n\n"
)


def _print_legal_notice() -> None:
    if os.environ.get("S0_LEGAL_NOTICE_SHOWN"):
        return
    os.environ["S0_LEGAL_NOTICE_SHOWN"] = "1"
    sys.stderr.write(_LEGAL_NOTICE)


def resolve_target(path: str) -> DevTarget:
    if sys.platform == "win32":
        if path.startswith("/dev/"):
            raise SafetyError(
                f"'{path}' is a Linux/UNIX device path and is not valid on Windows.\n"
                f"  Tip: On Windows, use drive letters (e.g. D:, E:) or physical drive paths (\\\\.\\PhysicalDrive1).\n"
                f"  Run 's0 list' to inspect detected drive targets on this machine."
            )
        if (
            (":" in path and len(path.strip()) <= 3)
            or "physicaldrive" in path.lower()
            or path.startswith("\\\\.\\")
        ):
            sz = 0
            try:
                from windows.cli.s0_eraser import get_windows_target_size
                sz = get_windows_target_size(path)
            except Exception:
                pass
            return DevTarget(path=path, kind="block", capacity_bytes=sz, storage_type="UNKNOWN")

    if sys.platform != "win32" and ((":" in path and len(path.strip()) <= 3) or path.startswith("\\\\.\\") or "physicaldrive" in path.lower()):
        os_name = "macOS" if sys.platform == "darwin" else "Linux"
        tip_example = "/dev/disk2" if sys.platform == "darwin" else "/dev/sdb or /dev/nvme0n1"
        raise SafetyError(
            f"'{path}' is a Windows device path and is not valid on {os_name}.\n"
            f"  Tip: On {os_name}, use block/raw device nodes such as {tip_example}.\n"
            f"  Run 's0 list' to inspect detected drive targets on this machine."
        )

    if sys.platform == "darwin" and (path.startswith("/dev/rdisk") or path.startswith("/dev/disk")):
        sz = 0
        try:
            from macos.cli.s0_eraser import get_macos_target_size
            sz = get_macos_target_size(path)
        except Exception:
            pass
        rpath = path.replace("/dev/disk", "/dev/rdisk")
        return DevTarget(path=rpath, kind="block", capacity_bytes=sz, storage_type="UNKNOWN")

    p = Path(path)
    is_blk = False
    try:
        is_blk = p.is_block_device() or (sys.platform == "darwin" and p.is_char_device())
    except Exception:
        pass
    if is_blk:
        for t in list_block_targets():
            if Path(t.path).resolve() == p.resolve():
                return t
        size = get_block_device_size(p)
        if size <= 0:
            raise SafetyError(f"Block device {p} has zero or unreadable capacity.")
        return DevTarget(path=str(p), kind="block", capacity_bytes=size)
    return image_target(path)


_resolve_target = resolve_target


def _print_plan(
    target: DevTarget, candidate, alternatives, warnings: list[str], hpa_dco: dict | None
) -> None:
    m = candidate.method
    gib = target.capacity_bytes / (1024**3)
    size_str = f"{gib:.1f} GiB" if gib >= 1 else (f"{target.capacity_bytes / (1024**2):.1f} MiB" if target.capacity_bytes >= 1024**2 else f"{target.capacity_bytes} B")
    print(f"[s0 plan]  Target        : {target.path} ({target.kind}, {target.storage_type}, {size_str})")
    if m is None:
        print("[s0 plan]  Method        : NONE AVAILABLE")
        print(f"[s0 plan]  Reason        : {candidate.reason}")
        return
    plan: Plan = m.plan(target)
    print(f"[s0 plan]  Method        : {plan.method_id}")
    print(f"[s0 plan]  NIST Category : {plan.nist_category}")
    print(f"[s0 plan]  Summary       : {plan.summary}")
    if plan.method_id.startswith("ATA_SECURE_ERASE") or "NVME" in plan.method_id:
        print("[s0 plan]  Firmware Note : Firmware-level Purge methods are simulated/fixture-tested;")
        print("                         real-world behavior varies across vendors. Verify device support.")
    if plan.commands:
        print("[s0 plan]  Commands      :")
        for c in plan.commands:
            print(f"[s0 plan]    - {c}")
    all_warnings = warnings + plan.warnings
    if all_warnings:
        print("[s0 plan]  Warnings      :")
        for w in all_warnings:
            print(f"[s0 plan]    ! {w}")
    if alternatives:
        print("[s0 plan]  Alternatives  :")
        for a in alternatives:
            state = "available" if a.available else "unavailable"
            print(f"[s0 plan]    - [{state}] {a.reason}")
    if hpa_dco and (
        hpa_dco.get("hpa_present") or hpa_dco.get("dco_present") or hpa_dco.get("note")
    ):
        print("[s0 plan]  HPA/DCO       :")
        hpa_status = "Detected" if hpa_dco.get("hpa_present") else ("None" if hpa_dco.get("hpa_present") is False else "Unknown")
        dco_status = "Detected" if hpa_dco.get("dco_present") else ("None" if hpa_dco.get("dco_present") is False else "Unknown")
        print(f"[s0 plan]    HPA Present : {hpa_status}")
        print(f"[s0 plan]    DCO Present : {dco_status}")
        if hpa_dco.get("note"):
            print(f"[s0 plan]    Note        : {hpa_dco['note']}")
        if hpa_dco.get("restore_command"):
            print(f"[s0 plan]    Action      : remove BEFORE wiping: {hpa_dco['restore_command']}")


# --------------------------------------------------------------------------- #
# Module 1: Media & File Sanitization Subcommands
# --------------------------------------------------------------------------- #


def cmd_list(args) -> int:
    targets = list_block_targets()
    mounted = set()
    try:
        with open("/proc/mounts") as f:
            mounted = {line.split()[0] for line in f}
    except OSError:
        pass

    if getattr(args, "output_format", "text") == "json":
        data = [
            {
                "path": t.path,
                "kind": t.kind,
                "storage_type": t.storage_type,
                "capacity_bytes": t.capacity_bytes,
                "model": t.model,
                "serial": t.serial,
                "mounted": any(m.startswith(t.path) for m in mounted),
                "os_drive": is_os_device(t.path),
            }
            for t in targets
        ]
        print(json.dumps(data, indent=2))
        return 0

    if not targets:
        print("(no block devices found)")
        return 0
    print("[s0 list]  Inventorying attached block devices and forensic images...\n")
    path_w = max(14, max(len(t.path) for t in targets))
    print(
        f"{'PATH':<{path_w}} {'TYPE':<7} {'STORAGE':<10} {'CAPACITY':>12}  "
        f"{'MODEL':<24} {'SERIAL':<16} {'MOUNTED?':<9} OS_DRIVE?"
    )
    for t in targets:
        cap = f"{t.capacity_bytes / 2**30:.1f} GiB"
        is_mounted = "YES" if any(m.startswith(t.path) for m in mounted) else "-"
        is_os = "YES [OS]" if is_os_device(t.path) else "-"
        print(
            f"{t.path:<{path_w}} {t.kind:<7} {t.storage_type:<10} {cap:>12}  "
            f"{(t.model or '—')[:24]:<24} {(t.serial or '—')[:16]:<16} {is_mounted:<9} {is_os}"
        )
    print("\nImage-file targets work too (no root needed): use --target /path/to/file.img")
    return 0


def cmd_plan(args) -> int:
    if not getattr(args, "target", None):
        print("error: the following arguments are required: --target", file=sys.stderr)
        return 2

    try:
        target = _resolve_target(args.target)
    except (FileNotFoundError, SafetyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if target.capacity_bytes <= 0:
        print(f"error: target {target.path} has zero or unreadable capacity.", file=sys.stderr)
        return 2

    if sys.platform == "win32" and target.kind == "block":
        gib = target.capacity_bytes / (1024**3)
        size_str = f"{gib:.1f} GiB" if gib >= 1 else f"{target.capacity_bytes / (1024**2):.1f} MiB"
        print(f"[s0 plan]  Target        : {target.path} ({target.kind}, {target.storage_type}, {size_str})")
        print(f"[s0 plan]  Method        : OVERWRITE_ZERO_1PASS")
        print(f"[s0 plan]  NIST Category : Clear")
        print(f"[s0 plan]  Summary       : Windows raw volume/drive overwriting with volume lock and dismount")
        print("\n[s0 plan]  DRY RUN — nothing was written. Run `s0 wipe` when satisfied.")
        return 0

    if sys.platform == "darwin" and target.kind == "block":
        gib = target.capacity_bytes / (1024**3)
        size_str = f"{gib:.1f} GiB" if gib >= 1 else f"{target.capacity_bytes / (1024**2):.1f} MiB"
        print(f"[s0 plan]  Target        : {target.path} ({target.kind}, {target.storage_type}, {size_str})")
        print(f"[s0 plan]  Method        : OVERWRITE_ZERO_1PASS")
        print(f"[s0 plan]  NIST Category : Clear")
        print(f"[s0 plan]  Summary       : macOS raw character device (/dev/rdisk) overwriting with fcntl(F_FULLFSYNC)")
        print("\n[s0 plan]  DRY RUN — nothing was written. Run `s0 wipe` when satisfied.")
        return 0

    try:
        warnings = check_safety(target, force=args.force)
    except SafetyError as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2

    candidate, alternatives = select_method(
        target,
        passes=args.passes,
        pattern=args.pattern,
        prefer_firmware=not args.no_firmware,
        discard_justification=args.discard_purge_justification,
    )
    hpa_dco = None
    if target.kind == "block" and not target.path.startswith("/dev/nvme") and shutil.which("hdparm"):
        hpa_dco = hpa_dco_report(target)
    _print_plan(target, candidate, alternatives, warnings, hpa_dco)
    print("\n[s0 plan]  DRY RUN — nothing was written. Run `s0 wipe` when satisfied.")
    return 0


def cmd_wipe(args) -> int:
    _print_legal_notice()
    if not _validate_cli_metadata(args):
        return 2

    pattern = getattr(args, "pattern", "zero")
    if pattern not in ("zero", "random"):
        print(f"error: invalid --pattern '{pattern}'. Supported patterns: zero, random", file=sys.stderr)
        return 2

    targets = getattr(args, "targets", None)
    target_arg = getattr(args, "target", None)

    if not targets and not target_arg:
        print("error: one of --target or --targets is required", file=sys.stderr)
        return 2

    is_file_mode = False
    if targets:
        for tgt in targets:
            try:
                p = Path(tgt)
                if p.is_block_device() or (sys.platform == "darwin" and p.is_char_device()) or (sys.platform == "win32" and str(tgt).lower().startswith(("\\\\.\\", "//./"))):
                    print(
                        f"error: '{tgt}' is a block storage device. Use '--target {tgt}' for whole-drive sanitization. '--targets' is strictly for files and directories.",
                        file=sys.stderr,
                    )
                    return 2
            except Exception:
                pass
        is_file_mode = True
        args.targets = targets
    elif target_arg:
        t_path = Path(target_arg)
        is_blk = False
        try:
            is_blk = t_path.is_block_device() or (sys.platform == "darwin" and t_path.is_char_device())
        except Exception:
            pass

        if not is_blk:
            if t_path.is_dir():
                is_file_mode = True
                args.targets = [target_arg]
            elif t_path.is_file() and t_path.suffix.lower() not in (".img", ".raw", ".iso", ".bin"):
                is_file_mode = True
                args.targets = [target_arg]

    if is_file_mode:
        return cmd_erase_files(args)

    passes_val = getattr(args, "passes", 1)
    if passes_val < 1 or passes_val > 100:
        print(f"error: --passes must be between 1 and 100 (got {passes_val}).", file=sys.stderr)
        return 2

    samples_val = getattr(args, "verify_samples", 64)
    if samples_val < 1 or samples_val > 10000:
        print(f"error: --verify-samples must be between 1 and 10000 (got {samples_val}).", file=sys.stderr)
        return 2

    t_start = time.monotonic()
    start_time = _now()
    try:
        target = _resolve_target(args.target)
    except (FileNotFoundError, SafetyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if target.capacity_bytes <= 0:
        print(f"error: target {target.path} has zero or unreadable capacity.", file=sys.stderr)
        return 2

    if sys.platform == "win32" and target.kind == "block":
        try:
            from windows.cli.s0_eraser import wipe_drive_or_partition_windows, check_windows_wipe_safety
        except ImportError:
            print("error: Windows drive wipe requires the s0 Windows engine (windows.cli.s0_eraser).\n"
                  "  Ensure the S0 installation includes Windows components or repo root is on sys.path.", file=sys.stderr)
            return 2
        try:
            check_windows_wipe_safety(target.path, force=args.force)
        except PermissionError as exc:
            print(f"REFUSED: {exc}", file=sys.stderr)
            return 2

        if not args.yes:
            print(f"\n[s0 wipe]  Target        : {target.path}")
            print(f"[s0 wipe]  Method        : OVERWRITE_ZERO_1PASS (Windows Native)")
            print(f"[s0 wipe]  NIST Category : Clear")
            print(f"[s0 wipe]  Summary       : Windows raw volume overwrite with volume lock and dismount")
            ans = input(f"\nType '{target.path}' to confirm permanent erasure of {target.path} (Windows Native): ")
            if ans.strip() != str(target.path):
                print("aborted — nothing was written", file=sys.stderr)
                return 2
        else:
            sys.stderr.write(f"[s0 wipe plan] target={target.path} method=OVERWRITE_ZERO_1PASS tier=Clear\n")

        key_path = default_issuer_key(args.key)
        _warn_if_demo_key(key_path)
        res_win, cert = wipe_drive_or_partition_windows(
            target=target.path,
            passes=args.passes,
            pattern=args.pattern,
            operator_id=args.operator,
            organization=args.organization,
            signing_key_path=key_path,
            generate_certificate=True,
            force=args.force,
        )
        if not cert:
            print(f"error: wiping failed: {res_win.error}", file=sys.stderr)
            return 1

        try:
            blk = record_audit_event(cert, operation_type="DRIVE_ERASE", private_key=key_path)
            if not getattr(args, "json", False):
                print(f"[s0 wipe]  Audit Ledger  : recorded block #{blk.block_index} ({blk.block_hash[:16]}...)")
        except Exception as exc:
            print(f"WARNING: failed to record event into audit ledger: {exc}", file=sys.stderr)

        out_dir = Path(args.out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        cert_json = out_dir / f"certificate_{cert['cert_uuid'][:8]}.json"
        cert_json.write_text(json.dumps(cert, indent=2) + "\n")

        qr_url_tpl = args.qr_url_template
        portal_url_val = _validate_portal_url(getattr(args, "portal_url", None))
        if portal_url_val and "{cert_uuid}" not in portal_url_val:
            qr_url_tpl = f"{portal_url_val.rstrip('/')}/?cert={{cert_uuid}}"

        pdf_path = None
        if not args.no_pdf:
            from s0_core import pdfgen
            pdf_path = out_dir / f"certificate_{cert['cert_uuid'][:8]}.pdf"
            pdfgen.generate_pdf(cert, pdf_path, qr_url_template=qr_url_tpl)
            pdfgen.write_qr_file(cert, out_dir / f"certificate_{cert['cert_uuid'][:8]}.qr.png")

        if args.json:
            print(json.dumps({"status": cert["result"]["status"], "certificate": str(cert_json), "pdf": str(pdf_path) if pdf_path else None, "cert_uuid": cert["cert_uuid"]}, indent=2))
        else:
            print(f"\n[s0 wipe]  Result        : {cert['result']['status']}")
            print(f"[s0 wipe]  Certificate   : {cert_json}")
            if pdf_path:
                print(f"[s0 wipe]  PDF           : {pdf_path}")
        return 0 if res_win.status == "success" else 1

    if sys.platform == "darwin" and target.kind == "block":
        try:
            from macos.cli.s0_eraser import wipe_drive_or_partition_macos, check_macos_wipe_safety
        except ImportError:
            print("error: macOS drive wipe requires the s0 macOS engine (macos.cli.s0_eraser).\n"
                  "  Ensure the S0 installation includes macOS components or repo root is on sys.path.", file=sys.stderr)
            return 2
        try:
            check_macos_wipe_safety(target.path, force=args.force)
        except PermissionError as exc:
            print(f"REFUSED: {exc}", file=sys.stderr)
            return 2

        if not args.yes:
            print(f"\n[s0 wipe]  Target        : {target.path}")
            print(f"[s0 wipe]  Method        : OVERWRITE_ZERO_1PASS (macOS Native)")
            print(f"[s0 wipe]  NIST Category : Clear")
            print(f"[s0 wipe]  Summary       : macOS raw character device (/dev/rdisk) overwrite with fcntl(F_FULLFSYNC)")
            print(f"[s0 wipe]  HPA/DCO       : Not supported on macOS (requires Linux with hdparm)")
            ans = input(f"\nType '{target.path}' to confirm permanent erasure of {target.path} (macOS Native): ")
            if ans.strip() != str(target.path):
                print("aborted — nothing was written", file=sys.stderr)
                return 2
        else:
            sys.stderr.write(f"[s0 wipe plan] target={target.path} method=OVERWRITE_ZERO_1PASS tier=Clear\n")

        key_path = default_issuer_key(args.key)
        _warn_if_demo_key(key_path)
        res_mac, cert = wipe_drive_or_partition_macos(
            target=target.path,
            passes=args.passes,
            pattern=args.pattern,
            operator_id=args.operator,
            organization=args.organization,
            signing_key_path=key_path,
            generate_certificate=True,
            force=args.force,
        )
        if not cert:
            print(f"error: wiping failed: {res_mac.error}", file=sys.stderr)
            return 1

        try:
            blk = record_audit_event(cert, operation_type="DRIVE_ERASE", private_key=key_path)
            if not getattr(args, "json", False):
                print(f"[s0 wipe]  Audit Ledger  : recorded block #{blk.block_index} ({blk.block_hash[:16]}...)")
        except Exception as exc:
            print(f"WARNING: failed to record event into audit ledger: {exc}", file=sys.stderr)

        out_dir = Path(args.out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        cert_json = out_dir / f"certificate_{cert['cert_uuid'][:8]}.json"
        cert_json.write_text(json.dumps(cert, indent=2) + "\n")

        qr_url_tpl = args.qr_url_template
        portal_url_val = _validate_portal_url(getattr(args, "portal_url", None))
        if portal_url_val and "{cert_uuid}" not in portal_url_val:
            qr_url_tpl = f"{portal_url_val.rstrip('/')}/?cert={{cert_uuid}}"

        pdf_path = None
        if not args.no_pdf:
            from s0_core import pdfgen
            pdf_path = pdfgen.generate_pdf(
                cert,
                out_dir / f"certificate_{cert['cert_uuid'][:8]}.pdf",
                qr_url_template=qr_url_tpl,
            )
            pdfgen.write_qr_file(cert, out_dir / f"certificate_{cert['cert_uuid'][:8]}.qr.png")

        if args.json:
            print(json.dumps({"status": cert["result"]["status"], "certificate": str(cert_json), "pdf": str(pdf_path) if pdf_path else None, "cert_uuid": cert["cert_uuid"]}, indent=2))
        else:
            print(f"\n[s0 wipe]  Result        : {cert['result']['status']}")
            print(f"[s0 wipe]  Certificate   : {cert_json}")
            if pdf_path:
                print(f"[s0 wipe]  PDF           : {pdf_path}")
        return 0 if res_mac.status == "success" else 1

    try:
        warnings = check_safety(target, force=args.force)
    except SafetyError as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2
    for w in warnings:
        print(f"WARNING: {w}", file=sys.stderr)

    candidate, alternatives = select_method(
        target,
        passes=args.passes,
        pattern=args.pattern,
        prefer_firmware=not args.no_firmware,
        discard_justification=args.discard_purge_justification,
    )
    if candidate.method is None:
        print(f"error: no applicable wipe method ({candidate.reason})", file=sys.stderr)
        return 2

    plan = candidate.method.plan(target)

    hpa_dco = None
    is_virtual_block = target.path.startswith(("/dev/loop", "/dev/ram", "/dev/zram"))
    if target.kind == "block" and not target.path.startswith("/dev/nvme") and not is_virtual_block:
        if not shutil.which("hdparm"):
            hpa_msg = (
                f"hdparm is not installed — cannot verify whether {target.path} has "
                f"a Host Protected Area (HPA) or Device Configuration Overlay (DCO). "
                f"Install hdparm or pass --force to proceed without verification."
            )
            if not args.force:
                print(f"REFUSED: {hpa_msg}", file=sys.stderr)
                return 2
            warnings.append(hpa_msg)
        else:
            hpa_dco = hpa_dco_report(target)
            hpa_present = hpa_dco.get("hpa_present")
            dco_present = hpa_dco.get("dco_present")
            is_fw = plan.method_id.startswith("ATA_SECURE_ERASE") or "NVME" in plan.method_id
            if hpa_present is None and dco_present is None:
                hpa_msg = (
                    f"HPA/DCO status for {target.path} is indeterminate "
                    f"({hpa_dco.get('note') or 'device did not respond to hdparm'}). "
                    f"Pass --force to proceed anyway."
                )
                if not args.force:
                    print(f"REFUSED: {hpa_msg}", file=sys.stderr)
                    return 2
                warnings.append(hpa_msg)
            elif (hpa_present or dco_present) and not is_fw:
                hpa_msg = (
                    f"target {target.path} has an active Host Protected Area (HPA) or Device Configuration Overlay (DCO) "
                    f"(visible: {hpa_dco.get('visible_max')}, native: {hpa_dco.get('native_max')}). "
                    f"Overwrite-based sanitization ({plan.method_id}) cannot reach hidden sectors beyond visible capacity."
                )
                if not args.force:
                    print(
                        f"REFUSED: {hpa_msg}\n  Remove HPA/DCO using '{hpa_dco.get('restore_command')}' or pass --force to proceed anyway.",
                        file=sys.stderr,
                    )
                    return 2
                warnings.append(hpa_msg)

    if not args.yes:
        _print_plan(target, candidate, alternatives, warnings, hpa_dco)
        if "ATA_SECURE_ERASE" in plan.method_id or "NVME" in plan.method_id:
            print("\n⚠  NOTICE: Firmware-level Purge methods (ATA/NVMe) are simulated/fixture-tested;", file=sys.stderr)
            print("   real-world behavior varies across vendors. Verify device support prior to production use.", file=sys.stderr)
        answer = input(
            f"\nType '{target.path}' to confirm permanent erasure ({plan.method_id}, NIST {plan.nist_category}): "
        )
        if answer.strip() != str(target.path):
            print("aborted — nothing was written", file=sys.stderr)
            return 2
    else:
        sys.stderr.write(f"[s0 wipe plan] target={target.path} method={plan.method_id} tier={plan.nist_category}\n")

    planted = None
    pre_samples = None
    offsets = None
    if args.plant_markers:
        marker = b"S0-DEMO-CONFIDENTIAL-" + secrets.token_hex(8).encode()
        count = max(8, target.capacity_bytes // (4 * 1024 * 1024))
        if not getattr(args, "json", False):
            print(f"[s0 wipe] Planting {count} verification markers...", file=sys.stderr)
        plant_patterns(
            target.path,
            [(i * (target.capacity_bytes // count), marker) for i in range(count)],
            progress_fn=lambda msg: sys.stderr.write(f"\r[s0 wipe] {msg}  ") if not getattr(args, "json", False) else None,
        )
        if not getattr(args, "json", False):
            sys.stderr.write("\n")
        planted = [marker]
        print(f"planted {count} copies of a demo marker (will require 0 hits after)", file=sys.stderr)

    if args.pattern == "random":
        offsets, pre_samples = take_pre_samples(target, samples=getattr(args, "verify_samples", 64))

    # Initialize unified progress bar
    total_bytes = target.capacity_bytes * getattr(args, "passes", 1)
    bar = ProgressBar(total_bytes, operation="s0 wipe")
    _last_temp_time: list[float] = [0.0]  # mutable cell so the closure can mutate it
    _last_temp_val: list = [None]

    def _get_temp() -> str:
        """Return temperature string, throttled to at most once per 2 seconds."""
        now = time.monotonic()
        if now - _last_temp_time[0] >= 2.0:
            _last_temp_time[0] = now
            _last_temp_val[0] = read_temperature(target.path)
        t = _last_temp_val[0]
        return f"Temp: {t}°C" if t is not None else ""

    def progress(msg: str) -> None:
        temp_str = _get_temp()

        # Overwrite progress matching: "pass X/Y: N.N Unit / M.M Unit ..."
        m_over = re.search(r"pass (\d+)/(\d+):\s+([\d.]+)\s+(B|KiB|MiB|GiB|TiB)", msg)
        if m_over:
            p_idx = int(m_over.group(1)) - 1
            val = float(m_over.group(3))
            unit = m_over.group(4)
            mult = {"B": 1, "KiB": 1024, "MiB": 1048576, "GiB": 1073741824, "TiB": 1099511627776}.get(unit, 1)
            bytes_in_pass = int(val * mult)
            curr_total = (p_idx * target.capacity_bytes) + bytes_in_pass
            bar.update(curr_total, extra=temp_str)
            return

        # Discard progress matching
        m_disc = re.search(r"\((\d+)%\)", msg)
        if m_disc:
            pct = int(m_disc.group(1))
            bar.update(int(target.capacity_bytes * (pct / 100.0)), extra=temp_str)
            return

        # Sanitize percentage matching
        m_san = re.search(r"sanitize progress:\s+(\d+)%", msg)
        if m_san:
            pct = int(m_san.group(1))
            bar.update(int(target.capacity_bytes * (pct / 100.0)), extra=temp_str)
            return

        # Fallback for milestone / step lines
        if not getattr(args, "json", False):
            print(f"[{time.monotonic() - t_start:8.1f}s] {msg}", file=sys.stderr)

    progress(f"wiping {target.display} with {plan.method_id} (NIST {plan.nist_category})")
    try:
        result = candidate.method.run(target, progress)
        temp = read_temperature(target.path)
        temp_str = f"Temp: {temp}°C" if temp is not None else ""
        bar.finish(extra=temp_str)
        if not getattr(args, "json", False):
            print("[s0 wipe] Sanitization pass complete. Buffers flushed to disk.", file=sys.stderr)
    except KeyboardInterrupt:
        bar.finish(extra="CANCELLED")
        print("\n⚠  Wipe interrupted by user (Ctrl+C). Target may be partially overwritten.", file=sys.stderr)
        return 130
    end_time = _now()

    verif, _post = verify_wipe(
        target,
        args.pattern,
        samples=args.verify_samples,
        planted_needles=planted,
        pre_samples=pre_samples,
        offsets=offsets,
    )
    if not verif.get("all_samples_match_wipe_pattern", False):
        result.status = "failure"
        result.errors.append(
            "post-wipe verification FAILED — sampled sectors did not match expected pattern"
        )

    key_path = default_issuer_key(args.key)
    _warn_if_demo_key(key_path)
    if key_path is None:
        print("error: no issuer signing key found.", file=sys.stderr)
        return 2

    cert = make_certificate(
        target,
        candidate.method,
        result,
        start_time,
        end_time,
        operator_id=args.operator,
        organization=args.organization,
        tool_version=__version__,
        key_path=key_path,
        verification=verif,
        extra_notes=warnings + [f"elapsed {time.monotonic() - t_start:.1f}s"],
    )

    # Record in local hash-chained audit ledger
    try:
        blk = record_audit_event(cert, operation_type="DRIVE_ERASE", private_key=key_path)
        if not getattr(args, "json", False):
            print(f"[s0 wipe]  Audit Ledger  : recorded block #{blk.block_index} ({blk.block_hash[:16]}...)")
    except Exception as exc:
        print(f"WARNING: failed to record event into audit ledger: {exc}", file=sys.stderr)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    cert_json = out_dir / f"certificate_{cert['cert_uuid'][:8]}.json"
    cert_json.write_text(json.dumps(cert, indent=2) + "\n")

    # Resolve URL template
    qr_url_tpl = args.qr_url_template
    portal_url_val = _validate_portal_url(getattr(args, "portal_url", None))
    if portal_url_val and "{cert_uuid}" not in portal_url_val:
        qr_url_tpl = f"{portal_url_val.rstrip('/')}/?cert={{cert_uuid}}"

    pdf_path = None
    if not args.no_pdf:
        from s0_core import pdfgen

        pdf_path = pdfgen.generate_pdf(
            cert,
            out_dir / f"certificate_{cert['cert_uuid'][:8]}.pdf",
            qr_url_template=qr_url_tpl,
        )
        pdfgen.write_qr_file(cert, out_dir / f"certificate_{cert['cert_uuid'][:8]}.qr.png")

    ok = result.status == "success" and verif.get("all_samples_match_wipe_pattern") is True
    if args.json:
        print(
            json.dumps(
                {
                    "status": cert["result"]["status"],
                    "verified": verif.get("all_samples_match_wipe_pattern"),
                    "certificate": str(cert_json),
                    "pdf": str(pdf_path) if pdf_path else None,
                    "cert_uuid": cert["cert_uuid"],
                },
                indent=2,
            )
        )
    else:
        print(f"\n[s0 wipe]  Result        : {cert['result']['status']}")
        print(f"[s0 wipe]  Verification  : {json.dumps(verif)}")
        print(f"[s0 wipe]  Certificate   : {cert_json}")
        if pdf_path:
            print(f"[s0 wipe]  PDF           : {pdf_path}")
    return 0 if ok else 1


# --------------------------------------------------------------------------- #
# File & Folder Sanitization (invoked via s0 wipe)
# --------------------------------------------------------------------------- #


def cmd_erase_files(args) -> int:
    _print_legal_notice()
    if not _validate_cli_metadata(args):
        return 2

    pattern = getattr(args, "pattern", "zero")
    if pattern not in ("zero", "random"):
        print(f"error: invalid --pattern '{pattern}'. Supported patterns: zero, random", file=sys.stderr)
        return 2

    passes_val = getattr(args, "passes", 1)
    if passes_val < 1 or passes_val > 100:
        print(f"error: --passes must be between 1 and 100 (got {passes_val}).", file=sys.stderr)
        return 2

    print(f"==> S0: Secure File & Folder Sanitization")

    key_path = default_issuer_key(getattr(args, "key", None))
    _warn_if_demo_key(key_path)
    if key_path is None and not getattr(args, "no_certificate", False):
        print(
            "error: no issuer signing key found.\n"
            "S0 requires a valid Ed25519 signing key to issue compliance certificates and audit records.\n"
            "Specify --key <path> or pass --no-certificate to explicitly run without compliance certification.",
            file=sys.stderr,
        )
        return 2

    if getattr(args, "no_certificate", False):
        print("WARNING: --no-certificate specified. No compliance certificate or audit log will be generated.", file=sys.stderr)

    targets = [Path(t) for t in args.targets]
    print(f"==> Target items ({len(targets)}): {[str(t) for t in targets]}")

    total_est = sum(p.stat().st_size for p in targets if p.is_file()) * getattr(args, "passes", 1)
    bar = ProgressBar(max(total_est, 1024), operation="s0 wipe") if total_est > 0 else None

    def erase_progress_cb(path_str: str, written: int, total_f: int) -> None:
        if bar:
            bar.update(written, extra=Path(path_str).name[:20])

    try:
        summary = erase_batch(
            targets,
            passes=args.passes,
            pattern=args.pattern,
            operator_id=args.operator,
            organization=args.organization,
            signing_key_path=key_path,
            progress_callback=erase_progress_cb,
            generate_certificate=not getattr(args, "no_certificate", False),
            force=getattr(args, "force", False),
        )
        if bar:
            bar.finish()
    except KeyboardInterrupt:
        if bar:
            bar.finish(extra="CANCELLED")
        print("\n⚠  Erasure interrupted by user (Ctrl+C). Some files may be partially erased.", file=sys.stderr)
        return 130

    print(f"\n[s0 erase-file]  Files Processed : {summary.total_files}")
    print(f"[s0 erase-file]  Successful      : {summary.successful_files}")
    print(f"[s0 erase-file]  Failed          : {summary.failed_files}")
    print(f"[s0 erase-file]  Bytes Sanitized : {summary.total_bytes_processed} bytes")

    if summary.certificate:
        try:
            blk = record_audit_event(summary.certificate, operation_type="FILE_ERASE", private_key=key_path)
            print(f"[s0 erase-file]  Audit Ledger    : recorded block #{blk.block_index} ({blk.block_hash[:16]}...)")
        except Exception as exc:
            print(f"WARNING: failed to record event into audit ledger: {exc}", file=sys.stderr)

        out_dir = Path(args.out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        cert_p = out_dir / f"file_wipe_certificate_{summary.certificate['cert_uuid'][:8]}.json"
        cert_p.write_text(json.dumps(summary.certificate, indent=2) + "\n")
        print(f"[s0 erase-file]  Certificate     : {cert_p}")

        if not getattr(args, "no_pdf", False):
            try:
                from s0_core import pdfgen
                qr_url_tpl = getattr(args, "qr_url_template", "https://s0-verify.pages.dev/?cert={cert_uuid}")
                portal_url_val = _validate_portal_url(getattr(args, "portal_url", None))
                if portal_url_val and "{cert_uuid}" not in portal_url_val:
                    qr_url_tpl = f"{portal_url_val.rstrip('/')}/?cert={{cert_uuid}}"
                pdf_p = out_dir / f"file_wipe_certificate_{summary.certificate['cert_uuid'][:8]}.pdf"
                qr_p = out_dir / f"file_wipe_certificate_{summary.certificate['cert_uuid'][:8]}.qr.png"
                pdfgen.generate_pdf(summary.certificate, pdf_p, qr_url_template=qr_url_tpl)
                pdfgen.write_qr_file(summary.certificate, qr_p)
                print(f"[s0 erase-file]  PDF Certificate : {pdf_p}")
            except Exception:
                pass
        if getattr(args, "json", False):
            print(json.dumps({
                "status": "success" if summary.failed_files == 0 else "failure",
                "successful_files": summary.successful_files,
                "failed_files": summary.failed_files,
                "bytes_overwritten": summary.bytes_overwritten,
                "certificate": str(cert_p) if summary.certificate else None,
                "cert_uuid": summary.certificate.get("cert_uuid") if summary.certificate else None
            }, indent=2))
    elif not getattr(args, "no_certificate", False):
        print("WARNING: Sanitization completed, but certificate generation failed (see warnings).", file=sys.stderr)

    return 0 if summary.failed_files == 0 else 1


# --------------------------------------------------------------------------- #
# Module 2: File Carving Subcommands
# --------------------------------------------------------------------------- #


def cmd_carve(args) -> int:
    _print_legal_notice()
    if not _validate_cli_metadata(args):
        return 2
    print(f"==> S0 Module 2: Advanced File Carving & Recovery")

    key_path = default_issuer_key(args.key)
    _warn_if_demo_key(key_path)
    if key_path is None and not getattr(args, "no_certificate", False):
        print(
            "error: no issuer signing key found.\n"
            "S0 requires a valid Ed25519 signing key to issue forensic manifest certificates.\n"
            "Specify --key <path> or pass --no-certificate to explicitly run without compliance certification.",
            file=sys.stderr,
        )
        return 2

    if getattr(args, "no_certificate", False):
        print("WARNING: --no-certificate specified. No forensic recovery manifest will be issued.", file=sys.stderr)

    print(f"Target Media: {args.target}")
    print(f"Output Dir  : {args.out_dir}")

    target_path = Path(args.target)
    target_size = 0
    if target_path.is_block_device():
        if is_os_device(str(target_path)):
            sys.stderr.write(
                "\n\033[33m[!] ADVISORY: Target hosts the active running operating system / root filesystem.\n"
                "    Live OS background writes, swap/pagefile activity, and SSD TRIM will overwrite deleted\n"
                "    clusters in real time, degrading recovery yield. For forensically sound recovery,\n"
                "    boot the s0 Live ISO or acquire an offline bit-stream image (s0 image).\033[0m\n\n"
            )
        try:
            target_size = get_block_device_size(target_path)
        except Exception:
            pass
    elif target_path.is_file():
        target_size = target_path.stat().st_size

    bar = ProgressBar(target_size, operation="s0 carve") if target_size > 0 else None
    _last_carve_temp_time: list[float] = [0.0]
    _last_carve_temp_val: list = [None]

    def carve_progress_cb(scanned: int, total: int, found: int) -> None:
        if bar:
            now = time.monotonic()
            if now - _last_carve_temp_time[0] >= 2.0:
                _last_carve_temp_time[0] = now
                _last_carve_temp_val[0] = read_temperature(args.target)
            temp = _last_carve_temp_val[0]
            extra = f"Found: {found:,}"
            if temp is not None:
                extra += f" | Temp: {temp}°C"
            bar.update(scanned, extra=extra)

    exts = [e.strip() for e in args.extensions.split(",")] if args.extensions else None

    custom_sigs = None
    if getattr(args, "custom_sig", None):
        sig_arg = args.custom_sig.strip()
        sig_path = Path(sig_arg)
        try:
            if sig_path.exists():
                raw_data = json.loads(sig_path.read_text(encoding="utf-8"))
            else:
                raw_data = json.loads(sig_arg)
            if isinstance(raw_data, dict):
                raw_data = [raw_data]
            custom_sigs = [signature_from_dict(d) for d in raw_data]
            print(f"Loaded {len(custom_sigs)} custom forensic signature(s): {', '.join(s.name for s in custom_sigs)}")
        except Exception as err:
            print(f"error: failed to parse custom signatures from '{args.custom_sig}': {err}", file=sys.stderr)
            return 2

    try:
        summary = carve_image(
            args.target,
            args.out_dir,
            extensions=exts,
            custom_signatures=custom_sigs,
            min_confidence=args.min_confidence,
            operator_id=args.operator,
            organization=args.organization,
            signing_key_path=key_path,
            progress_callback=carve_progress_cb,
            generate_certificate=not getattr(args, "no_certificate", False),
        )
        if bar:
            bar.finish(extra=f"Found: {summary.files_recovered:,}")
    except KeyboardInterrupt:
        if bar:
            bar.finish(extra="CANCELLED")
        print("\n⚠  File carving interrupted by user (Ctrl+C).", file=sys.stderr)
        return 130

    print(f"\n[s0 carve]  Bytes Scanned    : {summary.total_bytes_scanned}")
    print(f"[s0 carve]  Candidates Found : {summary.total_candidates_found}")
    print(f"[s0 carve]  Files Recovered  : {summary.files_recovered}")

    if summary.carved_files:
        print(f"\n{'ID':<14} {'EXT':<6} {'SIZE':>10}  {'CONF':>6}  {'SHA256 (PREFIX)':<20} FILENAME")
        for c in summary.carved_files[:20]:
            print(
                f"{c.file_id:<14} {c.extension:<6} {c.size_bytes:>10}  {c.confidence_score:>5}%  {c.sha256[:16]:<20} {c.filename}"
            )
        if len(summary.carved_files) > 20:
            print(f"... and {len(summary.carved_files) - 20} more files (see recovery_index.json).")

    idx_file = Path(args.out_dir) / "recovery_index.json"
    if idx_file.exists():
        print(f"[s0 carve]  Recovery Index   : {idx_file}")

    if summary.manifest_certificate:
        try:
            blk = record_audit_event(summary.manifest_certificate, operation_type="FILE_CARVE", private_key=key_path)
            print(f"[s0 carve]  Audit Ledger     : recorded block #{blk.block_index} ({blk.block_hash[:16]}...)")
        except Exception as exc:
            print(f"WARNING: failed to record event into audit ledger: {exc}", file=sys.stderr)

        out_dir = Path(args.out_dir)
        cert_p = (
            out_dir / f"carving_manifest_{summary.manifest_certificate['cert_uuid'][:8]}.json"
        )
        cert_p.write_text(json.dumps(summary.manifest_certificate, indent=2) + "\n")
        print(f"[s0 carve]  Manifest File    : {cert_p}")

        if not getattr(args, "no_pdf", False):
            try:
                from s0_core import pdfgen
                qr_url_tpl = getattr(args, "qr_url_template", "https://s0-verify.pages.dev/?cert={cert_uuid}")
                portal_url_val = _validate_portal_url(getattr(args, "portal_url", None))
                if portal_url_val and "{cert_uuid}" not in portal_url_val:
                    qr_url_tpl = f"{portal_url_val.rstrip('/')}/?cert={{cert_uuid}}"
                pdf_p = out_dir / f"carving_manifest_{summary.manifest_certificate['cert_uuid'][:8]}.pdf"
                qr_p = out_dir / f"carving_manifest_{summary.manifest_certificate['cert_uuid'][:8]}.qr.png"
                pdfgen.generate_pdf(summary.manifest_certificate, pdf_p, qr_url_template=qr_url_tpl)
                pdfgen.write_qr_file(summary.manifest_certificate, qr_p)
                print(f"[s0 carve]  PDF Certificate  : {pdf_p}")
            except Exception:
                pass

    return 0


# --------------------------------------------------------------------------- #
# Hash-Chained Audit Ledger Subcommands
# --------------------------------------------------------------------------- #


def cmd_audit(args) -> int:
    if args.audit_action == "list":
        blocks = list_audit_blocks(limit=args.limit)
        print(f"[s0 audit]  Ledger        : Hash-Chained Cryptographic Audit Ledger ({len(blocks)} blocks)")
        print(
            f"{'IDX':<5} {'TIMESTAMP':<20} {'OPERATION':<14} {'OPERATOR':<14} {'TARGET_ID':<20} {'BLOCK_HASH':<16}"
        )
        for b in blocks:
            print(
                f"{b.block_index:<5} {b.timestamp[:19]:<20} {b.operation_type:<14} {b.operator_id:<14} {b.target_id[:20]:<20} {b.block_hash[:16]}..."
            )
        return 0

    elif args.audit_action == "verify":
        print("[s0 audit]  Auditing hash-chained cryptographic ledger...")
        trusted_keys = None
        if getattr(args, "key", None):
            from s0_core.crypto import load_public_pem

            trusted_keys = [load_public_pem(args.key)]
        report = verify_audit_ledger(trusted_public_keys=trusted_keys)
        if report.is_valid:
            if getattr(report, "is_demo_signed", False):
                print("[s0 audit]  Chain Status  : WARN : VALID & CONTINUOUS — UNACCREDITED DEMO KEY")
                if getattr(report, "demo_key_warning", None):
                    print(f"               {report.demo_key_warning}")
            else:
                print("[s0 audit]  Chain Status  : OK : VALID & CONTINUOUS")
        else:
            reason = report.reason or ""
            if "not in the trusted key set" in reason or "unknown issuer key" in reason:
                print("[s0 audit]  Chain Status  : WARN : UNVERIFIABLE — SIGNING KEY NOT IN TRUST SET")
            else:
                print("[s0 audit]  Chain Status  : ERROR : BROKEN / TAMPER DETECTED")
        print(f"[s0 audit]  Blocks Tested : {report.total_blocks_verified}")
        print(f"[s0 audit]  Details       : {report.reason}")
        return 0 if report.is_valid else 1

    return 0


# --------------------------------------------------------------------------- #
# Zero-Trust Verification & Key Generation
# --------------------------------------------------------------------------- #


def cmd_verify(args) -> int:
    cert_path = Path(args.certificate)
    if not cert_path.is_file():
        print(f"error: certificate file {args.certificate} does not exist", file=sys.stderr)
        return 2

    try:
        cert_data = json.loads(cert_path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"error: invalid certificate JSON: {exc}", file=sys.stderr)
        return 2

    pub_keys = []
    if args.key:
        p = Path(args.key)
        if not p.is_file():
            print(f"error: public key file {args.key} does not exist", file=sys.stderr)
            return 2
        from s0_core.crypto import load_public_pem
        pub_keys.append(load_public_pem(p))
    else:
        # Load demo public key if present
        demo_pub = Path(__file__).resolve().parents[3] / "core" / "keys" / "demo_issuer_public.pem"
        if demo_pub.is_file():
            from s0_core.crypto import load_public_pem
            pub_keys.append(load_public_pem(demo_pub))

    from s0_core.certificate import verify_certificate
    ok, reason = verify_certificate(cert_data, pub_keys)
    if ok:
        print("[s0 verify]  Status       : OK : CERTIFICATE AUTHENTIC & VERIFIED")
        print(f"[s0 verify]  UUID         : {cert_data.get('cert_uuid')}")
        print(f"[s0 verify]  Result       : {cert_data.get('result', {}).get('status')}")
        print(f"[s0 verify]  NIST Tier    : {cert_data.get('wipe', {}).get('nist_category')}")
        print(f"[s0 verify]  Device       : {cert_data.get('device', {}).get('device_id')}")
        print(f"[s0 verify]  Issuer       : {cert_data.get('issuer', {}).get('organization')}")
        print(f"[s0 verify]  Fingerprint  : {cert_data.get('signature', {}).get('public_key_fingerprint')}")
        return 0
    else:
        print(f"[s0 verify]  Status       : ERROR : CERTIFICATE VERIFICATION FAILED: {reason}", file=sys.stderr)
        return 1


def cmd_keygen(args) -> int:
    from s0_core import crypto
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    priv = crypto.generate_private_key()
    pub = priv.public_key()
    priv_p = out_dir / f"{args.name}_private.pem"
    pub_p = out_dir / f"{args.name}_public.pem"
    crypto.write_private_pem(priv, priv_p)
    crypto.write_public_pem(pub, pub_p)
    fp = crypto.public_key_fingerprint(pub)
    print("[s0 keygen]  Generated Ed25519 Keypair :")
    print(f"[s0 keygen]    Private Key : {priv_p} (Keep secret & offline!)")
    print(f"[s0 keygen]    Public Key  : {pub_p}")
    print(f"[s0 keygen]    Fingerprint : {fp}")
    return 0


# --------------------------------------------------------------------------- #
# Maintenance & Upgrade Commands
# --------------------------------------------------------------------------- #


def cmd_upgrade(args) -> int:
    """Upgrade S0 installation to the latest version."""
    print("╔══════════════════════════════════════════════════════════════════╗")
    print("║      S0 (Sector Zero) — Suite Upgrade & Maintenance Tool         ║")
    print("╚══════════════════════════════════════════════════════════════════╝")
    print()

    repo_dir = None
    env_dir = os.environ.get("S0_INSTALL_DIR")
    if env_dir and Path(env_dir).is_dir():
        repo_dir = Path(env_dir)
    else:
        home_s0 = Path.home() / ".s0"
        if home_s0.is_dir() and (home_s0 / ".git").is_dir():
            repo_dir = home_s0
        else:
            cur = Path(__file__).resolve()
            for parent in [cur] + list(cur.parents):
                if (parent / ".git").is_dir():
                    repo_dir = parent
                    break

    if not repo_dir:
        print("[s0 upgrade]  ERROR : Could not locate S0 git installation repository.", file=sys.stderr)
        print("To install or upgrade S0, run:")
        if sys.platform == "win32":
            print("  irm https://s0-install.pages.dev/upgrade-ps1 -OutFile s0-upgrade.ps1")
            print("  # Inspect s0-upgrade.ps1 before running, then run:")
            print("  powershell -ExecutionPolicy Bypass -File .\\s0-upgrade.ps1")
        else:
            print("  curl -fsSL https://s0-install.pages.dev/upgrade-sh -o s0-upgrade.sh")
            print("  # Inspect s0-upgrade.sh before running, then run:")
            print("  bash s0-upgrade.sh")
        return 1

    print(f"[s0 upgrade]  Found S0 installation at: {repo_dir}")
    try:
        cur_hash = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"], cwd=str(repo_dir), text=True
        ).strip()
        print(f"[s0 upgrade]  Current commit: {cur_hash}")
        print("[s0 upgrade]  Pulling latest changes from GitHub origin/master...")
        subprocess.check_call(["git", "fetch", "origin", "master", "-q"], cwd=str(repo_dir))
        latest_hash = subprocess.check_output(
            ["git", "rev-parse", "--short", "origin/master"], cwd=str(repo_dir), text=True
        ).strip()

        if cur_hash == latest_hash and not getattr(args, "force", False):
            print(f"[s0 upgrade]  OK : S0 is already up-to-date at commit {cur_hash}.")
        else:
            subprocess.check_call(["git", "pull", "--ff-only", "origin", "master", "-q"], cwd=str(repo_dir))
            print(f"[s0 upgrade]  OK : Source updated: {cur_hash} → {latest_hash}")

        py_bin = sys.executable
        print("[s0 upgrade]  Refreshing dependencies...")
        subprocess.check_call([py_bin, "-m", "pip", "install", "--upgrade", "pip", "-q"])
        subprocess.check_call([py_bin, "-m", "pip", "install", "-e", str(repo_dir / "core" / "python"), "-q"])
        subprocess.check_call([py_bin, "-m", "pip", "install", "-e", str(repo_dir / "linux" / "cli"), "-q"])
        subprocess.check_call([py_bin, "-m", "pip", "install", "reportlab", "qrcode", "pillow", "-q"])
        print("[s0 upgrade]  OK : Dependencies refreshed.")

        ver = subprocess.check_output([py_bin, "-m", "s0_cli.main", "--version"], text=True).strip()
        print()
        print(f"[s0 upgrade]  OK : S0 upgraded successfully to {ver} ({latest_hash})")
        return 0
    except Exception as exc:
        print(f"[s0 upgrade]  ERROR : Upgrade failed: {exc}", file=sys.stderr)
        return 1


def cmd_uninstall(args) -> int:
    """Safely uninstall S0 from the system."""
    print("╔══════════════════════════════════════════════════════════════════╗")
    print("║      S0 (Sector Zero) — Uninstallation Tool                      ║")
    print("╚══════════════════════════════════════════════════════════════════╝")
    print()

    if sys.platform == "win32":
        print("[s0 uninstall]  On Windows, run the official uninstallation script:")
        print("    curl -fsSL https://s0-install.pages.dev/uninstall-ps1 -o s0-uninstall.ps1")
        print("    # Inspect s0-uninstall.ps1 before running, then run:")
        print("    powershell -ExecutionPolicy Bypass -File .\\s0-uninstall.ps1")
        return 0

    repo_dir = None
    env_dir = os.environ.get("S0_INSTALL_DIR")
    if env_dir and Path(env_dir).is_dir():
        repo_dir = Path(env_dir)
    else:
        home_s0 = Path.home() / ".s0"
        if home_s0.is_dir():
            repo_dir = home_s0
        else:
            cur = Path(__file__).resolve()
            for parent in [cur] + list(cur.parents):
                if (parent / ".git").is_dir():
                    repo_dir = parent
                    break

    if not repo_dir:
        print("[s0 uninstall]  ERROR : Could not locate S0 installation directory.", file=sys.stderr)
        print("To manually uninstall S0, download and run the script:")
        print("  curl -fsSL https://s0-install.pages.dev/uninstall-sh -o s0-uninstall.sh")
        print("  # Inspect s0-uninstall.sh before running, then run:")
        print("  bash s0-uninstall.sh")
        return 1

    print(f"[s0 uninstall]  Target S0 directory: {repo_dir}")
    audit_db = Path.home() / ".s0" / "s0_audit.db"
    purge_all = getattr(args, "purge_all", False) or getattr(args, "purge", False)
    if audit_db.is_file():
        if purge_all:
            print("[s0 uninstall]  Purging audit ledger as requested (--purge-all specified).")
        else:
            import time as _time
            timestamp = _time.strftime("%Y%m%d_%H%M%S")
            bak_dest = Path.home() / f"s0_audit.db.bak.{timestamp}"
            try:
                shutil.copy2(audit_db, bak_dest)
                print(f"[s0 uninstall]  Audit ledger safely preserved at: {bak_dest}")
                print("                (Use --purge-all if you intentionally wish to destroy the audit log.)")
            except Exception as exc:
                print(f"[s0 uninstall]  WARN : Could not back up audit ledger: {exc}", file=sys.stderr)

    if not getattr(args, "yes", False):
        try:
            confirm = input("Are you sure you want to uninstall s0? [y/N]: ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print("\nAborted.")
            return 1
        if confirm != "y":
            print("Uninstallation cancelled.")
            return 0

    print("[s0 uninstall]  Removing symlinks...")
    symlink_candidates = [
        Path.home() / ".local" / "bin" / "s0",
        Path.home() / "bin" / "s0",
        Path("/usr/local/bin/s0"),
    ]
    for sym in symlink_candidates:
        if sym.is_symlink() or sym.exists():
            try:
                sym.unlink()
                print(f"[s0 uninstall]  OK : Removed symlink: {sym}")
            except Exception as exc:
                print(f"[s0 uninstall]  WARN : Could not remove {sym}: {exc}", file=sys.stderr)

    # If repo_dir strictly resolves to ~/.s0, remove it safely
    home_s0 = (Path.home() / ".s0").resolve()
    if repo_dir.resolve() == home_s0:
        print(f"[s0 uninstall]  Removing installation directory: {repo_dir}...")
        try:
            shutil.rmtree(repo_dir, ignore_errors=True)
            print("[s0 uninstall]  OK : Directory removed.")
        except Exception as exc:
            print(f"[s0 uninstall]  ERROR : Error removing directory: {exc}", file=sys.stderr)
    else:
        print(f"[s0 uninstall]  Notice: {repo_dir} is a development checkout or custom repository; files preserved.")

    print()
    print("[s0 uninstall]  OK : S0 uninstalled successfully.")
    return 0


# --------------------------------------------------------------------------- #
# Module 3: Forensic Bit-Stream Drive Imaging & Cloning
# --------------------------------------------------------------------------- #


def cmd_image(args) -> int:
    """Forensic bit-stream disk acquisition and device cloning."""
    from .imager import ImagingOptions, acquire_image

    _print_legal_notice()
    if not _validate_cli_metadata(args):
        return 2
    print("╔══════════════════════════════════════════════════════════════════╗")
    print("║      S0 (Sector Zero) — Forensic Disk Imager & Bit-Stream Copy  ║")
    print("╚══════════════════════════════════════════════════════════════════╝")
    print()

    dst_p = Path(args.destination)
    is_blk = False
    try:
        is_blk = dst_p.is_block_device() or (sys.platform == "darwin" and dst_p.is_char_device())
    except Exception:
        pass
    if sys.platform == "win32" and ("physicaldrive" in args.destination.lower() or args.destination.startswith("\\\\.\\")):
        is_blk = True

    if is_blk and not args.yes:
        print(f"⚠️  WARNING: Target destination '{args.destination}' is a PHYSICAL BLOCK DEVICE!")
        print("   Writing will OVERWRITE all existing partition tables, filesystems, and data.")
        try:
            conf = input(f"Type '{args.destination}' to confirm clone to {args.destination}: ").strip()
        except EOFError:
            conf = ""
        if conf != str(args.destination):
            print("Aborted by operator.")
            return 1

    bar = ProgressBar(total_bytes=1, operation="Forensic Acquisition")

    def _progress(bytes_copied, total_bytes, speed, bad_sectors):
        if bar.total <= 1 and total_bytes > 0:
            bar.total = total_bytes
        extra = f"{speed:.1f} MB/s"
        if bad_sectors > 0:
            extra += f" | Bad Sectors: {bad_sectors}"
        bar.update(bytes_copied, extra=extra)

    key_path = default_issuer_key(getattr(args, "key", None))
    _warn_if_demo_key(key_path)
    if key_path is None and not getattr(args, "no_certificate", False):
        print(
            "error: no issuer signing key found.\n"
            "S0 requires a valid Ed25519 signing key to issue forensic acquisition certificates.\n"
            "Specify --key <path> or pass --no-certificate to explicitly run without compliance certification.",
            file=sys.stderr,
        )
        return 2

    options = ImagingOptions(
        source=args.source,
        destination=args.destination,
        block_size=args.block_size,
        error_recovery=not args.no_recovery,
        operator=args.operator,
        organization=args.organization,
        key_path=key_path,
        no_certificate=args.no_certificate,
        out_dir=args.out_dir,
        force=getattr(args, "force", False),
    )

    print(f"[s0 image]  Source          : {args.source}")
    print(f"[s0 image]  Destination     : {args.destination}")
    print(f"[s0 image]  Block Size      : {args.block_size:,} bytes")
    print(f"[s0 image]  Fault Tol.      : {'Enabled (Zero-fill bad blocks)' if not args.no_recovery else 'Disabled (Abort on error)'}")
    print()

    try:
        result = acquire_image(options, progress_callback=_progress)
        bar.finish()
    except KeyboardInterrupt:
        bar.finish(extra="CANCELLED")
        print("\n⚠  Imaging cancelled by user (Ctrl+C). Target may be incomplete.", file=sys.stderr)
        return 130
    print()

    if result.error:
        print(f"[s0 image]  Status          : ERROR : ACQUISITION FAILED: {result.error}", file=sys.stderr)
        return 1

    if result.bad_sectors_count > 0:
        print(f"[s0 image]  Status          : WARN : ACQUISITION COMPLETED WITH ERRORS ({result.bad_sectors_count} bad sectors zero-filled)")
    else:
        print("[s0 image]  Status          : OK : FORENSIC ACQUISITION COMPLETED")

    print(f"[s0 image]  Operation       : {'Drive Clone' if result.is_clone else 'Raw Bit-Stream Image'}")
    print(f"[s0 image]  Bytes Acquired  : {result.bytes_copied:,} bytes ({result.bytes_copied / (1024**3):.2f} GB)")
    print(f"[s0 image]  Duration        : {result.duration_seconds:.2f} seconds ({result.speed_mbps:.1f} MB/s)")
    print(f"[s0 image]  Bad Sectors     : {result.bad_sectors_count}")
    hash_label = "Image SHA-256" if result.bad_sectors_count > 0 else "Source SHA-256"
    print(f"[s0 image]  {hash_label:<16}: {result.source_sha256}")
    print(f"[s0 image]  Source MD5      : {result.source_md5}")
    if result.manifest_path:
        print(f"[s0 image]  Manifest File   : {result.manifest_path}")
    if result.manifest_certificate:
        if getattr(result, "audit_ledger_recorded", False):
            print(f"[s0 image]  Certificate     : {result.manifest_certificate.get('cert_uuid')} (Signed & Appended to Audit Ledger)")
        else:
            err_suffix = f": {result.audit_ledger_error}" if getattr(result, "audit_ledger_error", None) else ""
            print(f"[s0 image]  Certificate     : {result.manifest_certificate.get('cert_uuid')} (Signed, WARNING: Audit Ledger write failed{err_suffix})")
        if not getattr(args, "no_pdf", False):
            try:
                from s0_core import pdfgen
                out_dir_p = Path(args.out_dir)
                qr_url_tpl = getattr(args, "qr_url_template", "https://s0-verify.pages.dev/?cert={cert_uuid}")
                portal_url_val = _validate_portal_url(getattr(args, "portal_url", None))
                if portal_url_val and "{cert_uuid}" not in portal_url_val:
                    qr_url_tpl = f"{portal_url_val.rstrip('/')}/?cert={{cert_uuid}}"
                pdf_p = out_dir_p / f"certificate_{result.manifest_certificate['cert_uuid'][:8]}.pdf"
                qr_p = out_dir_p / f"certificate_{result.manifest_certificate['cert_uuid'][:8]}.qr.png"
                pdfgen.generate_pdf(result.manifest_certificate, pdf_p, qr_url_template=qr_url_tpl)
                pdfgen.write_qr_file(result.manifest_certificate, qr_p)
                print(f"[s0 image]  PDF Certificate : {pdf_p}")
            except Exception as exc:
                print(f"[s0 image]  WARN : PDF generation warning: {exc}", file=sys.stderr)
    print()
    return 0


# --------------------------------------------------------------------------- #
# Module 8: Web Dashboard Launcher
# --------------------------------------------------------------------------- #


def cmd_web(args) -> int:
    """Launch the s0 local Web Dashboard in browser."""
    import subprocess
    import time
    import webbrowser
    import threading

    port = getattr(args, "port", None) or CONFIG.get("api_port", 8669)
    host = getattr(args, "host", None) or "127.0.0.1"
    url = f"http://{host}:{port}"

    # Sudo / Root privilege detection
    is_root = False
    if hasattr(os, "geteuid"):
        is_root = (os.geteuid() == 0)
    elif sys.platform == "win32":
        try:
            import ctypes
            is_root = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            is_root = False

    if not is_root:
        print("\033[1;33m[s0 web]  WARN : s0 web is running without root (sudo) privileges.\033[0m")
        print("\033[33m[s0 web]         Drive wiping and raw disk acquisition will not be available.\033[0m")
        print("\033[33m[s0 web]         For full forensic drive operations, launch with: sudo s0 web\033[0m\n")

    # Verify dependencies: fastapi and uvicorn
    deps_missing = []
    try:
        import fastapi  # noqa: F401
    except ImportError:
        deps_missing.append("fastapi")
    try:
        import uvicorn  # noqa: F401
    except ImportError:
        deps_missing.append("uvicorn")

    if deps_missing:
        print(f"\n[s0 web]  WARN : Missing required web dashboard dependencies: {', '.join(deps_missing)}", file=sys.stderr)
        try:
            ans = input(f"Would you like s0 to install {' '.join(deps_missing)} now? [Y/n]: ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print("\nAborted.", file=sys.stderr)
            return 1
        if ans in ("", "y", "yes"):
            print(f"[s0 web]  Installing {' '.join(deps_missing)}...")
            res = subprocess.run([sys.executable, "-m", "pip", "install", *deps_missing], check=False)
            if res.returncode != 0:
                print(f"[s0 web]  ERROR : Failed to install dependencies. Please run: pip install {' '.join(deps_missing)}", file=sys.stderr)
                return 1
            print("[s0 web]  OK : Dependencies installed successfully.\n")
        else:
            print(f"[s0 web]  ERROR : Aborted. Install manually: pip install {' '.join(deps_missing)}", file=sys.stderr)
            return 1

    # Locate web dashboard app directory
    possible_roots = [
        Path(__file__).resolve().parents[3],
        Path.home() / ".s0",
        Path("/opt/s0"),
    ]
    web_dir = None
    for root in possible_roots:
        cand_web = root / "web"
        if cand_web.is_dir() and (cand_web / "app.py").is_file():
            web_dir = cand_web
            break

    if not web_dir:
        print("[s0 web]  ERROR : Could not locate s0 Web Dashboard files (app.py).", file=sys.stderr)
        return 1

    import secrets
    session_token = secrets.token_hex(32)
    token_path = Path.home() / ".s0" / "web_auth_token"
    try:
        token_path.parent.mkdir(parents=True, exist_ok=True)
        token_path.write_text(session_token, encoding="utf-8")
        try:
            os.chmod(token_path, 0o600)
        except Exception:
            pass
    except Exception:
        pass

    auth_url = f"{url}/?token={session_token}"

    print("╔══════════════════════════════════════════════════════════════════╗")
    print("║      S0 (Sector Zero) — Unified Web Forensics Dashboard         ║")
    print("╚══════════════════════════════════════════════════════════════════╝")
    print(f"[s0 web]  Address  : {url}")
    print(f"[s0 web]  Auth URL : {auth_url}")
    print(f"[s0 web]  Token    : {token_path} (mode 0600)")
    print(f"[s0 web]  Binding  : {host} (Strict loopback isolation)")
    print(f"[s0 web]  Status   : Live — Press CTRL+C to stop")
    print()

    cmd = [
        sys.executable,
        "-m",
        "uvicorn",
        "app:app",
        "--host",
        host,
        "--port",
        str(port),
    ]

    env = dict(os.environ)
    env["S0_WEB_AUTH_TOKEN"] = session_token

    proc = subprocess.Popen(cmd, cwd=str(web_dir), env=env)

    if not getattr(args, "no_browser", False):
        def _open():
            time.sleep(1.2)
            try:
                webbrowser.open(auth_url)
            except Exception:
                pass
        threading.Thread(target=_open, daemon=True).start()


    try:
        proc.wait()
    except KeyboardInterrupt:
        print("\n[s0 web]  Stopping web dashboard...")
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
        print("[s0 web]  Server terminated.")

    return 0


# --------------------------------------------------------------------------- #
# CLI Parser Setup
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="s0",
        description="S0 (Sector Zero) — Unified Forensic Sanitization & Recovery CLI",
        epilog="⚖ LEGAL: Only operate on storage media you own or have explicit written authorization to process.",
    )
    p.add_argument("--version", action="version", version=f"s0 {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    # 1. Drive Eraser Subcommands
    lst = sub.add_parser("list", help="list block-device wipe targets")
    lst.add_argument(
        "--output-format",
        choices=["text", "json"],
        default="text",
        help="output format (default: text)",
    )
    lst.set_defaults(func=cmd_list)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--version", action="version", version=f"s0 {__version__}")
    common.add_argument("--target", help="target drive, image, file, or directory")
    common.add_argument(
        "--passes",
        "-p",
        type=int,
        default=1,
        help="overwrite passes (default 1 — one pass IS Clear per NIST 800-88)",
    )
    common.add_argument(
        "--pattern",
        choices=["zero", "random"],
        default="zero",
        help="overwrite pattern: 'zero' (single/multi-pass zeros) or 'random' (CSPRNG bytes)",
    )
    common.add_argument(
        "--no-firmware",
        action="store_true",
        help="skip firmware methods (ATA SE/NVMe sanitize); overwrite only",
    )
    common.add_argument(
        "--discard-purge-justification",
        metavar="TEXT",
        help="record drive-spec deterministic-TRIM evidence to let BLKDISCARD claim Purge",
    )
    common.add_argument(
        "--force", action="store_true", help="override mounted/root safety refusals"
    )

    pln = sub.add_parser("plan", parents=[common], help="dry-run: show what would happen")
    pln.set_defaults(func=cmd_plan)

    wp = sub.add_parser("wipe", parents=[common], help="wipe drive, file(s), or folder(s), verify, issue signed certificate")
    wp.add_argument("--targets", "-t", nargs="+", help="multiple target files or directories to sanitize")
    wp.add_argument("--yes", "-y", action="store_true", help="skip interactive confirmation prompt")
    wp.add_argument("--key", "--signing-key", help="issuer private key PEM (default: demo issuer key)")
    wp.add_argument("--out-dir", default=".", help="directory to store certificate, PDF, and QR assets (default: .)")
    wp.add_argument("--operator", "--operator-id", default=CONFIG.get("default_operator", "op-forensic"), help="operator identifier for certificate")
    wp.add_argument("--organization", default=CONFIG.get("default_organization", "Digital Forensics & Data Sanitization Lab"), help="organization name for certificate")
    wp.add_argument(
        "--no-certificate",
        action="store_true",
        help="explicitly run without generating an Ed25519 compliance certificate",
    )
    wp.add_argument("--no-pdf", action="store_true", help="skip generating human-readable PDF compliance certificate")
    wp.add_argument("--verify-samples", type=int, default=64, help="number of readback samples to verify (default: 64)")
    wp.add_argument(
        "--plant-markers",
        action="store_true",
        help="plant recoverable markers first, then require 0 grep hits afterwards",
    )
    wp.add_argument("--json", action="store_true", help="machine-readable stdout")
    wp.add_argument(
        "--portal-url",
        default=CONFIG.get("verification_portal_url", "https://s0-verify.pages.dev/"),
        help="verification portal base URL (default: https://s0-verify.pages.dev/)",
    )
    wp.add_argument(
        "--qr-url-template",
        dest="qr_url_template",
        default=CONFIG.get("qr_url_template", "https://s0-verify.pages.dev/?cert={cert_uuid}"),
        help="URL template for encoded verification QR code",
    )
    wp.set_defaults(func=cmd_wipe)

    # 2. File Carving & Recovery Subcommand
    crv = sub.add_parser("carve", help="advanced file carving and recovery from raw images / media")
    crv.add_argument("--target", required=True, help="raw disk image or block device to scan")
    crv.add_argument("--out-dir", required=True, help="directory to store carved files")
    crv.add_argument("--extensions", help="comma-separated file extensions to carve (e.g. jpg,png,pdf,zip)")
    crv.add_argument(
        "--custom-sig",
        help="path to JSON file (or inline JSON) defining custom file signature(s) with header/footer hex magic bytes",
    )
    crv.add_argument("--min-confidence", type=int, default=50, help="minimum confidence score (0-100)")
    crv.add_argument("--operator", "--operator-id", default=CONFIG.get("default_operator", "op-forensic"), help="operator identifier for manifest")
    crv.add_argument("--organization", default=CONFIG.get("default_organization", "Digital Forensics & Data Sanitization Lab"), help="organization name for manifest")
    crv.add_argument("--key", "--signing-key", help="signing key path (default: demo issuer key)")
    crv.add_argument(
        "--no-certificate",
        action="store_true",
        help="explicitly run without generating an Ed25519 forensic manifest certificate",
    )
    crv.add_argument("--no-pdf", action="store_true", help="skip generating printable PDF certificate")
    crv.set_defaults(func=cmd_carve)

    # 3. Hash-Chained Audit Ledger Subcommand
    aud = sub.add_parser("audit", help="cryptographic audit ledger and hash-chain continuity management")
    aud.add_argument("audit_action", choices=["list", "verify"], help="list audit blocks or verify hash chain")
    aud.add_argument("--limit", type=int, default=50, help="limit number of records displayed")
    aud.add_argument("--key", help="path to trusted public key PEM for strict signature verification")
    aud.set_defaults(func=cmd_audit)

    # 4. Offline Verification Subcommand
    vr = sub.add_parser("verify", help="verify a signed certificate offline against trusted public keys")
    vr.add_argument("certificate", help="path to certificate JSON")
    vr.add_argument("--key", help="path to trusted public key PEM")
    vr.set_defaults(func=cmd_verify)

    # 5. Key Generation Subcommand
    kg = sub.add_parser("keygen", help="generate Ed25519 signing keypair for an authority or operator")
    kg.add_argument("--out-dir", default=".", help="directory to store private and public keys")
    kg.add_argument("--name", default="operator_key", help="key filename prefix")
    kg.set_defaults(func=cmd_keygen)

    # 6. Upgrade Subcommand
    upg = sub.add_parser("upgrade", help="upgrade S0 suite to the latest version from GitHub")
    upg.add_argument("--force", action="store_true", help="force re-installation of dependencies even if up to date")
    upg.set_defaults(func=cmd_upgrade)

    # 7. Uninstall Subcommand
    uinst = sub.add_parser("uninstall", help="safely remove s0 suite from this system")
    uinst.add_argument("--yes", "-y", action="store_true", help="skip interactive confirmation prompt")
    uinst.add_argument("--keep-audit", action="store_true", help="back up audit ledger (~/.s0/s0_audit.db) before removal")
    uinst.set_defaults(func=cmd_uninstall)

    # 8. Forensic Imaging & Cloning Subcommands (image & clone alias)
    for img_cmd in ("image", "clone"):
        img = sub.add_parser(img_cmd, help="forensic bit-stream drive imaging, cloning, and fault-tolerant acquisition")
        img.add_argument("--source", required=True, help="path to source block device or raw image file")
        img.add_argument("--destination", "--dest", required=True, help="path to destination image file or block device")
        img.add_argument("--block-size", type=int, default=1048576, help="buffer block size in bytes (default: 1048576 / 1MB)")
        img.add_argument("--no-recovery", action="store_true", help="abort on I/O read error instead of zero-filling bad sectors")
        img.add_argument("--out-dir", default=".", help="directory to store acquisition manifest and certificate")
        img.add_argument("--operator", "--operator-id", default=CONFIG.get("default_operator", "op-forensic"), help="operator ID")
        img.add_argument("--organization", default=CONFIG.get("default_organization", "Digital Forensics & Data Sanitization Lab"), help="organization name")
        img.add_argument("--key", "--signing-key", help="path to Ed25519 issuer private key PEM")
        img.add_argument("--no-certificate", action="store_true", help="skip generating signed Ed25519 acquisition certificate")
        img.add_argument("--no-pdf", action="store_true", help="skip generating printable PDF certificate")
        img.add_argument("--yes", "-y", action="store_true", help="skip interactive confirmation when cloning to a physical disk")
        img.add_argument("--force", action="store_true", help="overwrite destination image file if it already exists")
        img.set_defaults(func=cmd_image)

    # 9. Web Dashboard Subcommand
    wb = sub.add_parser("web", help="launch local s0 Web Dashboard in browser (FastAPI loopback)")
    wb.add_argument("--port", type=int, default=CONFIG.get("api_port", 8669), help="port to bind (default: 8669)")
    wb.add_argument("--host", default="127.0.0.1", help="host to bind (default: 127.0.0.1 loopback)")
    wb.add_argument("--no-browser", action="store_true", help="start web server without opening browser")
    wb.set_defaults(func=cmd_web)

    # 10. Bootable Live Media (Live ISO & USB Station)
    try:
        from .live_manager import register_live_parser
        register_live_parser(sub)
    except ImportError:
        from s0_cli.live_manager import register_live_parser
        register_live_parser(sub)

    return p


def main(argv=None) -> int:
    try:
        raw_args = sys.argv[1:] if argv is None else list(argv)
        is_suppressed = any(flag in raw_args for flag in ("--quiet", "-q", "--json"))
        if not is_suppressed and sys.stdout.isatty():
            if not raw_args or raw_args in (["--help"], ["-h"]):
                _print_banner()

        args = build_parser().parse_args(argv)
        return args.func(args)
    except KeyboardInterrupt:
        print("\n\n⚠  Operation cancelled by user (Ctrl+C).", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
