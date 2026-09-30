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

from s0 import certificate as cert_mod
from s0 import platform
from s0 import resources
from s0.config import CONFIG
from s0.terminal import EX_CANTCREAT, EX_CONFIG, EX_DATAERR, EX_FAILURE, \
    EX_INTERRUPTED, EX_IOERR, EX_NOINPUT, EX_NOPERM, EX_OK, EX_SOFTWARE, \
    EX_TEMPFAIL, EX_USAGE
from s0.terminal import OutputPolicy
from s0.cli.ui import (UI, Column, add_global_arguments, artifact, human_bytes,
                       human_int, policy_from_args)
from s0.progress import ProgressBar

from s0 import __version__, __version_str__
from s0.audit import init_audit_db, list_audit_blocks, record_audit_event, verify_audit_ledger
from s0.carve import carve_image, signature_from_dict
from s0.cli.devices import (
    SafetyError,
    check_safety,
    get_block_device_size,
    image_target,
    is_os_device,
    list_block_targets,
)
from s0.cli.devices import Target as DevTarget
from s0.cli.file_eraser import erase_batch
from s0.wipe.methods.ata import AtaSecureEraseMethod, hpa_dco_report
from s0.wipe.methods.base import Plan
from s0.wipe.methods.overwrite import OverwriteMethod, plant_patterns
from s0.temperature import read_temperature
from s0.wipe.planner import (
    default_issuer_key,
    make_certificate,
    select_method,
    take_pre_samples,
    verify_wipe,
)


from s0.crypto import is_demo_key


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
    from s0.validation import validate_metadata_str
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


def _print_banner(policy=None) -> None:
    """Show the ASCII banner only on an interactive TTY, for bare `s0` or `--help`.

    It is chrome, so it goes to stderr: `s0 list | tee report.txt` must not have
    a logo baked into the middle of the evidence record.
    """
    if policy is not None:
        if policy.quiet or policy.fmt != "text" or not policy.err_is_tty:
            return
    elif not sys.stderr.isatty():
        return
    out = policy.err_stream if policy is not None else sys.stderr
    cyan = "\033[1;36m" if (policy is None or policy.use_color) else ""
    bold = "\033[1m"
    dim = "\033[2m"
    link = "\033[4;36m"
    reset = "\033[0m"
    for line in _S0_ASCII.strip("\n").split("\n"):
        out.write(f"{cyan}{line}{reset}\n")
    ver = CONFIG.get("version", __version__)
    out.write(f"{bold}  Sector Zero (s0){reset} v{ver}\n")
    out.write(f"  {dim}@kartik2005221{reset}  {link}https://github.com/kartik2005221/s0{reset}\n\n")
    out.flush()


_LEGAL_NOTICE = (
    "\n\033[1;33m⚖  LEGAL & RESPONSIBLE USE NOTICE:\033[0m\n"
    "\033[33m   Only operate on storage media you own or have explicit written authorization\n"
    "   to process. Unauthorized wiping, erasure, or forensic recovery may violate\n"
    "   computer crime legislation (e.g., CFAA 18 U.S.C. § 1030, Computer Misuse Act,\n"
    "   IT Act 2000 §§ 43/66). s0 is a digital forensic sanitization and recovery tool.\033[0m\n\n"
)


def _print_legal_notice() -> None:
    """Print the legal notice once per process, to stderr, never into piped data."""
    if os.environ.get("S0_LEGAL_NOTICE_SHOWN"):
        return
    os.environ["S0_LEGAL_NOTICE_SHOWN"] = "1"
    sys.stderr.write(_LEGAL_NOTICE)
    sys.stderr.flush()


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

    if sys.platform != "win32" and (platform.looks_like_windows_volume_letter(path)
                                    or platform.is_windows_volume_path(path)):
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
    is_blk = platform.is_block_device(p)
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


def _print_plan(ui, target: DevTarget, candidate, alternatives,
                warnings: list[str], hpa_dco: dict | None) -> None:
    """Render the dry-run plan through the shared presentation layer."""
    m = candidate.method
    ui.heading("Sanitization plan (dry run)")
    ui.key("Target", f"{target.path} ({target.kind}, {target.storage_type}, "
                     f"{human_bytes(target.capacity_bytes)})")
    if m is None:
        ui.key("Method", "NONE AVAILABLE")
        ui.key("Reason", candidate.reason)
        return
    plan: Plan = m.plan(target)
    ui.key("Method", plan.method_id)
    ui.key("NIST category", plan.nist_category)
    ui.key("Summary", plan.summary)
    if plan.method_id.startswith(("ATA_", "NVME_", "SCSI_")):
        ui.warn("Firmware-level Purge methods are constructed to ACS-4 / NVMe / SBC and "
                "are fixture-tested here, but real-world behaviour varies by vendor and "
                "firmware revision. Verify device support before relying on it.")
    if plan.commands:
        ui.note("")
        ui.key("Commands", "")
        for c in plan.commands:
            ui.note(f"    {c}")
    all_warnings = list(warnings) + list(plan.warnings)
    if all_warnings:
        ui.note("")
        ui.key("Warnings", "")
        for w in all_warnings:
            ui.warn(w)
    if alternatives:
        ui.note("")
        ui.key("Alternatives", "")
        for a in alternatives:
            state = ui.status("ok" if a.available else "skip", "available" if a.available else "unavailable")
            ui.note(f"    {state} {a.reason}")
    if hpa_dco and (hpa_dco.get("hpa_present") or hpa_dco.get("dco_present")
                    or hpa_dco.get("note")):
        ui.note("")
        ui.key("HPA / DCO", "")
        ui.key("  HPA present",
               "Detected" if hpa_dco.get("hpa_present") else
               ("None" if hpa_dco.get("hpa_present") is False else "Unknown"))
        ui.key("  DCO present",
               "Detected" if hpa_dco.get("dco_present") else
               ("None" if hpa_dco.get("dco_present") is False else "Unknown"))
        if hpa_dco.get("note"):
            ui.key("  Note", hpa_dco["note"])
        if hpa_dco.get("restore_command"):
            ui.key("  Action", f"remove BEFORE wiping: {hpa_dco['restore_command']}")


# --------------------------------------------------------------------------- #
# Module 1: Media & File Sanitization Subcommands
# --------------------------------------------------------------------------- #


def cmd_list(args) -> int:
    """Inventory of block-device and image-file sanitization targets."""
    ui = getattr(args, "ui", None) or UI(OutputPolicy(), "list")
    targets = list_block_targets()
    mounted = set()
    try:
        with open("/proc/mounts") as f:
            mounted = {line.split()[0] for line in f}
    except OSError:
        pass

    rows = [
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

    if ui.policy.fmt == "json":
        ui.finish(result={"targets": rows, "target_count": len(rows),
                          "note": "Image-file targets work too: use --target /path/to/file.img"})
        return EX_OK
    if ui.policy.fmt == "csv":
        ui.line("path,kind,storage_type,capacity_bytes,model,serial,mounted,os_drive")
        for r in rows:
            ui.line(",".join([
                r["path"], r["kind"], r["storage_type"], str(r["capacity_bytes"]),
                r["model"] or "", r["serial"] or "",
                "yes" if r["mounted"] else "no", "yes" if r["os_drive"] else "no",
            ]))
        return EX_OK

    if not rows:
        ui.note("(no block devices found)")
        ui.note("Image-file targets work too (no root needed): --target /path/to/file.img")
        return EX_OK

    ui.note("Inventory of attached block devices and forensic image targets")
    ui.table(
        [
            Column("PATH", max_width=28),
            Column("TYPE"),
            Column("STORAGE"),
            Column("CAPACITY", align="r"),
            Column("MODEL", max_width=24),
            Column("SERIAL", max_width=18),
            Column("MOUNTED", align="r"),
            Column("OS DRIVE", align="r"),
        ],
        [
            [
                r["path"], r["kind"], r["storage_type"], human_bytes(r["capacity_bytes"]),
                r["model"] or "—", r["serial"] or "—",
                "YES" if r["mounted"] else "-",
                "YES [OS]" if r["os_drive"] else "-",
            ]
            for r in rows
        ],
    )
    ui.note("")
    ui.key("Targets", human_int(len(rows)))
    ui.key("Operating system", human_int(sum(1 for r in rows if r["os_drive"])))
    ui.key("Currently mounted", human_int(sum(1 for r in rows if r["mounted"])))
    ui.note("")
    ui.note("Image-file targets work too (no root needed): use --target /path/to/file.img")
    return EX_OK


def cmd_plan(args) -> int:
    """Dry run: show exactly what `s0 wipe` would do, and nothing else.

    Also the place where s0 interrogates the device and prints the sanitization
    method ladder, so an operator can see whether the tier they need is actually
    attainable on this medium before committing to it.
    """
    ui = getattr(args, "ui", None) or UI(OutputPolicy(), "plan")
    if not getattr(args, "target", None):
        ui.error("the following arguments are required: --target")
        return EX_USAGE

    try:
        target = _resolve_target(args.target)
    except FileNotFoundError:
        ui.error(f"target not found: {args.target}")
        return EX_NOINPUT
    except SafetyError as exc:
        ui.error(str(exc))
        return EX_NOPERM

    if target.capacity_bytes <= 0:
        ui.error(f"target {target.path} has zero or unreadable capacity")
        return EX_DATAERR

    # Interrogate the medium. Read-only: IDENTIFY-style reads and sysfs only.
    from s0.wipe.methods.capabilities import probe_capabilities, plan_ladder
    caps = probe_capabilities(target.path, kind=target.kind)
    requested = getattr(args, "require_tier", None) or (
        "Purge" if getattr(args, "firmware", False) else "Clear")
    ladder = plan_ladder(caps, requested)

    try:
        warnings = check_safety(target, force=args.force)
    except SafetyError as exc:
        ui.error(f"REFUSED: {exc}")
        warnings = [str(exc)]

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

    selected_plan = candidate.method.plan(target) if candidate.method else None

    if ui.policy.fmt in ("json", "csv"):
        ui.finish(result={
            "target": {
                "path": target.path, "kind": target.kind,
                "capacity_bytes": target.capacity_bytes,
                "storage_type": target.storage_type,
                "model": target.model, "serial": target.serial,
            },
            "selected_method": selected_plan.method_id if selected_plan else None,
            "selected_nist_category": selected_plan.nist_category if selected_plan else None,
            "summary": selected_plan.summary if selected_plan else candidate.reason,
            "capabilities": {
                "probed": caps.probed,
                "probe_method": caps.probe_method,
                "transport": caps.transport,
                "best_available_tier": caps.best_tier(),
                "notes": caps.notes,
                "errors": caps.errors,
            },
            "requested_tier": ladder["requested_tier"],
            "satisfiable": ladder["satisfiable"],
            "refusal_reason": ladder["refusal_reason"],
            "ladder": ladder["ladder"],
            "warnings": list(warnings) + list(selected_plan.warnings if selected_plan else []),
            "alternatives": [
                {
                    "method": alt.method.method_id if alt.method else None,
                    "tier": alt.method.nist_category if alt.method else None,
                    "available": alt.available,
                    "reason": alt.reason,
                }
                for alt in (alternatives or [])
            ],
        })
        return EX_OK if ladder["satisfiable"] else EX_TEMPFAIL

    _print_plan(ui, target, candidate, alternatives, warnings, hpa_dco)

    ui.heading("Sanitization capability probe")
    for line in caps.summary_lines():
        ui.key(line.split(":")[0], line.split(":", 1)[1].strip() if ":" in line else line)
    for n in caps.notes:
        ui.warn(n)
    for e in caps.errors:
        ui.warn(e)

    ui.heading("Method ladder (best available first)")
    ui.table(
        [Column("TIER", max_width=22), Column("METHOD", max_width=30),
         Column("MECHANISM", max_width=68)],
        [[e["tier"], e["method"], e["mechanism"]] for e in ladder["ladder"]],
    )
    ui.note("")
    if ladder["satisfiable"]:
        ui.key("Requested tier", f"{requested} - achievable on this device")
    else:
        ui.key("Requested tier", f"{requested} - NOT ACHIEVABLE")
        ui.note("")
        ui.error(ladder["refusal_reason"])

    ui.note("")
    ui.note("DRY RUN - nothing was written. Run `s0 wipe` when satisfied.")
    return EX_OK if ladder["satisfiable"] else EX_TEMPFAIL


def cmd_wipe(args) -> int:
    """Sanitize a drive, image, file or folder, verify, and issue a certificate.

    Refuses to silently downgrade: if the operator asserts a tier with
    ``--require-tier`` and the device cannot achieve it, s0 stops and says why.
    Passing ``--allow-downgrade`` converts that refusal into an explicit,
    signed, recorded decision -- never a silent one.
    """
    ui = getattr(args, "ui", None) or UI(OutputPolicy(), "wipe")
    _print_legal_notice()
    if not _validate_cli_metadata(args):
        return EX_USAGE

    pattern = getattr(args, "pattern", "zero")
    if pattern not in ("zero", "random"):
        ui.error(f"invalid --pattern '{pattern}'. Supported patterns: zero, random")
        return EX_DATAERR

    targets = getattr(args, "targets", None)
    target_arg = getattr(args, "target", None)

    if not targets and not target_arg:
        ui.error("one of --target or --targets is required")
        return EX_USAGE

    # --- tier gate, before anything is opened for writing ---
    require_tier = getattr(args, "require_tier", None)
    if getattr(args, "firmware", False):
        require_tier = "Purge"
    if require_tier:
        from s0.wipe.methods.capabilities import probe_capabilities, plan_ladder
        try:
            probe_target = _resolve_target(target_arg or targets[0])
        except (FileNotFoundError, SafetyError) as exc:
            ui.error(str(exc))
            return EX_NOINPUT
        caps = probe_capabilities(probe_target.path, kind=probe_target.kind)
        ladder = plan_ladder(caps, require_tier)
        if not ladder["satisfiable"]:
            if not getattr(args, "allow_downgrade", False):
                ui.error(ladder["refusal_reason"])
                return EX_TEMPFAIL
            ui.warn("PROCEEDING AS AN EXPLICIT DOWNGRADE: "
                    + str(ladder["refusal_reason"]))
            ui.warn("the downgrade is recorded on the certificate; the resulting "
                    f"claim is {ladder['best_available_tier']}, not {require_tier}.")

    is_file_mode = False
    if targets:
        for tgt in targets:
            try:
                p = Path(tgt)
                if platform.is_block_device(p):
                    ui.error(f"'{tgt}' is a block storage device. Use '--target {tgt}' "
                             f"for whole-drive sanitization; '--targets' is strictly for "
                             f"files and directories.")
                    return EX_USAGE
            except Exception:
                pass
        is_file_mode = True
        args.targets = targets
    elif target_arg:
        t_path = Path(target_arg)
        is_blk = platform.is_block_device(t_path)

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
            from s0 import pdfgen
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
            from s0 import pdfgen
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
                    ui.error(hpa_msg)
                    return EX_NOPERM
                warnings.append(hpa_msg)
            elif (hpa_present or dco_present) and not is_fw:
                hpa_msg = (
                    f"target {target.path} has an active Host Protected Area (HPA) or Device Configuration Overlay (DCO) "
                    f"(visible: {hpa_dco.get('visible_max')}, native: {hpa_dco.get('native_max')}). "
                    f"Overwrite-based sanitization ({plan.method_id}) cannot reach hidden sectors beyond visible capacity."
                )
                if not args.force:
                    ui.error(hpa_msg)
                    ui.note(f"  Remove the hidden area with "
                            f"'{hpa_dco.get('restore_command')}', or pass --force to "
                            f"accept a wipe that cannot reach those sectors.")
                    return EX_NOPERM
                warnings.append(hpa_msg)

    if not args.yes:
        _print_plan(ui, target, candidate, alternatives, warnings, hpa_dco)
        if plan.method_id.startswith(("ATA_", "NVME_", "SCSI_")):
            ui.warn("Firmware-level Purge methods are constructed to ACS-4 / NVMe / SBC "
                    "and fixture-tested here, but real-world behaviour varies by vendor "
                    "and firmware revision. Verify device support before relying on it.")
        try:
            answer = input(
                f"\nType '{target.path}' to confirm permanent erasure "
                f"({plan.method_id}, NIST {plan.nist_category}): ")
        except (EOFError, KeyboardInterrupt):
            answer = ""
        if answer.strip() != str(target.path):
            ui.note("Aborted - nothing was written.")
            return EX_OK
    else:
        ui.note(f"[s0 wipe plan] target={target.path} method={plan.method_id} "
                f"tier={plan.nist_category}")

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
        ui.note(f"[{time.monotonic() - t_start:8.1f}s] {msg}")

    progress(f"wiping {target.display} with {plan.method_id} (NIST {plan.nist_category})")
    try:
        result = candidate.method.run(target, progress)
        temp = read_temperature(target.path)
        temp_str = f"Temp: {temp}°C" if temp is not None else ""
        bar.finish(extra=temp_str)
        ui.note("Sanitization pass complete; buffers flushed to disk.")
    except KeyboardInterrupt:
        bar.finish(extra="CANCELLED")
        ui.error("WIPE INTERRUPTED (Ctrl+C). The target may be partially overwritten "
                 "and must not be released. Re-run s0 wipe to completion, or escalate "
                 "to a physical destruction method.")
        return EX_INTERRUPTED
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
        ui.error("no issuer signing key found")
        return EX_CONFIG

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
    blk = None
    ledger_error = None
    try:
        blk = record_audit_event(cert, operation_type="DRIVE_ERASE", private_key=key_path)
    except Exception as exc:
        ledger_error = str(exc)
        ui.warn(f"the sanitization completed but could NOT be recorded in the audit "
                f"ledger: {exc}. The certificate exists; the chain of custody has a gap.")

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
        from s0 import pdfgen

        pdf_path = pdfgen.generate_pdf(
            cert,
            out_dir / f"certificate_{cert['cert_uuid'][:8]}.pdf",
            qr_url_template=qr_url_tpl,
        )
        pdfgen.write_qr_file(cert, out_dir / f"certificate_{cert['cert_uuid'][:8]}.qr.png")

    ok = result.status == "success" and verif.get("all_samples_match_wipe_pattern") is True
    sampled = verif.get("samples_checked", 0)
    state = "ok" if ok else "error"

    if ui.policy.fmt in ("json", "csv"):
        ui.finish(
            result={
                "target": target.path,
                "method": cert["wipe"]["method"],
                "nist_category": cert["wipe"]["nist_category"],
                "passes": cert["wipe"].get("passes"),
                "pattern": cert["wipe"].get("pattern"),
                "bytes_processed": cert["wipe"]["bytes_processed"],
                "status": cert["result"]["status"],
                "verified": verif.get("all_samples_match_wipe_pattern"),
                "samples_checked": sampled,
                "sample_bytes_each": verif.get("sample_bytes_each"),
                "planted_pattern_hits_after": verif.get("planted_pattern_hits_after"),
                "cert_uuid": cert["cert_uuid"],
                "warnings": warnings,
            },
            status="success" if ok else "failure",
            errors=([{"code": "E_VERIFICATION", "message": e} for e in result.errors]
                    + ([{"code": "E_LEDGER", "message": ledger_error}] if ledger_error else [])),
            artifacts=[a for a in (
                artifact(cert_json, "certificate", cert["signature"].get("signed_payload_hash")),
                artifact(pdf_path, "pdf_certificate") if pdf_path else None,
                artifact(out_dir / f"certificate_{cert['cert_uuid'][:8]}.qr.png", "qr_code"),
            ) if a],
            audit=({"block_index": blk.block_index, "block_hash": blk.block_hash,
                    "prev_hash": getattr(blk, "prev_hash", None)} if blk else None),
            signature=cert["signature"],
        )
        return EX_OK if ok else 1

    ui.heading("Sanitization result")
    ui.key("Result", ui.status(state, cert["result"]["status"].upper()))
    ui.key("Method", f"{cert['wipe']['method']} (NIST {cert['wipe']['nist_category']})")
    ui.key("Bytes processed", human_bytes(cert["wipe"]["bytes_processed"]))
    ui.key("Verification", f"{sampled} read-back sample"
                           f"{'' if sampled == 1 else 's'}"
                           f" - {'all match the wipe pattern' if verif.get('all_samples_match_wipe_pattern') else 'MISMATCH'}")
    if verif.get("planted_pattern_hits_after") is not None:
        ui.key("Planted markers", f"{verif['planted_pattern_hits_after']} hit(s) after sanitization")
    ui.key("Certificate", str(cert_json))
    if pdf_path:
        ui.key("PDF certificate", str(pdf_path))
    if blk:
        ui.key("Audit ledger", f"block #{blk.block_index} ({blk.block_hash[:16]})")
    for w in warnings:
        ui.warn(w)
    for e in result.errors:
        ui.error(e)
    ui.note("")
    if not ok:
        ui.error("sanitization did not complete cleanly: the certificate records the "
                 "failure and must not be presented as a completed wipe.")
    return EX_OK if ok else 1


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
                from s0 import pdfgen
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


def _iso(ts) -> str:
    """Render a UNIX timestamp as UTC, or a dash when there is no trustworthy one.

    A deletion time that is absent is reported as absent. Printing a sentinel as
    1601 or as the year 30828 would put a false date in an evidence report.
    """
    if ts is None:
        return "—"
    try:
        return datetime.fromtimestamp(float(ts), timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return "—"


def cmd_carve(args) -> int:
    """Recover deleted and unallocated files from an image, image file or device."""
    ui = getattr(args, "ui", None) or UI(OutputPolicy(), "carve")
    _print_legal_notice()
    if not _validate_cli_metadata(args):
        return EX_USAGE
    ui.note("S0 - Forensic File Carving & Recovery")

    key_path = default_issuer_key(args.key)
    _warn_if_demo_key(key_path)
    if key_path is None and not getattr(args, "no_certificate", False):
        ui.error("no issuer signing key found. s0 requires a valid Ed25519 signing key to "
                "issue forensic manifest certificates. Specify --key <path>, or pass "
                "--no-certificate to explicitly run without compliance certification.")
        return EX_CONFIG

    if getattr(args, "no_certificate", False):
        print("WARNING: --no-certificate specified. No forensic recovery manifest will be issued.", file=sys.stderr)

    ui.key("Target media", str(args.target))
    ui.key("Output directory", str(args.out_dir))

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
            ui.error(f"failed to parse custom signatures from '{args.custom_sig}': {err}")
            return EX_DATAERR

    try:
        carve_policy = None
        if getattr(args, "all_space", False):
            from s0.carve.policy import CarvePolicy as _CarvePolicy
            carve_policy = _CarvePolicy()
            carve_policy.use_free_space_only = False
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
            policy=carve_policy,
        )
        if bar:
            bar.finish(extra=f"Found: {summary.files_recovered:,}")
    except KeyboardInterrupt:
        if bar:
            bar.finish(extra="CANCELLED")
        ui.warn("File carving interrupted by the operator (Ctrl+C); "
                "the recovery index written so far is still valid.")
        return EX_INTERRUPTED
    except FileNotFoundError as exc:
        if bar:
            bar.finish(extra="FAILED")
        ui.error(str(exc))
        return EX_NOINPUT
    except PermissionError as exc:
        if bar:
            bar.finish(extra="DENIED")
        ui.error(f"permission denied: {exc}")
        return EX_NOPERM
    except OSError as exc:
        if bar:
            bar.finish(extra="FAILED")
        ui.error(f"I/O error: {exc}")
        return EX_IOERR

    from s0.carve.boundary import BOUNDARY_LABELS

    ranked = sorted(summary.carved_files, key=lambda c: (-c.confidence_score, -c.size_bytes))
    rejected_pct = (
        100.0 * summary.rejected_candidates / max(1, summary.total_candidates_found)
    )

    if ui.policy.fmt in ("json", "csv"):
        ui.finish(
            result={
                "target_path": summary.target_path,
                "source_filesystem": summary.source_filesystem,
                "total_bytes_scanned": summary.total_bytes_scanned,
                "candidates_seen": summary.total_candidates_found,
                "candidates_rejected": summary.rejected_candidates,
                "candidates_rejected_percent": int(rejected_pct * 100),
                "files_recovered": summary.files_recovered,
                "bytes_recovered": summary.bytes_recovered,
                "recovery_rate_ppm": summary.recovery_rate_ppm(),
                "output_budget_bytes": summary.output_budget_bytes,
                "budget_stop_reason": summary.budget_stop_reason,
                "by_category": summary.by_category,
                "by_recovery_method": summary.by_method,
                "allocation_aware_search": summary.free_space is not None,
                "free_space": summary.free_space,
                "deleted_names_from_journal": summary.deleted_names_from_journal,
                "allocated_candidates_skipped": summary.allocated_candidates_skipped,
                "allocated_bytes_skipped": summary.allocated_bytes_skipped,
                "rejection_summary": [
                    {"reason": reason, "count": count}
                    for reason, count in summary.rejection_summary
                ],
                "recovered_files": [
                    {
                        "file_id": c.file_id,
                        "filename": c.filename,
                        "extension": c.extension,
                        "category": c.category,
                        "offset": c.offset,
                        "size_bytes": c.size_bytes,
                        "sha256": c.sha256,
                        "confidence_score": c.confidence_score,
                        "recovery_method": c.recovery_method,
                        "boundary_method": c.boundary_method,
                        "is_fragmented": c.is_fragmented,
                        "fragment_count": c.fragment_count,
                        "original_name": c.original_name,
                        "original_path": c.original_path,
                        "deleted_at": c.deleted_at,
                        "recovered_path": c.recovered_path,
                        "heuristics": c.heuristics,
                    }
                    for c in ranked
                ],
            },
            status="success",
            artifacts=[artifact(Path(args.out_dir) / "recovery_index.json",
                                "recovery_index")],
        )
        return EX_OK

    ui.heading("Recovery summary")
    ui.key("Bytes scanned", human_bytes(summary.total_bytes_scanned))
    ui.key("Candidates seen", human_int(summary.total_candidates_found))
    ui.key("Candidates rejected", f"{human_int(summary.rejected_candidates)} ({rejected_pct:.1f}%)")
    ui.key("Files recovered", f"{summary.files_recovered} ({human_bytes(summary.bytes_recovered)})")
    ui.key("Output written", human_bytes(summary.output_budget_bytes))
    if summary.budget_stop_reason:
        ui.key("Budget stopped", summary.budget_stop_reason)
    if summary.free_space:
        ui.key("Search space", (
            f"unallocated only ({human_bytes(summary.free_space['free_bytes'])} free in "
            f"{summary.free_space['range_count']} extent(s), "
            f"{summary.free_space['free_ppm'] / 10_000:.1f}% of volume)"
        ))
        excluded = (summary.free_space["volume_bytes"] - summary.free_space["free_bytes"])
        if excluded > 0:
            ui.key("Excluded as live", human_bytes(excluded))
        if summary.allocated_candidates_skipped:
            ui.key("Signatures in live data", (
                f"{human_int(summary.allocated_candidates_skipped)} not offered to the carver"
            ))
    else:
        ui.key("Search space", (
            "whole volume (--all-space)"
            if getattr(args, "all_space", False)
            else "whole volume (no trustworthy allocation map)"
        ))
    ui.key("Source filesystem", summary.source_filesystem.upper())
    ui.note("")

    if ranked:
        # Highest confidence first: a genuine recovery must never sit below a
        # long tail of weak candidates, which is what discovery order used to do.
        ui.table(
            [
                Column("RECOVERY", max_width=18),
                Column("EXT", max_width=8),
                Column("SIZE", align="r"),
                Column("CONF", align="r"),
                Column("END OF FILE", max_width=26),
                Column("ORIGINAL NAME", max_width=26),
                Column("SHA256", max_width=18),
            ],
            [
                [
                    c.recovery_method, c.extension, human_int(c.size_bytes),
                    f"{c.confidence_score}%",
                    BOUNDARY_LABELS.get(c.boundary_method, c.boundary_method),
                    c.original_name or "—", c.sha256[:16],
                ]
                for c in ranked
            ],
            max_rows=25,
        )
        ui.note("")
        ui.key("By category", ", ".join(f"{k}={v}" for k, v in sorted(summary.by_category.items())))
        ui.key("By method", ", ".join(f"{k}={v}" for k, v in sorted(summary.by_method.items())))

    if summary.deleted_names_from_journal:
        rows = summary.deleted_names_from_journal
        ui.note("")
        ui.heading("Deleted names from the NTFS change journal")
        ui.note(ui.status("info", (
            f"{len(rows)} name(s). The journal records names and times, not "
            f"content, so these are leads and not recovered files. They are "
            f"not included in the recovered count above.")))
        ui.table(
            [
                Column("DELETED NAME", max_width=34),
                Column("PREVIOUS NAME", max_width=22),
                Column("DELETED AT", align="r"),
                Column("MFT ENTRY", align="r"),
                # Prose, not an identifier: the start of the value is the part
                # that carries the meaning, so it is cut from the right.
                Column("EVIDENCE", max_width=14, tail=False),
            ],
            [
                [
                    r["name"],
                    r.get("renamed_from") or "—",
                    _iso(r.get("deleted_at")),
                    str(r.get("mft_entry", "—")),
                    "both structures" if r.get("corroborated_by_mft") else "journal only",
                ]
                for r in rows[:20]
            ],
            max_rows=20,
        )
        if len(rows) > 20:
            ui.note(f"  ... and {len(rows) - 20} more; see the recovery index.")

    if not ranked:
        ui.note(ui.status("warn", "no file passed both boundary resolution and "
                                  "structural validation"))
        if summary.rejection_summary:
            ui.note("")
            ui.note("Most common rejection reasons:")
            for reason, count in summary.rejection_summary[:5]:
                ui.note(f"  {human_int(count):>9}  {reason}")

    if summary.warnings:
        ui.note("")
        for w in summary.warnings:
            ui.warn(w)

    ui.note("")
    ui.key("Recovery index", str(Path(args.out_dir) / "recovery_index.json"))

    blk = None
    if summary.manifest_certificate:
        try:
            blk = record_audit_event(summary.manifest_certificate, operation_type="FILE_CARVE", private_key=key_path)
            print(f"[s0 carve]  Audit Ledger     : recorded block #{blk.block_index} ({blk.block_hash[:16]}...)")
        except Exception as exc:
            ui.warn(f"failed to record the event in the audit ledger: {exc}")

        out_dir = Path(args.out_dir)
        cert_p = (
            out_dir / f"carving_manifest_{summary.manifest_certificate['cert_uuid'][:8]}.json"
        )
        cert_p.write_text(json.dumps(summary.manifest_certificate, indent=2) + "\n")
        ui.key("Signed manifest", str(cert_p))

        if not getattr(args, "no_pdf", False):
            try:
                from s0 import pdfgen
                qr_url_tpl = getattr(args, "qr_url_template", "https://s0-verify.pages.dev/?cert={cert_uuid}")
                portal_url_val = _validate_portal_url(getattr(args, "portal_url", None))
                if portal_url_val and "{cert_uuid}" not in portal_url_val:
                    qr_url_tpl = f"{portal_url_val.rstrip('/')}/?cert={{cert_uuid}}"
                pdf_p = out_dir / f"carving_manifest_{summary.manifest_certificate['cert_uuid'][:8]}.pdf"
                qr_p = out_dir / f"carving_manifest_{summary.manifest_certificate['cert_uuid'][:8]}.qr.png"
                pdfgen.generate_pdf(summary.manifest_certificate, pdf_p, qr_url_template=qr_url_tpl)
                pdfgen.write_qr_file(summary.manifest_certificate, qr_p)
                ui.key("PDF certificate", str(pdf_p))
            except Exception as exc:
                ui.warn(f"could not render the PDF certificate: {exc}")

    if blk is not None:
        ui.key("Audit ledger", f"block #{blk.block_index} ({blk.block_hash[:16]})")
    return EX_OK


# --------------------------------------------------------------------------- #
# Hash-Chained Audit Ledger Subcommands
# --------------------------------------------------------------------------- #


def cmd_audit(args) -> int:
    """Hash-chained audit ledger: list blocks, or verify chain integrity."""
    ui = getattr(args, "ui", None) or UI(OutputPolicy(), "audit")
    action = args.audit_action

    if action == "list":
        blocks = list_audit_blocks(limit=args.limit)
        if ui.policy.fmt in ("json", "csv"):
            ui.finish(result={"block_count": len(blocks), "blocks": [
                {
                    "block_index": b.block_index,
                    "timestamp": b.timestamp,
                    "operation_type": b.operation_type,
                    "operator_id": b.operator_id,
                    "target_id": b.target_id,
                    "block_hash": b.block_hash,
                    "prev_hash": getattr(b, "prev_hash", None),
                } for b in blocks
            ]})
            return EX_OK
        ui.heading(f"Hash-chained cryptographic audit ledger ({human_int(len(blocks))} blocks)")
        ui.table(
            [Column("IDX", align="r"), Column("TIMESTAMP", max_width=22),
             Column("OPERATION", max_width=16), Column("OPERATOR", max_width=16),
             Column("TARGET", max_width=24), Column("BLOCK HASH", max_width=20)],
            [[b.block_index, b.timestamp, b.operation_type, b.operator_id,
              b.target_id, b.block_hash[:16] + "..."] for b in blocks],
        )
        return EX_OK

    if action == "verify":
        trusted_keys = None
        if getattr(args, "key", None):
            from s0.crypto import load_public_pem
            trusted_keys = [load_public_pem(args.key)]

        report = verify_audit_ledger(trusted_public_keys=trusted_keys)
        reason = report.reason or ""

        if report.is_valid and getattr(report, "is_demo_signed", False):
            state, label = "warn", "VALID & CONTINUOUS - SIGNED WITH UNACCREDITED DEMO KEY"
        elif report.is_valid:
            state, label = "ok", "VALID & CONTINUOUS"
        elif "not in the trusted key set" in reason or "unknown issuer key" in reason:
            state, label = "warn", "UNVERIFIABLE - SIGNING KEY NOT IN THE TRUST SET"
        else:
            state, label = "error", "CHAIN INTEGRITY FAILURE"

        if ui.policy.fmt in ("json", "csv"):
            ui.finish(
                result={
                    "is_valid": report.is_valid,
                    "is_demo_signed": getattr(report, "is_demo_signed", False),
                    "total_blocks_verified": report.total_blocks_verified,
                    "status_label": label,
                    "reason": reason,
                    "demo_key_warning": getattr(report, "demo_key_warning", None),
                },
                status="success" if report.is_valid else "failure",
            )
            return EX_OK if report.is_valid else EX_FAILURE

        ui.heading("Auditing the hash-chained cryptographic ledger")
        ui.key("Chain status", ui.status(state, label))
        ui.key("Blocks tested", human_int(report.total_blocks_verified))
        ui.key("Details", reason or "-")
        if state == "warn" and getattr(report, "demo_key_warning", None):
            ui.note("")
            ui.warn(report.demo_key_warning)
        return EX_OK if report.is_valid else EX_FAILURE

    return EX_USAGE


def cmd_verify(args) -> int:
    """Verify a signed certificate offline against a trusted public key."""
    ui = getattr(args, "ui", None) or UI(OutputPolicy(), "verify")
    cert_path = Path(args.certificate)
    if not cert_path.is_file():
        ui.error(f"certificate file {args.certificate} does not exist")
        return EX_NOINPUT
    if cert_path.stat().st_size > 8 * 1024 * 1024:
        ui.error(f"certificate file {args.certificate} is implausibly large for a certificate")
        return EX_DATAERR

    try:
        cert_data = json.loads(cert_path.read_text(encoding="utf-8"))
    except Exception as exc:
        ui.error(f"invalid certificate JSON: {exc}")
        return EX_DATAERR
    if not isinstance(cert_data, dict):
        ui.error("certificate must be a JSON object")
        return EX_DATAERR

    from s0.crypto import load_public_pem
    pub_keys = []
    if args.key:
        key_path = Path(args.key)
        if not key_path.is_file():
            ui.error(f"public key file {args.key} does not exist")
            return EX_NOINPUT
        pub_keys.append(load_public_pem(key_path))
    else:
        try:
            pub_keys.append(load_public_pem(resources.demo_public_key()))
        except FileNotFoundError:
            pass
    if not pub_keys:
        ui.error("no trusted public key available; pass --key <issuer_public.pem>")
        return EX_CONFIG

    from s0.certificate import verify_certificate
    ok, reason = verify_certificate(cert_data, pub_keys)
    demo = (cert_data.get("signature", {}).get("public_key_fingerprint")
            == "sha256:8396af8c07a7d40f98ba492cf2b61e23fa768e66a9f627b02a9caff464e48c06")

    if ui.policy.fmt in ("json", "csv"):
        ui.finish(
            result={
                "ok": ok,
                "reason": reason,
                "cert_uuid": cert_data.get("cert_uuid"),
                "result_status": cert_data.get("result", {}).get("status"),
                "nist_category": cert_data.get("wipe", {}).get("nist_category"),
                "method": cert_data.get("wipe", {}).get("method"),
                "device_id": cert_data.get("device", {}).get("device_id"),
                "organization": cert_data.get("issuer", {}).get("organization"),
                "operator_id": cert_data.get("issuer", {}).get("operator_id"),
                "public_key_fingerprint": cert_data.get("signature", {}).get("public_key_fingerprint"),
                "unaccredited_demo_key": demo,
            },
            status="success" if ok else "failure",
        )
        return EX_OK if ok else EX_FAILURE

    if ok:
        state = "warn" if demo else "ok"
        label = ("AUTHENTIC - but signed with an unaccredited demonstration key"
                 if demo else "AUTHENTIC & CRYPTOGRAPHICALLY VERIFIED")
        ui.heading("Offline certificate verification")
        ui.key("Status", ui.status(state, label))
        if demo:
            ui.warn("demo-key signatures must not be used for legal chain of custody "
                    "or regulatory compliance")
    else:
        ui.heading("Offline certificate verification")
        ui.key("Status", ui.status("error", "VERIFICATION FAILED"))
        ui.key("Reason", reason)

    ui.key("Certificate UUID", cert_data.get("cert_uuid", "-"))
    ui.key("Issued at", cert_data.get("issued_at", "-"))
    ui.key("Issuer", f"{cert_data.get('issuer', {}).get('organization', '-')} / "
                     f"{cert_data.get('issuer', {}).get('operator_id', '-')}")
    ui.key("Tool", f"{cert_data.get('tool', {}).get('name', '-')} "
                   f"v{cert_data.get('tool', {}).get('version', '-')}")
    ui.key("Method", f"{cert_data.get('wipe', {}).get('method', '-')} "
                     f"({cert_data.get('wipe', {}).get('nist_category', '-')})")
    ui.key("Device", cert_data.get("device", {}).get("device_id", "-"))
    ui.key("Result", cert_data.get("result", {}).get("status", "-"))
    ui.key("Key fingerprint", cert_data.get("signature", {}).get("public_key_fingerprint", "-"))
    if not ok:
        ui.note("")
        ui.key("Reason", reason)
    return EX_OK if ok else EX_FAILURE


def cmd_keygen(args) -> int:
    """Generate an Ed25519 signing keypair for an issuing authority or operator."""
    ui = getattr(args, "ui", None) or UI(OutputPolicy(), "keygen")
    from s0 import crypto
    out_dir = Path(args.out_dir)
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        ui.error(f"cannot create output directory {out_dir}: {exc}")
        return EX_CANTCREAT

    priv = crypto.generate_private_key()
    pub = priv.public_key()
    priv_p = out_dir / f"{args.name}_private.pem"
    pub_p = out_dir / f"{args.name}_public.pem"
    try:
        crypto.write_private_pem(priv, priv_p)
        crypto.write_public_pem(pub, pub_p)
        os.chmod(priv_p, 0o600)          # a private key must not be group/world readable
    except OSError as exc:
        ui.error(f"cannot write the keypair: {exc}")
        return EX_CANTCREAT

    fp = crypto.public_key_fingerprint(pub)
    if ui.policy.fmt in ("json", "csv"):
        ui.finish(result={
            "algorithm": "Ed25519",
            "private_key_path": str(priv_p.resolve()),
            "public_key_path": str(pub_p.resolve()),
            "fingerprint": fp,
        }, artifacts=[artifact(priv_p, "private_key"), artifact(pub_p, "public_key")])
        return EX_OK

    ui.heading("Generated Ed25519 signing keypair")
    ui.key("Algorithm", "Ed25519 (RFC 8032)")
    ui.key("Private key", f"{priv_p}  <- keep secret and offline")
    ui.key("Public key", str(pub_p))
    ui.key("Fingerprint", fp)
    ui.note("")
    ui.note("The private key is written with mode 0600. It is the root of trust for "
            "every certificate this authority will ever issue: anyone holding it can "
            "forge certificates that verify. Back it up offline and never commit it.")
    return EX_OK


# --------------------------------------------------------------------------- #
# Maintenance & Upgrade Commands
# --------------------------------------------------------------------------- #


def get_upgrade_branch(args) -> str:
    """Which upstream branch to track.

    The installed checkout's own branch is the right answer, not a hard-coded
    `master`: a contributor working on a feature branch who runs `s0 upgrade`
    should not have their work silently fast-forwarded onto the release line.
    """
    explicit = getattr(args, "branch", None)
    if explicit:
        return explicit
    env = os.environ.get("S0_UPGRADE_BRANCH")
    if env:
        return env
    try:
        cur = subprocess.check_output(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            text=True, timeout=10).strip()
        if cur and cur != "HEAD":
            return cur
    except (OSError, subprocess.SubprocessError):
        pass
    return "master"


def cmd_upgrade(args) -> int:
    """Upgrade the s0 installation to the latest published version."""
    ui = getattr(args, "ui", None) or UI(OutputPolicy(), "upgrade")
    ui.banner("S0 — Suite Upgrade & Maintenance")

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
        ui.error("could not locate the s0 installation repository")
        ui.note("To install or upgrade s0, run:")
        if sys.platform == "win32":
            ui.note("  irm https://s0-install.pages.dev/upgrade-ps1 -OutFile s0-upgrade.ps1")
            ui.note("  # Inspect s0-upgrade.ps1 before running, then:")
            ui.note("  powershell -ExecutionPolicy Bypass -File .\\s0-upgrade.ps1")
        else:
            ui.note("  curl -fsSL https://s0-install.pages.dev/upgrade-sh -o s0-upgrade.sh")
            ui.note("  # Inspect s0-upgrade.sh before running, then:")
            ui.note("  bash s0-upgrade.sh")
        return 1

    ui.key("Installation", str(repo_dir))
    try:
        cur_hash = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"], cwd=str(repo_dir), text=True
        ).strip()
        ui.key("Current commit", cur_hash)
        branch = get_upgrade_branch(args)
        ui.note(f"Fetching origin/{branch}...")
        subprocess.check_call(["git", "fetch", "origin", branch, "-q"], cwd=str(repo_dir))
        latest_hash = subprocess.check_output(
            ["git", "rev-parse", "--short", f"origin/{branch}"], cwd=str(repo_dir), text=True
        ).strip()

        if cur_hash == latest_hash and not getattr(args, "force", False):
            ui.key("Source", f"already up to date at commit {cur_hash}")
        else:
            subprocess.check_call(
                ["git", "pull", "--ff-only", "origin", get_upgrade_branch(args), "-q"],
                cwd=str(repo_dir))
            ui.key("Source", f"updated {cur_hash} -> {latest_hash}")

        py_bin = sys.executable
        ui.note("Refreshing dependencies...")
        subprocess.check_call([py_bin, "-m", "pip", "install", "--upgrade", "pip", "-q"])
        for pkg in (".",):
            subprocess.check_call(
                [py_bin, "-m", "pip", "install", "-e", str(repo_dir / pkg), "-q"])
        subprocess.check_call(
            [py_bin, "-m", "pip", "install", "reportlab", "qrcode", "pillow", "-q"])
        ui.key("Dependencies", "refreshed")

        ver = subprocess.check_output(
            [py_bin, "-m", "s0.cli.main", "--version"], text=True).strip()
        ui.note("")
        ui.key("Result", ui.status("ok", f"s0 upgraded to {ver} ({latest_hash})"))
        return EX_OK
    except subprocess.CalledProcessError as exc:
        ui.error(f"upgrade failed while running {exc.cmd[0]}: {exc}")
        return EX_SOFTWARE
    except Exception as exc:
        ui.error(f"upgrade failed: {exc}")
        return EX_SOFTWARE


def cmd_uninstall(args) -> int:
    """Safely uninstall s0, preserving the audit ledger and issued certificates."""
    ui = getattr(args, "ui", None) or UI(OutputPolicy(), "uninstall")
    ui.banner("S0 — Uninstallation")

    if sys.platform == "win32":
        ui.heading("On Windows, use the official uninstallation script")
        ui.note("    curl -fsSL https://s0-install.pages.dev/uninstall-ps1 -o s0-uninstall.ps1")
        ui.note("    # Inspect s0-uninstall.ps1 before running, then:")
        ui.note("    powershell -ExecutionPolicy Bypass -File .\\s0-uninstall.ps1")
        return EX_OK

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
        ui.error("could not locate the s0 installation directory")
        ui.note("To uninstall s0 manually, download and run the script:")
        ui.note("  curl -fsSL https://s0-install.pages.dev/uninstall-sh -o s0-uninstall.sh")
        ui.note("  # Inspect s0-uninstall.sh before running, then:")
        ui.note("  bash s0-uninstall.sh")
        return EX_NOINPUT
        return 1

    ui.key("Target directory", str(repo_dir))
    audit_db = Path.home() / ".s0" / "s0_audit.db"
    purge_all = getattr(args, "purge_all", False) or getattr(args, "purge", False)
    if audit_db.is_file():
        if purge_all:
            ui.warn("PURGING the audit ledger as requested (--purge-all). This is "
                    "irreversible: every historical chain-of-custody record is destroyed.")
        else:
            import time as _time
            timestamp = _time.strftime("%Y%m%d_%H%M%S")
            bak_dest = Path.home() / f"s0_audit.db.bak.{timestamp}"
            try:
                shutil.copy2(audit_db, bak_dest)
                legacy_dest = Path.home() / "s0_audit.db.bak"
                shutil.copy2(audit_db, legacy_dest)
                ui.key("Audit ledger", f"preserved at {bak_dest}")
                ui.note("    (use --purge-all only to destroy the audit log deliberately)")
            except Exception as exc:
                ui.warn(f"could not back up the audit ledger: {exc}")

    if not getattr(args, "yes", False):
        ui.warn("This removes the s0 installation from this system. Issued "
                "certificates are NOT revoked by uninstalling.")
        try:
            confirm = input("Are you sure you want to uninstall s0? [y/N]: ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            ui.note("")
            ui.note("Aborted.")
            return EX_INTERRUPTED
        if confirm != "y":
            ui.note("Uninstallation cancelled.")
            return EX_OK

    ui.note("Removing command symlinks...")
    removed = 0
    for sym in (Path.home() / ".local" / "bin" / "s0",
                Path.home() / "bin" / "s0",
                Path("/usr/local/bin/s0")):
        if sym.is_symlink() or sym.exists():
            try:
                sym.unlink()
                removed += 1
            except OSError as exc:
                ui.warn(f"could not remove {sym}: {exc}")
    ui.key("Symlinks removed", human_int(removed))

    # Only ever delete a directory that is exactly ~/.s0. A development checkout
    # or a custom install path is left alone: uninstalling a tool must not
    # destroy the user's source tree.
    home_s0 = (Path.home() / ".s0").resolve()
    if repo_dir.resolve() == home_s0:
        ui.note(f"Removing installation directory: {repo_dir}")
        try:
            shutil.rmtree(repo_dir, ignore_errors=True)
            ui.key("Installation", ui.status("ok", "removed"))
        except OSError as exc:
            ui.error(f"could not remove the installation directory: {exc}")
            return EX_CANTCREAT
    else:
        ui.warn(f"{repo_dir} is a development checkout or a custom install path; "
                f"its files were preserved. Remove it by hand if that is what you want.")

    ui.note("")
    ui.key("Result", ui.status("ok", "s0 uninstalled"))
    return EX_OK


# --------------------------------------------------------------------------- #
# Module 3: Forensic Bit-Stream Drive Imaging & Cloning
# --------------------------------------------------------------------------- #


def cmd_image(args) -> int:
    """Forensic bit-stream acquisition and device-to-device cloning.

    Also serves `s0 clone`; the two are the same code path with different
    confirmation semantics.
    """
    ui = getattr(args, "ui", None) or UI(OutputPolicy(), "image")
    from s0.image.imager import ImagingOptions, acquire_image

    _print_legal_notice()
    if not _validate_cli_metadata(args):
        return EX_USAGE

    dst_p = Path(args.destination)
    is_blk = platform.is_block_device(dst_p)

    if is_blk and not args.yes:
        ui.error(f"the destination '{args.destination}' is a PHYSICAL BLOCK DEVICE. "
                 f"Writing will destroy all existing partition tables, filesystems and data.")
        try:
            conf = input(f"Type '{args.destination}' to confirm clone to "
                         f"{args.destination}: ").strip()
        except (EOFError, KeyboardInterrupt):
            conf = ""
        if conf != str(args.destination):
            ui.note("Aborted by the operator.")
            return EX_OK

    bar = ui.progress(1, operation="Forensic Acquisition")

    def _progress(bytes_copied, total_bytes, speed, bad_sectors):
        if bar.total <= 1 and total_bytes > 0:
            bar.total = total_bytes
        extra = f"{speed:.1f} MB/s"
        if bad_sectors > 0:
            extra += f" | bad sectors: {bad_sectors}"
        bar.update(bytes_copied, extra=extra)

    key_path = default_issuer_key(getattr(args, "key", None))
    _warn_if_demo_key(key_path)
    if key_path is None and not getattr(args, "no_certificate", False):
        ui.error("no issuer signing key found. s0 requires a valid Ed25519 signing key "
                 "to issue forensic acquisition certificates. Specify --key <path>, or "
                 "pass --no-certificate to run without compliance certification.")
        return EX_CONFIG

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

    ui.key("Source", str(args.source))
    ui.key("Destination", str(args.destination))
    ui.key("Block size", human_bytes(args.block_size))
    ui.key("Fault tolerance",
           "enabled (zero-fill unreadable blocks)" if not args.no_recovery
           else "disabled (abort on the first I/O error)")
    ui.note("")

    try:
        result = acquire_image(options, progress_callback=_progress)
        bar.finish()
    except SafetyError as exc:
        bar.finish(extra="REFUSED")
        ui.error(f"refused: {exc}")
        return EX_NOPERM
    except KeyboardInterrupt:
        bar.finish(extra="CANCELLED")
        ui.error("acquisition cancelled by the operator (Ctrl+C). The destination "
                 "image is INCOMPLETE and must not be used as evidence.")
        return EX_INTERRUPTED
    except FileNotFoundError as exc:
        bar.finish(extra="FAILED")
        ui.error(str(exc))
        return EX_NOINPUT
    except PermissionError as exc:
        bar.finish(extra="DENIED")
        ui.error(f"permission denied: {exc}")
        return EX_NOPERM
    except OSError as exc:
        bar.finish(extra="FAILED")
        ui.error(f"I/O error: {exc}")
        return EX_IOERR

    if result.error:
        bar.finish(extra="FAILED")
        ui.error(f"acquisition failed: {result.error}")
        return EX_IOERR

    hash_label = "Image SHA-256" if result.bad_sectors_count > 0 else "Source SHA-256"
    status = ("partial" if result.bad_sectors_count > 0 else "success")

    if ui.policy.fmt in ("json", "csv"):
        ui.finish(
            result={
                "operation": "clone" if result.is_clone else "image",
                "status": status,
                "source": str(args.source),
                "destination": str(args.destination),
                "bytes_copied": result.bytes_copied,
                "bad_sectors": result.bad_sectors_count,
                "duration_seconds": int(result.duration_seconds),
                "speed_mbps": int(result.speed_mbps),
                "source_sha256": result.source_sha256,
                "source_md5": result.source_md5,
                "block_size": args.block_size,
                "fault_tolerance": not args.no_recovery,
                "manifest_path": result.manifest_path,
                "cert_uuid": (result.manifest_certificate or {}).get("cert_uuid"),
                "audit_ledger_recorded": bool(getattr(result, "audit_ledger_recorded", False)),
            },
            status=status,
            errors=([{"code": "E_BAD_SECTORS",
                      "message": f"{result.bad_sectors_count} unreadable blocks were "
                                 f"zero-filled; the destination is not a faithful copy",
                      "context": {"count": result.bad_sectors_count}}]
                    if result.bad_sectors_count else None),
            artifacts=[a for a in (
                artifact(result.manifest_path, "acquisition_manifest") if result.manifest_path else None,
            ) if a],
        )
        return EX_OK if status == "success" else 1

    ui.heading("Acquisition result")
    if result.bad_sectors_count > 0:
        ui.key("Status", ui.status("warn", f"COMPLETED WITH ERRORS - "
                                            f"{result.bad_sectors_count} unreadable blocks "
                                            f"were zero-filled"))
        ui.warn("the destination is NOT a faithful copy of the source. NIST SP 800-86 "
                "treats an acquisition with substituted content as a different artifact; "
                "record the substituted ranges before offering this image as evidence.")
    else:
        ui.key("Status", ui.status("ok", "FORENSIC ACQUISITION COMPLETED"))
    ui.key("Operation", "Drive Clone" if result.is_clone else "Raw bit-stream image")
    ui.key("Bytes acquired", f"{human_int(result.bytes_copied)} "
                             f"({human_bytes(result.bytes_copied)})")
    ui.key("Duration", f"{result.duration_seconds:.1f} s at {result.speed_mbps:.1f} MB/s")
    ui.key("Bad sectors", human_int(result.bad_sectors_count))
    ui.key(hash_label, result.source_sha256)
    ui.key("Source MD5", result.source_md5)
    if result.manifest_path:
        ui.key("Manifest file", str(result.manifest_path))
    if result.manifest_certificate:
        recorded = bool(getattr(result, "audit_ledger_recorded", False))
        ui.key("Certificate", f"{result.manifest_certificate.get('cert_uuid')} "
                              f"({'signed and appended to the audit ledger' if recorded else 'signed, NOT recorded in the audit ledger'})")
        if not recorded and getattr(result, "audit_ledger_error", None):
            ui.warn(f"audit ledger write failed: {result.audit_ledger_error}")
        if not getattr(args, "no_pdf", False):
            try:
                from s0 import pdfgen
                out_dir_p = Path(args.out_dir)
                qr_url_tpl = getattr(args, "qr_url_template",
                                    "https://s0-verify.pages.dev/?cert={cert_uuid}")
                portal_url_val = _validate_portal_url(getattr(args, "portal_url", None))
                if portal_url_val and "{cert_uuid}" not in portal_url_val:
                    qr_url_tpl = f"{portal_url_val.rstrip('/')}/?cert={{cert_uuid}}"
                stem = result.manifest_certificate["cert_uuid"][:8]
                pdf_p = out_dir_p / f"certificate_{stem}.pdf"
                qr_p = out_dir_p / f"certificate_{stem}.qr.png"
                pdfgen.generate_pdf(result.manifest_certificate, pdf_p, qr_url_template=qr_url_tpl)
                pdfgen.write_qr_file(result.manifest_certificate, qr_p)
                ui.key("PDF certificate", str(pdf_p))
            except Exception as exc:
                ui.warn(f"PDF generation failed: {exc}")
    ui.note("")
    return EX_OK if status == "success" else 1


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
        r for r in (resources.repo_root(), Path.home() / ".s0", Path("/opt/s0"))
        if r is not None
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
    p.add_argument("--version", action="version", version=f"s0 {__version_str__}")
    add_global_arguments(p)
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
    common.add_argument("--version", action="version", version=f"s0 {__version_str__}")
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
    pln.add_argument("--require-tier", choices=("Clear", "Purge", "Destroy"), default=None,
                     help="assert the minimum sanitization tier the medium must support; "
                          "s0 refuses when the device cannot achieve it")
    pln.add_argument("--firmware", action="store_true",
                     help="shortcut for --require-tier Purge: only firmware-mediated "
                          "Purge methods satisfy this request")
    pln.add_argument("--json", action="store_true", help="shorthand for --format json")
    pln.add_argument("--output-format", choices=("text", "json"), default=None,
                     help=argparse.SUPPRESS)
    pln.set_defaults(func=cmd_plan)

    wp = sub.add_parser("wipe", parents=[common], help="wipe drive, file(s), or folder(s), verify, issue signed certificate")
    wp.add_argument("--targets", "-t", nargs="+", help="multiple target files or directories to sanitize")
    wp.add_argument("--require-tier", choices=("Clear", "Purge", "Destroy"), default=None,
                    help="refuse to run unless the device can achieve this tier. "
                         "s0 will not silently downgrade: without this flag the "
                         "selected method is always reported, whatever it is")
    wp.add_argument("--allow-downgrade", action="store_true",
                    help="if --require-tier cannot be met, proceed with the best "
                         "available method and record the downgrade on the certificate")
    wp.add_argument("--sanitize", choices=("block-erase", "crypto-erase", "overwrite"),
                    default=None,
                    help="force a specific firmware sanitize action (ATA 0xB4 / "
                         "NVMe 0x84 / SCSI 0x48) instead of the automatic choice")
    wp.add_argument("--sanitize-passes", type=int, default=1,
                    help="pass count for --sanitize overwrite (1-255; 0 is refused "
                         "because the specification reads 0 as SIXTEEN passes)")
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
    crv.add_argument(
        "--all-space",
        action="store_true",
        help=(
            "search the whole volume instead of only unallocated space. By default the "
            "filesystem's own allocation map is read (ext4/FAT32/exFAT/NTFS) and carving is "
            "restricted to free space, so files that are still allocated are not reported as "
            "recoveries. Use this only when the allocation map cannot be trusted."
        ),
    )
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
    upg.add_argument("--branch", help="upstream branch to track (default: this checkout's own branch)")
    upg.set_defaults(func=cmd_upgrade)

    # 7. Uninstall Subcommand
    uinst = sub.add_parser("uninstall", help="safely remove s0 suite from this system")
    uinst.add_argument("--yes", "-y", action="store_true", help="skip interactive confirmation prompt")
    uinst.add_argument("--purge-all", "--purge", action="store_true", help="permanently delete audit ledger without backup")
    uinst.add_argument("--keep-audit", action="store_true", help="legacy flag: audit ledger is now backed up by default")
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
        from s0.live.live_manager import register_live_parser
        register_live_parser(sub)
    except ImportError:
        from s0.live.live_manager import register_live_parser
        register_live_parser(sub)

    _attach_global_arguments(p)
    return p


def _attach_global_arguments(root: argparse.ArgumentParser) -> None:
    """Give every subcommand the same global output flags.

    Without this, `--quiet` or `--json` would work on `carve` and silently do
    nothing on `wipe`, which is exactly the kind of inconsistency that makes a
    tool impossible to script. Applied as a post-pass so subparsers registered
    dynamically (the `live` group) are covered too.
    """
    def walk(parser: argparse.ArgumentParser) -> None:
        for action in parser._actions:
            if isinstance(action, argparse._SubParsersAction):
                for child in action.choices.values():
                    add_global_arguments(child)
                    walk(child)

    walk(root)


def main(argv=None) -> int:
    """Entry point.

    Contract enforced here, once, for every subcommand:

    * the global output flags are resolved before any command runs;
    * the banner is chrome and is suppressed off-TTY, under ``--quiet`` and
      under a structured output format;
    * the resolved :class:`UI` is attached to ``args`` so no command has to
      re-derive presentation settings;
    * ``KeyboardInterrupt`` maps to 130 and argparse's own failure to
      ``EX_USAGE`` (64) rather than a bare 2.
    """
    raw_args = sys.argv[1:] if argv is None else list(argv)
    try:
        parser = build_parser()
        args = parser.parse_args(argv)

        policy = policy_from_args(args)
        args.ui = UI(policy, command=getattr(args, "command", "s0"))
        args.policy = policy

        if not raw_args or raw_args in (["--help"], ["-h"]):
            _print_banner(policy)

        code = args.func(args)
        return int(code) if code is not None else EX_OK
    except KeyboardInterrupt:
        sys.stderr.write("\n\n!  Operation cancelled by the operator (Ctrl+C).\n")
        return EX_INTERRUPTED
    except SystemExit as exc:
        code = exc.code
        if code is None:
            return EX_OK
        if isinstance(code, int):
            # argparse exits 2 for a usage error; sysexits says 64.
            return EX_USAGE if code == 2 else code
        sys.stderr.write(f"{code}\n")
        return EX_USAGE


if __name__ == "__main__":
    raise SystemExit(main())
