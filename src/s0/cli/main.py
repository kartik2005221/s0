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

from s0 import __version__, __version_str__, platform, resources
from s0.audit import list_audit_blocks, record_audit_event, verify_audit_ledger
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
from s0.cli.ui import UI, Column, add_global_arguments, artifact, human_bytes, human_int, policy_from_args
from s0.config import CONFIG
from s0.crypto import is_demo_key
from s0.progress import ProgressBar
from s0.temperature import read_temperature
from s0.terminal import (
    EX_CANTCREAT,
    EX_CONFIG,
    EX_DATAERR,
    EX_FAILURE,
    EX_INTERRUPTED,
    EX_IOERR,
    EX_NOINPUT,
    EX_NOPERM,
    EX_OK,
    EX_SOFTWARE,
    EX_TEMPFAIL,
    EX_USAGE,
    OutputPolicy,
)
from s0.wipe.methods.ata import hpa_dco_report
from s0.wipe.methods.base import Plan
from s0.wipe.methods.overwrite import plant_patterns
from s0.wipe.planner import (
    default_issuer_key,
    make_certificate,
    select_method,
    take_pre_samples,
    verify_wipe,
)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _validate_portal_url(url: str | None) -> str | None:
    if not url:
        return url
    import urllib.parse

    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("https", "http"):
        sys.stderr.write(f"\n❌ Error: Invalid portal URL scheme '{parsed.scheme}': must be http or https\n")
        sys.exit(1)
    if parsed.scheme == "http" and parsed.hostname not in ("localhost", "127.0.0.1"):
        sys.stderr.write(
            "\n❌ Error: Plaintext HTTP portal URL is restricted to localhost/127.0.0.1; use HTTPS for remote hosts\n"
        )
        sys.exit(1)
    if parsed.username or parsed.password:
        sys.stderr.write("\n❌ Error: Portal URL must not contain embedded user credentials (@)\n")
        sys.exit(1)
    if any(c in url for c in "<>\"'`\\| "):
        sys.stderr.write("\n❌ Error: Portal URL contains disallowed characters\n")
        sys.exit(1)
    return url


def _ui_policy(args):
    """The OutputPolicy for this invocation, or None if not built yet.

    The legal notice and the demo-key warning are emitted from deep inside command
    handlers, long after `main()` has built the policy. They were reading their own
    hard-coded escapes instead, which is why `--no-color`, `--color never` and
    `NO_COLOR=1` were all ignored for exactly those two messages.
    """
    ui = getattr(args, "ui", None)
    return getattr(ui, "policy", None) if ui is not None else None


def _warn_if_demo_key(key_path: Path | None, policy=None) -> None:
    """Warn when signing with the unaccredited demo key.

    The escapes used to be literal, so the notice stayed yellow under
    `--no-color`, `--color never` and `NO_COLOR=1`. It goes through the policy now,
    like every other coloured string.
    """
    if key_path is None or not is_demo_key(key_path):
        return
    out = policy.err_stream if policy is not None else sys.stderr
    use = policy.use_color if policy is not None else True
    yellow = "\033[33m" if use else ""
    reset = "\033[0m" if use else ""
    out.write(
        f"\n{yellow}[!] NOTICE: Operation signed with unaccredited demonstration "
        "key (demo_issuer_private.pem).\n"
        "    DO NOT use this certificate for legal chain-of-custody or regulatory "
        f"compliance.{reset}\n\n"
    )


def _prepare_out_dir(args, *, ui=None) -> Path | None:
    """Create and prove the output directory is writable *before* anything is erased.

    Every command that produces artefacts used to discover an unwritable `--out-dir` at
    the moment it first tried to write, which is after the destructive work. The
    reported consequences:

    * `s0 wipe --targets f --out-dir /ro/sub` erased the file, then raised
      PermissionError, which the top-level handler reported as "This is a bug in s0"
      with exit 70. The exit-code table promises 73 (`EX_CANTCREAT`) for exactly this.
    * the same with an `--out-dir` that is a regular file gave `FileExistsError`, also
      exit 70.

    In both cases the target was gone and no certificate existed. So the directory is
    created and probed here, and a failure returns the documented code with nothing
    written.

    The probe is a real file create-and-delete rather than `os.access`, because
    `os.access` answers for the *real* uid while a process with capabilities or a
    read-only mount can still fail on write, and `access` lies on those.
    """
    raw = getattr(args, "out_dir", None) or "."
    out_dir = Path(raw)

    if out_dir.exists() and not out_dir.is_dir():
        msg = f"error: --out-dir {out_dir} exists and is not a directory"
        (ui.error(msg) if ui else print(msg, file=sys.stderr))
        return None

    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        msg = f"error: cannot create --out-dir {out_dir}: {exc.strerror or exc}"
        (ui.error(msg) if ui else print(msg, file=sys.stderr))
        return None

    probe = out_dir / f".s0-write-probe-{os.getpid()}"
    try:
        probe.write_bytes(b"")
        probe.unlink()
    except OSError as exc:
        msg = f"error: --out-dir {out_dir} is not writable: {exc.strerror or exc}. Nothing has been written."
        (ui.error(msg) if ui else print(msg, file=sys.stderr))
        try:
            probe.unlink()
        except OSError:
            pass
        return None
    return out_dir


def _load_issuer_key(args, ui=None) -> tuple[Path | None, str | None]:
    """Resolve *and load* the signing key before any destructive step.

    Resolving the path is not enough. `--key /path/to/a-file-that-is-not-a-key`
    resolved fine, the target was erased, certificate generation then failed to load the
    key, and the handler warned and returned 0 -- a destroyed target, no evidence, and a
    success exit code.

    Loading here turns that into an error before the first write.
    """
    from s0 import crypto

    key_path = default_issuer_key(getattr(args, "key", None))
    _warn_if_demo_key(key_path, _ui_policy(args))

    if key_path is None:
        if getattr(args, "no_certificate", False):
            return None, None
        msg = (
            "error: no issuer signing key found.\n"
            "s0 requires a valid Ed25519 signing key to issue compliance certificates.\n"
            "Specify --key <path> or pass --no-certificate to run without certification."
        )
        (ui.error(msg) if ui else print(msg, file=sys.stderr))
        return None, "config"

    try:
        crypto.load_private_pem(key_path)
    except Exception as exc:
        msg = (
            f"error: --key {key_path} is not a usable Ed25519 private key: "
            f"{type(exc).__name__}: {exc}. Nothing has been erased."
        )
        (ui.error(msg) if ui else print(msg, file=sys.stderr))
        return None, "config"

    return key_path, None


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
    use = policy.use_color if policy is not None else True
    cyan = "\033[1;36m" if use else ""
    bold = "\033[1m" if use else ""
    dim = "\033[2m" if use else ""
    link = "\033[4;36m" if use else ""
    reset = "\033[0m" if use else ""
    for line in _S0_ASCII.strip("\n").split("\n"):
        out.write(f"{cyan}{line}{reset}\n")
    ver = CONFIG.get("version", __version__)
    out.write(f"{bold}  Sector Zero (s0){reset} v{ver}\n")
    out.write(f"  {dim}@kartik2005221{reset}  {link}https://github.com/kartik2005221/s0{reset}\n\n")
    out.flush()


_LEGAL_NOTICE = (
    "\n⚖  LEGAL & RESPONSIBLE USE NOTICE:\n"
    "   Only operate on storage media you own or have explicit written authorization\n"
    "   to process. Unauthorized wiping, erasure, or forensic recovery may violate\n"
    "   computer crime legislation (e.g., CFAA 18 U.S.C. § 1030, Computer Misuse Act,\n"
    "   IT Act 2000 §§ 43/66). s0 is a digital forensic sanitization and recovery tool.\n\n"
)


def _color_allowed(policy=None) -> bool:
    """Whether escapes may be emitted.

    Prefers the caller's OutputPolicy. With no policy in scope, falls back to the
    environment, which is what the report exercised: `NO_COLOR=1` was ignored by
    every hard-coded string in this module.
    """
    if policy is not None:
        return bool(policy.use_color)
    import os as _os

    if _os.environ.get("NO_COLOR"):
        return False
    if _os.environ.get("S0_NO_COLOR") or _os.environ.get("TERM") == "dumb":
        return False
    return True


def _c(text: str, code: str, policy=None) -> str:
    """Wrap `text` in an ANSI `code` only when the policy allows colour.

    Every literal escape in this module went through hard-coded strings, so
    `--no-color`, `--color never` and `NO_COLOR=1` were all ignored by the legal
    notice, the demo-key notice, the root-filesystem advisory and the `s0 web`
    root warning. `--quiet` was ignored too, since none of these consulted the
    quiet flag.
    """
    return f"\033[{code}m{text}\033[0m" if _color_allowed(policy) else text


def _print_legal_notice(policy=None) -> None:
    """Print the legal notice once per process, to stderr, never into piped data."""
    if os.environ.get("S0_LEGAL_NOTICE_SHOWN"):
        return
    os.environ["S0_LEGAL_NOTICE_SHOWN"] = "1"
    use = policy.use_color if policy is not None else True
    notice = _LEGAL_NOTICE
    if use:
        notice = notice.replace(
            "⚖  LEGAL & RESPONSIBLE USE NOTICE:", "\033[1;33m⚖  LEGAL & RESPONSIBLE USE NOTICE:\033[0m"
        )
    sys.stderr.write(notice)
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
                from s0.platform.windows.s0_eraser import get_windows_target_size

                sz = get_windows_target_size(path)
            except Exception:
                pass
            return DevTarget(path=path, kind="block", capacity_bytes=sz, storage_type="UNKNOWN")

    if sys.platform != "win32" and (
        platform.looks_like_windows_volume_letter(path) or platform.is_windows_volume_path(path)
    ):
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
            from s0.platform.macos.s0_eraser import get_macos_target_size

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


def _print_plan(
    ui, target: DevTarget, candidate, alternatives, warnings: list[str], hpa_dco: dict | None
) -> None:
    """Render the dry-run plan through the shared presentation layer."""
    m = candidate.method
    ui.heading("Sanitization plan (dry run)")
    ui.key(
        "Target",
        f"{target.path} ({target.kind}, {target.storage_type}, {human_bytes(target.capacity_bytes)})",
    )
    if m is None:
        ui.key("Method", "NONE AVAILABLE")
        ui.key("Reason", candidate.reason)
        return
    plan: Plan = m.plan(target)
    ui.key("Method", plan.method_id)
    ui.key("NIST category", plan.nist_category)
    ui.key("Summary", plan.summary)
    if plan.method_id.startswith(("ATA_", "NVME_", "SCSI_")):
        ui.warn(
            "Firmware-level Purge methods are constructed to ACS-4 / NVMe / SBC and "
            "are fixture-tested here, but real-world behaviour varies by vendor and "
            "firmware revision. Verify device support before relying on it."
        )
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
    if hpa_dco and (hpa_dco.get("hpa_present") or hpa_dco.get("dco_present") or hpa_dco.get("note")):
        ui.note("")
        ui.key("HPA / DCO", "")
        ui.key(
            "  HPA present",
            "Detected"
            if hpa_dco.get("hpa_present")
            else ("None" if hpa_dco.get("hpa_present") is False else "Unknown"),
        )
        ui.key(
            "  DCO present",
            "Detected"
            if hpa_dco.get("dco_present")
            else ("None" if hpa_dco.get("dco_present") is False else "Unknown"),
        )
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

    # Detection problems reach both streams. They already went to the log; without
    # this they did not reach the envelope, so `s0 list --json` reported
    # `"warnings": []` while the operator's terminal complained three times about
    # the same device. The output meant for automation was the one that looked clean.
    from s0.cli.devices import drain_detection_warnings

    for message in drain_detection_warnings():
        ui.warn(message)

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
        ui.finish(
            result={
                "targets": rows,
                "target_count": len(rows),
                "note": "Image-file targets work too: use --target /path/to/file.img",
            }
        )
        return EX_OK
    if ui.policy.fmt == "csv":
        ui.line("path,kind,storage_type,capacity_bytes,model,serial,mounted,os_drive")
        for r in rows:
            ui.line(
                ",".join(
                    [
                        r["path"],
                        r["kind"],
                        r["storage_type"],
                        str(r["capacity_bytes"]),
                        r["model"] or "",
                        r["serial"] or "",
                        "yes" if r["mounted"] else "no",
                        "yes" if r["os_drive"] else "no",
                    ]
                )
            )
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
                r["path"],
                r["kind"],
                r["storage_type"],
                human_bytes(r["capacity_bytes"]),
                r["model"] or "—",
                r["serial"] or "—",
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
    from s0.wipe.methods.capabilities import plan_ladder, probe_capabilities

    caps = probe_capabilities(target.path, kind=target.kind)
    requested = getattr(args, "require_tier", None) or (
        "Purge" if getattr(args, "firmware", False) else "Clear"
    )
    ladder = plan_ladder(caps, requested)

    refused = False
    try:
        warnings = check_safety(target, force=args.force)
    except SafetyError as exc:
        ui.error(f"REFUSED: {exc}")
        warnings = [str(exc)]
        # A refusal must not exit 0. `s0 plan --target /dev/vda` printed REFUSED and
        # returned success, so an agent gating on the plan -- the documented first step
        # -- concluded the device was safe to wipe. The capability ladder may well be
        # satisfiable; the *plan* is not, because the target itself is refused.
        refused = True

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
        ui.finish(
            result={
                "target": {
                    "path": target.path,
                    "kind": target.kind,
                    "capacity_bytes": target.capacity_bytes,
                    "storage_type": target.storage_type,
                    "model": target.model,
                    "serial": target.serial,
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
                        "method": alt.method.id if alt.method else None,
                        "tier": alt.method.nist_category if alt.method else None,
                        "available": alt.available,
                        "reason": alt.reason,
                    }
                    for alt in (alternatives or [])
                ],
            }
        )
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
        [Column("TIER", max_width=22), Column("METHOD", max_width=30), Column("MECHANISM", max_width=68)],
        [[e["tier"], e["method"], e["mechanism"]] for e in ladder["ladder"]],
    )
    ui.note("")
    if ladder["satisfiable"]:
        ui.key("Requested tier", f"{requested} - achievable on this device")
    else:
        ui.key("Requested tier", f"{requested} - NOT ACHIEVABLE")
        ui.note("")
        ui.error(ladder["refusal_reason"])

    # For a regular file, `wipe --target` does one of two quite different destructive
    # things depending on whether the file looks like a raw disk image: keep it and
    # overwrite in place, or erase it and unlink it. `plan` used to describe both as
    # "1-pass zero overwrite", so an operator reading the plan could not tell that the
    # file they were about to point at would be *deleted*. Say which, and why.
    if getattr(target, "kind", "") == "image" or Path(target.path).is_file():
        t_path = Path(target.path)
        if t_path.is_file():
            as_image = _looks_like_raw_image(t_path)
            if as_image:
                ui.key("File outcome", "kept - overwritten in place")
                ui.note(f"    recognised as a raw disk image: {_image_reason(t_path)}")
            else:
                ui.key("File outcome", "ERASED AND REMOVED - the file will be deleted")
                ui.note(
                    f"    not recognised as a raw disk image: {human_bytes(t_path.stat().st_size)}. "
                    f"A file is treated as an image when it is at least 1 MiB, 512-byte "
                    f"aligned, and either carries a known image signature or is a whole "
                    f"number of 1 MiB (or 63-sector CD track) units. Anything else takes "
                    f"the file-erase path, which unlinks it. Use `s0 carve` or copy the "
                    f"file first if you meant to preserve it."
                )

    ui.note("")
    ui.note("DRY RUN - nothing was written. Run `s0 wipe` when satisfied.")
    # A refusal must not exit 0. See the note where `refused` is set.
    if refused:
        return EX_NOPERM
    return EX_OK if ladder["satisfiable"] else EX_TEMPFAIL


#: Suffixes that suggest "raw disk image". These are a hint, never a decision:
#: `_looks_like_raw_image` confirms with a signature or a sector-aligned size
#: before treating a file as an image, because a suffix alone is not evidence.
IMAGE_SUFFIXES = (".img", ".raw", ".iso", ".bin")


def _image_reason(path) -> str:
    """Why `_looks_like_raw_image` said yes, in the terms the operator can check.

    Two independent tests can pass and an operator debugging a surprise needs to know
    which one fired: a signature, or the size-and-alignment shape. Claiming a signature
    that is not there would make the explanation useless.
    """
    size = path.stat().st_size
    human = human_bytes(size)
    if size < 1024 * 1024:
        return f"{human}, but under the 1 MiB minimum"
    if size % 512:
        return f"{human}, but not 512-byte aligned"
    if _has_known_image_magic(_read_head_bytes(path, 512)):
        return f"{human}, sector-aligned, and carries a known image signature"
    if size % (1024 * 1024) == 0:
        return f"{human}, a whole number of 1 MiB units"
    if size % (2048 * 63) == 0:
        return f"{human}, a whole number of 63-sector CD track units"
    return f"{human}, sector-aligned"


def _looks_like_raw_image(path) -> bool:
    """True when this regular file should be treated as a disk image.

    Content, not suffix. A file is treated as a raw image when it carries a known
    image signature, or when its size is a whole number of 512-byte sectors -- the
    property that actually matters for a sector-addressed image. `s0 wipe
    --target` on an image overwrites in place and keeps the file; on anything else
    it erases, which deletes the file.

    Guessing from the extension got this wrong in both directions: a 600 MB `.dat`
    that really was a disk image was deleted, and a 40 KB `.img` that was a
    spreadsheet was overwritten as though it were a device.
    """
    suffix = path.suffix.lower()
    try:
        size = path.stat().st_size
    except OSError:
        return suffix in IMAGE_SUFFIXES

    # Sector-aligned and non-trivial: the shape of a raw image.
    if size >= 1024 * 1024 and size % 512 == 0:
        head = _read_head_bytes(path, 512)
        if _has_known_image_magic(head):
            return True
        # Sector-aligned with no recognised magic is still far more likely to be a
        # raw image than a document. Require a whole number of 1 MiB or of 63-sector
        # CD tracks to avoid claiming ordinary files.
        return size % (1024 * 1024) == 0 or size % (2048 * 63) == 0

    if suffix in IMAGE_SUFFIXES and _has_known_image_magic(_read_head_bytes(path, 512)):
        return True
    return False


def _read_head_bytes(path, count: int) -> bytes:
    try:
        with open(path, "rb") as handle:
            return handle.read(count)
    except OSError:
        return b""


def _has_known_image_magic(head: bytes) -> bool:
    if not head:
        return False
    # VMDK sparse extent header, qcow2, VDI, VHDX, VDI, raw dd, ISO 9660.
    magics = (
        b"QFI\xfb",
        b"conectix",
        b"vhdxfile",
        b"KDMV",
        b"\x1f\x8b",  # qcow2/vhdx/vdi/gz
    )
    return any(head.startswith(m) for m in magics) or head[257:262] == b"CD001"


def cmd_wipe(args) -> int:
    """Sanitize a drive, image, file or folder, verify, and issue a certificate.

    Refuses to silently downgrade: if the operator asserts a tier with
    ``--require-tier`` and the device cannot achieve it, s0 stops and says why.
    Passing ``--allow-downgrade`` converts that refusal into an explicit,
    signed, recorded decision -- never a silent one.
    """
    ui = getattr(args, "ui", None) or UI(OutputPolicy(), "wipe")
    _print_legal_notice(getattr(args, "policy", None) or policy_from_args(args))
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
        from s0.wipe.methods.capabilities import plan_ladder, probe_capabilities

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
            ui.warn("PROCEEDING AS AN EXPLICIT DOWNGRADE: " + str(ladder["refusal_reason"]))
            ui.warn(
                "the downgrade is recorded on the certificate; the resulting "
                f"claim is {ladder['best_available_tier']}, not {require_tier}."
            )

    is_file_mode = False
    if targets:
        for tgt in targets:
            try:
                p = Path(tgt)
                if platform.is_block_device(p):
                    ui.error(
                        f"'{tgt}' is a block storage device. Use '--target {tgt}' "
                        f"for whole-drive sanitization; '--targets' is strictly for "
                        f"files and directories."
                    )
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
            elif t_path.is_file() and not _looks_like_raw_image(t_path):
                # A regular file that is not a recognised raw disk image takes the
                # file-erase path.
                #
                # This used to be decided by extension alone -- anything not in
                # (".img", ".raw", ".iso", ".bin") -- so the *same command* silently
                # did two different destructive things:
                #
                #   s0 wipe --target evidence.bin --yes   -> overwritten, kept
                #   s0 wipe --target evidence.dat --yes   -> ERASED
                #
                # Nothing in the help text, the manual or the AI skill said so. Two
                # identical files differed only in their suffix, and the operator had
                # no way to know which they had.
                is_file_mode = True
                args.targets = [target_arg]

    if getattr(args, "dry_run", False) and is_file_mode:
        # The dry-run gate used to sit *below* this dispatch, so a file or folder
        # target was handed to cmd_erase_files -- which never reads dry_run --
        # before the flag was ever consulted. `s0 wipe --targets FILE --dry-run`
        # therefore deleted the file and printed "Successful: 1".
        #
        # The path guard still has to run: a dry run that resolves a destructive
        # target is exactly when an operator learns the target is refused.
        refused: list[str] = []
        try:
            from s0.safety import ProtectedPathError, check_path_is_destructive

            for t in args.targets:
                try:
                    # Returns warnings when --force overrode a refusal; those
                    # must still be shown, not discarded.
                    refused.extend(check_path_is_destructive(t, force=getattr(args, "force", False)))
                except ProtectedPathError as exc:
                    refused.append(str(exc))
        except ImportError:
            pass
        ui.note("[s0 wipe]  Dry run: nothing will be written.")
        ui.note(
            f"mode:    file/folder erase ({len(args.targets)} target{'s' if len(args.targets) != 1 else ''})"
        )
        for t in args.targets:
            ui.note(f"target:  {t}")
        ui.note(f"passes:  {getattr(args, 'passes', 1)}")
        ui.note(f"pattern: {getattr(args, 'pattern', 'zero')}")
        if refused:
            ui.warn("This target would be REFUSED without --force:")
            for reason in refused:
                ui.warn(f"  {reason}")
        else:
            ui.note("Re-run without --dry-run to erase these files.")
        return 0

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
            from s0.platform.windows.s0_eraser import (
                check_windows_wipe_safety,
                wipe_drive_or_partition_windows,
            )
        except ImportError:
            print(
                "error: Windows drive wipe requires the s0 Windows engine (s0.platform.windows.s0_eraser).\n"
                "  Ensure the S0 installation includes Windows components or repo root is on sys.path.",
                file=sys.stderr,
            )
            return 2
        try:
            check_windows_wipe_safety(target.path, force=args.force)
        except PermissionError as exc:
            print(f"REFUSED: {exc}", file=sys.stderr)
            return 2

        if not args.yes:
            print(f"\n[s0 wipe]  Target        : {target.path}")
            print("[s0 wipe]  Method        : OVERWRITE_ZERO_1PASS (Windows Native)")
            print("[s0 wipe]  NIST Category : Clear")
            print("[s0 wipe]  Summary       : Windows raw volume overwrite with volume lock and dismount")
            ans = input(
                f"\nType '{target.path}' to confirm permanent erasure of {target.path} (Windows Native): "
            )
            if ans.strip() != str(target.path):
                print("aborted — nothing was written", file=sys.stderr)
                return 2
        else:
            sys.stderr.write(f"[s0 wipe plan] target={target.path} method=OVERWRITE_ZERO_1PASS tier=Clear\n")

        key_path = default_issuer_key(args.key)
        _warn_if_demo_key(key_path, _ui_policy(args))
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
                print(
                    f"[s0 wipe]  Audit Ledger  : recorded block #{blk.block_index} ({blk.block_hash[:16]}...)"
                )
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
            print(
                json.dumps(
                    {
                        "status": cert["result"]["status"],
                        "certificate": str(cert_json),
                        "pdf": str(pdf_path) if pdf_path else None,
                        "cert_uuid": cert["cert_uuid"],
                    },
                    indent=2,
                )
            )
        else:
            print(f"\n[s0 wipe]  Result        : {cert['result']['status']}")
            print(f"[s0 wipe]  Certificate   : {cert_json}")
            if pdf_path:
                print(f"[s0 wipe]  PDF           : {pdf_path}")
        return 0 if res_win.status == "success" else 1

    if sys.platform == "darwin" and target.kind == "block":
        try:
            from s0.platform.macos.s0_eraser import check_macos_wipe_safety, wipe_drive_or_partition_macos
        except ImportError:
            print(
                "error: macOS drive wipe requires the s0 macOS engine (s0.platform.macos.s0_eraser).\n"
                "  Ensure the S0 installation includes macOS components or repo root is on sys.path.",
                file=sys.stderr,
            )
            return 2
        try:
            check_macos_wipe_safety(target.path, force=args.force)
        except PermissionError as exc:
            print(f"REFUSED: {exc}", file=sys.stderr)
            return 2

        if not args.yes:
            print(f"\n[s0 wipe]  Target        : {target.path}")
            print("[s0 wipe]  Method        : OVERWRITE_ZERO_1PASS (macOS Native)")
            print("[s0 wipe]  NIST Category : Clear")
            print(
                "[s0 wipe]  Summary       : macOS raw character device (/dev/rdisk) overwrite with fcntl(F_FULLFSYNC)"
            )
            print("[s0 wipe]  HPA/DCO       : Not supported on macOS (requires Linux with hdparm)")
            ans = input(
                f"\nType '{target.path}' to confirm permanent erasure of {target.path} (macOS Native): "
            )
            if ans.strip() != str(target.path):
                print("aborted — nothing was written", file=sys.stderr)
                return 2
        else:
            sys.stderr.write(f"[s0 wipe plan] target={target.path} method=OVERWRITE_ZERO_1PASS tier=Clear\n")

        key_path = default_issuer_key(args.key)
        _warn_if_demo_key(key_path, _ui_policy(args))
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
                print(
                    f"[s0 wipe]  Audit Ledger  : recorded block #{blk.block_index} ({blk.block_hash[:16]}...)"
                )
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
            print(
                json.dumps(
                    {
                        "status": cert["result"]["status"],
                        "certificate": str(cert_json),
                        "pdf": str(pdf_path) if pdf_path else None,
                        "cert_uuid": cert["cert_uuid"],
                    },
                    indent=2,
                )
            )
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

    if getattr(args, "dry_run", False):
        # `--dry-run` is attached to every subcommand with the help text "plan
        # only; never write to the target", and only `s0 live flash` ever read it.
        # So the documented way to preview a wipe actually wiped the target.
        # Verified by probe: a 4 MB image's md5 changed under `s0 wipe --dry-run`.
        ui.note("[s0 wipe]  Dry run: nothing will be written.")
        ui.note(f"target:  {target.path}")
        ui.note(f"kind:    {target.kind}")
        if getattr(target, "capacity_bytes", None):
            ui.note(f"size:    {target.capacity_bytes} bytes")
        ui.note(f"method:  {plan.method_id}")
        ui.note(f"tier:    {plan.nist_category}")
        for w in warnings:
            ui.note(f"warning: {w}")
        ui.note("Re-run without --dry-run to perform this operation.")
        return 0

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
                    ui.note(
                        f"  Remove the hidden area with "
                        f"'{hpa_dco.get('restore_command')}', or pass --force to "
                        f"accept a wipe that cannot reach those sectors."
                    )
                    return EX_NOPERM
                warnings.append(hpa_msg)

    if not args.yes:
        _print_plan(ui, target, candidate, alternatives, warnings, hpa_dco)
        if plan.method_id.startswith(("ATA_", "NVME_", "SCSI_")):
            ui.warn(
                "Firmware-level Purge methods are constructed to ACS-4 / NVMe / SBC "
                "and fixture-tested here, but real-world behaviour varies by vendor "
                "and firmware revision. Verify device support before relying on it."
            )
        try:
            # The prompt goes to stderr: stdout is reserved for records, and a
            # prompt is chrome. `input()` writes to stdout by default.
            print(
                f"\nType '{target.path}' to confirm permanent erasure "
                f"({plan.method_id}, NIST {plan.nist_category}): ",
                end="",
                file=sys.stderr,
                flush=True,
            )
            answer = input()
        except (EOFError, KeyboardInterrupt):
            # An interrupt is not a success. Previously a Ctrl-C here was
            # swallowed into answer="" and then exited 0, so
            # `s0 wipe --yes-less && next_step` ran the next step.
            ui.note("Aborted by interrupt - nothing was written.")
            return EX_TEMPFAIL
        except RuntimeError:
            # `input()` raises RuntimeError("lost sys.stdin") when fd 0 is closed,
            # which is what happens under `s0 wipe --target X <&-`. It was not
            # caught, so that produced a raw traceback.
            ui.note("Cannot confirm: standard input is closed. Refusing to write.")
            return EX_TEMPFAIL
        if answer.strip() != str(target.path):
            # Non-zero: an operator abort is not a completed operation.
            # `s0 wipe --target X && echo "wipe succeeded"` printed "succeeded"
            # after the operator deliberately declined.
            ui.note("Aborted - nothing was written.")
            return EX_TEMPFAIL
    else:
        ui.note(f"[s0 wipe plan] target={target.path} method={plan.method_id} tier={plan.nist_category}")

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
            progress_fn=lambda msg: (
                sys.stderr.write(f"\r[s0 wipe] {msg}  ") if not getattr(args, "json", False) else None
            ),
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
        bar.abort("TARGET PARTIALLY OVERWRITTEN")
        ui.error(
            "WIPE INTERRUPTED (Ctrl+C). The target may be partially overwritten "
            "and must not be released. Re-run s0 wipe to completion, or escalate "
            "to a physical destruction method."
        )
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
        result.errors.append("post-wipe verification FAILED — sampled sectors did not match expected pattern")

    key_path = default_issuer_key(args.key)
    _warn_if_demo_key(key_path, _ui_policy(args))
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
        ui.warn(
            f"the sanitization completed but could NOT be recorded in the audit "
            f"ledger: {exc}. The certificate exists; the chain of custody has a gap."
        )

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
            errors=(
                [{"code": "E_VERIFICATION", "message": e} for e in result.errors]
                + ([{"code": "E_LEDGER", "message": ledger_error}] if ledger_error else [])
            ),
            artifacts=[
                a
                for a in (
                    artifact(cert_json, "certificate", cert["signature"].get("signed_payload_hash")),
                    artifact(pdf_path, "pdf_certificate") if pdf_path else None,
                    artifact(out_dir / f"certificate_{cert['cert_uuid'][:8]}.qr.png", "qr_code"),
                )
                if a
            ],
            audit=(
                {
                    "block_index": blk.block_index,
                    "block_hash": blk.block_hash,
                    "prev_hash": getattr(blk, "prev_hash", None),
                }
                if blk
                else None
            ),
            signature=cert["signature"],
        )
        return EX_OK if ok else 1

    ui.heading("Sanitization result")
    ui.key("Result", ui.status(state, cert["result"]["status"].upper()))
    ui.key("Method", f"{cert['wipe']['method']} (NIST {cert['wipe']['nist_category']})")
    ui.key("Bytes processed", human_bytes(cert["wipe"]["bytes_processed"]))
    ui.key(
        "Verification",
        f"{sampled} read-back sample"
        f"{'' if sampled == 1 else 's'}"
        f" - {'all match the wipe pattern' if verif.get('all_samples_match_wipe_pattern') else 'MISMATCH'}",
    )
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
        ui.error(
            "sanitization did not complete cleanly: the certificate records the "
            "failure and must not be presented as a completed wipe."
        )
    return EX_OK if ok else 1


# --------------------------------------------------------------------------- #
# File & Folder Sanitization (invoked via s0 wipe)
# --------------------------------------------------------------------------- #


def cmd_erase_files(args) -> int:
    _print_legal_notice(getattr(args, "policy", None) or policy_from_args(args))
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

    print("==> S0: Secure File & Folder Sanitization", file=sys.stderr)

    # Everything that can make the *evidence* unwritable is resolved before the first
    # byte is erased. Three separate inputs used to fail after the erase instead:
    # an unusable --key, an unwritable --out-dir, and an unencodable --operator.
    key_path, key_error = _load_issuer_key(args)
    if key_error:
        return EX_CONFIG

    if getattr(args, "no_certificate", False):
        print(
            "WARNING: --no-certificate specified. No compliance certificate or audit log will be generated.",
            file=sys.stderr,
        )

    targets = [Path(t) for t in args.targets]
    print(f"==> Target items ({len(targets)}): {[str(t) for t in targets]}", file=sys.stderr)

    # The certificate, the PDF and the QR code all land here. Discovering the directory
    # was unwritable *after* the erase meant a destroyed target, no evidence, and --
    # because the mkdir raised -- "This is a bug in s0" with exit 70 instead of the
    # documented 73 (EX_CANTCREAT).
    if _prepare_out_dir(args) is None:
        return EX_CANTCREAT

    # One bar per file, sized from the total the eraser reports for that file.
    # This used to build a single bar from the summed size of every target, so
    # every file's own byte count was measured against a total that belonged to
    # the whole batch -- a small file in a mixed batch could render "0 B / 293 KiB",
    # a denominator belonging to no file the operator was looking at.
    ui_obj = getattr(args, "ui", None) or UI(_ui_policy(args) or OutputPolicy(), "wipe")
    bar = ui_obj.file_progress("s0 wipe")

    def erase_progress_cb(path_str: str, written: int, total_f: int) -> None:
        bar.update(path_str, written, total_f)

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
        bar.close()
    except SafetyError as exc:
        # The shared path guard refused. This used to surface as an uncaught
        # traceback ending in `raise SafetyError(str(exc)) from exc`, because
        # nothing on the file/folder route caught it.
        print(f"error: {exc}", file=sys.stderr)
        return EX_NOPERM
    except KeyboardInterrupt:
        bar.close(extra="CANCELLED")
        print(
            "\n⚠  Erasure interrupted by user (Ctrl+C). Some files may be partially erased.", file=sys.stderr
        )
        return 130

    print(f"\n[s0 erase-file]  Files Processed : {summary.total_files}", file=sys.stderr)
    print(f"[s0 erase-file]  Successful      : {summary.successful_files}", file=sys.stderr)
    print(f"[s0 erase-file]  Failed          : {summary.failed_files}", file=sys.stderr)
    print(f"[s0 erase-file]  Bytes Sanitized : {summary.total_bytes_processed} bytes", file=sys.stderr)

    if summary.certificate:
        try:
            blk = record_audit_event(summary.certificate, operation_type="FILE_ERASE", private_key=key_path)
            print(
                f"[s0 erase-file]  Audit Ledger    : recorded block #{blk.block_index} ({blk.block_hash[:16]}...)",
                file=sys.stderr,
            )
        except Exception as exc:
            print(f"WARNING: failed to record event into audit ledger: {exc}", file=sys.stderr)

        out_dir = Path(args.out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        cert_p = out_dir / f"file_wipe_certificate_{summary.certificate['cert_uuid'][:8]}.json"
        cert_p.write_text(json.dumps(summary.certificate, indent=2) + "\n")
        print(f"[s0 erase-file]  Certificate     : {cert_p}", file=sys.stderr)

        if not getattr(args, "no_pdf", False):
            try:
                from s0 import pdfgen

                qr_url_tpl = getattr(
                    args, "qr_url_template", "https://sector-zero.pages.dev/verify/?cert={cert_uuid}"
                )
                portal_url_val = _validate_portal_url(getattr(args, "portal_url", None))
                if portal_url_val and "{cert_uuid}" not in portal_url_val:
                    qr_url_tpl = f"{portal_url_val.rstrip('/')}/?cert={{cert_uuid}}"
                pdf_p = out_dir / f"file_wipe_certificate_{summary.certificate['cert_uuid'][:8]}.pdf"
                qr_p = out_dir / f"file_wipe_certificate_{summary.certificate['cert_uuid'][:8]}.qr.png"
                pdfgen.generate_pdf(summary.certificate, pdf_p, qr_url_template=qr_url_tpl)
                pdfgen.write_qr_file(summary.certificate, qr_p)
                print(f"[s0 erase-file]  PDF Certificate : {pdf_p}", file=sys.stderr)
            except Exception:
                pass
        if getattr(args, "json", False):
            print(
                json.dumps(
                    {
                        "status": "success" if summary.failed_files == 0 else "failure",
                        "successful_files": summary.successful_files,
                        "failed_files": summary.failed_files,
                        "bytes_overwritten": summary.total_bytes_processed,
                        "certificate": str(cert_p) if summary.certificate else None,
                        "cert_uuid": summary.certificate.get("cert_uuid") if summary.certificate else None,
                    },
                    indent=2,
                )
            )
    elif summary.total_files == 0:
        # Not a failure, and not a signing problem: there was nothing to erase, so
        # there is nothing to certify. Saying "certificate generation failed" here
        # would send an operator looking for a key or a permissions problem that does
        # not exist.
        print("NOTE: nothing was erased, so no certificate was issued.", file=sys.stderr)
        for w in summary.warnings:
            if "no files were erased" in w:
                print(f"  {w}", file=sys.stderr)
    elif not getattr(args, "no_certificate", False):
        print(
            "WARNING: Sanitization completed, but certificate generation failed (see warnings).",
            file=sys.stderr,
        )

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


def _confidence_0_100(raw: str) -> int:
    """argparse type for a percentage the tool can actually express.

    Accepting 999 produced a successful run that carved nothing, and the only way
    to tell that apart from "nothing was recoverable" was to read the report. The
    web tier already bounds this to 0-100; the CLI did not, so the same value was
    accepted in one interface and refused in the other.
    """
    try:
        value = int(raw)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"invalid confidence value {raw!r}: expected an integer 0-100"
        ) from None
    if not 0 <= value <= 100:
        raise argparse.ArgumentTypeError(f"confidence {value} is out of range: expected 0-100")
    return value


def cmd_carve(args) -> int:
    """Recover deleted and unallocated files from an image, image file or device."""
    ui = getattr(args, "ui", None) or UI(OutputPolicy(), "carve")
    _print_legal_notice(_ui_policy(args))
    if not _validate_cli_metadata(args):
        return EX_USAGE
    ui.note("S0 - Forensic File Carving & Recovery")

    # Both resolved before the scan. `carve` on an unwritable --out-dir used to run the
    # whole carve and then die in the write, so the operator paid for a full pass over a
    # large image and got nothing out of it.
    key_path, key_error = _load_issuer_key(args, ui=ui)
    if key_error:
        return EX_CONFIG
    if _prepare_out_dir(args, ui=ui) is None:
        return EX_CANTCREAT

    if getattr(args, "no_certificate", False):
        print(
            "WARNING: --no-certificate specified. No forensic recovery manifest will be issued.",
            file=sys.stderr,
        )

    ui.key("Target media", str(args.target))
    ui.key("Output directory", str(args.out_dir))

    target_path = Path(args.target)
    # Refuse a target that is not there, with a clean exit, before any work starts.
    # Without this the size probe below quietly yields 0, the engine later opens a
    # path that does not exist, and the operator saw a two-page Python traceback
    # for the ordinary mistake of a typo in a filename.
    if not target_path.exists() and not str(args.target).startswith("/dev/"):
        ui.error(f"target not found: {args.target}")
        return EX_NOINPUT

    target_size = 0
    if target_path.is_block_device():
        if is_os_device(str(target_path)):
            sys.stderr.write(
                f"\n{_c('[!] ADVISORY: Target hosts the active running operating system / root filesystem.', '33')}\n"
                "    Live OS background writes, swap/pagefile activity, and SSD TRIM will overwrite deleted\n"
                "    clusters in real time, degrading recovery yield. For forensically sound recovery,\n"
                f"    boot the s0 Live ISO or acquire an offline bit-stream image (s0 image).\n\n"
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
            print(
                f"Loaded {len(custom_sigs)} custom forensic signature(s): {', '.join(s.name for s in custom_sigs)}"
            )
        except Exception as err:
            ui.error(f"failed to parse custom signatures from '{args.custom_sig}': {err}")
            return EX_DATAERR

    try:
        carve_policy = None
        if getattr(args, "all_space", False):
            from s0.carve.policy import CarvePolicy as _CarvePolicy

            carve_policy = _CarvePolicy()
            carve_policy.use_free_space_only = False
        known_hashes = None
        if getattr(args, "hash_set", None):
            from s0.carve.suppression import SuppressionError, load_hash_set

            algos = [a.strip() for a in (args.hash_algorithms or "").split(",") if a.strip()]
            try:
                known_hashes = load_hash_set(args.hash_set, algorithms=algos or None)
            except SuppressionError as exc:
                ui.error(f"--hash-set unusable: {exc}")
                return EX_DATAERR
            ui.key("Known-file set", known_hashes.describe())

        resume = None
        if getattr(args, "session", None):
            from s0.carve import session as _session

            try:
                resume = _session.CarveSession.read(args.session)
            except _session.SessionError as exc:
                ui.error(f"--session unusable: {exc}")
                return EX_DATAERR
            ui.key("Resuming from", f"{args.session} ({len(resume.entries)} extent(s) recorded)")

        summary = carve_image(
            args.target,
            args.out_dir,
            extensions=exts,
            custom_signatures=custom_sigs,
            min_confidence=args.min_confidence,
            known_hashes=known_hashes,
            resume=resume,
            operator_id=args.operator,
            organization=args.organization,
            signing_key_path=key_path,
            progress_callback=carve_progress_cb,
            generate_certificate=not getattr(args, "no_certificate", False),
            policy=carve_policy,
        )
        if bar:
            bar.finish(extra=f"Found: {summary.files_recovered:,}")

        # An explicit extension filter that matches nothing is almost always a
        # typo, and it used to exit 0 having produced nothing -- indistinguishable,
        # to a script, from an image with no recoverable files. Only the explicit
        # filter triggers this: an unfiltered carve that finds nothing is a
        # legitimate result and still exits 0.
        if exts and not summary.carved_files:
            ui.error(f"no files of the requested type were recovered ({', '.join(sorted(exts))})")
            ui.note(
                "Nothing was written. Check the extensions against the image, "
                "or drop --extensions to carve every supported type."
            )
            return EX_DATAERR
    except KeyboardInterrupt:
        if bar:
            bar.abort("CANCELLED")
        ui.warn(
            "File carving interrupted by the operator (Ctrl+C); "
            "the recovery index written so far is still valid."
        )
        return EX_INTERRUPTED
    except Exception as exc:
        # A session that names a different image is an operator error, not a
        # crash. The library raises so a programmatic caller cannot ignore it;
        # here it has to become a message and a non-zero exit, because a
        # traceback tells the examiner nothing about what to do next.
        from s0.carve import session as _session_mod

        if isinstance(exc, _session_mod.SessionError):
            ui.error(str(exc))
            return EX_DATAERR
        raise
    except FileNotFoundError as exc:
        if bar:
            bar.abort("FAILED")
        ui.error(str(exc))
        return EX_NOINPUT
    except PermissionError as exc:
        if bar:
            bar.abort("DENIED")
        ui.error(f"permission denied: {exc}")
        return EX_NOPERM
    except OSError as exc:
        if bar:
            bar.abort("FAILED")
        ui.error(f"I/O error: {exc}")
        return EX_IOERR

    from s0.carve.boundary import BOUNDARY_LABELS

    ranked = sorted(summary.carved_files, key=lambda c: (-c.confidence_score, -c.size_bytes))
    rejected_pct = 100.0 * summary.rejected_candidates / max(1, summary.total_candidates_found)

    if getattr(args, "write_session", None):
        from s0.carve import session as _session

        try:
            written = (
                _session.CarveSession(
                    target_path=summary.target_path,
                    target_size=summary.total_bytes_scanned or 0,
                    fingerprint=_session.CarveSession.compute_fingerprint(Path(args.target)),
                )
                .merge(summary.carved_files, out_dir=Path(args.out_dir))
                .write(Path(args.write_session))
            )
            ui.key("Session written", f"{written} ({len(summary.carved_files)} extent(s))")
        except (OSError, _session.SessionError, ValueError) as exc:
            # A session that cannot be written means the next run of a long carve
            # starts from nothing, so the operator has to know. This used to be a
            # warning and still exited 0, so a script driving an overnight carve
            # believed it was resumable when it was not.
            ui.error(f"could not write the session file: {exc}")
            return EX_CANTCREAT

    # Bodyfiles, written before any format branch so that --format json produces
    # the same artifacts as the text output. An artifact that only appears in one
    # output format is an artifact nobody finds.
    bodyfile_artifacts: list[Path] = []
    bodyfile_rows: list[tuple] = []
    if getattr(args, "bodyfile", None) or getattr(args, "gaps_bodyfile", None):
        from s0.carve import bodyfile as bf

        extents = summary.recovered_extents
        scanned_to = summary.total_bytes_scanned
        if getattr(args, "bodyfile", None):
            rows, nbytes = bf.write_bodyfile(
                args.bodyfile,
                extents,
                comment=(
                    "s0 recovered-file bodyfile\n"
                    f"target: {summary.target_path}\n"
                    f"{len(extents)} merged range(s)"
                ),
            )
            bodyfile_artifacts.append(Path(args.bodyfile))
            bodyfile_rows.append(
                ("Bodyfile (recovered)", args.bodyfile, f"{rows} range(s), {human_bytes(nbytes)}")
            )
        if getattr(args, "gaps_bodyfile", None):
            gaps = bf.complement(extents, 0, max(0, scanned_to - 1))
            rows, nbytes = bf.write_bodyfile(
                args.gaps_bodyfile,
                gaps,
                comment=(
                    "s0 searched-but-unrecovered ranges\n"
                    f"target: {summary.target_path}\n"
                    f"searched {scanned_to} byte(s); {len(gaps)} gap(s)"
                ),
            )
            bodyfile_artifacts.append(Path(args.gaps_bodyfile))
            bodyfile_rows.append(
                ("Bodyfile (gaps)", args.gaps_bodyfile, f"{rows} range(s), {human_bytes(nbytes)}")
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
                # Without the reasons, candidates_rejected is a bare number and a
                # pipeline cannot distinguish a clean run from a lossy one.
                "rejection_summary": [
                    {"reason": reason, "count": count} for reason, count in (summary.rejection_summary or [])
                ],
                "by_category": summary.by_category,
                "by_recovery_method": summary.by_method,
                "allocation_aware_search": summary.free_space is not None,
                "free_space": summary.free_space,
                "deleted_names_from_journal": summary.deleted_names_from_journal,
                "allocated_candidates_skipped": summary.allocated_candidates_skipped,
                "allocated_bytes_skipped": summary.allocated_bytes_skipped,
                "candidates_prefiltered_in_memory": summary.candidates_prefiltered,
                "resumed_from_session": summary.resumed_from_session,
                "suppressed_known_files": summary.suppressed_known,
                "suppressed_known_bytes": summary.suppressed_known_bytes,
                "suppression_note": summary.suppression_note,
                "bodyfiles": [str(p) for p in bodyfile_artifacts],
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
                        "name_provenance": c.provenance,
                        "deleted_at": c.deleted_at,
                        "recovered_path": c.recovered_path,
                        "heuristics": c.heuristics,
                    }
                    for c in ranked
                ],
            },
            status="success",
            artifacts=[artifact(Path(args.out_dir) / "recovery_index.json", "recovery_index")]
            + [artifact(p, "bodyfile") for p in bodyfile_artifacts],
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

    # H4: a carve that recovers less than it saw used to report only the count,
    # so the reasons lived exclusively in recovery_index.json. An examiner reading
    # the terminal saw "Candidates rejected: 400" with no way to tell 400 rejected
    # because they were duplicates from one file's worth of slack space apart from
    # 400 that were the only copies of anything -- which is the difference between
    # a clean result and a missed file.
    if summary.rejection_summary:
        ui.key("Why candidates were rejected", "")
        for reason, count in summary.rejection_summary[:8]:
            ui.note(f"    {human_int(count):>9}  {reason}")
        remaining = sum(c for _r, c in summary.rejection_summary[8:])
        if remaining:
            ui.note(
                f"    {human_int(remaining):>9}  ... and {len(summary.rejection_summary) - 8} more reason(s)"
            )
        ui.note("")
        ui.note(
            "Per-candidate detail, including the byte offset of each rejected "
            "candidate, is in recovery_index.json."
        )
        ui.note("")
    if summary.free_space:
        ui.key(
            "Search space",
            (
                f"unallocated only ({human_bytes(summary.free_space['free_bytes'])} free in "
                f"{summary.free_space['range_count']} extent(s), "
                f"{summary.free_space['free_ppm'] / 10_000:.1f}% of volume)"
            ),
        )
        excluded = summary.free_space["volume_bytes"] - summary.free_space["free_bytes"]
        if excluded > 0:
            ui.key("Excluded as live", human_bytes(excluded))
        if summary.allocated_candidates_skipped:
            ui.key(
                "Signatures in live data",
                (f"{human_int(summary.allocated_candidates_skipped)} not offered to the carver"),
            )
    else:
        ui.key(
            "Search space",
            (
                "whole volume (--all-space)"
                if getattr(args, "all_space", False)
                else "whole volume (no trustworthy allocation map)"
            ),
        )
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
                    c.recovery_method,
                    c.extension,
                    human_int(c.size_bytes),
                    f"{c.confidence_score}%",
                    BOUNDARY_LABELS.get(c.boundary_method, c.boundary_method),
                    c.original_name or "—",
                    c.sha256[:16],
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
        ui.note(
            ui.status(
                "info",
                (
                    f"{len(rows)} name(s). The journal records names and times, not "
                    f"content, so these are leads and not recovered files. They are "
                    f"not included in the recovered count above."
                ),
            )
        )
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
        ui.note(ui.status("warn", "no file passed both boundary resolution and structural validation"))
        if summary.rejection_summary:
            ui.note("")
            ui.note("Most common rejection reasons:")
            for reason, count in summary.rejection_summary[:5]:
                ui.note(f"  {human_int(count):>9}  {reason}")

    if summary.warnings:
        ui.note("")
        for w in summary.warnings:
            ui.warn(w)

    if bodyfile_rows:
        ui.note("")
        for label, path, detail in bodyfile_rows:
            ui.key(label, f"{path} ({detail})")

    if summary.suppressed_known:
        ui.note("")
        ui.key(
            "Known-file suppression",
            f"{summary.suppressed_known} file(s) withheld: {summary.suppression_note}",
        )

    ui.note("")
    ui.key("Recovery index", str(Path(args.out_dir) / "recovery_index.json"))

    blk = None
    if summary.manifest_certificate:
        try:
            blk = record_audit_event(
                summary.manifest_certificate, operation_type="FILE_CARVE", private_key=key_path
            )
            print(
                f"[s0 carve]  Audit Ledger     : recorded block #{blk.block_index} ({blk.block_hash[:16]}...)"
            )
        except Exception as exc:
            ui.warn(f"failed to record the event in the audit ledger: {exc}")

        out_dir = Path(args.out_dir)
        cert_p = out_dir / f"carving_manifest_{summary.manifest_certificate['cert_uuid'][:8]}.json"
        cert_p.write_text(json.dumps(summary.manifest_certificate, indent=2) + "\n")
        ui.key("Signed manifest", str(cert_p))

        if not getattr(args, "no_pdf", False):
            try:
                from s0 import pdfgen

                qr_url_tpl = getattr(
                    args, "qr_url_template", "https://sector-zero.pages.dev/verify/?cert={cert_uuid}"
                )
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
            ui.finish(
                result={
                    "block_count": len(blocks),
                    "blocks": [
                        {
                            "block_index": b.block_index,
                            "timestamp": b.timestamp,
                            "operation_type": b.operation_type,
                            "operator_id": b.operator_id,
                            "target_id": b.target_id,
                            "block_hash": b.block_hash,
                            "prev_hash": getattr(b, "prev_hash", None),
                        }
                        for b in blocks
                    ],
                }
            )
            return EX_OK
        ui.heading(f"Hash-chained cryptographic audit ledger ({human_int(len(blocks))} blocks)")
        ui.table(
            [
                Column("IDX", align="r"),
                Column("TIMESTAMP", max_width=22),
                Column("OPERATION", max_width=16),
                Column("OPERATOR", max_width=16),
                Column("TARGET", max_width=24),
                Column("BLOCK HASH", max_width=20),
            ],
            [
                [
                    b.block_index,
                    b.timestamp,
                    b.operation_type,
                    b.operator_id,
                    b.target_id,
                    b.block_hash[:16] + "...",
                ]
                for b in blocks
            ],
        )
        return EX_OK

    if action == "verify":
        from s0.crypto import load_public_pem

        # `--key` was a single path passed straight to `load_public_pem`, so
        # `--key <directory>` raised IsADirectoryError as a raw traceback, and a
        # ledger signed by more than one key could not be verified at all. It is
        # now repeatable and accepts a directory of *.pem, matching the
        # `~/.s0/keys/` convention the default loader already uses.
        raw_keys = getattr(args, "key", None)
        if isinstance(raw_keys, str):
            raw_keys = [raw_keys]
        # With action="append" + nargs="+", each occurrence contributes a list, so
        # `--key a.pem --key b.pem` arrives as [["a.pem"], ["b.pem"]]. Flatten, and
        # accept a single string too so a programmatic caller is not punished for it.
        flattened: list[str] = []
        for entry in raw_keys or []:
            if isinstance(entry, (list, tuple)):
                flattened.extend(str(item) for item in entry)
            else:
                flattened.append(str(entry))
        key_paths: list[Path] = []
        for entry in flattened:
            candidate = Path(entry)
            if candidate.is_dir():
                key_paths.extend(sorted(candidate.glob("*.pem")))
            else:
                key_paths.append(candidate)
        if raw_keys and not key_paths:
            ui.error(f"no *.pem public keys found in {raw_keys}")
            return EX_NOINPUT
        trusted_keys = None
        if key_paths:
            trusted_keys = []
            for candidate in key_paths:
                try:
                    trusted_keys.append(load_public_pem(candidate))
                except Exception as exc:
                    ui.error(f"cannot load public key {candidate}: {exc}")
                    return EX_DATAERR
            ui.note(f"Loaded {len(trusted_keys)} trusted issuer key(s).")

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


def _signature_object(cert_data) -> dict:
    """The certificate's `signature` member, or an empty dict if it is not an object.

    `.get("signature", {})` only supplies its default when the key is *absent*. A
    certificate carrying `"signature": null`, `[]`, `7` or a string passed the key
    straight through, so the following `.get(...)` raised AttributeError and the
    operator saw "This is a bug in s0" with exit 70 for what is simply a malformed
    document. `verify_certificate` already rejects all of these with
    "signature: required object"; this only stops the demo-key probe from crashing
    before that verdict is printed.
    """
    value = cert_data.get("signature") if isinstance(cert_data, dict) else None
    return value if isinstance(value, dict) else {}


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
    demo = (
        _signature_object(cert_data).get("public_key_fingerprint")
        == "sha256:8396af8c07a7d40f98ba492cf2b61e23fa768e66a9f627b02a9caff464e48c06"
    )

    if ui.policy.fmt in ("json", "csv"):
        # A demo-key signature is cryptographically valid and evidentially
        # worthless: the private key is published in the repository, so anyone can
        # mint a certificate that verifies. The text output already says
        # "AUTHENTIC - but signed with an unaccredited demonstration key"; the
        # machine-readable form reported top-level status "success" with the
        # caveat buried in a nested field, so a pipeline reading `status` or `ok`
        # treated an unaccredited document as a passing one.
        #
        # The signature still verified, and that is reported truthfully -- as
        # "unverified_issuer" rather than "success", plus the reason.
        if ok and demo:
            machine_status = "unverified_issuer"
            machine_ok = False
            machine_reason = (
                f"{reason}; signed with the published demonstration key, which "
                f"verifies but carries no evidentiary weight"
            )
        else:
            machine_status = "success" if ok else "failure"
            machine_ok = ok
            machine_reason = reason

        ui.finish(
            result={
                "ok": machine_ok,
                "status": machine_status,
                "reason": machine_reason,
                "cert_uuid": cert_data.get("cert_uuid"),
                "result_status": cert_data.get("result", {}).get("status"),
                "nist_category": cert_data.get("wipe", {}).get("nist_category"),
                "method": cert_data.get("wipe", {}).get("method"),
                "device_id": cert_data.get("device", {}).get("device_id"),
                "organization": cert_data.get("issuer", {}).get("organization"),
                "operator_id": cert_data.get("issuer", {}).get("operator_id"),
                "public_key_fingerprint": _signature_object(cert_data).get("public_key_fingerprint"),
                "signature_verified": ok,
                "unaccredited_demo_key": demo,
            },
            status=machine_status,
        )
        if ok and demo:
            # Non-zero: a script driving this must not read an unaccredited
            # certificate as a pass. It still needs the document to be reported, so
            # this is EX_TEMPFAIL rather than an error.
            return EX_TEMPFAIL
        return EX_OK if ok else EX_FAILURE

    # Computed once so the verdict cannot depend on the output format. Text mode
    # used to exit 0 for a demo-key certificate while --json exited 75 for the very
    # same file, so a script on the human path treated a document the tool itself
    # calls evidentially worthless as a pass -- purely because it had not asked for
    # JSON.
    _verify_exit = _verify_exit_code(ok, demo)

    if ok:
        state = "warn" if demo else "ok"
        label = (
            "AUTHENTIC - but signed with an unaccredited demonstration key"
            if demo
            else "AUTHENTIC & CRYPTOGRAPHICALLY VERIFIED"
        )
        ui.heading("Offline certificate verification")
        ui.key("Status", ui.status(state, label))
        if demo:
            ui.warn(
                "demo-key signatures must not be used for legal chain of custody or regulatory compliance"
            )
    else:
        ui.heading("Offline certificate verification")
        ui.key("Status", ui.status("error", "VERIFICATION FAILED"))
        ui.key("Reason", reason)

    ui.key("Certificate UUID", cert_data.get("cert_uuid", "-"))
    ui.key("Issued at", cert_data.get("issued_at", "-"))
    ui.key(
        "Issuer",
        f"{cert_data.get('issuer', {}).get('organization', '-')} / "
        f"{cert_data.get('issuer', {}).get('operator_id', '-')}",
    )
    ui.key(
        "Tool",
        f"{cert_data.get('tool', {}).get('name', '-')} v{cert_data.get('tool', {}).get('version', '-')}",
    )
    ui.key(
        "Method",
        f"{cert_data.get('wipe', {}).get('method', '-')} "
        f"({cert_data.get('wipe', {}).get('nist_category', '-')})",
    )
    ui.key("Device", cert_data.get("device", {}).get("device_id", "-"))
    ui.key("Result", cert_data.get("result", {}).get("status", "-"))
    ui.key("Key fingerprint", _signature_object(cert_data).get("public_key_fingerprint", "-"))
    if not ok:
        ui.note("")
        ui.key("Reason", reason)
    return _verify_exit


def _verify_exit_code(ok: bool, demo: bool) -> int:
    """The single source of truth for what `s0 verify` exits with.

    Presentation must not change the verdict. Three cases:

    * a genuine signature from a real issuer -- 0;
    * no valid signature -- EX_FAILURE;
    * a valid signature from the *published* demonstration key -- EX_TEMPFAIL.

    The third used to be 75 for --json/--csv and 0 for text, so one certificate was
    a pass or a failure depending on a formatting flag. It verifies
    cryptographically and carries no evidentiary weight, so it is neither a success
    nor an error; EX_TEMPFAIL is the closest fit, and it is non-zero so a pipeline
    cannot read an unaccredited document as a pass.
    """
    if not ok:
        return EX_FAILURE
    return EX_TEMPFAIL if demo else EX_OK


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

    # `--name` becomes a filename, so it must not be a path. `out_dir / "../x_private.pem"`
    # normalises to one level *above* out_dir, and `out_dir / "/tmp/x_private.pem"`
    # discards out_dir entirely -- so an unchecked name can create or, worse, overwrite
    # a `*_private.pem` somewhere the operator never named. Validate it as a filename.
    name = str(getattr(args, "name", "") or "")
    bad = (
        not name
        or name in (".", "..")
        or name.startswith((".", "-"))
        or "/" in name
        or "\\" in name
        or any(ord(c) < 0x20 or ord(c) == 0x7F for c in name)
    )
    if bad:
        ui.error(
            f"invalid --name {name!r}: it must be a plain filename prefix -- no path "
            f"separators, no leading '.' or '-', no control characters"
        )
        return EX_USAGE

    priv_p = out_dir / f"{name}_private.pem"
    pub_p = out_dir / f"{name}_public.pem"

    # Refuse to replace an existing private key. This tool calls the key "the root of
    # trust for every certificate this authority will ever issue", and running
    # `s0 keygen` twice in the same directory used to silently overwrite it -- new key,
    # exit 0, no warning, no backup. Every previously signed certificate then points at
    # a key that no longer exists locally, and nothing says so.
    if priv_p.exists() and not getattr(args, "force", False):
        ui.error(
            f"refusing to overwrite the existing private key {priv_p}.\n"
            f"  Replacing it invalidates every certificate already signed with it, and "
            f"the old key is not recoverable from here.\n"
            f"  Choose a different --name, remove the file yourself if you are certain, "
            f"or pass --force to replace it deliberately."
        )
        return EX_CANTCREAT
    if priv_p.exists():
        ui.warn(f"--force: replacing the existing private key {priv_p}")
        try:
            priv_p.unlink()
        except OSError as exc:
            ui.error(f"cannot remove the existing private key {priv_p}: {exc}")
            return EX_CANTCREAT

    priv = crypto.generate_private_key()
    pub = priv.public_key()
    try:
        crypto.write_private_pem(priv, priv_p)
        crypto.write_public_pem(pub, pub_p)
        os.chmod(priv_p, 0o600)  # a private key must not be group/world readable
    except OSError as exc:
        ui.error(f"cannot write the keypair: {exc}")
        return EX_CANTCREAT

    fp = crypto.public_key_fingerprint(pub)
    if ui.policy.fmt in ("json", "csv"):
        ui.finish(
            result={
                "algorithm": "Ed25519",
                "private_key_path": str(priv_p.resolve()),
                "public_key_path": str(pub_p.resolve()),
                "fingerprint": fp,
            },
            artifacts=[artifact(priv_p, "private_key"), artifact(pub_p, "public_key")],
        )
        return EX_OK

    ui.heading("Generated Ed25519 signing keypair")
    ui.key("Algorithm", "Ed25519 (RFC 8032)")
    ui.key("Private key", f"{priv_p}  <- keep secret and offline")
    ui.key("Public key", str(pub_p))
    ui.key("Fingerprint", fp)
    ui.note("")
    ui.note(
        "The private key is written with mode 0600. It is the root of trust for "
        "every certificate this authority will ever issue: anyone holding it can "
        "forge certificates that verify. Back it up offline and never commit it."
    )
    return EX_OK


# --------------------------------------------------------------------------- #
# Maintenance & Upgrade Commands
# --------------------------------------------------------------------------- #


def get_upgrade_branch(args, repo_dir: str | Path | None = None) -> str:
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
    # Must run *inside the checkout*. Run in the process CWD -- the ordinary case,
    # since `s0 upgrade` is invoked from wherever the user happens to be -- `git`
    # printed "fatal: not a git repository", the exception was swallowed, and the
    # function returned "master". A contributor on a feature branch then had master
    # pulled into their working tree, silently.
    if repo_dir is not None:
        try:
            cur = subprocess.check_output(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                cwd=str(repo_dir),
                text=True,
                timeout=10,
                stderr=subprocess.DEVNULL,
            ).strip()
            if cur and cur != "HEAD":
                return cur
        except (OSError, subprocess.SubprocessError):
            pass
        # Deliberately NOT "master". This branch's installer pins a ref precisely
        # because master is not installable, so falling back to it re-introduces the
        # bug the installer fix removed.
        return "agent/harness"

    try:
        cur = subprocess.check_output(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            text=True,
            timeout=10,
            stderr=subprocess.DEVNULL,
        ).strip()
        if cur and cur != "HEAD":
            return cur
    except (OSError, subprocess.SubprocessError):
        pass
    return "agent/harness"


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
            ui.note("  irm https://sector-zero.pages.dev/upgrade-ps1 -OutFile s0-upgrade.ps1")
            ui.note("  # Inspect s0-upgrade.ps1 before running, then:")
            ui.note("  powershell -ExecutionPolicy Bypass -File .\\s0-upgrade.ps1")
        else:
            ui.note("  curl -fsSL https://sector-zero.pages.dev/upgrade-sh -o s0-upgrade.sh")
            ui.note("  # Inspect s0-upgrade.sh before running, then:")
            ui.note("  bash s0-upgrade.sh")
        return 1

    ui.key("Installation", str(repo_dir))
    try:
        cur_hash = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"], cwd=str(repo_dir), text=True
        ).strip()
        ui.key("Current commit", cur_hash)
        branch = get_upgrade_branch(args, repo_dir)
        ui.note(f"Fetching origin/{branch}...")
        subprocess.check_call(["git", "fetch", "origin", branch, "-q"], cwd=str(repo_dir))
        latest_hash = subprocess.check_output(
            ["git", "rev-parse", "--short", f"origin/{branch}"], cwd=str(repo_dir), text=True
        ).strip()

        if cur_hash == latest_hash and not getattr(args, "force", False):
            ui.key("Source", f"already up to date at commit {cur_hash}")
        else:
            subprocess.check_call(
                ["git", "pull", "--ff-only", "origin", get_upgrade_branch(args, repo_dir), "-q"],
                cwd=str(repo_dir),
            )
            ui.key("Source", f"updated {cur_hash} -> {latest_hash}")

        py_bin = sys.executable
        ui.note("Refreshing dependencies...")
        subprocess.check_call([py_bin, "-m", "pip", "install", "--upgrade", "pip", "-q"])
        subprocess.check_call([py_bin, "-m", "pip", "install", "-e", str(repo_dir), "-q"])
        # The unpinned `pip install reportlab qrcode pillow` bypassed the lock file
        # this branch added, so an upgrade silently resolved "newest at upgrade
        # time" -- the exact non-reproducibility requirements.lock exists to remove.
        # If the lock is present, use it and say so; otherwise fall back and say that
        # too, rather than quietly diverging.
        lock = repo_dir / "requirements.lock"
        if lock.is_file():
            subprocess.check_call([py_bin, "-m", "pip", "install", "--require-hashes", "-r", str(lock), "-q"])
            ui.key("Dependencies", f"refreshed from {lock.name} (hash-pinned)")
        else:
            subprocess.check_call([py_bin, "-m", "pip", "install", "reportlab", "qrcode", "pillow", "-q"])
            ui.key("Dependencies", "refreshed (no requirements.lock; versions unpinned)")

        ver = subprocess.check_output([py_bin, "-m", "s0.cli.main", "--version"], text=True).strip()

        # Report where HEAD actually is, not where origin thinks it is. The old line
        # printed `latest_hash` -- the remote's hash -- next to the *installed*
        # version, so a run where the pull was a no-op still claimed "upgraded to
        # <new hash>" while the checkout never moved. Reading HEAD back is the only
        # way to make that sentence true.
        head_after = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"], cwd=str(repo_dir), text=True, timeout=10
        ).strip()
        ui.note("")
        if head_after != cur_hash:
            ui.key("Result", ui.status("ok", f"s0 upgraded to {ver} ({head_after})"))
        else:
            ui.key(
                "Result",
                ui.status(
                    "warn",
                    f"s0 is at {ver} ({head_after}); the checkout did not move, so no "
                    f"source upgrade happened",
                ),
            )
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
        ui.note("    curl -fsSL https://sector-zero.pages.dev/uninstall-ps1 -o s0-uninstall.ps1")
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
        ui.note("  curl -fsSL https://sector-zero.pages.dev/uninstall-sh -o s0-uninstall.sh")
        ui.note("  # Inspect s0-uninstall.sh before running, then:")
        ui.note("  bash s0-uninstall.sh")
        return EX_NOINPUT
        return 1

    ui.key("Target directory", str(repo_dir))
    audit_db = Path.home() / ".s0" / "s0_audit.db"
    purge_all = getattr(args, "purge_all", False) or getattr(args, "purge", False)
    if audit_db.is_file():
        if purge_all:
            ui.warn(
                "PURGING the audit ledger as requested (--purge-all). This is "
                "irreversible: every historical chain-of-custody record is destroyed."
            )
        else:
            import time as _time

            timestamp = _time.strftime("%Y%m%d_%H%M%S")
            bak_dest = Path.home() / f"s0_audit.db.bak.{timestamp}"
            try:
                shutil.copy2(audit_db, bak_dest)
                # One backup, timestamped. This also wrote an un-timestamped
                # `~/s0_audit.db.bak` beside it -- a second, silently-overwritten copy
                # of the chain of custody in the user's home directory, whose
                # existence depended on how many times they had run uninstall.
                ui.key("Audit ledger", f"preserved at {bak_dest}")
                ui.note("    (use --purge-all only to destroy the audit log deliberately)")
            except Exception as exc:
                ui.warn(f"could not back up the audit ledger: {exc}")

    if not getattr(args, "yes", False):
        ui.warn(
            "This removes the s0 installation from this system. Issued "
            "certificates are NOT revoked by uninstalling."
        )
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
    for sym in (Path.home() / ".local" / "bin" / "s0", Path.home() / "bin" / "s0", Path("/usr/local/bin/s0")):
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
        ui.warn(
            f"{repo_dir} is a development checkout or a custom install path; "
            f"its files were preserved. Remove it by hand if that is what you want."
        )

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

    _print_legal_notice(_ui_policy(args))
    if not _validate_cli_metadata(args):
        return EX_USAGE

    dst_p = Path(args.destination)
    is_blk = platform.is_block_device(dst_p)

    if is_blk and not args.yes:
        ui.error(
            f"the destination '{args.destination}' is a PHYSICAL BLOCK DEVICE. "
            f"Writing will destroy all existing partition tables, filesystems and data."
        )
        try:
            conf = input(f"Type '{args.destination}' to confirm clone to {args.destination}: ").strip()
        except (EOFError, KeyboardInterrupt):
            conf = ""
        if conf != str(args.destination):
            ui.note("Aborted by the operator.")
            return EX_OK

    # Created on the first real progress report, sized from what the imager
    # measured. It used to be created up front with a placeholder total of 1 byte
    # and patched later, which meant every refusal before the first byte was
    # copied drew "1 B / 1 B | 100.0%" -- a completed-looking bar for an
    # acquisition that never began. Nothing is drawn until there is progress to
    # report, so a refused run shows its refusal and no bar.
    _bar: list[ProgressBar] = []

    def _progress(bytes_copied, total_bytes, speed, bad_sectors):
        extra = f"{speed:.1f} MB/s"
        if bad_sectors > 0:
            extra += f" | bad sectors: {bad_sectors}"
        if not _bar:
            _bar.append(ui.progress(max(int(total_bytes), 1), operation="Forensic Acquisition"))
        _bar[0].update(bytes_copied, extra=extra)

    def _end_acquisition(outcome: str = "") -> None:
        if not _bar:
            return
        if outcome:
            _bar[0].abort(outcome)
        else:
            _bar[0].finish()

    # `image` copies the whole source first and only then writes its manifest, so an
    # unusable --key or an unwritable --out-dir used to leave a full multi-gigabyte copy
    # on disk with no manifest and no certificate attesting to it. Both are resolved
    # before acquire_image() opens the source.
    key_path, key_error = _load_issuer_key(args, ui=ui)
    if key_error:
        return EX_CONFIG
    if _prepare_out_dir(args, ui=ui) is None:
        return EX_CANTCREAT

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
    ui.key(
        "Fault tolerance",
        "enabled (zero-fill unreadable blocks)"
        if not args.no_recovery
        else "disabled (abort on the first I/O error)",
    )
    ui.note("")

    try:
        result = acquire_image(options, progress_callback=_progress)
        _end_acquisition()
    except SafetyError as exc:
        _end_acquisition("REFUSED")
        ui.error(f"refused: {exc}")
        return EX_NOPERM
    except KeyboardInterrupt:
        _end_acquisition("CANCELLED")
        ui.error(
            "acquisition cancelled by the operator (Ctrl+C). The destination "
            "image is INCOMPLETE and must not be used as evidence."
        )
        return EX_INTERRUPTED
    except FileNotFoundError as exc:
        _end_acquisition("FAILED")
        ui.error(str(exc))
        return EX_NOINPUT
    except PermissionError as exc:
        _end_acquisition("DENIED")
        ui.error(f"permission denied: {exc}")
        return EX_NOPERM
    except OSError as exc:
        _end_acquisition("FAILED")
        ui.error(f"I/O error: {exc}")
        return EX_IOERR

    if result.error:
        _end_acquisition("FAILED")
        ui.error(f"acquisition failed: {result.error}")
        return EX_IOERR

    hash_label = "Image SHA-256" if result.bad_sectors_count > 0 else "Source SHA-256"
    status = "partial" if result.bad_sectors_count > 0 else "success"

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
            errors=(
                [
                    {
                        "code": "E_BAD_SECTORS",
                        "message": f"{result.bad_sectors_count} unreadable blocks were "
                        f"zero-filled; the destination is not a faithful copy",
                        "context": {"count": result.bad_sectors_count},
                    }
                ]
                if result.bad_sectors_count
                else None
            ),
            artifacts=[
                a
                for a in (
                    artifact(result.manifest_path, "acquisition_manifest") if result.manifest_path else None,
                )
                if a
            ],
        )
        return EX_OK if status == "success" else 1

    ui.heading("Acquisition result")
    if result.bad_sectors_count > 0:
        ui.key(
            "Status",
            ui.status(
                "warn",
                f"COMPLETED WITH ERRORS - {result.bad_sectors_count} unreadable blocks were zero-filled",
            ),
        )
        ui.warn(
            "the destination is NOT a faithful copy of the source. NIST SP 800-86 "
            "treats an acquisition with substituted content as a different artifact; "
            "record the substituted ranges before offering this image as evidence."
        )
    else:
        ui.key("Status", ui.status("ok", "FORENSIC ACQUISITION COMPLETED"))
    ui.key("Operation", "Drive Clone" if result.is_clone else "Raw bit-stream image")
    ui.key("Bytes acquired", f"{human_int(result.bytes_copied)} ({human_bytes(result.bytes_copied)})")
    ui.key("Duration", f"{result.duration_seconds:.1f} s at {result.speed_mbps:.1f} MB/s")
    ui.key("Bad sectors", human_int(result.bad_sectors_count))
    ui.key(hash_label, result.source_sha256)
    ui.key("Source MD5", result.source_md5)
    if result.manifest_path:
        ui.key("Manifest file", str(result.manifest_path))
    if result.manifest_certificate:
        recorded = bool(getattr(result, "audit_ledger_recorded", False))
        ui.key(
            "Certificate",
            f"{result.manifest_certificate.get('cert_uuid')} "
            f"({'signed and appended to the audit ledger' if recorded else 'signed, NOT recorded in the audit ledger'})",
        )
        if not recorded and getattr(result, "audit_ledger_error", None):
            ui.warn(f"audit ledger write failed: {result.audit_ledger_error}")
        if not getattr(args, "no_pdf", False):
            try:
                from s0 import pdfgen

                out_dir_p = Path(args.out_dir)
                qr_url_tpl = getattr(
                    args, "qr_url_template", "https://sector-zero.pages.dev/verify/?cert={cert_uuid}"
                )
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
    import threading
    import time
    import webbrowser

    port = getattr(args, "port", None) or CONFIG.get("api_port", 8669)
    host = getattr(args, "host", None) or "127.0.0.1"
    url = f"http://{host}:{port}"

    # Sudo / Root privilege detection
    is_root = False
    if hasattr(os, "geteuid"):
        is_root = os.geteuid() == 0
    elif sys.platform == "win32":
        try:
            import ctypes

            is_root = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            is_root = False

    if not is_root:
        policy_ = getattr(args, "policy", None)
        print(
            _c("[s0 web]  WARN : s0 web is running without root (sudo) privileges.", "1;33", policy_),
            file=sys.stderr,
        )
        print(
            _c(
                "[s0 web]         Drive wiping and raw disk acquisition will not be available.", "33", policy_
            ),
            file=sys.stderr,
        )
        print(
            "\033[33m[s0 web]         For full forensic drive operations, launch with: sudo s0 web\033[0m\n"
        )

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
        print(
            f"\n[s0 web]  WARN : Missing required web dashboard dependencies: {', '.join(deps_missing)}",
            file=sys.stderr,
        )
        try:
            ans = input(f"Would you like s0 to install {' '.join(deps_missing)} now? [Y/n]: ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print("\nAborted.", file=sys.stderr)
            return 1
        if ans in ("", "y", "yes"):
            print(f"[s0 web]  Installing {' '.join(deps_missing)}...")
            res = subprocess.run([sys.executable, "-m", "pip", "install", *deps_missing], check=False)
            if res.returncode != 0:
                print(
                    f"[s0 web]  ERROR : Failed to install dependencies. Please run: pip install {' '.join(deps_missing)}",
                    file=sys.stderr,
                )
                return 1
            print("[s0 web]  OK : Dependencies installed successfully.\n")
        else:
            print(
                f"[s0 web]  ERROR : Aborted. Install manually: pip install {' '.join(deps_missing)}",
                file=sys.stderr,
            )
            return 1

    # Locate the dashboard by module, not by path.
    #
    # This searched `<repo>/web/app.py`, `~/.s0/web/app.py` and `/opt/s0/web`.
    # Refactor 0dd50d9 ("one s0 distribution under src/") moved the app to
    # `s0/web/app.py`, so none of those candidates exists any more and every
    # `s0 web` died with "Could not locate s0 Web Dashboard files (app.py)" --
    # while `python -m uvicorn s0.web.app:app` worked. The ISO's own
    # `s0-web.service` already used the module form, which is the hint.
    #
    # Depending on a source-tree layout is the real defect: a pip-installed user
    # has no `<repo>/web` at all, only site-packages.
    import importlib.util

    if importlib.util.find_spec("s0.web.app") is None:
        print("[s0 web]  ERROR : The s0 web dashboard is not installed.", file=sys.stderr)
        print("    The dashboard needs the web extra:", file=sys.stderr)
        print("      pip install 's0[web]'", file=sys.stderr)
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
    if sys.stderr.isatty():
        print(f"[s0 web]  Auth URL : {auth_url}")
    else:
        # Not a TTY: this is a log, a pipe, or an agent transcript, all of which outlive
        # the session and none of which need the token in clear. The file has it.
        print(f"[s0 web]  Auth URL : (withheld: not a terminal; see {token_path})")
    print(f"[s0 web]  Token    : {token_path} (mode 0600)")
    # The banner claimed "Strict loopback isolation" whatever `--host` said. With
    # `--host 0.0.0.0` the server listens on every interface and the label is a lie the
    # operator reads at the exact moment they are deciding how exposed this is. The only
    # thing protecting a non-loopback bind is the session token -- the Host allow-list
    # checks the header the client chose to send, so it stops nothing.
    loopback = host in ("127.0.0.1", "::1", "localhost")
    print(f"[s0 web]  Binding  : {host}" + (" (loopback only)" if loopback else ""))
    if not loopback:
        print(
            f"\033[1;31m[s0 web]  WARNING : {host} is not a loopback address, so this "
            f"dashboard is reachable from the network.\033[0m"
        )
        print(
            "[s0 web]            Authentication is still required and every /api route is "
            "token-guarded, but the token is now the only thing between the network and a "
            "destructive API."
        )
        print("[s0 web]            Use the default 127.0.0.1 unless you have a specific reason.")
    print("[s0 web]  Status   : Live — Press CTRL+C to stop")
    print()

    cmd = [
        sys.executable,
        "-m",
        "uvicorn",
        "s0.web.app:app",
        "--host",
        host,
        "--port",
        str(port),
    ]

    env = dict(os.environ)
    env["S0_WEB_AUTH_TOKEN"] = session_token

    # cwd is deliberately not the source tree: the app resolves its own
    # package data through importlib, so it does not need to run from a
    # checkout, and pinning cwd there would re-create the layout coupling
    # this change just removed.
    proc = subprocess.Popen(cmd, env=env)

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
    lst.set_defaults(func=cmd_list)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--version", action="version", version=f"s0 {__version_str__}")
    common.add_argument("--target", help="target drive, image, file, or directory")
    common.add_argument(
        "--passes",
        "-p",
        type=int,
        default=1,
        help=(
            "overwrite passes (default 1: one zero pass is the Clear-tier technique in\n"
            "NIST SP 800-88 Rev. 2). Verification is by sampling, so this is a bound on\n"
            "residual data, not a guarantee the medium is blank -- see --verify-samples"
        ),
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
    common.add_argument("--force", action="store_true", help="override mounted/root safety refusals")

    pln = sub.add_parser("plan", parents=[common], help="dry-run: show what would happen")
    pln.add_argument(
        "--require-tier",
        choices=("Clear", "Purge", "Destroy"),
        default=None,
        help="assert the minimum sanitization tier the medium must support; "
        "s0 refuses when the device cannot achieve it",
    )
    pln.add_argument(
        "--firmware",
        action="store_true",
        help="shortcut for --require-tier Purge: only firmware-mediated Purge methods satisfy this request",
    )
    pln.set_defaults(func=cmd_plan)

    wp = sub.add_parser(
        "wipe", parents=[common], help="wipe drive, file(s), or folder(s), verify, issue signed certificate"
    )
    wp.add_argument("--targets", "-t", nargs="+", help="multiple target files or directories to sanitize")
    wp.add_argument(
        "--require-tier",
        choices=("Clear", "Purge", "Destroy"),
        default=None,
        help="refuse to run unless the device can achieve this tier. "
        "s0 will not silently downgrade: without this flag the "
        "selected method is always reported, whatever it is",
    )
    wp.add_argument(
        "--allow-downgrade",
        action="store_true",
        help="if --require-tier cannot be met, proceed with the best "
        "available method and record the downgrade on the certificate",
    )
    # --sanitize and --sanitize-passes were declared here and read nowhere, so
    # `s0 wipe --sanitize crypto-erase` silently fell back to the automatic
    # choice and reported OVERWRITE_ZERO_1PASS. Their help described ATA 0xB4 /
    # NVMe 0x84 selection and a 1-255 range check for a value never validated.
    # Removed rather than left as a lie: forcing a specific firmware sanitize
    # action is a real feature and is not implemented. Until it is, method
    # selection stays automatic, and --require-tier is how an operator asserts a
    # tier rather than naming a command.
    wp.add_argument("--yes", "-y", action="store_true", help="skip interactive confirmation prompt")
    wp.add_argument("--key", "--signing-key", help="issuer private key PEM (default: demo issuer key)")
    wp.add_argument(
        "--out-dir", default=".", help="directory to store certificate, PDF, and QR assets (default: .)"
    )
    wp.add_argument(
        "--operator",
        "--operator-id",
        default=CONFIG.get("default_operator", "op-forensic"),
        help="operator identifier for certificate",
    )
    wp.add_argument(
        "--organization",
        default=CONFIG.get("default_organization", "Digital Forensics & Data Sanitization Lab"),
        help="organization name for certificate",
    )
    wp.add_argument(
        "--no-certificate",
        action="store_true",
        help="explicitly run without generating an Ed25519 compliance certificate",
    )
    wp.add_argument(
        "--no-pdf", action="store_true", help="skip generating human-readable PDF compliance certificate"
    )
    wp.add_argument(
        "--verify-samples",
        type=int,
        default=64,
        help=(
            "blocks sampled for readback verification (default: 64). Sampling bounds\n"
            "residual data rather than eliminating it: 64 clean blocks mean under ~45,730\n"
            "ppm (4.573%%) residual at 95%% confidence. Raise it for a tighter bound, or\n"
            "use --require-tier Purge to prefer a hardware erase. The bound is recorded\n"
            "in the certificate."
        ),
    )
    wp.add_argument(
        "--plant-markers",
        action="store_true",
        help="plant recoverable markers first, then require 0 grep hits afterwards",
    )
    wp.add_argument(
        "--portal-url",
        default=CONFIG.get("verification_portal_url", "https://sector-zero.pages.dev/verify/"),
        help="verification portal base URL (default: https://sector-zero.pages.dev/verify/)",
    )
    wp.add_argument(
        "--qr-url-template",
        dest="qr_url_template",
        default=CONFIG.get("qr_url_template", "https://sector-zero.pages.dev/verify/?cert={cert_uuid}"),
        help="URL template for encoded verification QR code",
    )
    wp.set_defaults(func=cmd_wipe)

    # 2. File Carving & Recovery Subcommand
    crv = sub.add_parser(
        "carve",
        help="advanced file carving and recovery from raw images / media",
        description=(
            "Carve files from a raw image or block device.\n\n"
            "Recovery is signature-anchored: a file is recovered from a header to a\n"
            "validated footer or an in-band end marker. Where no end marker survives,\n"
            "s0 stops at the last validated boundary and says so rather than padding to\n"
            "a guess, because a wrong length yields a file that looks intact and is\n"
            "wrong. Container formats (MP4/HEIF, Matroska/WebM, ZIP, RAR, GZIP, and\n"
            "the decompression containers) are parsed rather than scanned, and\n"
            "fragmented files are reassembled by their in-band sequence numbers.\n\n"
            "Run `s0 carve --target IMG --out-dir OUT` with no --extensions to carve\n"
            "everything in the registry; the supported-format table is in\n"
            "skills/s0-forensics/references/carving-signatures.md."
        ),
    )
    crv.add_argument("--target", required=True, help="raw disk image or block device to scan")
    crv.add_argument("--out-dir", required=True, help="directory to store carved files")
    crv.add_argument(
        "--extensions",
        help=(
            "comma-separated extensions to carve (e.g. jpg,png,pdf,zip,mp4,mkv). "
            "Omit to carve everything in the registry"
        ),
    )
    crv.add_argument(
        "--custom-sig",
        help="path to JSON file (or inline JSON) defining custom file signature(s) with header/footer hex magic bytes",
    )
    crv.add_argument(
        "--min-confidence",
        type=_confidence_0_100,
        default=50,
        metavar="0-100",
        help="minimum confidence score (0-100); a value outside this range is "
        "rejected rather than silently carving nothing",
    )
    crv.add_argument(
        "--session",
        help="resume from a session file written by an earlier run: extents it "
        "already recovered are not carved again (refused if the image has "
        "changed since)",
    )
    crv.add_argument(
        "--write-session",
        help="write a session file recording this run's recovered extents, so an "
        "interrupted carve can be resumed",
    )
    crv.add_argument(
        "--hash-set",
        help="suppress files already known: a hash list (md5/sha1/sha256/sha512, "
        "bare or NSRL-style) or a directory to hash in place",
    )
    crv.add_argument(
        "--hash-algorithms",
        help="comma-separated algorithms to keep from --hash-set (default: all found)",
    )
    crv.add_argument(
        "--bodyfile",
        help="write a bodyfile of the recovered byte ranges, for a second tool to "
        "read the same bytes instead of the whole volume again",
    )
    crv.add_argument(
        "--gaps-bodyfile",
        help="write a bodyfile of the ranges that were searched but produced no "
        "file. For fragmented recovery the holes are the finding.",
    )
    crv.add_argument(
        "--operator",
        "--operator-id",
        default=CONFIG.get("default_operator", "op-forensic"),
        help="operator identifier for manifest",
    )
    crv.add_argument(
        "--organization",
        default=CONFIG.get("default_organization", "Digital Forensics & Data Sanitization Lab"),
        help="organization name for manifest",
    )
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
    aud.add_argument(
        "audit_action", choices=["list", "verify"], help="list audit blocks or verify hash chain"
    )
    aud.add_argument("--limit", type=int, default=50, help="limit number of records displayed")
    aud.add_argument(
        "--key",
        # `append` + `nargs="+"` accepts both spellings the help advertises:
        #   --key a.pem b.pem      (one flag, several values)
        #   --key a.pem --key b.pem (repeated)
        # Without `append`, repeating the flag silently overwrote the earlier
        # value, so only the last key was trusted -- and the run then failed
        # closed with UNVERIFIABLE, which reads as tampering rather than as a
        # dropped argument.
        action="append",
        nargs="+",
        metavar="KEY",
        help=(
            "trusted issuer public key(s): one or more PEM files, and/or a\n"
            "directory of *.pem. Repeatable. A ledger signed by more than one\n"
            "key needs every signer supplied, or verification stops at the\n"
            "first block it cannot attribute."
        ),
    )
    aud.set_defaults(func=cmd_audit)

    # 4. Offline Verification Subcommand
    vr = sub.add_parser("verify", help="verify a signed certificate offline against trusted public keys")
    vr.add_argument("certificate", help="path to certificate JSON")
    vr.add_argument("--key", help="path to trusted public key PEM")
    vr.set_defaults(func=cmd_verify)

    # 5. Key Generation Subcommand
    kg = sub.add_parser("keygen", help="generate Ed25519 signing keypair for an authority or operator")
    kg.add_argument("--out-dir", default=".", help="directory to store private and public keys")
    kg.add_argument(
        "--name",
        default="operator_key",
        help="filename prefix for the keypair; a plain name, not a path",
    )
    kg.add_argument(
        "--force",
        action="store_true",
        help="replace an existing private key in --out-dir. Every certificate already "
        "signed with it stops being attributable, so this is deliberate or it is a mistake",
    )
    kg.set_defaults(func=cmd_keygen)

    # 6. Upgrade Subcommand
    upg = sub.add_parser("upgrade", help="upgrade S0 suite to the latest version from GitHub")
    upg.add_argument(
        "--force", action="store_true", help="force re-installation of dependencies even if up to date"
    )
    upg.add_argument("--branch", help="upstream branch to track (default: this checkout's own branch)")
    upg.set_defaults(func=cmd_upgrade)

    # 7. Uninstall Subcommand
    uinst = sub.add_parser("uninstall", help="safely remove s0 suite from this system")
    uinst.add_argument("--yes", "-y", action="store_true", help="skip interactive confirmation prompt")
    uinst.add_argument(
        "--purge-all", "--purge", action="store_true", help="permanently delete audit ledger without backup"
    )
    uinst.set_defaults(func=cmd_uninstall)

    # 8. Forensic Imaging & Cloning Subcommands.
    #
    # `image` and `clone` share an implementation and therefore share flags, but
    # they are not the same operation and the help should say which is which: an
    # image is written to a *file*, a clone is written to a *device*. Both were
    # described identically, so a reader could not tell from `--help` that one of
    # them overwrites a disk.
    _ACQUISITION_HELP = {
        "image": "acquire a bit-stream image to a FILE (preserves evidence; the source is not modified)",
        "clone": "clone a block device to ANOTHER DEVICE (destructive on the destination; "
        "the source is not modified)",
    }
    for img_cmd in ("image", "clone"):
        img = sub.add_parser(img_cmd, help=_ACQUISITION_HELP[img_cmd])
        img.description = (
            _ACQUISITION_HELP[img_cmd].capitalize()
            + ". Both commands share the same options; only the destination kind differs."
        )
        img.add_argument("--source", required=True, help="path to source block device or raw image file")
        img.add_argument(
            "--destination",
            "--dest",
            required=True,
            help=(
                "destination image FILE"
                if img_cmd == "image"
                else "destination BLOCK DEVICE (cloning overwrites it)"
            ),
        )
        img.add_argument(
            "--block-size",
            type=int,
            default=1048576,
            help="buffer block size in bytes (default: 1048576 / 1MB)",
        )
        img.add_argument(
            "--no-recovery",
            action="store_true",
            help="abort on I/O read error instead of zero-filling bad sectors",
        )
        img.add_argument(
            "--out-dir", default=".", help="directory to store acquisition manifest and certificate"
        )
        img.add_argument(
            "--operator",
            "--operator-id",
            default=CONFIG.get("default_operator", "op-forensic"),
            help="operator ID",
        )
        img.add_argument(
            "--organization",
            default=CONFIG.get("default_organization", "Digital Forensics & Data Sanitization Lab"),
            help="organization name",
        )
        img.add_argument("--key", "--signing-key", help="path to Ed25519 issuer private key PEM")
        img.add_argument(
            "--no-certificate",
            action="store_true",
            help="skip generating signed Ed25519 acquisition certificate",
        )
        img.add_argument("--no-pdf", action="store_true", help="skip generating printable PDF certificate")
        img.add_argument(
            "--yes",
            "-y",
            action="store_true",
            help="skip interactive confirmation when cloning to a physical disk",
        )
        img.add_argument(
            "--force", action="store_true", help="overwrite destination image file if it already exists"
        )
        img.set_defaults(func=cmd_image)

    # 9. Web Dashboard Subcommand
    wb = sub.add_parser("web", help="launch local s0 Web Dashboard in browser (FastAPI loopback)")
    wb.add_argument(
        "--port", type=int, default=CONFIG.get("api_port", 8669), help="port to bind (default: 8669)"
    )
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
                    add_global_arguments(child, suppress_defaults=True)
                    walk(child)

    walk(root)


#: Sub-subcommands that take their own options and can therefore be swallowed by a
#: preceding `nargs="+"` option.
_AUDIT_ACTIONS = ("list", "verify")


def _hoist_audit_action(argv):
    """Make `s0 audit --key K verify` work as well as `s0 audit verify --key K`.

    `--key` is `nargs="+"` so several keys can be supplied at once, which means
    argparse hands it ["K", "verify"] and then fails with "the following arguments
    are required: audit_action" -- an error naming an internal field, for a command
    whose documented form works fine. Fixing it inside the handler is impossible
    because argparse raises before any handler runs.

    argparse cannot express "greedy, but stop at this token", so argv is fixed
    before parsing. Only that exact shape is touched: an `audit` invocation whose
    action appears after a `--key`, and nothing else.
    """
    if not argv or "audit" not in argv:
        return argv
    audit_at = list(argv).index("audit")
    if audit_at + 1 < len(argv) and argv[audit_at + 1] in _AUDIT_ACTIONS:
        return argv  # already in the documented order
    if "--key" not in argv[audit_at:]:
        return argv  # no --key involved
    key_at = argv.index("--key", audit_at)
    tail = argv[key_at + 1 :]
    for action in _AUDIT_ACTIONS:
        if action in tail:
            rest = [a for a in tail if a != action]
            return argv[: audit_at + 1] + [action] + argv[audit_at + 1 : key_at] + ["--key"] + rest
    return argv


# Commands that create output. `--dry-run` is attached to every subcommand by the
# shared parent parser with the help text "plan only; never write to the target",
# but only `wipe` (on its block-device path) and `live flash` ever read it. So
# `s0 image --dry-run` wrote a full image, `s0 clone --dry-run` cloned, and
# `s0 carve --dry-run` wrote carved files and appended to the audit ledger --
# each while claiming to have written nothing.
#
# Enforced at the single point where a handler is invoked rather than inside each
# handler. A per-handler check is a convention that the next command added will
# forget; this is a property of the program.
# Commands that change nothing, so --dry-run is a no-op for them.
#
# This was an allowlist of *writers* ("image", "clone", "carve") with everything
# else falling through to its own handler. That shape fails open: any command not
# named there is assumed safe, so `keygen` wrote a private key, `live download`
# pulled 573 MB, `upgrade` ran a real git fetch and three pip installs, and
# `uninstall` wrote a new database backup -- each while claiming to have written
# nothing. Naming every future writer in a tuple is not a property anyone can rely
# on; the next command added is wrong the day it lands.
#
# Inverted: everything is refused unless it is *known* read-only. A new command is
# then safe by default and has to be opted out, which is the direction a mistake
# should point.
_DRY_RUN_READ_ONLY = ("list", "plan", "audit", "verify")


def _dry_run_guard(args) -> int | None:
    """Stop a state-changing command under --dry-run. Returns None to proceed.

    `web` is included as read-only because it only serves the dashboard; it starts a
    server but performs no wipe, image, download or install on the operator's behalf.
    Commands that implement their own richer dry run -- `wipe`, which prints a full
    per-target plan, and `live flash` -- keep doing so.
    """
    if not getattr(args, "dry_run", False):
        return None
    command = getattr(args, "command", "")
    if command in _DRY_RUN_READ_ONLY or command in ("web", "wipe"):
        return None

    # `live` is a command *group*, and its sub-actions differ: `live flash` performs
    # its own careful dry run, while `live download` does not and will pull ~550 MB.
    # Exempting the whole group -- which is what this did at first -- reinstates the
    # exact bug the allowlist was meant to remove. So the exemption is per sub-action,
    # and anything unrecognised falls through to the guard.
    if command == "live":
        sub = str(getattr(args, "live_action", "") or getattr(args, "action", "") or "")
        if sub in ("flash", "devices"):
            return None

    ui = getattr(args, "ui", None) or UI(policy_from_args(args), command=command)
    ui.note(f"[s0 {command}]  Dry run: nothing will be written.")
    source = getattr(args, "source", None) or getattr(args, "target", None)
    if source:
        ui.note(f"source:      {source}")
    destination = getattr(args, "destination", None)
    if destination:
        ui.note(f"destination: {destination}")
    out_dir = getattr(args, "out_dir", None)
    if out_dir:
        ui.note(f"out-dir:     {out_dir}")
    for flag, label in (("extensions", "extensions"), ("min_confidence", "min-confidence")):
        value = getattr(args, flag, None)
        if value:
            ui.note(f"{label}: {value}")
    label = command
    if command == "live":
        sub = str(getattr(args, "live_action", "") or "")
        if sub:
            label = f"live {sub}"
    ui.note(f"Re-run without --dry-run to perform the {label}.")
    return EX_OK


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
        args = parser.parse_args(_hoist_audit_action(raw_args))

        policy = policy_from_args(args)
        args.ui = UI(policy, command=getattr(args, "command", "s0"), argv=raw_args[1:])
        args.policy = policy

        if not raw_args or raw_args in (["--help"], ["-h"]):
            _print_banner(policy)

        guard = _dry_run_guard(args)
        if guard is not None:
            return guard

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
    except BrokenPipeError:
        # `s0 list | head` closes the pipe early. That is ordinary shell usage, not
        # a failure, and the interpreter's shutdown message about flushing stdout
        # is noise on top of it.
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except OSError:
            pass
        return EX_OK
    except Exception as exc:
        # Last resort. Previously there was no catch-all here at all, so any
        # unexpected exception surfaced as a raw Python traceback -- which tells an
        # examiner nothing about what to do next, and buries the actual message
        # under a page of frames. `--target /nonexistent` on carve printed one.
        if os.environ.get("S0_TRACEBACK"):
            raise
        ui = getattr(locals().get("args"), "ui", None)
        message = f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
        if ui is not None:
            ui.error(f"error: {message}")
            ui.note("This is a bug in s0. Re-run with S0_TRACEBACK=1 for the full traceback.")
        else:
            sys.stderr.write(f"error: {message}\n")
            sys.stderr.write("This is a bug in s0. Re-run with S0_TRACEBACK=1 for the full traceback.\n")
        return EX_SOFTWARE


if __name__ == "__main__":
    raise SystemExit(main())
