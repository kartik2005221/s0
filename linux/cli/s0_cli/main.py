"""S0 (Sector Zero) — Unified Forensic Sanitization & Recovery CLI.

Subcommands:
  1. Drive Eraser:
     s0 list                       inventory of block devices
     s0 plan  --target PATH        dry-run: method, tier, warnings
     s0 wipe  --target PATH        sanitize drive, verify, issue certificate

  2. File & Folder Eraser:
     s0 erase --targets PATH...    secure deletion & metadata scrubbing

  3. Advanced File Carving & Recovery:
     s0 carve --target PATH --out-dir DIR   signature & structure recovery

  4. Blockchain Audit Ledger:
     s0 audit list                 display cryptographic audit blocks
     s0 audit verify               verify blockchain hash-chain integrity

  5. Offline Verification & Key Management:
     s0 verify CERT_JSON           verify signed certificate offline
     s0 keygen                     generate Ed25519 authority/operator keypair
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from s0_core import certificate as cert_mod
from s0_core.progress import ProgressBar

from . import __version__
from .audit import init_audit_db, list_audit_blocks, record_audit_event, verify_audit_ledger
from .carver import carve_image, signature_from_dict
from .devices import SafetyError, check_safety, get_block_device_size, image_target, list_block_targets
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


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _resolve_target(path: str) -> DevTarget:
    if sys.platform == "win32" and (
        (":" in path and len(path.strip()) <= 3)
        or "physicaldrive" in path.lower()
        or path.startswith(r"\\.\\")
    ):
        sz = 0
        try:
            from windows.cli.s0_eraser import get_windows_target_size
            sz = get_windows_target_size(path)
        except Exception:
            pass
        return DevTarget(path=path, kind="block", capacity_bytes=sz, storage_type="UNKNOWN")

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


def _print_plan(
    target: DevTarget, candidate, alternatives, warnings: list[str], hpa_dco: dict | None
) -> None:
    m = candidate.method
    print(f"target          : {target.display}")
    if m is None:
        print("method          : NONE AVAILABLE")
        print(f"reason          : {candidate.reason}")
        return
    plan: Plan = m.plan(target)
    print(f"method          : {plan.method_id}")
    print(f"nist category   : {plan.nist_category}")
    print(f"summary         : {plan.summary}")
    if plan.commands:
        print("commands        :")
        for c in plan.commands:
            print(f"  - {c}")
    all_warnings = warnings + plan.warnings
    if all_warnings:
        print("warnings        :")
        for w in all_warnings:
            print(f"  ! {w}")
    if alternatives:
        print("alternatives    :")
        for a in alternatives:
            state = "available" if a.available else "unavailable"
            print(f"  - [{state}] {a.reason}")
    if hpa_dco and (
        hpa_dco.get("hpa_present") or hpa_dco.get("dco_present") or hpa_dco.get("note")
    ):
        print("hpa/dco         : " + json.dumps(hpa_dco))
        if hpa_dco.get("restore_command"):
            print(f"                  remove BEFORE wiping: {hpa_dco['restore_command']}")


# --------------------------------------------------------------------------- #
# Module 1: Drive Eraser Subcommands
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
            }
            for t in targets
        ]
        print(json.dumps(data, indent=2))
        return 0

    if not targets:
        print("(no block devices found)")
        return 0
    print(
        f"{'PATH':<14} {'TYPE':<7} {'STORAGE':<10} {'CAPACITY':>12}  "
        f"{'MODEL':<24} {'SERIAL':<16} MOUNTED?"
    )
    for t in targets:
        cap = f"{t.capacity_bytes / 2**30:.1f} GiB"
        is_mounted = "YES" if any(m.startswith(t.path) for m in mounted) else "-"
        print(
            f"{t.path:<14} {t.kind:<7} {t.storage_type:<10} {cap:>12}  "
            f"{(t.model or '—')[:24]:<24} {(t.serial or '—')[:16]:<16} {is_mounted}"
        )
    print("\nImage-file targets work too (no root needed): use --target /path/to/file.img")
    return 0


def cmd_plan(args) -> int:
    try:
        target = _resolve_target(args.target)
    except (FileNotFoundError, SafetyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if target.capacity_bytes <= 0:
        print(f"error: target {target.path} has zero or unreadable capacity.", file=sys.stderr)
        return 2

    if sys.platform == "win32" and target.kind == "block":
        print(f"target          : {target.path}")
        print(f"method          : OVERWRITE_ZERO_1PASS")
        print(f"nist category   : Clear")
        print(f"summary         : Windows raw volume/drive overwriting with volume lock and dismount")
        print("\nDRY RUN — nothing was written. Run `s0 wipe` when satisfied.")
        return 0

    if sys.platform == "darwin" and target.kind == "block":
        print(f"target          : {target.path}")
        print(f"method          : OVERWRITE_ZERO_1PASS")
        print(f"nist category   : Clear")
        print(f"summary         : macOS raw character device (/dev/rdisk) overwriting with fcntl(F_FULLFSYNC)")
        print("\nDRY RUN — nothing was written. Run `s0 wipe` when satisfied.")
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
    print("\nDRY RUN — nothing was written. Run `s0 wipe` when satisfied.")
    return 0


def cmd_wipe(args) -> int:
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
        from windows.cli.s0_eraser import wipe_drive_or_partition_windows, check_windows_wipe_safety
        try:
            check_windows_wipe_safety(target.path, force=args.force)
        except PermissionError as exc:
            print(f"REFUSED: {exc}", file=sys.stderr)
            return 2

        if not args.yes:
            ans = input(f"\nType '{target.path}' to confirm permanent erasure of {target.path} (Windows Native): ")
            if ans.strip() != str(target.path):
                print("aborted — nothing was written", file=sys.stderr)
                return 2

        key_path = default_issuer_key(args.key)
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
                print(f"audit ledger  : recorded block #{blk.block_index} ({blk.block_hash[:16]}...)")
        except Exception as exc:
            print(f"WARNING: failed to record event into audit ledger: {exc}", file=sys.stderr)

        out_dir = Path(args.out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        cert_json = out_dir / f"certificate_{cert['cert_uuid'][:8]}.json"
        cert_json.write_text(json.dumps(cert, indent=2) + "\n")

        qr_url_tpl = args.qr_url_template
        if getattr(args, "portal_url", None) and "{cert_uuid}" not in args.portal_url:
            qr_url_tpl = f"{args.portal_url.rstrip('/')}/?cert={{cert_uuid}}"

        pdf_path = None
        if not args.no_pdf:
            from s0_core import pdfgen
            pdf_path = out_dir / f"certificate_{cert['cert_uuid'][:8]}.pdf"
            pdfgen.generate_pdf(cert, pdf_path, qr_url_template=qr_url_tpl)
            pdfgen.write_qr_file(cert, out_dir / f"certificate_{cert['cert_uuid'][:8]}.qr.png")

        if args.json:
            print(json.dumps({"status": cert["result"]["status"], "certificate": str(cert_json), "pdf": str(pdf_path) if pdf_path else None, "cert_uuid": cert["cert_uuid"]}, indent=2))
        else:
            print(f"\nresult        : {cert['result']['status']}")
            print(f"certificate   : {cert_json}" + (f"\nPDF           : {pdf_path}" if pdf_path else ""))
        return 0 if res_win.status == "success" else 1

    if sys.platform == "darwin" and target.kind == "block":
        from macos.cli.s0_eraser import wipe_drive_or_partition_macos, check_macos_wipe_safety
        try:
            check_macos_wipe_safety(target.path, force=args.force)
        except PermissionError as exc:
            print(f"REFUSED: {exc}", file=sys.stderr)
            return 2

        if not args.yes:
            ans = input(f"\nType '{target.path}' to confirm permanent erasure of {target.path} (macOS Native): ")
            if ans.strip() != str(target.path):
                print("aborted — nothing was written", file=sys.stderr)
                return 2

        key_path = default_issuer_key(args.key)
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
                print(f"audit ledger  : recorded block #{blk.block_index} ({blk.block_hash[:16]}...)")
        except Exception as exc:
            print(f"WARNING: failed to record event into audit ledger: {exc}", file=sys.stderr)

        out_dir = Path(args.out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        cert_json = out_dir / f"certificate_{cert['cert_uuid'][:8]}.json"
        cert_json.write_text(json.dumps(cert, indent=2) + "\n")

        qr_url_tpl = args.qr_url_template
        if getattr(args, "portal_url", None) and "{cert_uuid}" not in args.portal_url:
            qr_url_tpl = f"{args.portal_url.rstrip('/')}/?cert={{cert_uuid}}"

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
            print(f"\nresult        : {cert['result']['status']}")
            print(f"certificate   : {cert_json}" + (f"\nPDF           : {pdf_path}" if pdf_path else ""))
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
    if not args.yes:
        _print_plan(target, candidate, alternatives, warnings, None)
        answer = input(
            f"\nType '{target.path}' to confirm permanent erasure ({plan.method_id}, NIST {plan.nist_category}): "
        )
        if answer.strip() != str(target.path):
            print("aborted — nothing was written", file=sys.stderr)
            return 2

    planted = None
    pre_samples = None
    offsets = None
    if args.plant_markers:
        marker = b"S0-DEMO-CONFIDENTIAL-" + secrets.token_hex(8).encode()
        count = max(8, target.capacity_bytes // (4 * 1024 * 1024))
        plant_patterns(
            target.path, [(i * (target.capacity_bytes // count), marker) for i in range(count)]
        )
        planted = [marker]
        print(f"planted {count} copies of a demo marker (will require 0 hits after)", file=sys.stderr)

    if args.pattern == "random":
        offsets, pre_samples = take_pre_samples(target)

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
    result = candidate.method.run(target, progress)
    temp = read_temperature(target.path)
    temp_str = f"Temp: {temp}°C" if temp is not None else ""
    bar.finish(extra=temp_str)
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

    # Record in local blockchain audit ledger
    try:
        blk = record_audit_event(cert, operation_type="DRIVE_ERASE", private_key=key_path)
        if not getattr(args, "json", False):
            print(f"audit ledger  : recorded block #{blk.block_index} ({blk.block_hash[:16]}...)")
    except Exception as exc:
        print(f"WARNING: failed to record event into audit ledger: {exc}", file=sys.stderr)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    cert_json = out_dir / f"certificate_{cert['cert_uuid'][:8]}.json"
    cert_json.write_text(json.dumps(cert, indent=2) + "\n")

    # Resolve URL template
    qr_url_tpl = args.qr_url_template
    if getattr(args, "portal_url", None) and "{cert_uuid}" not in args.portal_url:
        qr_url_tpl = f"{args.portal_url.rstrip('/')}/?cert={{cert_uuid}}"

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
        print(f"\nresult        : {cert['result']['status']}")
        print(f"verification  : {json.dumps(verif)}")
        print(f"certificate   : {cert_json}" + (f"\nPDF           : {pdf_path}" if pdf_path else ""))
    return 0 if ok else 1


# --------------------------------------------------------------------------- #
# Module 2: File & Folder Eraser Subcommand
# --------------------------------------------------------------------------- #


def cmd_erase_files(args) -> int:
    print(f"==> S0 Module 2: Secure File & Folder Eraser")

    key_path = default_issuer_key(args.key)
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
    bar = ProgressBar(max(total_est, 1024), operation="s0 erase") if total_est > 0 else None

    def erase_progress_cb(path_str: str, written: int, total_f: int) -> None:
        if bar:
            bar.update(written, extra=Path(path_str).name[:20])

    summary = erase_batch(
        targets,
        passes=args.passes,
        pattern=args.pattern,
        operator_id=args.operator,
        organization=args.organization,
        signing_key_path=key_path,
        progress_callback=erase_progress_cb,
        generate_certificate=not getattr(args, "no_certificate", False),
    )
    if bar:
        bar.finish()

    print(f"\nFiles Processed: {summary.total_files}")
    print(f"Successful     : {summary.successful_files}")
    print(f"Failed         : {summary.failed_files}")
    print(f"Bytes Sanitized: {summary.total_bytes_processed} bytes")

    if summary.certificate:
        try:
            blk = record_audit_event(summary.certificate, operation_type="FILE_ERASE", private_key=key_path)
            print(f"Audit Ledger   : recorded block #{blk.block_index} ({blk.block_hash[:16]}...)")
        except Exception as exc:
            print(f"WARNING: failed to record event into audit ledger: {exc}", file=sys.stderr)

        out_dir = Path(args.out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        cert_p = out_dir / f"file_wipe_certificate_{summary.certificate['cert_uuid'][:8]}.json"
        cert_p.write_text(json.dumps(summary.certificate, indent=2) + "\n")
        print(f"Certificate    : {cert_p}")

        if not getattr(args, "no_pdf", False):
            try:
                from s0_core import pdfgen
                qr_url_tpl = getattr(args, "qr_url_template", "https://s0-vp.vercel.app/?cert={cert_uuid}")
                if getattr(args, "portal_url", None) and "{cert_uuid}" not in args.portal_url:
                    qr_url_tpl = f"{args.portal_url.rstrip('/')}/?cert={{cert_uuid}}"
                pdf_p = out_dir / f"file_wipe_certificate_{summary.certificate['cert_uuid'][:8]}.pdf"
                qr_p = out_dir / f"file_wipe_certificate_{summary.certificate['cert_uuid'][:8]}.qr.png"
                pdfgen.generate_pdf(summary.certificate, pdf_p, qr_url_template=qr_url_tpl)
                pdfgen.write_qr_file(summary.certificate, qr_p)
                print(f"PDF Certificate: {pdf_p}")
            except Exception:
                pass
    elif not getattr(args, "no_certificate", False):
        print("WARNING: Sanitization completed, but certificate generation failed (see warnings).", file=sys.stderr)

    return 0 if summary.failed_files == 0 else 1


# --------------------------------------------------------------------------- #
# Module 3: File Carving Subcommands
# --------------------------------------------------------------------------- #


def cmd_carve(args) -> int:
    print(f"==> S0 Module 3: Advanced File Carving & Recovery")

    key_path = default_issuer_key(args.key)
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

    print(f"\nBytes Scanned  : {summary.total_bytes_scanned}")
    print(f"Candidates Found: {summary.total_candidates_found}")
    print(f"Files Recovered : {summary.files_recovered}")

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
        print(f"Recovery Index File       : {idx_file}")

    if summary.manifest_certificate:
        try:
            blk = record_audit_event(summary.manifest_certificate, operation_type="FILE_CARVE", private_key=key_path)
            print(f"Audit Ledger              : recorded block #{blk.block_index} ({blk.block_hash[:16]}...)")
        except Exception as exc:
            print(f"WARNING: failed to record event into audit ledger: {exc}", file=sys.stderr)

        out_dir = Path(args.out_dir)
        cert_p = (
            out_dir / f"carving_manifest_{summary.manifest_certificate['cert_uuid'][:8]}.json"
        )
        cert_p.write_text(json.dumps(summary.manifest_certificate, indent=2) + "\n")
        print(f"\nForensic Recovery Manifest: {cert_p}")

    return 0


# --------------------------------------------------------------------------- #
# Module 4: Blockchain Audit Ledger Subcommands
# --------------------------------------------------------------------------- #


def cmd_audit(args) -> int:
    if args.audit_action == "list":
        blocks = list_audit_blocks(limit=args.limit)
        print(f"==> S0 Blockchain Cryptographic Audit Ledger ({len(blocks)} blocks)")
        print(
            f"{'IDX':<5} {'TIMESTAMP':<20} {'OPERATION':<14} {'OPERATOR':<14} {'TARGET_ID':<20} {'BLOCK_HASH':<16}"
        )
        for b in blocks:
            print(
                f"{b.block_index:<5} {b.timestamp[:19]:<20} {b.operation_type:<14} {b.operator_id:<14} {b.target_id[:20]:<20} {b.block_hash[:16]}..."
            )
        return 0

    elif args.audit_action == "verify":
        print("==> Auditing Blockchain Cryptographic Hash Chain...")
        trusted_keys = None
        if getattr(args, "key", None):
            from s0_core.crypto import load_public_pem

            trusted_keys = [load_public_pem(args.key)]
        report = verify_audit_ledger(trusted_public_keys=trusted_keys)
        print(f"Chain Status : {'✅ VALID & CONTINUOUS' if report.is_valid else '❌ BROKEN / TAMPER DETECTED'}")
        print(f"Blocks Tested: {report.total_blocks_verified}")
        print(f"Details      : {report.reason}")
        return 0 if report.is_valid else 1

    return 0


# --------------------------------------------------------------------------- #
# Module 5: Offline Verification & Key Generation
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
        print(f"✅ CERTIFICATE AUTHENTIC & VERIFIED")
        print(f"UUID         : {cert_data.get('cert_uuid')}")
        print(f"Status       : {cert_data.get('result', {}).get('status')}")
        print(f"NIST Tier    : {cert_data.get('wipe', {}).get('nist_category')}")
        print(f"Device       : {cert_data.get('device', {}).get('device_id')}")
        print(f"Issuer       : {cert_data.get('issuer', {}).get('organization')}")
        print(f"Fingerprint  : {cert_data.get('signature', {}).get('public_key_fingerprint')}")
        return 0
    else:
        print(f"❌ CERTIFICATE VERIFICATION FAILED: {reason}", file=sys.stderr)
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
    print(f"Generated Ed25519 Keypair:")
    print(f"  Private Key : {priv_p} (Keep secret & offline!)")
    print(f"  Public Key  : {pub_p}")
    print(f"  Fingerprint : {fp}")
    return 0


# --------------------------------------------------------------------------- #
# Module 6: Upgrade & Maintenance
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
        print("[ERROR] Could not locate S0 git installation repository.", file=sys.stderr)
        print("To install or upgrade S0, run:")
        if sys.platform == "win32":
            print("  irm https://raw.githubusercontent.com/kartik2005221/s0/master/scripts/upgrade.ps1 | iex")
        else:
            print("  curl -sSL https://raw.githubusercontent.com/kartik2005221/s0/master/scripts/upgrade.sh | bash")
        return 1

    print(f"[*] Found S0 installation at: {repo_dir}")
    try:
        cur_hash = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"], cwd=str(repo_dir), text=True
        ).strip()
        print(f"[*] Current commit: {cur_hash}")
        print("[*] Pulling latest changes from GitHub origin/master...")
        subprocess.check_call(["git", "fetch", "origin", "master", "-q"], cwd=str(repo_dir))
        latest_hash = subprocess.check_output(
            ["git", "rev-parse", "--short", "origin/master"], cwd=str(repo_dir), text=True
        ).strip()

        if cur_hash == latest_hash and not getattr(args, "force", False):
            print(f"[✓] S0 is already up-to-date at commit {cur_hash}.")
        else:
            subprocess.check_call(["git", "pull", "--ff-only", "origin", "master", "-q"], cwd=str(repo_dir))
            print(f"[✓] Source updated: {cur_hash} → {latest_hash}")

        py_bin = sys.executable
        print("[*] Refreshing dependencies...")
        subprocess.check_call([py_bin, "-m", "pip", "install", "--upgrade", "pip", "-q"])
        subprocess.check_call([py_bin, "-m", "pip", "install", "-e", str(repo_dir / "core" / "python"), "-q"])
        subprocess.check_call([py_bin, "-m", "pip", "install", "-e", str(repo_dir / "linux" / "cli"), "-q"])
        subprocess.check_call([py_bin, "-m", "pip", "install", "reportlab", "qrcode", "pillow", "-q"])
        print("[✓] Dependencies refreshed.")

        ver = subprocess.check_output([py_bin, "-m", "s0_cli.main", "--version"], text=True).strip()
        print()
        print(f"✅ S0 upgraded successfully to {ver} ({latest_hash})")
        return 0
    except Exception as exc:
        print(f"[ERROR] Upgrade failed: {exc}", file=sys.stderr)
        return 1


# --------------------------------------------------------------------------- #
# Module 7: Forensic Bit-Stream Drive Imaging & Cloning
# --------------------------------------------------------------------------- #


def cmd_image(args) -> int:
    """Forensic bit-stream disk acquisition and device cloning."""
    from .imager import ImagingOptions, acquire_image

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
    if sys.platform == "win32" and ("physicaldrive" in args.destination.lower() or args.destination.startswith(r"\\.\\")):
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

    options = ImagingOptions(
        source=args.source,
        destination=args.destination,
        block_size=args.block_size,
        error_recovery=not args.no_recovery,
        operator=args.operator,
        organization=args.organization,
        key_path=args.key,
        no_certificate=args.no_certificate,
        out_dir=args.out_dir,
    )

    print(f"[*] Source      : {args.source}")
    print(f"[*] Destination : {args.destination}")
    print(f"[*] Block Size  : {args.block_size:,} bytes")
    print(f"[*] Fault Tol.  : {'Enabled (Zero-fill bad blocks)' if not args.no_recovery else 'Disabled (Abort on error)'}")
    print()

    result = acquire_image(options, progress_callback=_progress)
    bar.finish()
    print()

    if not result.success:
        print(f"❌ ACQUISITION FAILED: {result.error}", file=sys.stderr)
        return 1

    print("✅ FORENSIC ACQUISITION COMPLETED SUCCESSFULLY")
    print(f"   Operation       : {'Drive Clone' if result.is_clone else 'Raw Bit-Stream Image'}")
    print(f"   Bytes Acquired  : {result.bytes_copied:,} bytes ({result.bytes_copied / (1024**3):.2f} GB)")
    print(f"   Duration        : {result.duration_seconds:.2f} seconds ({result.speed_mbps:.1f} MB/s)")
    print(f"   Bad Sectors     : {result.bad_sectors_count}")
    print(f"   Source SHA-256  : {result.source_sha256}")
    print(f"   Source MD5      : {result.source_md5}")
    if result.manifest_path:
        print(f"   Manifest File   : {result.manifest_path}")
    if result.manifest_certificate:
        print(f"   Certificate     : {result.manifest_certificate.get('cert_uuid')} (Signed & Appended to Audit Ledger)")
    print()
    return 0


# --------------------------------------------------------------------------- #
# CLI Parser Setup
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="s0",
        description="S0 (Sector Zero) — Unified Forensic Sanitization & Recovery CLI",
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
    common.add_argument("--target", required=True, help="block device path OR image file path")
    common.add_argument(
        "--passes",
        type=int,
        default=1,
        help="overwrite passes (default 1 — one pass IS Clear per NIST 800-88)",
    )
    common.add_argument("--pattern", choices=["zero", "random"], default="zero")
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

    wp = sub.add_parser("wipe", parents=[common], help="wipe target, verify, issue signed certificate")
    wp.add_argument("--yes", action="store_true", help="skip interactive WIPE prompt")
    wp.add_argument("--key", help="issuer private key PEM")
    wp.add_argument("--out-dir", default=".")
    wp.add_argument("--operator", default="unknown-operator")
    wp.add_argument("--organization", default="Digital Forensics & Data Sanitization Lab")
    wp.add_argument("--no-pdf", action="store_true")
    wp.add_argument("--verify-samples", type=int, default=64)
    wp.add_argument(
        "--plant-markers",
        action="store_true",
        help="plant recoverable markers first, then require 0 grep hits afterwards",
    )
    wp.add_argument("--json", action="store_true", help="machine-readable stdout")
    wp.add_argument(
        "--portal-url",
        default="https://s0-vp.vercel.app/",
        help="verification portal base URL",
    )
    wp.add_argument(
        "--qr-url-template",
        dest="qr_url_template",
        default="https://s0-vp.vercel.app/?cert={cert_uuid}",
    )
    wp.set_defaults(func=cmd_wipe)

    # 2. File & Folder Eraser Subcommand (erase & erase-files alias)
    for fe_cmd in ("erase", "erase-files"):
        fe = sub.add_parser(fe_cmd, help="securely erase files and folders with metadata cleansing")
        fe.add_argument("--targets", nargs="+", required=True, help="paths to files or directories to sanitize")
        fe.add_argument("--passes", type=int, default=1, help="number of overwrite passes")
        fe.add_argument("--pattern", choices=["zero", "random"], default="zero")
        fe.add_argument("--out-dir", default=".")
        fe.add_argument("--operator", default="op-forensic")
        fe.add_argument("--organization", default="Digital Forensics & Data Sanitization Lab")
        fe.add_argument("--key", help="signing key path")
        fe.add_argument(
            "--no-certificate",
            action="store_true",
            help="explicitly run without generating an Ed25519 compliance certificate",
        )
        fe.add_argument("--no-pdf", action="store_true", help="skip rendering PDF certificate")
        fe.add_argument(
            "--portal-url",
            default="https://s0-vp.vercel.app/",
            help="verification portal base URL",
        )
        fe.add_argument(
            "--qr-url-template",
            default="https://s0-vp.vercel.app/?cert={cert_uuid}",
            help="URL template for verification QR",
        )
        fe.add_argument(
            "--verify-samples",
            type=int,
            default=64,
            help="number of readback samples for verification (default: 64)",
        )
        fe.set_defaults(func=cmd_erase_files)

    # 3. File Carving & Recovery Subcommand
    crv = sub.add_parser("carve", help="advanced file carving and recovery from raw images / media")
    crv.add_argument("--target", required=True, help="raw disk image or block device to scan")
    crv.add_argument("--out-dir", required=True, help="directory to store carved files")
    crv.add_argument("--extensions", help="comma-separated file extensions to carve (e.g. jpg,png,pdf,zip)")
    crv.add_argument(
        "--custom-sig",
        help="path to JSON file (or inline JSON) defining custom file signature(s) with header/footer hex magic bytes",
    )
    crv.add_argument("--min-confidence", type=int, default=50, help="minimum confidence score (0-100)")
    crv.add_argument("--operator", default="op-forensic")
    crv.add_argument("--organization", default="Digital Forensics & Data Sanitization Lab")
    crv.add_argument("--key", help="signing key path")
    crv.add_argument(
        "--no-certificate",
        action="store_true",
        help="explicitly run without generating an Ed25519 forensic manifest certificate",
    )
    crv.set_defaults(func=cmd_carve)

    # 4. Blockchain Audit Ledger Subcommand
    aud = sub.add_parser("audit", help="cryptographic audit ledger and blockchain continuity management")
    aud.add_argument("audit_action", choices=["list", "verify"], help="list audit blocks or verify hash chain")
    aud.add_argument("--limit", type=int, default=50, help="limit number of records displayed")
    aud.add_argument("--key", help="path to trusted public key PEM for strict signature verification")
    aud.set_defaults(func=cmd_audit)

    # 5. Offline Verification Subcommand
    vr = sub.add_parser("verify", help="verify a signed certificate offline against trusted public keys")
    vr.add_argument("certificate", help="path to certificate JSON")
    vr.add_argument("--key", help="path to trusted public key PEM")
    vr.set_defaults(func=cmd_verify)

    # 6. Key Generation Subcommand
    kg = sub.add_parser("keygen", help="generate Ed25519 signing keypair for an authority or operator")
    kg.add_argument("--out-dir", default=".", help="directory to store private and public keys")
    kg.add_argument("--name", default="operator_key", help="key filename prefix")
    kg.set_defaults(func=cmd_keygen)

    # 7. Upgrade Subcommand
    upg = sub.add_parser("upgrade", help="upgrade S0 suite to the latest version from GitHub")
    upg.add_argument("--force", action="store_true", help="force re-installation of dependencies even if up to date")
    upg.set_defaults(func=cmd_upgrade)

    # 8. Forensic Imaging & Cloning Subcommands (image & clone alias)
    for img_cmd in ("image", "clone"):
        img = sub.add_parser(img_cmd, help="forensic bit-stream drive imaging, cloning, and fault-tolerant acquisition")
        img.add_argument("--source", required=True, help="path to source block device or raw image file")
        img.add_argument("--destination", "--dest", required=True, help="path to destination image file or block device")
        img.add_argument("--block-size", type=int, default=1048576, help="buffer block size in bytes (default: 1048576 / 1MB)")
        img.add_argument("--no-recovery", action="store_true", help="abort on I/O read error instead of zero-filling bad sectors")
        img.add_argument("--out-dir", default=".", help="directory to store acquisition manifest and certificate")
        img.add_argument("--operator", default="op-forensic", help="operator ID")
        img.add_argument("--organization", default="Digital Forensics & Incident Response Lab", help="organization name")
        img.add_argument("--key", help="path to Ed25519 issuer private key PEM")
        img.add_argument("--no-certificate", action="store_true", help="skip generating signed Ed25519 acquisition certificate")
        img.add_argument("--yes", action="store_true", help="skip interactive confirmation when cloning to a physical disk")
        img.set_defaults(func=cmd_image)

    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
