"""TrustWipe Unified Forensic & Sanitization CLI (SIH26149 / NTRO).

Subcommands:
  1. Drive Eraser:
     trustwipe-wipe list                       inventory of block devices
     trustwipe-wipe plan  --target PATH        dry-run: method, tier, warnings
     trustwipe-wipe wipe  --target PATH        sanitize drive, verify, issue certificate

  2. File & Folder Eraser:
     trustwipe-wipe erase-files --targets PATH...   secure deletion & metadata scrubbing

  3. Advanced File Carving & Recovery:
     trustwipe-wipe carve --target PATH --out-dir DIR   signature & structure recovery

  4. Blockchain Audit Ledger:
     trustwipe-wipe audit list                 display cryptographic audit blocks
     trustwipe-wipe audit verify               verify blockchain hash-chain integrity
"""

from __future__ import annotations

import argparse
import json
import secrets
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from trustwipe_core import certificate as cert_mod

from . import __version__
from .audit import init_audit_db, list_audit_blocks, record_audit_event, verify_audit_ledger
from .carver import carve_image
from .devices import SafetyError, check_safety, image_target, list_block_targets
from .devices import Target as DevTarget
from .file_eraser import erase_batch
from .methods.ata import AtaSecureEraseMethod, hpa_dco_report
from .methods.base import Plan
from .methods.overwrite import OverwriteMethod, plant_patterns
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
    p = Path(path)
    if p.is_block_device():
        for t in list_block_targets():
            if Path(t.path) == p.resolve():
                return t
        return DevTarget(path=str(p), kind="block", capacity_bytes=p.stat().st_size)
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
        import json
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
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
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
    print("\nDRY RUN — nothing was written. Run `wipe` when satisfied.")
    return 0


def cmd_wipe(args) -> int:
    t_start = time.monotonic()
    start_time = _now()
    try:
        target = _resolve_target(args.target)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
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
            f"\nType WIPE to erase {target.path} ({plan.method_id}, NIST {plan.nist_category}): "
        )
        if answer.strip() != "WIPE":
            print("aborted — nothing was written", file=sys.stderr)
            return 2

    planted = None
    pre_samples = None
    offsets = None
    if args.plant_markers:
        marker = b"SIH-DEMO-CONFIDENTIAL-" + secrets.token_hex(8).encode()
        count = max(8, target.capacity_bytes // (4 * 1024 * 1024))
        plant_patterns(
            target.path, [(i * (target.capacity_bytes // count), marker) for i in range(count)]
        )
        planted = [marker]
        print(f"planted {count} copies of a demo marker (will require 0 hits after)", file=sys.stderr)

    if args.pattern == "random":
        offsets, pre_samples = take_pre_samples(target)

    def progress(msg: str) -> None:
        print(f"[{time.monotonic() - t_start:8.1f}s] {msg}", file=sys.stderr)

    progress(f"wiping {target.display} with {plan.method_id} (NIST {plan.nist_category})")
    result = candidate.method.run(target, progress)
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
        record_audit_event(cert, operation_type="DRIVE_ERASE")
    except Exception:
        pass

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    cert_json = out_dir / f"certificate_{cert['cert_uuid'][:8]}.json"
    cert_json.write_text(json.dumps(cert, indent=2) + "\n")

    pdf_path = None
    if not args.no_pdf:
        from trustwipe_core import pdfgen

        pdf_path = pdfgen.generate_pdf(
            cert,
            out_dir / f"certificate_{cert['cert_uuid'][:8]}.pdf",
            qr_url_template=args.qr_url_template,
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
# Module 2: File & Folder Eraser Subcommands
# --------------------------------------------------------------------------- #


def cmd_erase_files(args) -> int:
    print(f"==> TrustWipe Module 2: Secure File & Folder Eraser (NTRO)")
    targets = [Path(t) for t in args.targets]
    print(f"==> Target items ({len(targets)}): {[str(t) for t in targets]}")

    summary = erase_batch(
        targets,
        passes=args.passes,
        pattern=args.pattern,
        operator_id=args.operator,
        organization=args.organization,
        signing_key_path=args.key,
    )

    print(f"\nFiles Processed: {summary.total_files}")
    print(f"Successful     : {summary.successful_files}")
    print(f"Failed         : {summary.failed_files}")
    print(f"Bytes Sanitized: {summary.total_bytes_processed} bytes")

    if summary.certificate:
        try:
            record_audit_event(summary.certificate, operation_type="FILE_ERASE")
        except Exception:
            pass

        out_dir = Path(args.out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        cert_p = out_dir / f"file_wipe_certificate_{summary.certificate['cert_uuid'][:8]}.json"
        cert_p.write_text(json.dumps(summary.certificate, indent=2) + "\n")
        print(f"Certificate    : {cert_p}")

    return 0 if summary.failed_files == 0 else 1


# --------------------------------------------------------------------------- #
# Module 3: File Carving Subcommands
# --------------------------------------------------------------------------- #


def cmd_carve(args) -> int:
    print(f"==> TrustWipe Module 3: Advanced File Carving & Recovery (NTRO)")
    print(f"Target Media: {args.target}")
    print(f"Output Dir  : {args.out_dir}")

    exts = [e.strip() for e in args.extensions.split(",")] if args.extensions else None

    summary = carve_image(
        args.target,
        args.out_dir,
        extensions=exts,
        min_confidence=args.min_confidence,
        operator_id=args.operator,
        organization=args.organization,
        signing_key_path=args.key,
    )

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
            record_audit_event(summary.manifest_certificate, operation_type="FILE_CARVE")
        except Exception:
            pass

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
        print(f"==> TrustWipe Blockchain Cryptographic Audit Ledger ({len(blocks)} blocks)")
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
        report = verify_audit_ledger()
        print(f"Chain Status : {'✅ VALID & CONTINUOUS' if report.is_valid else '❌ BROKEN / TAMPER DETECTED'}")
        print(f"Blocks Tested: {report.total_blocks_verified}")
        print(f"Details      : {report.reason}")
        return 0 if report.is_valid else 1

    return 0


# --------------------------------------------------------------------------- #
# CLI Parser Setup
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="trustwipe-wipe",
        description="TrustWipe Unified Forensic Sanitization & Recovery CLI (NTRO)",
    )
    p.add_argument("--version", action="version", version=f"trustwipe-wipe {__version__}")
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
    common.add_argument("--version", action="version", version=f"trustwipe-wipe {__version__}")
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
    wp.add_argument("--organization", default="NTRO Digital Forensics & Data Sanitization Lab")
    wp.add_argument("--no-pdf", action="store_true")
    wp.add_argument("--verify-samples", type=int, default=64)
    wp.add_argument(
        "--plant-markers",
        action="store_true",
        help="plant recoverable markers first, then require 0 grep hits afterwards",
    )
    wp.add_argument("--json", action="store_true", help="machine-readable stdout")
    wp.add_argument(
        "--qr-url-template",
        dest="qr_url_template",
        default="https://verify.trustwipe.example/c/{cert_uuid}",
    )
    wp.set_defaults(func=cmd_wipe)

    # 2. File & Folder Eraser Subcommand
    fe = sub.add_parser("erase-files", help="securely erase files and folders with metadata cleansing")
    fe.add_argument("--targets", nargs="+", required=True, help="paths to files or directories to sanitize")
    fe.add_argument("--passes", type=int, default=1, help="number of overwrite passes")
    fe.add_argument("--pattern", choices=["zero", "random"], default="zero")
    fe.add_argument("--out-dir", default=".")
    fe.add_argument("--operator", default="op-ntro-forensic")
    fe.add_argument("--organization", default="NTRO Digital Forensics & Data Sanitization Lab")
    fe.add_argument("--key", help="signing key path")
    fe.set_defaults(func=cmd_erase_files)

    # 3. File Carving & Recovery Subcommand
    crv = sub.add_parser("carve", help="advanced file carving and recovery from raw images / media")
    crv.add_argument("--target", required=True, help="raw disk image or block device to scan")
    crv.add_argument("--out-dir", required=True, help="directory to store carved files")
    crv.add_argument("--extensions", help="comma-separated file extensions to carve (e.g. jpg,png,pdf,zip)")
    crv.add_argument("--min-confidence", type=int, default=50, help="minimum confidence score (0-100)")
    crv.add_argument("--operator", default="op-ntro-forensic")
    crv.add_argument("--organization", default="NTRO Digital Forensics & Data Sanitization Lab")
    crv.add_argument("--key", help="signing key path")
    crv.set_defaults(func=cmd_carve)

    # 4. Blockchain Audit Ledger Subcommand
    aud = sub.add_parser("audit", help="cryptographic audit ledger and blockchain continuity management")
    aud.add_argument("audit_action", choices=["list", "verify"], help="list audit blocks or verify hash chain")
    aud.add_argument("--limit", type=int, default=50, help="limit number of records displayed")
    aud.set_defaults(func=cmd_audit)

    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
