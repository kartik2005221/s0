"""trustwipe-wipe — the Linux wipe CLI.

    trustwipe-wipe list                     inventory of block devices
    trustwipe-wipe plan  --target PATH      dry-run: method, tier, warnings
    trustwipe-wipe wipe  --target PATH      do it, verify, issue certificate

Safety posture:
  * image files are the default demo/test medium (no root needed)
  * block devices with mounts or the running root FS are REFUSED without --force
  * nothing destructive happens before an explicit plan confirmation (--yes
    or interactive typing of WIPE)

Progress goes to stderr; the final certificate JSON summary can go to stdout
with --json so scripts/GUI can consume it.
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
from .devices import SafetyError, check_safety, image_target, list_block_targets
from .methods.ata import AtaSecureEraseMethod, hpa_dco_report
from .methods.overwrite import OverwriteMethod, plant_patterns
from .wipe import (default_issuer_key, make_certificate, select_method,
                   take_pre_samples, verify_wipe)
from .devices import Target as DevTarget


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


def _print_plan(target: DevTarget, candidate, alternatives, warnings: list[str],
                hpa_dco: dict | None) -> None:
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
    if hpa_dco and (hpa_dco.get("hpa_present") or hpa_dco.get("dco_present")
                    or hpa_dco.get("note")):
        print("hpa/dco         : " + json.dumps(hpa_dco))
        if hpa_dco.get("restore_command"):
            print(f"                  remove BEFORE wiping: {hpa_dco['restore_command']}")


# --------------------------------------------------------------------------- #
# subcommands
# --------------------------------------------------------------------------- #

def cmd_list(_args) -> int:
    targets = list_block_targets()
    if not targets:
        print("(no block devices found)")
        return 0
    mounted = set()
    try:
        with open("/proc/mounts") as f:
            mounted = {line.split()[0] for line in f}
    except OSError:
        pass
    print(f"{'PATH':<14} {'TYPE':<7} {'STORAGE':<10} {'CAPACITY':>12}  "
          f"{'MODEL':<24} {'SERIAL':<16} MOUNTED?")
    for t in targets:
        cap = f"{t.capacity_bytes / 2**30:.1f} GiB"
        is_mounted = "YES" if any(m.startswith(t.path) for m in mounted) else "-"
        print(f"{t.path:<14} {t.kind:<7} {t.storage_type:<10} {cap:>12}  "
              f"{(t.model or '—')[:24]:<24} {(t.serial or '—')[:16]:<16} {is_mounted}")
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
        target, passes=args.passes, pattern=args.pattern,
        prefer_firmware=not args.no_firmware,
        discard_justification=args.discard_purge_justification)
    hpa_dco = None
    if target.kind == "block" and not target.path.startswith("/dev/nvme") \
            and shutil.which("hdparm"):
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
        target, passes=args.passes, pattern=args.pattern,
        prefer_firmware=not args.no_firmware,
        discard_justification=args.discard_purge_justification)
    if candidate.method is None:
        print(f"error: no applicable wipe method ({candidate.reason})", file=sys.stderr)
        return 2

    # Confirmation gate — the last line of defence.
    plan = candidate.method.plan(target)
    if not args.yes:
        _print_plan(target, candidate, alternatives, warnings, None)
        answer = input(f'\nType WIPE to erase {target.path} '
                       f'({plan.method_id}, NIST {plan.nist_category}): ')
        if answer.strip() != "WIPE":
            print("aborted — nothing was written", file=sys.stderr)
            return 2

    planted = None
    pre_samples = None
    offsets = None
    if args.plant_markers:  # test/demo hook: prove erasure of known content
        marker = b"SIH-DEMO-CONFIDENTIAL-" + secrets.token_hex(8).encode()
        count = max(8, target.capacity_bytes // (4 * 1024 * 1024))
        plant_patterns(target.path,
                       [(i * (target.capacity_bytes // count), marker) for i in range(count)])
        planted = [marker]
        print(f"planted {count} copies of a demo marker (will require 0 hits after)",
              file=sys.stderr)

    if args.pattern == "random":
        offsets, pre_samples = take_pre_samples(target)

    def progress(msg: str) -> None:
        print(f"[{time.monotonic() - t_start:8.1f}s] {msg}", file=sys.stderr)

    progress(f"wiping {target.display} with {plan.method_id} "
             f"(NIST {plan.nist_category})")
    result = candidate.method.run(target, progress)
    end_time = _now()

    verif, _post = verify_wipe(
        target, args.pattern, samples=args.verify_samples,
        planted_needles=planted, pre_samples=pre_samples, offsets=offsets)
    if not verif.get("all_samples_match_wipe_pattern", False):
        result.status = "failure"
        result.errors.append("post-wipe verification FAILED — sampled sectors did "
                             "not match the expected post-wipe state")

    key_path = default_issuer_key(args.key)
    if key_path is None:
        print("error: no issuer signing key found. Generate one out-of-band:\n"
              "  .venv/bin/trustwipe-keygen --out-dir core/keys --name demo_issuer\n"
              "(see core/keys/README.md — the private key never ships in apps)",
              file=sys.stderr)
        return 2

    cert = make_certificate(
        target, candidate.method, result, start_time, end_time,
        operator_id=args.operator, organization=args.organization,
        tool_version=__version__, key_path=key_path,
        verification=verif,
        extra_notes=warnings + [
            f"elapsed {time.monotonic() - t_start:.1f}s",
        ],
    )

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    cert_json = out_dir / f"certificate_{cert['cert_uuid'][:8]}.json"
    cert_json.write_text(json.dumps(cert, indent=2) + "\n")

    pdf_path = None
    if not args.no_pdf:
        from trustwipe_core import pdfgen

        pdf_path = pdfgen.generate_pdf(cert, out_dir / f"certificate_{cert['cert_uuid'][:8]}.pdf",
                                       qr_url_template=args.qr_url_template)
        pdfgen.write_qr_file(cert, out_dir / f"certificate_{cert['cert_uuid'][:8]}.qr.png")

    ok = result.status == "success" and \
        verif.get("all_samples_match_wipe_pattern") is True
    if args.json:
        print(json.dumps({
            "status": cert["result"]["status"],
            "verified": verif.get("all_samples_match_wipe_pattern"),
            "certificate": str(cert_json),
            "pdf": str(pdf_path) if pdf_path else None,
            "cert_uuid": cert["cert_uuid"],
        }, indent=2))
    else:
        print(f"\nresult        : {cert['result']['status']}")
        print(f"verification  : {json.dumps(verif)}")
        print(f"certificate   : {cert_json}" +
              (f"\nPDF           : {pdf_path}" if pdf_path else ""))
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="trustwipe-wipe",
                                description="TrustWipe Linux secure-wipe CLI")
    p.add_argument("--version", action="version", version=f"trustwipe-wipe {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    lst = sub.add_parser("list", help="list block-device wipe targets")
    lst.set_defaults(func=cmd_list)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--target", required=True,
                        help="block device path OR image file path")
    common.add_argument("--passes", type=int, default=1,
                        help="overwrite passes (default 1 — one pass IS Clear per "
                             "NIST 800-88; more passes is policy theater, we say so)")
    common.add_argument("--pattern", choices=["zero", "random"], default="zero")
    common.add_argument("--no-firmware", action="store_true",
                        help="skip firmware methods (ATA SE/NVMe sanitize); overwrite only")
    common.add_argument("--discard-purge-justification", metavar="TEXT",
                        help="record drive-spec deterministic-TRIM evidence to let "
                             "BLKDISCARD claim Purge (validated against notes by core)")
    common.add_argument("--force", action="store_true",
                        help="override mounted/root safety refusals (you probably "
                             "do not want this; use the ISO)")

    pln = sub.add_parser("plan", parents=[common],
                         help="dry-run: show what would happen")
    pln.set_defaults(func=cmd_plan)

    wp = sub.add_parser("wipe", parents=[common],
                        help="wipe target, verify, issue signed certificate")
    wp.add_argument("--yes", action="store_true", help="skip interactive WIPE prompt")
    wp.add_argument("--key", help="issuer private key PEM (default: demo issuer)")
    wp.add_argument("--out-dir", default=".")
    wp.add_argument("--operator", default="unknown-operator")
    wp.add_argument("--organization", default="TrustWipe Demo Lab (unaccredited)")
    wp.add_argument("--no-pdf", action="store_true")
    wp.add_argument("--verify-samples", type=int, default=64)
    wp.add_argument("--plant-markers", action="store_true",
                    help="[demo/test] plant recoverable markers first, then require "
                         "0 grep hits afterwards")
    wp.add_argument("--json", action="store_true", help="machine-readable stdout")
    wp.add_argument("--qr-url-template", dest="qr_url_template",
                    default="https://verify.trustwipe.example/c/{cert_uuid}")
    wp.set_defaults(func=cmd_wipe)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
