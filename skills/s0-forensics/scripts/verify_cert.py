#!/usr/bin/env python3
"""s0 Forensic Skill — Standalone Certificate Verification Helper.

Usage:
    python verify_cert.py <path_to_certificate.json> [--key <path_to_public_key.pem>]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Resolve repository root
repo_root = Path(__file__).resolve().parents[3]
core_py = repo_root / "core" / "python"
if core_py.is_dir():
    sys.path.insert(0, str(core_py))

try:
    from s0_core import certificate, crypto
except ImportError:
    certificate = None
    crypto = None


def find_default_public_key() -> Path | None:
    """Find demo or authority public key in repository."""
    candidates = [
        repo_root / "core" / "keys" / "demo_issuer_public.pem",
        Path.home() / ".s0" / "keys" / "authority_public.pem",
        Path("/etc/s0/authority_public.pem"),
    ]
    for cand in candidates:
        if cand.is_file():
            return cand
    return None


def verify_certificate_file(cert_path: Path, key_path: Path | None = None) -> int:
    """Verify an s0 certificate file and print human-readable forensic summary."""
    if not cert_path.is_file():
        print(f"[ERROR] Certificate file not found: {cert_path}", file=sys.stderr)
        return 2

    try:
        with open(cert_path, "r", encoding="utf-8") as f:
            cert_data = json.load(f)
    except Exception as exc:
        print(f"[ERROR] Failed to parse JSON: {exc}", file=sys.stderr)
        return 1

    cert_uuid = cert_data.get("cert_uuid") or cert_data.get("certificate_uuid") or "unknown"
    issuer_obj = cert_data.get("issuer", {})
    operator = issuer_obj.get("operator_id") or cert_data.get("operator", "UNKNOWN")
    org = issuer_obj.get("organization") or cert_data.get("organization", "UNKNOWN")

    device_obj = cert_data.get("device", {})
    target = device_obj.get("model") or cert_data.get("target_device", "UNKNOWN")
    capacity = device_obj.get("capacity_bytes", 0)

    wipe_obj = cert_data.get("wipe", {})
    method = wipe_obj.get("method") or cert_data.get("sanitization_method", "UNKNOWN")
    nist_category = wipe_obj.get("nist_category") or cert_data.get("nist_category", "UNKNOWN")
    timestamp = wipe_obj.get("end_time") or cert_data.get("issued_at", "UNKNOWN")
    signature = cert_data.get("signature", {})
    fingerprint = signature.get("public_key_fingerprint") if isinstance(signature, dict) else cert_data.get("public_key_fingerprint", "unknown")

    print("╔══════════════════════════════════════════════════════════════════╗")
    print("║          s0 Forensic Certificate Verification Summary            ║")
    print("╚══════════════════════════════════════════════════════════════════╝")
    print(f"  UUID            : {cert_uuid}")
    print(f"  Target Device   : {target} ({capacity} bytes)")
    print(f"  Method Selected : {method}")
    print(f"  NIST Tier       : {nist_category}")
    print(f"  Issuer / Org    : {org} (Operator: {operator})")
    print(f"  Timestamp (UTC) : {timestamp}")
    print(f"  Claimed Key FP  : {fingerprint}")
    print("──────────────────────────────────────────────────────────────────")

    if not signature:
        print("  ❌ STATUS: UNSIGNED (No digital signature found)")
        return 1

    # Locate public key
    resolved_key = key_path or find_default_public_key()
    if not resolved_key or not resolved_key.is_file():
        print("  ⚠️  WARNING: No trusted public key found to verify signature.")
        print("     Specify --key /path/to/authority_public.pem")
        return 1

    if crypto and certificate:
        try:
            pubkey = crypto.load_public_pem(resolved_key)
            ok, reason = certificate.verify_certificate(cert_data, [pubkey])
            if ok:
                if crypto.is_demo_key(resolved_key):
                    print("  ⚠️  STATUS: VALID SIGNATURE — UNACCREDITED DEMO KEY")
                    print("     This certificate was signed with the bundled demonstration key.")
                    print("     DO NOT use for legal chain-of-custody or regulatory compliance.")
                else:
                    print("  ✅ STATUS: CRYPTOGRAPHICALLY VALID & TAMPER-FREE")
                print(f"  Key File: {resolved_key}")
                print(f"  Evidence: {reason}")
                return 0
            else:
                print("  ❌ STATUS: INVALID / VERIFICATION FAILED")
                print(f"  Reason: {reason}")
                return 1
        except Exception as err:
            print(f"  ❌ Verification error: {err}")
            return 1
    else:
        # Fallback to invoking s0 CLI
        import subprocess
        res = subprocess.run(["s0", "verify", str(cert_path), "--key", str(resolved_key)], capture_output=True, text=True)
        print(res.stdout or res.stderr)
        return res.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify s0 Forensic Certificate")
    parser.add_argument("certificate", type=Path, help="Path to certificate JSON")
    parser.add_argument("--key", type=Path, default=None, help="Optional trusted public key PEM")
    args = parser.parse_args()
    return verify_certificate_file(args.certificate, args.key)


if __name__ == "__main__":
    sys.exit(main())
