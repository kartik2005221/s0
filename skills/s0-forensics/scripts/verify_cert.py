#!/usr/bin/env python3
"""s0 Forensic Skill — Standalone Certificate Verification Helper.

Usage:
    python verify_cert.py <path_to_certificate.json> [--key <path_to_public_key.pem>]

The signature check needs s0, so the script finds s0 in whichever way the
machine it was copied to allows, and says plainly when it cannot:

1. **In a source checkout** — ancestors are walked for ``src/s0`` and put on
   ``sys.path``. Not ``parents[N]``: the depth is a property of where somebody
   put the file, not of what the file needs.
2. **An installed s0** — ``from s0 import certificate, crypto`` succeeds, and
   the real verifier runs in-process.
3. **The ``s0`` CLI** — on ``PATH``, or next to the interpreter running this
   script (a copied helper is usually run with a venv's own ``python``, whose
   ``bin/`` is often not on ``PATH``).
4. **None of those** — the certificate's metadata is still printed and the
   script exits 1 with the exact command to run, instead of dying on a path
   assumption.

Modes 1-3 must be distinguished from a *failed* verification: "s0 was not
found" is not "the certificate is bad", and this script never conflates them.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

#: Where a repository checkout keeps its importable package.
_SRC_DIRNAME = "src"

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def find_repo_root(start: Path) -> Path | None:
    """Walk up from *start* looking for the repository root.

    Not ``parents[N]``. The script is shipped in the wheel and in the checkout,
    and it is routinely copied somewhere shallower -- a scratch directory, a
    tmpdir, a container bind mount -- where ``parents[3]`` does not exist and
    indexing it raises ``IndexError`` before any useful work happens. Depth is a
    property of where somebody put the file, not of what the file needs.
    """
    try:
        here = start.resolve()
    except OSError:
        here = start
    for parent in (here, *here.parents):
        if (parent / _SRC_DIRNAME / "s0" / "__init__.py").is_file():
            return parent
        if (parent / "pyproject.toml").is_file() and (parent / "skills").is_dir():
            return parent
    return None


def _bootstrap_s0() -> tuple[object | None, object | None]:
    """Make ``s0`` importable if we can, without failing if we cannot."""
    repo_root = find_repo_root(Path(__file__))
    if repo_root is not None:
        src = repo_root / _SRC_DIRNAME
        if src.is_dir() and str(src) not in sys.path:
            sys.path.insert(0, str(src))
    try:
        from s0 import certificate, crypto
    except Exception:  # noqa: BLE001 - any import failure is
        return None, None  # the same answer: no in-process path
    return certificate, crypto


certificate, crypto = _bootstrap_s0()

#: Only meaningful when we are inside a checkout; ``None`` otherwise.
REPO_ROOT = find_repo_root(Path(__file__))


def default_key_candidates() -> list[Path]:
    """Trusted-key locations, most specific first.

    ``~/.s0/keys`` is what ``s0 audit verify`` itself trusts, so the standalone
    helper agrees with the tool rather than reaching for a different key.
    """
    candidates: list[Path] = []
    if REPO_ROOT is not None:
        candidates.append(REPO_ROOT / _SRC_DIRNAME / "s0" / "data" / "keys" / "demo_issuer_public.pem")
    candidates.append(Path.home() / ".s0" / "keys" / "authority_public.pem")
    candidates.append(Path("/etc/s0/authority_public.pem"))
    user_keys = Path.home() / ".s0" / "keys"
    if user_keys.is_dir():
        candidates.extend(sorted(user_keys.glob("*.pem")))
    return candidates


def find_default_public_key() -> Path | None:
    """First trusted key that actually exists, or ``None``."""
    seen: set[Path] = set()
    for cand in default_key_candidates():
        if cand in seen:
            continue
        seen.add(cand)
        if cand.is_file():
            return cand
    return None


def find_s0_cli() -> Path | None:
    """Locate the ``s0`` console script.

    ``PATH`` first, then next to the interpreter running this script. The second
    matters because a copied-out helper is usually run with a venv's own
    ``python``, and that venv's ``bin/`` is often not on ``PATH`` -- so without
    it a perfectly good install looks like no install at all, and the helper
    reports "not verified" about a certificate it could have verified.
    """
    found = shutil.which("s0")
    if found:
        return Path(found)
    for name in ("s0", "s0.exe"):
        sibling = Path(sys.executable).with_name(name)
        if sibling.is_file():
            return sibling
    return None


#: Every summary line uses this label width, so the block reads as one column.
_LABEL_WIDTH = 19


def _row(label: str, value) -> str:
    return f"  {label.ljust(_LABEL_WIDTH)}: {value}"


def _first(*values):
    """First value that is neither ``None`` nor an empty string."""
    for value in values:
        if value is not None and value != "":
            return value
    return None


def _human_bytes(n: int | None) -> str:
    if not isinstance(n, int) or n < 0:
        return "unknown"
    step = 1024.0
    value = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if value < step or unit == "PiB":
            return f"{value:,.0f} {unit}" if unit == "B" else f"{value:,.2f} {unit}"
        value /= step
    return f"{value:,.2f} PiB"


def _describe_target(device: dict, cert: dict) -> list[str]:
    """Lines identifying the target, from fields the schema actually has.

    Schema v1.0.0 gives ``device`` exactly: ``device_id``, ``device_type``,
    ``storage_type``, ``capacity_bytes`` (required) and ``model``,
    ``serial_number``, ``sector_size`` (optional). There is no ``target_device``
    member, so reading one yielded ``UNKNOWN`` for every valid certificate --
    including a file erase, which has no model to report in the first place.

    ``device_id`` is the field ``s0 verify`` itself displays, and it is always
    present, so it leads. The optional hardware fields are shown only when the
    certificate actually carries them.
    """
    lines: list[str] = []
    device_id = _first(device.get("device_id"), cert.get("device_id"))
    device_type = _first(device.get("device_type"), cert.get("device_type"))
    storage_type = _first(device.get("storage_type"), cert.get("storage_type"))
    capacity = device.get("capacity_bytes")

    if device_id:
        lines.append(_row("Target id", device_id))
    kind = ", ".join(str(x) for x in (device_type, storage_type) if x)
    if kind:
        lines.append(_row("Target kind", kind))
    if isinstance(capacity, int):
        lines.append(_row("Target capacity", f"{capacity} bytes ({_human_bytes(capacity)})"))
    model = device.get("model")
    if model:
        lines.append(_row("Target model", model))
    serial = device.get("serial_number")
    if serial:
        lines.append(_row("Target serial", serial))
    if not lines:
        lines.append(_row("Target", "(this certificate carries no `device` object)"))
    return lines


def _describe_verification(result: dict) -> list[str]:
    """Print what the verification block does and does not establish.

    A missing bound and a bound of zero are different claims, and a file erase
    has no bound at all because it was exhaustive rather than sampled. Printing
    ``0`` for the missing case states the stronger of the two without evidence.
    """
    lines: list[str] = []
    verif = result.get("verification")
    if not isinstance(verif, dict):
        lines.append(_row("Verification", "(none recorded in result.verification)"))
        return lines

    method = verif.get("method")
    if method:
        lines.append(_row("Verify method", method))
    checked = verif.get("samples_checked")
    population = verif.get("population_blocks")
    if checked is not None:
        detail = _row("Readbacks checked", checked)
        if population is not None:
            detail += f" of {population}"
        lines.append(detail)
    strategy = verif.get("sample_strategy")
    if strategy:
        lines.append(_row("Sample strategy", strategy))

    if "residual_fraction_upper_bound_ppm" in verif:
        ppm = verif["residual_fraction_upper_bound_ppm"]
        confidence = verif.get("confidence_percent")
        try:
            percent = f"{ppm / 10000:.4f}% of the medium"
        except TypeError:
            percent = str(ppm)
        suffix = f" at {confidence}% confidence" if confidence is not None else ""
        lines.append(_row("Residual bound", f"{percent}{suffix}"))
    else:
        lines.append(
            _row(
                "Residual bound",
                "NONE RECORDED -- this was not a statistical sample, so no "
                "bound applies (this is NOT a claim of 0)",
            )
        )

    attestation = verif.get("attestation")
    if attestation:
        lines.append(_row("Attestation", attestation))
    return lines


def verify_certificate_file(cert_path: Path, key_path: Path | None = None) -> int:
    """Verify an s0 certificate file and print a human-readable forensic summary."""
    if not cert_path.is_file():
        print(f"[ERROR] Certificate file not found: {cert_path}", file=sys.stderr)
        return 2

    try:
        with open(cert_path, encoding="utf-8") as f:
            cert_data = json.load(f)
    except Exception as exc:
        print(f"[ERROR] Failed to parse JSON: {exc}", file=sys.stderr)
        return 1
    if not isinstance(cert_data, dict):
        print("[ERROR] Certificate is not a JSON object.", file=sys.stderr)
        return 1

    cert_uuid = _first(cert_data.get("cert_uuid"), cert_data.get("certificate_uuid"), "unknown")
    issuer_obj = cert_data.get("issuer") or {}
    operator = _first(issuer_obj.get("operator_id"), cert_data.get("operator"), "UNKNOWN")
    org = _first(issuer_obj.get("organization"), cert_data.get("organization"), "UNKNOWN")

    device_obj = cert_data.get("device") or {}
    wipe_obj = cert_data.get("wipe") or {}
    result_obj = cert_data.get("result") or {}
    method = _first(wipe_obj.get("method"), cert_data.get("sanitization_method"), "UNKNOWN")
    nist_category = _first(wipe_obj.get("nist_category"), cert_data.get("nist_category"), "UNKNOWN")
    timestamp = _first(wipe_obj.get("end_time"), cert_data.get("issued_at"), "UNKNOWN")

    signature = cert_data.get("signature")
    if not isinstance(signature, dict):
        signature = {}
    fingerprint = _first(
        signature.get("public_key_fingerprint"), cert_data.get("public_key_fingerprint"), "unknown"
    )

    print("╔══════════════════════════════════════════════════════════════════╗")
    print("║          s0 Forensic Certificate Verification Summary            ║")
    print("╚══════════════════════════════════════════════════════════════════╝")
    print(_row("UUID", cert_uuid))
    for line in _describe_target(device_obj, cert_data):
        print(line)
    print(_row("Method selected", method))
    print(_row("NIST tier", nist_category))
    print(_row("Result status", result_obj.get("status", "UNKNOWN")))
    print(_row("Issuer / org", f"{org} (operator: {operator})"))
    print(_row("Timestamp (UTC)", timestamp))
    print(_row("Claimed key fp", fingerprint))
    print("──────────────────────────────────────────────────────────────────")
    for line in _describe_verification(result_obj):
        print(line)

    if not signature:
        print("  ❌ STATUS: UNSIGNED (no digital signature found)")
        return 1

    resolved_key = key_path if key_path is not None else find_default_public_key()
    if resolved_key is None or not resolved_key.is_file():
        searched = ", ".join(str(p) for p in default_key_candidates()) or "(no candidate locations)"
        print("  ⚠️  STATUS: NOT VERIFIED — no trusted public key was found.")
        print(f"     Looked for: {searched}")
        print("     Pass the issuer's public key explicitly:")
        print(f"       python {Path(__file__).name} {cert_path} --key /path/to/authority_public.pem")
        return 1

    if certificate is not None and crypto is not None:
        try:
            pubkey = crypto.load_public_pem(resolved_key)
            ok, reason = certificate.verify_certificate(cert_data, [pubkey])
        except Exception as err:  # noqa: BLE001
            print(f"  ❌ Verification error: {err}")
            return 1
        if ok:
            if crypto.is_demo_key(pubkey):
                print("  ⚠️  STATUS: VALID SIGNATURE — UNACCREDITED DEMO KEY")
                print("     This certificate was signed with the bundled demonstration key.")
                print("     DO NOT use for legal chain-of-custody or regulatory compliance.")
                print(_row("Key file", resolved_key))
                print(_row("Evidence", reason))
                return 75
            print("  ✅ STATUS: CRYPTOGRAPHICALLY VALID & TAMPER-FREE")
            print(_row("Key file", resolved_key))
            print(_row("Evidence", reason))
            return 0
        print("  ❌ STATUS: INVALID / VERIFICATION FAILED")
        print(_row("Reason", reason))
        return 1

    cli = find_s0_cli()
    if cli:
        print(f"  (the s0 package is not importable here; delegating to {cli})")
        res = subprocess.run(
            [str(cli), "verify", str(cert_path), "--key", str(resolved_key)],
            capture_output=True,
            text=True,
            check=False,
        )
        sys.stdout.write(res.stdout or "")
        sys.stderr.write(res.stderr or "")
        return res.returncode

    print("  ⚠️  STATUS: NOT VERIFIED — neither the `s0` package nor the `s0` CLI is")
    print("     available, so the signature could not be checked. This is neither a")
    print("     pass nor a fail: install s0 (`pip install s0`) or verify manually with")
    print(f"       s0 verify {cert_path} --key {resolved_key}")
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify s0 Forensic Certificate")
    parser.add_argument("certificate", type=Path, help="Path to certificate JSON")
    parser.add_argument(
        "--key",
        type=Path,
        default=None,
        help="trusted issuer public key PEM; defaults to the "
        "demonstration key in a source checkout, else "
        "~/.s0/keys/*.pem, else /etc/s0/authority_public.pem",
    )
    args = parser.parse_args()
    return verify_certificate_file(args.certificate, args.key)


if __name__ == "__main__":
    sys.exit(main())
