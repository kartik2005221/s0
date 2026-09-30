"""Wipe-certificate build / validate / sign / verify.

Schema: src/s0/data/cert_schema.json (v1.0.0). Canonicalization + signing contract:
core/CANONICAL_JSON.md. Validation here is a hand-rolled mirror of the JSON
Schema so the package stays dependency-light; core/tests keep it honest against
the schema file.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any

from . import crypto
from .canonical import canonicalize

SCHEMA_VERSION = "1.0.0"

WIPE_METHODS = {
    "OVERWRITE_ZERO_1PASS",
    "SHRED_RANDOM_NPASS",
    "BLKDISCARD",
    "ATA_SECURE_ERASE",
    "ATA_SECURE_ERASE_ENHANCED",
    "NVME_FORMAT_USER_DATA_ERASE",
    "NVME_FORMAT_CRYPTO_ERASE",
    "NVME_SANITIZE_BLOCK_ERASE",
    "NVME_SANITIZE_CRYPTO_ERASE",
    "WINDOWS_CLEAN_ALL",
    "WINDOWS_CIPHER_W",
    "WINDOWS_SED_KEY_DESTROY",
    "ANDROID_FACTORY_RESET_FBE",
    "ANDROID_USER_SPACE_OVERWRITE",
    "FORENSIC_CARVING",
    "FORENSIC_IMAGING",
    "FORENSIC_CLONING",
    "ATA_SANITIZE_BLOCK_ERASE",
    "ATA_SANITIZE_CRYPTO_SCRAMBLE",
    "ATA_SANITIZE_OVERWRITE",
    "NVME_SANITIZE_OVERWRITE",
    "NVME_SANITIZE_PURGE_REQUIRED",
    "SCSI_SANITIZE_BLOCK_ERASE",
    "SCSI_SANITIZE_CRYPTOGRAPHIC_ERASE",
    "SCSI_SANITIZE_OVERWRITE",
    "SCSI_UNMAP",
    "LUKS_KEYSLOT_ERASE",
    "OPAL_CRYPTO_ERASE",
    "FDE_KEY_DESTROY",
    "VENDOR_SECURE_ERASE",
    "RAID_CONTROLLER_PASSTHROUGH_SANITIZE",
}

NIST_CATEGORIES = {"Clear", "Purge", "Destroy", "N/A"}
PATTERNS = {"zero", "random", "firmware", "key_destruction", "carving", "imaging",
            "cloning", "not_applicable"}

# Permitted NIST tier per method — mirrors core/standards/nist_800_88_mapping.md §3.
# Enforced by validate() so a certificate cannot claim a tier its method never earned.
# BLKDISCARD may claim Purge ONLY with deterministic-TRIM justification in notes
# (validated as a notes-content check below).
METHOD_TIERS = {
    "OVERWRITE_ZERO_1PASS": {"Clear"},
    "SHRED_RANDOM_NPASS": {"Clear"},
    "BLKDISCARD": {"Clear", "Purge"},
    "ATA_SECURE_ERASE": {"Purge"},
    "ATA_SECURE_ERASE_ENHANCED": {"Purge"},
    "NVME_FORMAT_USER_DATA_ERASE": {"Purge"},
    "NVME_FORMAT_CRYPTO_ERASE": {"Purge"},
    "NVME_SANITIZE_BLOCK_ERASE": {"Purge"},
    "NVME_SANITIZE_CRYPTO_ERASE": {"Purge"},
    "WINDOWS_CLEAN_ALL": {"Clear"},
    "WINDOWS_CIPHER_W": {"Clear"},
    "WINDOWS_SED_KEY_DESTROY": {"Purge"},
    "ANDROID_FACTORY_RESET_FBE": {"Purge"},
    "ANDROID_USER_SPACE_OVERWRITE": {"Clear"},
    "FORENSIC_CARVING": {"N/A"},
    "FORENSIC_IMAGING": {"N/A"},
    "FORENSIC_CLONING": {"N/A"},
    # ATA Device Configuration Overlay / Sanitize feature set (ATA-4/ACS-4 opcode 0xB4)
    "ATA_SANITIZE_BLOCK_ERASE": {"Purge"},
    "ATA_SANITIZE_CRYPTO_SCRAMBLE": {"Purge"},
    "ATA_SANITIZE_OVERWRITE": {"Purge"},
    # NVMe Sanitize is admin opcode 0x84 (NOT 0xF4, which does not exist)
    "NVME_SANITIZE_OVERWRITE": {"Purge"},
    "NVME_SANITIZE_PURGE_REQUIRED": {"Purge"},
    # SCSI SANITIZE is opcode 0x48
    "SCSI_SANITIZE_BLOCK_ERASE": {"Purge"},
    "SCSI_SANITIZE_CRYPTOGRAPHIC_ERASE": {"Purge"},
    "SCSI_SANITIZE_OVERWRITE": {"Purge"},
    "SCSI_UNMAP": {"Clear"},
    # Full-disk / volume encryption key destruction
    "LUKS_KEYSLOT_ERASE": {"Purge"},
    "OPAL_CRYPTO_ERASE": {"Purge"},
    "FDE_KEY_DESTROY": {"Purge"},
    "VENDOR_SECURE_ERASE": {"Purge"},
    "RAID_CONTROLLER_PASSTHROUGH_SANITIZE": {"Purge"},
}
STATUSES = {"success", "failure", "partial", "reset_triggered"}
DEVICE_TYPES = {"internal_disk", "removable_disk", "image_file", "phone",
                "file", "file_set", "folder", "folder_tree",
                "logical_volume", "virtual_disk", "raid_logical_volume", "cloud_volume"}
STORAGE_TYPES = {"HDD", "SSD", "NVMe", "eMMC", "UFS", "SDCARD", "IMAGE_FILE", "UNKNOWN",
                 "file", "folder_tree", "LOGICAL_VOLUME", "VIRTUAL_DISK",
                 "RAID_LOGICAL_VOLUME", "CLOUD_BLOCK"}
PLATFORMS = {"linux", "windows", "macos", "android"}

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_DATETIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_FINGERPRINT_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")


class CertificateError(ValueError):
    """Structurally invalid certificate, or signing input problem."""


# --------------------------------------------------------------------------- #
# time helpers — integer-second UTC ISO 8601, cross-language friendly
# --------------------------------------------------------------------------- #

def now_utc() -> str:
    return format_utc(datetime.now(timezone.utc))


def format_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------- #
# validation
# --------------------------------------------------------------------------- #

def _walk_floats(node: Any, path: str, *, _depth: int = 0) -> list[str]:
    """Find any float anywhere in the payload — schema v1 is integers-only."""
    if _depth > 64:
        return [f"{path}: structure exceeds maximum nesting depth (64 levels)"]
    errors: list[str] = []
    if isinstance(node, bool) or node is None:
        return errors
    if isinstance(node, float):
        errors.append(f"{path}: float values are forbidden in schema v1")
    elif isinstance(node, dict):
        for k, v in node.items():
            errors.extend(_walk_floats(v, f"{path}.{k}", _depth=_depth + 1))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            errors.extend(_walk_floats(v, f"{path}[{i}]", _depth=_depth + 1))
    return errors


def validate(cert: dict, *, require_signature: bool = True) -> list[str]:
    """Return a list of human-readable validation errors (empty == valid).

    Mirrors src/s0/data/cert_schema.json without pulling in a jsonschema dependency.
    """
    errs: list[str] = []

    def need(cond: bool, msg: str) -> None:
        if not cond:
            errs.append(msg)

    def check_obj(obj: dict, name: str, required: set, allowed: set) -> None:
        missing = required - obj.keys()
        if missing:
            errs.append(f"{name}: missing {sorted(missing)}")
        unknown = obj.keys() - allowed
        if unknown:
            errs.append(f"{name}: unexpected fields {sorted(unknown)}")

    need(isinstance(cert, dict), "certificate must be a JSON object")
    if not isinstance(cert, dict):
        return errs

    check_obj(cert, "", {"schema_version", "cert_uuid", "issued_at", "issuer", "tool",
                         "device", "wipe", "result"},
              {"schema_version", "cert_uuid", "issued_at", "issuer", "tool", "device",
               "wipe", "result", "notes", "signature"})
    need(cert.get("schema_version") == SCHEMA_VERSION,
         f"schema_version must be {SCHEMA_VERSION!r}")
    need(bool(_UUID_RE.match(str(cert.get("cert_uuid", "")))), "cert_uuid: not a lowercase UUID")
    need(bool(_DATETIME_RE.match(str(cert.get("issued_at", "")))),
         "issued_at: must be ISO 8601 UTC 'YYYY-MM-DDTHH:MM:SSZ'")

    issuer = cert.get("issuer") or {}
    if isinstance(issuer, dict):
        check_obj(issuer, "issuer", {"organization", "operator_id"}, {"organization", "operator_id"})
        for f in ("organization", "operator_id"):
            need(isinstance(issuer.get(f), str) and issuer.get(f), f"issuer.{f}: non-empty string required")

    tool = cert.get("tool") or {}
    if isinstance(tool, dict):
        check_obj(tool, "tool", {"name", "version", "platform"}, {"name", "version", "platform", "os_kernel"})
        need(tool.get("platform") in PLATFORMS, "tool.platform: invalid")

    device = cert.get("device") or {}
    if isinstance(device, dict):
        check_obj(device, "device",
                  {"device_id", "device_type", "storage_type", "capacity_bytes"},
                  {"device_id", "device_type", "storage_type", "model", "serial_number",
                   "capacity_bytes", "sector_size"})
        need(device.get("device_type") in DEVICE_TYPES, "device.device_type: invalid")
        need(device.get("storage_type") in STORAGE_TYPES, "device.storage_type: invalid")
        cap = device.get("capacity_bytes")
        need(cap is None or (isinstance(cap, int) and not isinstance(cap, bool) and cap >= 0),
             "device.capacity_bytes: must be a non-negative integer")
        sector = device.get("sector_size")
        need(sector is None or (isinstance(sector, int) and not isinstance(sector, bool) and sector >= 1),
             "device.sector_size: must be a positive integer (minimum 1)")

    wipe = cert.get("wipe") or {}
    if isinstance(wipe, dict):
        check_obj(wipe, "wipe",
                  {"method", "nist_category", "start_time", "end_time", "bytes_processed"},
                  {"method", "nist_category", "passes", "pattern", "start_time", "end_time",
                   "bytes_processed"})
        need(wipe.get("method") in WIPE_METHODS, "wipe.method: invalid")
        need(wipe.get("nist_category") in NIST_CATEGORIES, "wipe.nist_category: invalid")
        if wipe.get("method") in WIPE_METHODS and wipe.get("nist_category") in NIST_CATEGORIES:
            need(wipe["nist_category"] in METHOD_TIERS[wipe["method"]],
                 f"wipe.nist_category {wipe['nist_category']!r} exceeds the tier permitted "
                 f"for method {wipe['method']!r} per the NIST mapping registry")
            if wipe["method"] == "BLKDISCARD" and wipe["nist_category"] == "Purge":
                notes_text = " ".join(cert.get("notes", []))
                need("deterministic" in notes_text.lower() or "drat" in notes_text.lower()
                     or "rzat" in notes_text.lower(),
                     "BLKDISCARD claiming Purge requires documented deterministic-read-"
                     "after-discard justification in notes")
        p = wipe.get("pattern")
        need(p is None or p in PATTERNS, "wipe.pattern: invalid")
        passes = wipe.get("passes")
        need(passes is None or (isinstance(passes, int) and not isinstance(passes, bool) and passes >= 1),
             "wipe.passes: must be an integer >= 1")
        for f in ("start_time", "end_time"):
            need(bool(_DATETIME_RE.match(str(wipe.get(f, "")))), f"wipe.{f}: must be 'YYYY-MM-DDTHH:MM:SSZ'")
        bp = wipe.get("bytes_processed")
        need(isinstance(bp, int) and not isinstance(bp, bool) and bp >= 0,
             "wipe.bytes_processed: non-negative integer required")

    result = cert.get("result") or {}
    if isinstance(result, dict):
        check_obj(result, "result", {"status"}, {"status", "errors", "verification"})
        need(result.get("status") in STATUSES, "result.status: invalid")
        errors_list = result.get("errors")
        need(errors_list is None or (isinstance(errors_list, list)
                                     and all(isinstance(e, str) for e in errors_list)),
             "result.errors: array of strings")
        verif = result.get("verification")
        if verif is not None:
            if not isinstance(verif, dict):
                errs.append("result.verification: must be an object")
            else:
                check_obj(verif, "result.verification", set(),
                          {"method", "samples_checked", "sample_bytes_each",
                           "all_samples_match_wipe_pattern", "planted_pattern_hits_after",
                           "pre_wipe_sample_hash", "sample_strategy", "population_blocks",
                           "confidence_percent", "residual_fraction_upper_bound_ppm",
                           "attestation", "smart_delta"})
                for f in ("samples_checked", "sample_bytes_each", "planted_pattern_hits_after",
                          "population_blocks", "confidence_percent",
                          "residual_fraction_upper_bound_ppm"):
                    v = verif.get(f)
                    need(v is None or (isinstance(v, int) and not isinstance(v, bool) and v >= 0),
                         f"result.verification.{f}: non-negative integer")
                cp = verif.get("confidence_percent")
                need(cp is None or cp <= 100,
                     "result.verification.confidence_percent: must be 0-100")
                for f in ("sample_strategy", "attestation"):
                    v = verif.get(f)
                    need(v is None or isinstance(v, str),
                         f"result.verification.{f}: string")
                sd = verif.get("smart_delta")
                need(sd is None or isinstance(sd, dict),
                     "result.verification.smart_delta: object")
                asm = verif.get("all_samples_match_wipe_pattern")
                need(asm is None or isinstance(asm, bool),
                     "result.verification.all_samples_match_wipe_pattern: boolean")

    notes = cert.get("notes")
    need(notes is None or (isinstance(notes, list) and all(isinstance(n, str) for n in notes)),
         "notes: array of strings")

    sig = cert.get("signature")
    if require_signature:
        need(isinstance(sig, dict), "signature: required object")
        if isinstance(sig, dict):
            check_obj(sig, "signature",
                      {"algorithm", "public_key_fingerprint", "signature_base64url"},
                      {"algorithm", "public_key_fingerprint", "signature_base64url",
                       "signed_payload_hash"})
            need(sig.get("algorithm") == "Ed25519", "signature.algorithm: only Ed25519 supported")
            need(bool(_FINGERPRINT_RE.match(str(sig.get("public_key_fingerprint", "")))),
                 "signature.public_key_fingerprint: must match 'sha256:<64 hex>'")
            need(bool(_B64URL_RE.match(str(sig.get("signature_base64url", "").rstrip("=")))) and
                 len(sig.get("signature_base64url", "")) >= 80,
                 "signature.signature_base64url: not a plausible base64url signature")
            sph = sig.get("signed_payload_hash")
            need(sph is None or bool(_FINGERPRINT_RE.match(str(sph))),
                 "signature.signed_payload_hash: must match 'sha256:<64 hex>'")

    # Schema-wide rule: no floats, anywhere (see CANONICAL_JSON.md rule 5).
    try:
        errs.extend(_walk_floats({k: v for k, v in cert.items() if k != "signature"}, "$"))
    except RecursionError:
        errs.append("structure exceeds recursion limit — likely adversarial input")

    return errs


# --------------------------------------------------------------------------- #
# build / sign / verify
# --------------------------------------------------------------------------- #

def new_cert_uuid() -> str:
    return str(uuid.uuid4())


def build_certificate(
    *,
    organization: str,
    operator_id: str,
    tool_name: str,
    tool_version: str,
    platform: str,
    device_id: str,
    device_type: str,
    storage_type: str,
    method: str,
    nist_category: str,
    start_time: str,
    end_time: str,
    bytes_processed: int,
    capacity_bytes: int,
    model: str | None = None,
    serial_number: str | None = None,
    sector_size: int | None = None,
    pattern: str | None = None,
    passes: int | None = None,
    status: str = "success",
    errors: list[str] | None = None,
    verification: dict | None = None,
    notes: list[str] | None = None,
    os_kernel: str | None = None,
    issued_at: str | None = None,
) -> dict:
    """Build an unsigned certificate with sane defaults; validates on the way out."""
    device: dict = {
        "device_id": device_id,
        "device_type": device_type,
        "storage_type": storage_type,
        "capacity_bytes": capacity_bytes,
    }
    for k, v in (("model", model), ("serial_number", serial_number), ("sector_size", sector_size)):
        if v is not None:
            device[k] = v

    wipe: dict = {
        "method": method,
        "nist_category": nist_category,
        "start_time": start_time,
        "end_time": end_time,
        "bytes_processed": bytes_processed,
    }
    if passes is not None:
        wipe["passes"] = passes
    if pattern is not None:
        wipe["pattern"] = pattern

    result: dict = {"status": status}
    if errors:
        result["errors"] = errors
    if verification is not None:
        result["verification"] = verification

    cert: dict = {
        "schema_version": SCHEMA_VERSION,
        "cert_uuid": new_cert_uuid(),
        "issued_at": issued_at or now_utc(),
        "issuer": {"organization": organization, "operator_id": operator_id},
        "tool": {"name": tool_name, "version": tool_version, "platform": platform},
        "device": device,
        "wipe": wipe,
        "result": result,
    }
    if os_kernel:
        cert["tool"]["os_kernel"] = os_kernel
    if notes:
        cert["notes"] = list(notes)

    problems = validate(cert, require_signature=False)
    if problems:
        raise CertificateError("; ".join(problems))
    return cert


def payload_of(cert: dict) -> dict:
    """The signed payload: everything except the 'signature' member."""
    return {k: v for k, v in cert.items() if k != "signature"}


def sign_certificate(cert: dict, private_key) -> dict:
    """Validate, then attach an Ed25519 signature over the canonical payload."""
    problems = validate(cert, require_signature=False)
    if problems:
        raise CertificateError("refusing to sign invalid certificate: " + "; ".join(problems))
    payload = canonicalize(payload_of(cert))
    public_key = private_key.public_key()
    signed = dict(cert)
    signed["signature"] = {
        "algorithm": "Ed25519",
        "public_key_fingerprint": crypto.public_key_fingerprint(public_key),
        "signature_base64url": crypto.sign_payload(private_key, payload),
        "signed_payload_hash": crypto.payload_sha256(payload),
    }
    return signed


def verify_certificate(cert: dict, trusted_keys) -> tuple[bool, str]:
    """Verify *cert* against one or more pinned public keys.

    Returns (ok, reason). Reasons are written for display in the portal/CLI:
    they state what was checked and what failed, never more than that.
    """
    trusted = list(trusted_keys)
    if not trusted:
        return False, "no trusted public keys supplied"
    problems = validate(cert, require_signature=True)
    if problems:
        return False, "invalid certificate structure: " + "; ".join(problems)

    try:
        payload = canonicalize(payload_of(cert))
    except Exception as exc:  # e.g. a float smuggled into a field we didn't type-check
        return False, f"cannot compute canonical payload: {exc}"

    claimed_fp = cert["signature"]["public_key_fingerprint"]
    sig = cert["signature"]["signature_base64url"]

    matching = [k for k in trusted if crypto.public_key_fingerprint(k) == claimed_fp]
    if not matching:
        return False, (
            f"unknown issuer key fingerprint {claimed_fp} — certificate was not "
            f"issued by any pinned authority"
        )
    for key in matching:
        if crypto.verify_payload(key, payload, sig):
            actual_payload_hash = crypto.payload_sha256(payload)
            claimed_payload_hash = cert.get("signature", {}).get("signed_payload_hash")
            if claimed_payload_hash and claimed_payload_hash != actual_payload_hash:
                return False, (
                    f"signed_payload_hash mismatch: certificate claims {claimed_payload_hash} "
                    f"but recomputed payload hash is {actual_payload_hash}"
                )
            return True, (
                f"valid Ed25519 signature from pinned key {claimed_fp}; "
                f"payload sha256 {actual_payload_hash}"
            )
    return False, (
        "signature does NOT match payload — the certificate content has been "
        "modified after signing, or the signature is corrupt"
    )
