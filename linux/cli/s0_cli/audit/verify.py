"""s0 Hash-Chained Audit Chain Verification Engine."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from s0_core import crypto
from s0_core.certificate import (
    canonicalize,
    payload_of,
    validate,
    verify_certificate,
)
from s0_core.crypto import load_public_pem

from .db import (
    DEFAULT_AUDIT_DB,
    GENESIS_PREV_HASH,
    compute_block_hash,
    compute_legacy_block_hash,
    get_db_connection,
    get_default_audit_db,
    init_audit_db,
)


@dataclass
class ChainAuditReport:
    is_valid: bool
    total_blocks_verified: int
    broken_block_index: Optional[int] = None
    reason: str = "Audit ledger is continuous, unbroken, and mathematically valid."
    details: List[str] = field(default_factory=list)
    is_demo_signed: bool = False
    demo_key_warning: Optional[str] = None


def get_default_trusted_keys() -> List:
    """Retrieve default trusted issuer public keys if available in standard locations."""
    keys = []
    candidates = [
        Path(__file__).resolve().parents[4] / "core" / "keys" / "demo_issuer_public.pem",
        Path("core/keys/demo_issuer_public.pem"),
    ]
    s0_user_keys = Path.home() / ".s0" / "keys"
    if s0_user_keys.is_dir():
        candidates.extend(sorted(s0_user_keys.glob("*.pem")))

    seen_fps = set()
    for cand in candidates:
        if cand.is_file():
            try:
                k = load_public_pem(cand)
                fp = crypto.public_key_fingerprint(k)
                if fp not in seen_fps:
                    seen_fps.add(fp)
                    keys.append(k)
            except Exception:
                pass
    return keys


def verify_audit_ledger(
    db_path: str | Path | None = None,
    trusted_public_keys: Optional[List] = None,
) -> ChainAuditReport:
    """Verify 100% cryptographic continuity of the hash-chained audit ledger."""
    if db_path is None:
        db_path = get_default_audit_db()
    db_file = Path(db_path)
    if not db_file.is_file():
        return ChainAuditReport(
            is_valid=False,
            total_blocks_verified=0,
            reason="Audit database not found — cannot verify a non-existent ledger.",
            details=["Database file does not exist."],
        )

    conn = get_db_connection(db_path)
    cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='audit_blocks'")
    if not cur.fetchone():
        conn.close()
        return ChainAuditReport(
            is_valid=False,
            total_blocks_verified=0,
            reason="Audit ledger is empty (no genesis block found).",
            details=["Database missing audit_blocks table."],
        )

    checkpoint_tip_index = None
    checkpoint_tip_hash = None
    cur_cp = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='chain_checkpoint'")
    if cur_cp.fetchone():
        cp_row = conn.execute("SELECT * FROM chain_checkpoint WHERE id = 1").fetchone()
        if cp_row:
            checkpoint_tip_index = cp_row["tip_index"]
            checkpoint_tip_hash = cp_row["tip_hash"]

    cp_file = Path(db_path).parent / (Path(db_path).stem + ".checkpoint.json")
    if cp_file.is_file():
        try:
            cp_data = json.loads(cp_file.read_text(encoding="utf-8"))
            f_idx = cp_data.get("tip_index")
            f_hash = cp_data.get("tip_hash")
            if f_idx is not None and (checkpoint_tip_index is None or f_idx > checkpoint_tip_index):
                checkpoint_tip_index = f_idx
                checkpoint_tip_hash = f_hash
        except Exception:
            pass

    cur = conn.execute("SELECT * FROM audit_blocks ORDER BY block_index ASC")
    blocks = cur.fetchall()
    conn.close()

    if not blocks:
        return ChainAuditReport(
            is_valid=False,
            total_blocks_verified=0,
            reason="Audit ledger is empty (no genesis block found).",
            details=["Database contains 0 records."],
        )

    effective_keys = list(trusted_public_keys) if trusted_public_keys is not None else get_default_trusted_keys()
    expected_prev = GENESIS_PREV_HASH
    details = []
    is_demo_signed = False

    for idx, b in enumerate(blocks):
        block_idx = b["block_index"]
        if block_idx != idx:
            return ChainAuditReport(
                is_valid=False,
                total_blocks_verified=idx,
                broken_block_index=block_idx,
                reason=f"Block sequence gap detected: expected index {idx}, found {block_idx}.",
                details=details,
            )

        # Check prev_hash link
        if b["prev_hash"] != expected_prev:
            return ChainAuditReport(
                is_valid=False,
                total_blocks_verified=idx,
                broken_block_index=block_idx,
                reason=f"Hash chain broken at block #{block_idx}: prev_hash does not match previous block hash.",
                details=details,
            )

        # Recompute block hash (supports Canonical JSON hash and legacy pipe hash)
        computed_hash = compute_block_hash(
            b["block_index"],
            b["timestamp"],
            b["operation_type"],
            b["target_id"],
            b["operator_id"],
            b["organization"],
            b["cert_uuid"],
            b["payload_hash"],
            b["signature"],
            b["prev_hash"],
        )

        if computed_hash != b["block_hash"]:
            legacy_hash = compute_legacy_block_hash(
                b["block_index"],
                b["timestamp"],
                b["operation_type"],
                b["target_id"],
                b["operator_id"],
                b["organization"],
                b["cert_uuid"],
                b["payload_hash"],
                b["signature"],
                b["prev_hash"],
            )
            if b["block_hash"] == legacy_hash:
                computed_hash = legacy_hash
            else:
                return ChainAuditReport(
                    is_valid=False,
                    total_blocks_verified=idx,
                    broken_block_index=block_idx,
                    reason=f"Data tampering detected in block #{block_idx}: recomputed hash {computed_hash} != stored hash {b['block_hash']}.",
                    details=details,
                )

        # Verify Ed25519 block signature if present or required
        keys_in_row = b.keys() if hasattr(b, "keys") else []
        block_sig = b["block_signature"] if "block_signature" in keys_in_row else ""

        if b["operation_type"] != "GENESIS":
            claimed_fp = ""
            if b["certificate_json"]:
                try:
                    c_data = json.loads(b["certificate_json"])
                    claimed_fp = c_data.get("signature", {}).get("public_key_fingerprint", "")
                except Exception:
                    claimed_fp = ""

            if block_sig and block_sig != "GENESIS_BLOCK_SIGNATURE":
                if effective_keys:
                    matching_keys = [k for k in effective_keys if not claimed_fp or crypto.public_key_fingerprint(k) == claimed_fp]
                    if not matching_keys:
                        matching_keys = list(effective_keys)
                    validating_keys = [k for k in matching_keys if crypto.verify_payload(k, b["block_hash"].encode("utf-8"), block_sig)]
                    if not validating_keys:
                        return ChainAuditReport(
                            is_valid=False,
                            total_blocks_verified=idx,
                            broken_block_index=block_idx,
                            reason=f"Block signature tampering detected in block #{block_idx}: block_signature does not match block_hash under trusted public keys.",
                            details=details,
                        )
                    if any(crypto.is_demo_key(k) for k in validating_keys) or claimed_fp == crypto.DEMO_KEY_FINGERPRINT:
                        is_demo_signed = True
            elif effective_keys and b["certificate_json"]:
                try:
                    c_data = json.loads(b["certificate_json"])
                    if c_data.get("signature", {}).get("signature_base64url"):
                        return ChainAuditReport(
                            is_valid=False,
                            total_blocks_verified=idx,
                            broken_block_index=block_idx,
                            reason=f"Block #{block_idx} is unsigned: missing required Ed25519 block_signature for signed certificate.",
                            details=details,
                        )
                except Exception:
                    pass

        # Verify embedded certificate structure, payload integrity, and cryptographic signature
        if b["certificate_json"] and b["operation_type"] != "GENESIS":
            try:
                cert_data = json.loads(b["certificate_json"])
                problems = validate(cert_data, require_signature=True)
                if problems:
                    return ChainAuditReport(
                        is_valid=False,
                        total_blocks_verified=idx,
                        broken_block_index=block_idx,
                        reason=f"Invalid certificate structure in block #{block_idx}: {'; '.join(problems)}",
                        details=details,
                    )

                # Cryptographic payload hash verification
                payload = canonicalize(payload_of(cert_data))
                recomputed_hash = crypto.payload_sha256(payload).replace("sha256:", "")
                if b["payload_hash"] != recomputed_hash:
                    return ChainAuditReport(
                        is_valid=False,
                        total_blocks_verified=idx,
                        broken_block_index=block_idx,
                        reason=f"Payload tampering detected in block #{block_idx}: recomputed {recomputed_hash} != stored {b['payload_hash']}",
                        details=details,
                    )

                # Cryptographic signature verification using effective trusted keys
                if effective_keys:
                    ok, reason = verify_certificate(cert_data, effective_keys)
                    if not ok:
                        return ChainAuditReport(
                            is_valid=False,
                            total_blocks_verified=idx,
                            broken_block_index=block_idx,
                            reason=f"Certificate signature invalid in block #{block_idx}: {reason}",
                            details=details,
                        )
                    if claimed_fp == crypto.DEMO_KEY_FINGERPRINT:
                        is_demo_signed = True
            except Exception as e:
                return ChainAuditReport(
                    is_valid=False,
                    total_blocks_verified=idx,
                    broken_block_index=block_idx,
                    reason=f"Malformed certificate in block #{block_idx}: {e}",
                    details=details,
                )

        details.append(f"Block #{block_idx} ({b['operation_type']}): Verified (Hash: {b['block_hash'][:16]}...)")
        expected_prev = b["block_hash"]

    if checkpoint_tip_index is not None and blocks:
        actual_tip_index = blocks[-1]["block_index"]
        actual_tip_hash = blocks[-1]["block_hash"]
        if actual_tip_index < checkpoint_tip_index:
            return ChainAuditReport(
                is_valid=False,
                total_blocks_verified=len(blocks),
                broken_block_index=actual_tip_index,
                reason=f"Ledger truncation detected: checkpoint recorded tip block #{checkpoint_tip_index}, but ledger only contains {len(blocks)} blocks (tip #{actual_tip_index}).",
                details=details,
                is_demo_signed=is_demo_signed,
            )
        if actual_tip_index == checkpoint_tip_index and checkpoint_tip_hash and actual_tip_hash != checkpoint_tip_hash:
            return ChainAuditReport(
                is_valid=False,
                total_blocks_verified=len(blocks),
                broken_block_index=actual_tip_index,
                reason=f"Ledger tip mismatch: checkpoint recorded tip hash {checkpoint_tip_hash}, but ledger tip is {actual_tip_hash}.",
                details=details,
                is_demo_signed=is_demo_signed,
            )

    demo_warning = None
    if is_demo_signed:
        demo_warning = (
            "Audit chain blocks or certificates were signed with the unaccredited demonstration key. "
            "Ledger is cryptographically continuous but MUST NOT be used for legal chain-of-custody."
        )

    return ChainAuditReport(
        is_valid=True,
        total_blocks_verified=len(blocks),
        reason=f"Hash-chained audit chain verified successfully across {len(blocks)} blocks.",
        details=details,
        is_demo_signed=is_demo_signed,
        demo_key_warning=demo_warning,
    )
