"""s0 Blockchain Audit Chain Verification Engine."""

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
    get_db_connection,
    init_audit_db,
)


@dataclass
class ChainAuditReport:
    is_valid: bool
    total_blocks_verified: int
    broken_block_index: Optional[int] = None
    reason: str = "Audit ledger is continuous, unbroken, and mathematically valid."
    details: List[str] = field(default_factory=list)


def get_default_trusted_keys() -> List:
    """Retrieve default trusted issuer public keys if available in standard locations."""
    keys = []
    for cand in [
        Path(__file__).resolve().parents[4] / "core" / "keys" / "demo_issuer_public.pem",
        Path(__file__).resolve().parents[3] / "core" / "keys" / "demo_issuer_public.pem",
        Path("core/keys/demo_issuer_public.pem"),
    ]:
        if cand.is_file():
            try:
                keys.append(load_public_pem(cand))
                break
            except Exception:
                pass
    return keys


def verify_audit_ledger(
    db_path: str | Path = DEFAULT_AUDIT_DB,
    trusted_public_keys: Optional[List] = None,
) -> ChainAuditReport:
    """Verify 100% cryptographic continuity of the blockchain audit ledger."""
    init_audit_db(db_path)
    conn = get_db_connection(db_path)
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

    keys_to_verify = list(trusted_public_keys) if trusted_public_keys else get_default_trusted_keys()
    expected_prev = GENESIS_PREV_HASH
    details = []

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

        # Recompute block hash
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
                if trusted_public_keys is not None:
                    matching_keys = [k for k in trusted_public_keys if not claimed_fp or crypto.public_key_fingerprint(k) == claimed_fp]
                    if not matching_keys:
                        matching_keys = list(trusted_public_keys)
                    sig_valid = any(crypto.verify_payload(k, b["block_hash"].encode("utf-8"), block_sig) for k in matching_keys)
                    if not sig_valid:
                        return ChainAuditReport(
                            is_valid=False,
                            total_blocks_verified=idx,
                            broken_block_index=block_idx,
                            reason=f"Block signature tampering detected in block #{block_idx}: block_signature does not match block_hash under trusted public keys.",
                            details=details,
                        )
                else:
                    default_keys = get_default_trusted_keys()
                    matching_default = [k for k in default_keys if crypto.public_key_fingerprint(k) == claimed_fp]
                    if matching_default:
                        sig_valid = any(crypto.verify_payload(k, b["block_hash"].encode("utf-8"), block_sig) for k in matching_default)
                        if not sig_valid:
                            return ChainAuditReport(
                                is_valid=False,
                                total_blocks_verified=idx,
                                broken_block_index=block_idx,
                                reason=f"Block signature tampering detected in block #{block_idx}: block_signature does not match recomputed block_hash for authority key.",
                                details=details,
                            )
            elif trusted_public_keys and b["certificate_json"]:
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

        # Verify embedded certificate structure and payload integrity
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

                if trusted_public_keys:
                    ok, reason = verify_certificate(cert_data, trusted_public_keys)
                    if not ok:
                        return ChainAuditReport(
                            is_valid=False,
                            total_blocks_verified=idx,
                            broken_block_index=block_idx,
                            reason=f"Certificate signature invalid in block #{block_idx}: {reason}",
                            details=details,
                        )
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

    return ChainAuditReport(
        is_valid=True,
        total_blocks_verified=len(blocks),
        reason=f"Blockchain audit chain verified successfully across {len(blocks)} blocks.",
        details=details,
    )
