"""TrustWipe Blockchain Audit Chain Verification Engine."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from trustwipe_core.certificate import verify_certificate
from trustwipe_core.crypto import load_public_pem

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
    details: List[str] = None


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

        # Optional: verify embedded certificate Ed25519 signature
        if trusted_public_keys and b["certificate_json"] and b["operation_type"] != "GENESIS":
            try:
                cert_data = json.loads(b["certificate_json"])
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
