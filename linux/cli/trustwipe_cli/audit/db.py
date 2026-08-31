"""TrustWipe Cryptographic Audit Ledger (Blockchain Hash-Chained Audit Log).

Theme: Blockchain & Cybersecurity (SIH26149).
Implements an immutable local append-only audit trail anchored by SHA-256 block hash chaining.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


GENESIS_PREV_HASH = "0" * 64
DEFAULT_AUDIT_DB = Path.home() / ".trustwipe" / "trustwipe_audit.db"


@dataclass
class AuditBlock:
    block_index: int
    timestamp: str
    operation_type: str  # "DRIVE_ERASE", "FILE_ERASE", "FILE_CARVE", "RECOVERY", "VERIFICATION"
    target_id: str
    operator_id: str
    organization: str
    cert_uuid: str
    payload_hash: str
    signature: str
    prev_hash: str
    block_hash: str
    certificate_json: Optional[str] = None


def compute_block_hash(
    block_index: int,
    timestamp: str,
    operation_type: str,
    target_id: str,
    operator_id: str,
    organization: str,
    cert_uuid: str,
    payload_hash: str,
    signature: str,
    prev_hash: str,
) -> str:
    """Compute deterministic SHA-256 block hash chaining all transaction fields."""
    content = f"{block_index}|{timestamp}|{operation_type}|{target_id}|{operator_id}|{organization}|{cert_uuid}|{payload_hash}|{signature}|{prev_hash}"
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def get_db_connection(db_path: str | Path) -> sqlite3.Connection:
    path = Path(db_path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    return conn


def init_audit_db(db_path: str | Path = DEFAULT_AUDIT_DB) -> Path:
    """Initialize audit database schema and insert Genesis block if empty."""
    conn = get_db_connection(db_path)
    with conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_blocks (
                block_index INTEGER PRIMARY KEY,
                timestamp TEXT NOT NULL,
                operation_type TEXT NOT NULL,
                target_id TEXT NOT NULL,
                operator_id TEXT NOT NULL,
                organization TEXT NOT NULL,
                cert_uuid TEXT NOT NULL,
                payload_hash TEXT NOT NULL,
                signature TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                block_hash TEXT NOT NULL,
                certificate_json TEXT
            );
            """
        )

        # Check if genesis block exists
        cur = conn.execute("SELECT COUNT(*) as count FROM audit_blocks")
        if cur.fetchone()["count"] == 0:
            genesis_time = "2026-01-01T00:00:00Z"
            genesis_hash = compute_block_hash(
                0,
                genesis_time,
                "GENESIS",
                "NTRO-SYSTEM",
                "system-root",
                "National Technical Research Organisation (NTRO)",
                "00000000-0000-0000-0000-000000000000",
                "0" * 64,
                "GENESIS_BLOCK_SIGNATURE",
                GENESIS_PREV_HASH,
            )
            conn.execute(
                """
                INSERT INTO audit_blocks (
                    block_index, timestamp, operation_type, target_id, operator_id,
                    organization, cert_uuid, payload_hash, signature, prev_hash, block_hash, certificate_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    0,
                    genesis_time,
                    "GENESIS",
                    "NTRO-SYSTEM",
                    "system-root",
                    "National Technical Research Organisation (NTRO)",
                    "00000000-0000-0000-0000-000000000000",
                    "0" * 64,
                    "GENESIS_BLOCK_SIGNATURE",
                    GENESIS_PREV_HASH,
                    genesis_hash,
                    json.dumps({"info": "TrustWipe Cryptographic Audit Ledger Genesis Block"}),
                ),
            )
    conn.close()
    return Path(db_path)


def record_audit_event(
    certificate: Dict[str, Any],
    operation_type: str = "DRIVE_ERASE",
    db_path: str | Path = DEFAULT_AUDIT_DB,
) -> AuditBlock:
    """Append a new verified transaction block to the hash-chained audit ledger."""
    init_audit_db(db_path)
    conn = get_db_connection(db_path)

    with conn:
        cur = conn.execute("SELECT * FROM audit_blocks ORDER BY block_index DESC LIMIT 1")
        tip = cur.fetchone()
        new_index = (tip["block_index"] + 1) if tip else 0
        prev_hash = tip["block_hash"] if tip else GENESIS_PREV_HASH

        timestamp = certificate.get("issued_at", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
        issuer = certificate.get("issuer", {})
        operator_id = issuer.get("operator_id", "unknown-operator")
        organization = issuer.get("organization", "unknown-org")
        target_id = certificate.get("device", {}).get("device_id", "target-unknown")
        cert_uuid = certificate.get("cert_uuid", "00000000-0000-0000-0000-000000000000")

        sig_obj = certificate.get("signature", {})
        signature = sig_obj.get("signature_base64url", "unsigned")
        payload_hash = sig_obj.get("signed_payload_hash", "sha256:" + "0" * 64).replace("sha256:", "")

        block_hash = compute_block_hash(
            new_index,
            timestamp,
            operation_type,
            target_id,
            operator_id,
            organization,
            cert_uuid,
            payload_hash,
            signature,
            prev_hash,
        )

        cert_json = json.dumps(certificate)

        conn.execute(
            """
            INSERT INTO audit_blocks (
                block_index, timestamp, operation_type, target_id, operator_id,
                organization, cert_uuid, payload_hash, signature, prev_hash, block_hash, certificate_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                new_index,
                timestamp,
                operation_type,
                target_id,
                operator_id,
                organization,
                cert_uuid,
                payload_hash,
                signature,
                prev_hash,
                block_hash,
                cert_json,
            ),
        )

    conn.close()

    return AuditBlock(
        block_index=new_index,
        timestamp=timestamp,
        operation_type=operation_type,
        target_id=target_id,
        operator_id=operator_id,
        organization=organization,
        cert_uuid=cert_uuid,
        payload_hash=payload_hash,
        signature=signature,
        prev_hash=prev_hash,
        block_hash=block_hash,
        certificate_json=cert_json,
    )


def list_audit_blocks(
    db_path: str | Path = DEFAULT_AUDIT_DB,
    operation_type: Optional[str] = None,
    limit: int = 100,
) -> List[AuditBlock]:
    """Retrieve audit blocks from the ledger with optional filtering."""
    init_audit_db(db_path)
    conn = get_db_connection(db_path)

    query = "SELECT * FROM audit_blocks"
    params = []
    if operation_type:
        query += " WHERE operation_type = ?"
        params.append(operation_type)
    query += " ORDER BY block_index ASC LIMIT ?"
    params.append(limit)

    cur = conn.execute(query, params)
    rows = cur.fetchall()
    conn.close()

    blocks = []
    for r in rows:
        blocks.append(
            AuditBlock(
                block_index=r["block_index"],
                timestamp=r["timestamp"],
                operation_type=r["operation_type"],
                target_id=r["target_id"],
                operator_id=r["operator_id"],
                organization=r["organization"],
                cert_uuid=r["cert_uuid"],
                payload_hash=r["payload_hash"],
                signature=r["signature"],
                prev_hash=r["prev_hash"],
                block_hash=r["block_hash"],
                certificate_json=r["certificate_json"],
            )
        )
    return blocks
