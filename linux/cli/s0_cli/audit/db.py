"""s0 Cryptographic Audit Ledger (Hash-Chained Audit Log).

Implements an immutable local append-only audit trail anchored by SHA-256 block hash chaining.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from s0_core import crypto


GENESIS_PREV_HASH = "0" * 64


def get_default_audit_db() -> Path:
    """Dynamically resolve audit database path, respecting S0_AUDIT_DB environment variable."""
    return Path(os.environ.get("S0_AUDIT_DB", str(Path.home() / ".s0" / "s0_audit.db")))


DEFAULT_AUDIT_DB = get_default_audit_db()



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
    block_signature: str = ""


from s0_core.canonical import canonicalize


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
    """Compute deterministic SHA-256 block hash chaining all transaction fields via Canonical JSON."""
    payload_for_hash = canonicalize({
        "block_index": block_index,
        "timestamp": timestamp,
        "operation_type": operation_type,
        "target_id": target_id,
        "operator_id": operator_id,
        "organization": organization,
        "cert_uuid": cert_uuid,
        "payload_hash": payload_hash,
        "signature": signature,
        "prev_hash": prev_hash,
    })
    return hashlib.sha256(payload_for_hash).hexdigest()


def compute_legacy_block_hash(
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
    """Legacy pipe-delimited block hash for backward compatibility with older ledgers."""
    content = f"{block_index}|{timestamp}|{operation_type}|{target_id}|{operator_id}|{organization}|{cert_uuid}|{payload_hash}|{signature}|{prev_hash}"
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def get_db_connection(db_path: str | Path | None = None) -> sqlite3.Connection:
    if db_path is None:
        db_path = get_default_audit_db()
    path = Path(db_path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    return conn


def init_audit_db(db_path: str | Path | None = None) -> Path:
    """Initialize audit database schema and insert Genesis block if empty."""
    if db_path is None:
        db_path = get_default_audit_db()
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
                certificate_json TEXT,
                block_signature TEXT DEFAULT '',
                UNIQUE(cert_uuid, operation_type)
            );
            """
        )

        cols = [col["name"] for col in conn.execute("PRAGMA table_info(audit_blocks)").fetchall()]
        if "block_signature" not in cols:
            conn.execute("ALTER TABLE audit_blocks ADD COLUMN block_signature TEXT DEFAULT ''")

        # Check if genesis block exists
        cur = conn.execute("SELECT COUNT(*) as count FROM audit_blocks")
        if cur.fetchone()["count"] == 0:
            genesis_time = "2026-01-01T00:00:00Z"
            genesis_hash = compute_block_hash(
                0,
                genesis_time,
                "GENESIS",
                "S0-SYSTEM",
                "system-root",
                "Forensic Sanitization Authority",
                "00000000-0000-0000-0000-000000000000",
                "0" * 64,
                "GENESIS_BLOCK_SIGNATURE",
                GENESIS_PREV_HASH,
            )
            conn.execute(
                """
                INSERT INTO audit_blocks (
                    block_index, timestamp, operation_type, target_id, operator_id,
                    organization, cert_uuid, payload_hash, signature, prev_hash, block_hash, certificate_json, block_signature
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    0,
                    genesis_time,
                    "GENESIS",
                    "S0-SYSTEM",
                    "system-root",
                    "Forensic Sanitization Authority",
                    "00000000-0000-0000-0000-000000000000",
                    "0" * 64,
                    "GENESIS_BLOCK_SIGNATURE",
                    GENESIS_PREV_HASH,
                    genesis_hash,
                    json.dumps({"info": "s0 Cryptographic Audit Ledger Genesis Block"}),
                    "GENESIS_BLOCK_SIGNATURE",
                ),
            )
    conn.close()
    return Path(db_path)


def record_audit_event(
    certificate: Dict[str, Any],
    operation_type: str = "DRIVE_ERASE",
    db_path: str | Path | None = None,
    private_key: Any = None,
) -> AuditBlock:
    """Append a new verified transaction block to the hash-chained audit ledger."""
    if db_path is None:
        db_path = get_default_audit_db()
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

        block_signature = ""
        key_to_use = private_key
        if key_to_use is None:
            # Fall back to default repo demo key if available
            cand = Path(__file__).resolve().parents[4] / "core" / "keys" / "demo_issuer_private.pem"
            if cand.is_file():
                key_to_use = cand

        if key_to_use is not None:
            try:
                if isinstance(key_to_use, (str, Path)):
                    priv_obj = crypto.load_private_pem(key_to_use)
                else:
                    priv_obj = key_to_use
                block_signature = crypto.sign_payload(priv_obj, block_hash.encode("utf-8"))
            except Exception:
                block_signature = ""

        cert_json = json.dumps(certificate)

        conn.execute(
            """
            INSERT INTO audit_blocks (
                block_index, timestamp, operation_type, target_id, operator_id,
                organization, cert_uuid, payload_hash, signature, prev_hash, block_hash, certificate_json, block_signature
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
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
                block_signature,
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
        block_signature=block_signature,
    )


def list_audit_blocks(
    db_path: str | Path | None = None,
    operation_type: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> List[AuditBlock]:
    """Retrieve audit blocks from the ledger with optional filtering and pagination."""
    if db_path is None:
        db_path = get_default_audit_db()
    init_audit_db(db_path)
    conn = get_db_connection(db_path)

    query = "SELECT * FROM audit_blocks"
    params = []
    if operation_type:
        query += " WHERE operation_type = ?"
        params.append(operation_type)
    query += " ORDER BY block_index ASC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    cur = conn.execute(query, params)
    rows = cur.fetchall()
    conn.close()

    blocks = []
    for r in rows:
        keys = r.keys() if hasattr(r, "keys") else []
        block_sig = r["block_signature"] if "block_signature" in keys else ""
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
                block_signature=block_sig or "",
            )
        )
    return blocks
