"""s0 Cryptographic Audit Ledger (Hash-Chained Audit Log).

Implements an immutable local append-only audit trail anchored by SHA-256 block hash chaining.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from s0 import resources

GENESIS_PREV_HASH = "0" * 64


def get_default_audit_db() -> Path:
    """Dynamically resolve audit database path, respecting S0_AUDIT_DB environment variable."""
    override = os.environ.get("S0_AUDIT_DB")
    if override:
        return Path(override)
    try:
        home = Path.home()
    except (RuntimeError, OSError):
        home = Path.cwd()
    return home / ".s0" / "s0_audit.db"


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
    certificate_json: str | None = None
    block_signature: str = ""


from s0.canonical import canonicalize


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
    payload_for_hash = canonicalize(
        {
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
        }
    )
    return hashlib.sha256(payload_for_hash).hexdigest()


#: How long to wait for another writer's lock. SQLite's default is 5s and it
#: reports "database is locked" the moment a writer holds the lock; a forensic run
#: may be appending from a UI, a CLI and a scheduled export at once.
BUSY_TIMEOUT_MS = 30_000


def get_db_connection(db_path: str | Path | None = None) -> sqlite3.Connection:
    """Open the ledger, creating it 0600 and waiting rather than failing on a lock.

    Two things were wrong here.

    sqlite3.connect creates the file with the process umask -- 0644 on a typical
    system, so world-readable. This file is the chain of custody: it records what
    was wiped, by whom, with signatures. Anyone who can write it can forge history,
    and anyone who can read it learns which evidence a user destroyed. The mode is
    enforced here rather than left to callers, because a permission a caller has to
    remember is a permission the next caller forgets, and the chmod is unconditional
    so a ledger left wide by an older version is narrowed too.

    And there was no busy_timeout, so a concurrent append failed immediately instead
    of waiting for the other writer to finish.
    """
    if db_path is None:
        db_path = get_default_audit_db()
    path = Path(db_path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)

    # sqlite3.connect takes no mode, so create the file ourselves at 0600 to close
    # the window in which it exists world-readable.
    if not path.exists():
        try:
            os.close(os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
        except FileExistsError:
            pass  # another process won; it set the mode
        except OSError:
            pass  # let connect() surface the real problem

    conn = sqlite3.connect(str(path), timeout=BUSY_TIMEOUT_MS / 1000)
    conn.row_factory = sqlite3.Row
    conn.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return conn


def _write_checkpoint(db_path: str | Path, tip_index: int, tip_hash: str, updated_at: str) -> None:
    """Write the chain checkpoint beside the ledger, 0600.

    This sidecar carries the same chain state as the ledger -- the tip index and
    hash -- so it gets the same mode. It was created with the process umask (0664
    on a typical system) while the database next to it was 0600, which meant
    tightening the ledger left a readable copy of its state beside it.

    Best-effort by design: a checkpoint that cannot be written must not fail an
    erase that has already happened. The ledger itself remains authoritative.
    """
    cp_file = Path(db_path).parent / (Path(db_path).stem + ".checkpoint.json")
    try:
        fd = os.open(str(cp_file), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        with open(fd, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"tip_index": tip_index, "tip_hash": tip_hash, "updated_at": updated_at}))
        os.chmod(cp_file, 0o600)  # mode is ignored for an existing file
    except OSError:
        pass


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

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS chain_checkpoint (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                tip_index INTEGER NOT NULL,
                tip_hash TEXT NOT NULL,
                updated_at TEXT NOT NULL
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
            conn.execute(
                """
                INSERT OR REPLACE INTO chain_checkpoint (id, tip_index, tip_hash, updated_at)
                VALUES (1, ?, ?, ?);
                """,
                (0, genesis_hash, genesis_time),
            )
            _write_checkpoint(db_path, 0, genesis_hash, genesis_time)
    conn.close()
    return Path(db_path)


def record_audit_event(
    certificate: dict[str, Any],
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
        # BEGIN IMMEDIATE takes the write lock *before* the tip is read, which makes
        # the read and the insert one atomic step. Reading the tip first is a race:
        # two processes both read tip N, both compute index N+1 against the same
        # prev_hash, and both try to insert. One wins; the loser collides on the
        # primary key or appends a second block at an index already taken, and a
        # duplicated index in a hash chain is exactly the artefact the ledger exists
        # to make impossible.
        #
        # A deferred transaction does not help: it upgrades to a write lock at the
        # first write, which is after this SELECT -- the whole window.
        conn.execute("BEGIN IMMEDIATE")
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
        try:
            from s0 import crypto
            from s0.canonical import canonicalize
            from s0.certificate import payload_of

            payload_hash = crypto.payload_sha256(canonicalize(payload_of(certificate))).replace("sha256:", "")
        except Exception:
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
        unsigned_reason = ""
        key_to_use = private_key
        if key_to_use is None:
            # Fall back to the packaged demo key if available.
            try:
                key_to_use = resources.demo_private_key()
            except FileNotFoundError:
                pass

        if key_to_use is not None:
            try:
                if isinstance(key_to_use, (str, Path)):
                    priv_obj = crypto.load_private_pem(key_to_use)
                else:
                    priv_obj = key_to_use
                block_signature = crypto.sign_payload(priv_obj, block_hash.encode("utf-8"))
            except Exception as exc:
                # Previously this swallowed the failure and recorded the block with
                # an empty signature. A block that cannot be signed is not evidence:
                # it asserts a chain entry nobody can attribute to an issuer, and it
                # sits in the same ledger as properly signed ones where nothing
                # marks the difference. Recording it unsigned is worse than refusing
                # it, because the erase has already happened and refusing loses the
                # record of that too -- so the failure is named in the block, which
                # makes it auditable rather than invisible.
                block_signature = ""
                unsigned_reason = f"{type(exc).__name__}: {exc}"

        if unsigned_reason:
            # Recorded in the certificate that is stored *inside* the block, so the
            # gap travels with the evidence. A verifier reading `block_signature`
            # sees the empty string; one reading the certificate sees why.
            notes = certificate.get("notes")
            certificate = dict(certificate)
            certificate["notes"] = list(notes or []) + [
                f"UNSIGNED LEDGER BLOCK: the issuer key could not sign this entry "
                f"({unsigned_reason}). The erase it records did happen; the block's "
                f"attribution could not be cryptographically established."
            ]

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
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS chain_checkpoint (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                tip_index INTEGER NOT NULL,
                tip_hash TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """
        )
        conn.execute(
            """
            INSERT OR REPLACE INTO chain_checkpoint (id, tip_index, tip_hash, updated_at)
            VALUES (1, ?, ?, ?);
            """,
            (new_index, block_hash, timestamp),
        )

    conn.close()

    _write_checkpoint(db_path, new_index, block_hash, timestamp)

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
    operation_type: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[AuditBlock]:
    """Retrieve audit blocks from the ledger with optional filtering and pagination.

    Reading does not create the ledger. `init_audit_db` used to run here, so simply
    *listing* blocks on a machine that had never erased anything created an empty
    chain of custody -- and under `--dry-run`, which promises to write nothing, it
    wrote a database and a checkpoint. Creating the ledger on a read also means
    "the ledger exists" stops meaning "something was recorded", which is the one
    fact a verifier needs it to mean.

    A missing ledger is an empty ledger.
    """
    if db_path is None:
        db_path = get_default_audit_db()
    if not Path(db_path).exists():
        return []
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
