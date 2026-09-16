"""Unit tests for s0 Audit Management & Blockchain Ledger."""

import json
import sqlite3
from pathlib import Path

import pytest
from s0_cli.audit import (
    init_audit_db,
    record_audit_event,
    list_audit_blocks,
    verify_audit_ledger,
)
from s0_cli.audit.db import compute_block_hash
from s0_core.certificate import build_certificate, sign_certificate
from s0_core.crypto import load_private_pem, load_public_pem


@pytest.fixture
def test_audit_db(tmp_path):
    db_file = tmp_path / "test_audit.db"
    init_audit_db(db_file)
    return db_file


@pytest.fixture
def sample_cert():
    priv = load_private_pem(Path(__file__).resolve().parents[3] / "core" / "keys" / "demo_issuer_private.pem")
    cert = build_certificate(
        organization="Audit Test Lab",
        operator_id="op-test-1",
        tool_name="s0-cli",
        tool_version="2.2.0",
        platform="linux",
        device_id="drive-12345",
        device_type="image_file",
        storage_type="IMAGE_FILE",
        method="OVERWRITE_ZERO_1PASS",
        nist_category="Clear",
        start_time="2026-08-31T07:00:00Z",
        end_time="2026-08-31T07:01:00Z",
        bytes_processed=1048576,
        capacity_bytes=1048576,
    )
    return sign_certificate(cert, priv)


def test_genesis_block_creation(test_audit_db):
    blocks = list_audit_blocks(test_audit_db)
    assert len(blocks) == 1
    assert blocks[0].block_index == 0
    assert blocks[0].operation_type == "GENESIS"

    report = verify_audit_ledger(test_audit_db)
    assert report.is_valid is True
    assert report.total_blocks_verified == 1


def test_append_audit_events_and_verify_chain(test_audit_db, sample_cert):
    # Append Drive Wipe
    b1 = record_audit_event(sample_cert, operation_type="DRIVE_ERASE", db_path=test_audit_db)
    assert b1.block_index == 1

    # Append File Wipe
    b2 = record_audit_event(sample_cert, operation_type="FILE_ERASE", db_path=test_audit_db)
    assert b2.block_index == 2
    assert b2.prev_hash == b1.block_hash

    # Append Carve
    b3 = record_audit_event(sample_cert, operation_type="FILE_CARVE", db_path=test_audit_db)
    assert b3.block_index == 3
    assert b3.prev_hash == b2.block_hash

    blocks = list_audit_blocks(test_audit_db)
    assert len(blocks) == 4  # Genesis + 3 events

    pub = load_public_pem(Path(__file__).resolve().parents[3] / "core" / "keys" / "demo_issuer_public.pem")
    report = verify_audit_ledger(test_audit_db, trusted_public_keys=[pub])
    assert report.is_valid is True
    assert report.total_blocks_verified == 4


def test_detect_data_tampering_in_ledger(test_audit_db, sample_cert):
    b1 = record_audit_event(sample_cert, operation_type="DRIVE_ERASE", db_path=test_audit_db)
    b2 = record_audit_event(sample_cert, operation_type="FILE_ERASE", db_path=test_audit_db)

    # Maliciously modify row in database (forge target_id)
    conn = sqlite3.connect(str(test_audit_db))
    conn.execute("UPDATE audit_blocks SET target_id = 'FORGED_SERIAL' WHERE block_index = 1")
    conn.commit()
    conn.close()

    report = verify_audit_ledger(test_audit_db)
    assert report.is_valid is False
    assert report.broken_block_index == 1
    assert "Data tampering detected" in report.reason


def test_detect_broken_chain_hash_link(test_audit_db, sample_cert):
    record_audit_event(sample_cert, operation_type="DRIVE_ERASE", db_path=test_audit_db)
    record_audit_event(sample_cert, operation_type="FILE_ERASE", db_path=test_audit_db)

    # Maliciously alter prev_hash of block #2
    conn = sqlite3.connect(str(test_audit_db))
    conn.execute("UPDATE audit_blocks SET prev_hash = '0000000000000000000000000000000000000000000000000000000000000000' WHERE block_index = 2")
    conn.commit()
    conn.close()

    report = verify_audit_ledger(test_audit_db)
    assert report.is_valid is False
    assert report.broken_block_index == 2
    assert "Hash chain broken" in report.reason


def test_detect_block_deletion_and_rehash(test_audit_db, sample_cert):
    """Verify that deleting an intermediate block and recomputing block_hash is detected by block signatures."""
    priv = load_private_pem(Path(__file__).resolve().parents[3] / "core" / "keys" / "demo_issuer_private.pem")
    pub = load_public_pem(Path(__file__).resolve().parents[3] / "core" / "keys" / "demo_issuer_public.pem")

    # Record two valid, signed blocks
    b1 = record_audit_event(sample_cert, operation_type="DRIVE_ERASE", db_path=test_audit_db, private_key=priv)
    b2 = record_audit_event(sample_cert, operation_type="FILE_ERASE", db_path=test_audit_db, private_key=priv)

    # Sanity check: valid prior to tampering
    rep_before = verify_audit_ledger(test_audit_db, trusted_public_keys=[pub])
    assert rep_before.is_valid is True
    assert rep_before.total_blocks_verified == 3  # Genesis + 2

    # Maliciously delete block #1 (an incriminating event)
    conn = sqlite3.connect(str(test_audit_db))
    conn.row_factory = sqlite3.Row
    conn.execute("DELETE FROM audit_blocks WHERE block_index = 1")

    # Get genesis hash
    genesis_row = conn.execute("SELECT block_hash FROM audit_blocks WHERE block_index = 0").fetchone()
    genesis_hash = genesis_row["block_hash"]

    # Read block #2
    b2_row = conn.execute("SELECT * FROM audit_blocks WHERE block_index = 2").fetchone()

    # Recompute block #2's hash as if it were block #1 linked directly to genesis
    new_hash = compute_block_hash(
        1,
        b2_row["timestamp"],
        b2_row["operation_type"],
        b2_row["target_id"],
        b2_row["operator_id"],
        b2_row["organization"],
        b2_row["cert_uuid"],
        b2_row["payload_hash"],
        b2_row["signature"],
        genesis_hash,
    )

    # Renumber block #2 to #1 and update prev_hash + block_hash
    conn.execute(
        "UPDATE audit_blocks SET block_index = 1, prev_hash = ?, block_hash = ? WHERE block_index = 2",
        (genesis_hash, new_hash),
    )
    conn.commit()
    conn.close()

    # Verification must detect that block #1's block_signature does NOT match the recomputed block_hash!
    rep_after = verify_audit_ledger(test_audit_db)
    assert rep_after.is_valid is False
    assert "signature" in rep_after.reason.lower()

    # Verification with trusted public keys must also fail
    rep_after_trusted = verify_audit_ledger(test_audit_db, trusted_public_keys=[pub])
    assert rep_after_trusted.is_valid is False
    assert "signature" in rep_after_trusted.reason.lower()
