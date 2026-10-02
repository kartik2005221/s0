"""Cross-runtime verification: runs the actual JS crypto-bundle.js in Node.js."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from s0.resources import repo_root

PORTAL = repo_root() / "site" / "verify"

# Probe for node
def find_node() -> str | None:
    candidates = [
        os.environ.get("NODE_BIN"),
        shutil.which("node"),
        shutil.which("nodejs"),
        str(Path.home() / ".hermes" / "node" / "bin" / "node"),
        "/usr/local/bin/node",
        "/usr/bin/node",
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return candidate
    return None

NODE = find_node()


@pytest.fixture
def node_available():
    if not NODE:
        pytest.skip("Node.js runtime not found on this system")


def test_sha512_nist_vectors(node_available):
    script = """
    const C = require('./vendor/crypto-bundle');
    const crypto = require('crypto');
    const msg = Buffer.from('abc');
    const expected = crypto.createHash('sha512').update(msg).digest('hex');
    const actual = Buffer.from(C.sha512(msg)).toString('hex');
    if (expected !== actual) {
      console.error('Mismatch: expected ' + expected + ' but got ' + actual);
      process.exit(1);
    }
    """
    result = subprocess.run(
        [NODE, "-e", script], capture_output=True, text=True, cwd=str(PORTAL)
    )
    assert result.returncode == 0, f"Node.js error: {result.stderr}"


def test_valid_cert_cross_verification(node_available):
    script = """
    const V = require('./verify');
    const cert = require('./tests/sample_valid_cert.json');
    const keys = require('./keys.json');
    const res = V.verifyCertificate(cert, keys.trusted_keys);
    console.log(JSON.stringify(res));
    if (!res.ok || res.status !== 'AUTHENTIC') {
      process.exit(1);
    }
    """
    result = subprocess.run(
        [NODE, "-e", script], capture_output=True, text=True, cwd=str(PORTAL)
    )
    assert result.returncode == 0, f"Node.js error: {result.stderr}"
    data = json.loads(result.stdout.strip())
    assert data["ok"] is True
    assert data["status"] == "AUTHENTIC"


def test_tampered_cert_cross_verification(node_available):
    script = """
    const V = require('./verify');
    const cert = require('./tests/sample_tampered_cert.json');
    const keys = require('./keys.json');
    const res = V.verifyCertificate(cert, keys.trusted_keys);
    console.log(JSON.stringify(res));
    if (res.ok || res.status !== 'TAMPERED_OR_CORRUPT') {
      process.exit(1);
    }
    """
    result = subprocess.run(
        [NODE, "-e", script], capture_output=True, text=True, cwd=str(PORTAL)
    )
    assert result.returncode == 0, f"Node.js error: {result.stderr}"
    data = json.loads(result.stdout.strip())
    assert data["ok"] is False
    assert data["status"] == "TAMPERED_OR_CORRUPT"


def test_mutated_payload_hash_cross_verification(node_available):
    script = """
    const V = require('./verify');
    const cert = JSON.parse(JSON.stringify(require('./tests/sample_valid_cert.json')));
    const keys = require('./keys.json');
    cert.signature.signed_payload_hash = 'sha256:' + '0'.repeat(64);
    const res = V.verifyCertificate(cert, keys.trusted_keys);
    console.log(JSON.stringify(res));
    if (res.ok || res.status !== 'PAYLOAD_HASH_MISMATCH') {
      process.exit(1);
    }
    """
    result = subprocess.run(
        [NODE, "-e", script], capture_output=True, text=True, cwd=str(PORTAL)
    )
    assert result.returncode == 0, f"Node.js error: {result.stderr}"
    data = json.loads(result.stdout.strip())
    assert data["ok"] is False
    assert data["status"] == "PAYLOAD_HASH_MISMATCH"


def test_float_and_duplicate_key_rejection(node_available):
    script = """
    const V = require('./verify');
    const validJson = JSON.stringify(require('./tests/sample_valid_cert.json'));
    // Float smuggle: replace 1048576 with 1048576.0
    const floatJson = validJson.replace('1048576', '1048576.0');
    const keys = require('./keys.json');

    const resFloat = V.verifyCertificate(floatJson, keys.trusted_keys);
    if (resFloat.ok || resFloat.status !== 'SCHEMA_INVALID') {
      console.error('Expected SCHEMA_INVALID for float, got: ' + JSON.stringify(resFloat));
      process.exit(1);
    }

    // Duplicate key
    const dupJson = '{"foo": 1, "foo": 2}';
    const errs = V.detectRawFloatsInJson(dupJson);
    if (!errs.some(e => e.includes('duplicate key'))) {
      console.error('Expected duplicate key error, got: ' + JSON.stringify(errs));
      process.exit(2);
    }
    """
    result = subprocess.run(
        [NODE, "-e", script], capture_output=True, text=True, cwd=str(PORTAL)
    )
    assert result.returncode == 0, f"Node.js error: {result.stderr}"
