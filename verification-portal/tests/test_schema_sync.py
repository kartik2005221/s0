"""The certificate schema is mirrored in three runtimes. This suite guarantees they
cannot drift.

    core/cert_schema.json                     -> the normative JSON Schema
    core/python/s0_core/certificate.py        -> the Python validator (no jsonschema dep)
    verification-portal/verify.js             -> the browser verifier (no bundler)

If these three ever disagree, a certificate the CLI happily issues is rejected by
the portal that is supposed to prove it authentic — which is exactly the class of
seamlessness defect this repo must not ship.
"""

from __future__ import annotations

import json
import re
import subprocess
import shutil
import os
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SCHEMA_PATH = REPO / "core" / "cert_schema.json"
VERIFY_JS = REPO / "verification-portal" / "verify.js"


@pytest.fixture(scope="module")
def schema():
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def py_registry():
    from s0_core import certificate as cert

    return {
        "WIPE_METHODS": cert.WIPE_METHODS,
        "DEVICE_TYPES": cert.DEVICE_TYPES,
        "STORAGE_TYPES": cert.STORAGE_TYPES,
        "PATTERNS": cert.PATTERNS,
        "NIST_CATEGORIES": cert.NIST_CATEGORIES,
        "STATUSES": cert.STATUSES,
        "PLATFORMS": cert.PLATFORMS,
        "METHOD_TIERS": cert.METHOD_TIERS,
        "SCHEMA_VERSION": cert.SCHEMA_VERSION,
    }


def find_node() -> str | None:
    for candidate in (
        os.environ.get("NODE_BIN"),
        shutil.which("node"),
        shutil.which("nodejs"),
        "/usr/local/bin/node",
        "/usr/bin/node",
    ):
        if candidate and Path(candidate).is_file():
            return candidate
    return None


@pytest.fixture(scope="module")
def js_registry():
    """Evaluate verify.js in Node and read back its exported schema registries."""
    node = find_node()
    if not node:
        pytest.skip("Node.js runtime not found on this system")
    portal = VERIFY_JS.parent
    script = """
      const path = require('path');
      const V = require(process.argv[1]);
      process.stdout.write(JSON.stringify({
        WIPE_METHODS: V.WIPE_METHODS,
        METHOD_TIERS: V.METHOD_TIERS,
        NIST_CATEGORIES: V.NIST_CATEGORIES,
      }));
    """
    proc = subprocess.run(
        [node, "-e", script, str(VERIFY_JS)],
        capture_output=True, text=True, timeout=60,
        cwd=str(portal),
    )
    if proc.returncode != 0:
        pytest.fail(f"could not evaluate verify.js in node: {proc.stderr[:2000]}")
    return json.loads(proc.stdout)


def _enum(schema, *path):
    node = schema
    for key in path:
        node = node[key]
    return set(node["enum"])


# --------------------------------------------------------------------------- #
# JSON Schema  <->  Python registry
# --------------------------------------------------------------------------- #


def test_schema_methods_match_python(schema, py_registry):
    assert _enum(schema, "properties", "wipe", "properties", "method") == set(py_registry["WIPE_METHODS"])


def test_schema_device_types_match_python(schema, py_registry):
    assert _enum(schema, "properties", "device", "properties", "device_type") == set(py_registry["DEVICE_TYPES"])


def test_schema_storage_types_match_python(schema, py_registry):
    assert _enum(schema, "properties", "device", "properties", "storage_type") == set(py_registry["STORAGE_TYPES"])


def test_schema_patterns_match_python(schema, py_registry):
    assert _enum(schema, "properties", "wipe", "properties", "pattern") == set(py_registry["PATTERNS"])


def test_schema_nist_categories_match_python(schema, py_registry):
    assert _enum(schema, "properties", "wipe", "properties", "nist_category") == set(py_registry["NIST_CATEGORIES"])


def test_schema_statuses_match_python(schema, py_registry):
    assert _enum(schema, "properties", "result", "properties", "status") == set(py_registry["STATUSES"])


def test_schema_platforms_match_python(schema, py_registry):
    assert _enum(schema, "properties", "tool", "properties", "platform") == set(py_registry["PLATFORMS"])


def test_schema_version_matches_python(schema, py_registry):
    assert schema["properties"]["schema_version"]["const"] == py_registry["SCHEMA_VERSION"]


# --------------------------------------------------------------------------- #
# JSON Schema  <->  JS verifier
# --------------------------------------------------------------------------- #


def test_js_methods_match_schema(schema, js_registry):
    assert _enum(schema, "properties", "wipe", "properties", "method") == set(js_registry["WIPE_METHODS"])


def test_js_method_tiers_match_python(py_registry, js_registry):
    py = {k: sorted(v) for k, v in py_registry["METHOD_TIERS"].items()}
    js = {k: sorted(v) for k, v in js_registry["METHOD_TIERS"].items()}
    assert js == py


# --------------------------------------------------------------------------- #
# Invariants that must hold regardless of the mirrors
# --------------------------------------------------------------------------- #


def test_every_method_has_a_permitted_tier(schema, py_registry):
    methods = _enum(schema, "properties", "wipe", "properties", "method")
    tiers = py_registry["METHOD_TIERS"]
    missing = sorted(methods - set(tiers))
    assert not missing, f"methods with no NIST tier mapping: {missing}"


def test_no_method_can_claim_more_than_purge(py_registry):
    for method, allowed in py_registry["METHOD_TIERS"].items():
        assert allowed <= {"Clear", "Purge", "Destroy", "N/A"}, f"{method} has bogus tiers {allowed}"


def test_every_firmware_purge_is_documented(schema, py_registry):
    """Every firmware-mediated Purge method must appear in the NIST mapping doc."""
    mapping = (REPO / "core" / "standards" / "nist_800_88_mapping.md").read_text(encoding="utf-8")
    firmware = sorted(
        m for m in py_registry["WIPE_METHODS"]
        if any(k in m for k in ("ATA_SANITIZE", "NVME_SANITIZE", "SCSI_SANITIZE", "OPAL_", "LUKS_", "FDE_"))
    )
    missing = [m for m in firmware if m not in mapping]
    assert not missing, f"undocumented in core/standards/nist_800_88_mapping.md: {missing}"


def test_verification_fields_have_no_floats(schema):
    """s0 Canonical JSON v1 forbids float fields anywhere in a signed payload."""
    verif = schema["properties"]["result"]["properties"]["verification"]["properties"]
    for name, spec in verif.items():
        t = spec.get("type")
        assert t != "number", f"result.verification.{name} is numeric and could serialise a float"


def test_portal_js_has_no_unsafe_only_invert_qr_attempt():
    """The vendored jsQR build throws on inversionAttempts:'onlyInvert'."""
    src = (REPO / "verification-portal" / "js" / "portal.js").read_text(encoding="utf-8")
    assert '"onlyInvert"' not in src and "'onlyInvert'" not in src, (
        "portal.js must not request jsQR's onlyInvert mode; it throws in the vendored build"
    )


def test_portal_scans_all_pdf_pages_for_qr():
    src = (REPO / "verification-portal" / "js" / "portal.js").read_text(encoding="utf-8")
    assert "getPage(1)" not in src, (
        "portal.js must scan every page: s0 certificates overflow the QR onto page 2"
    )


def test_dashboard_index_serves_auth_token():
    """Opening the dashboard without ?token= must still work."""
    app = (REPO / "web" / "app.py").read_text(encoding="utf-8")
    assert "s0-auth-token" in app, (
        "web/app.py must inject the session auth token into index.html; the dashboard "
        "JS reads <meta name=\"s0-auth-token\"> and otherwise 401s on every API call"
    )
