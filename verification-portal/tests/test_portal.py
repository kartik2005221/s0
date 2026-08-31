"""Cross-verification tests for Verification Portal (Phase 5)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from trustwipe_core.canonical import canonicalize_str, canonicalize
from trustwipe_core.certificate import (
    validate,
    verify_certificate,
    METHOD_TIERS,
    WIPE_METHODS,
    NIST_CATEGORIES,
)
from trustwipe_core.crypto import (
    load_public_pem,
    public_key_fingerprint,
    verify_payload,
)

PORTAL_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = PORTAL_DIR.parent


def test_portal_static_assets_exist():
    assert (PORTAL_DIR / "index.html").is_file()
    assert (PORTAL_DIR / "verify.js").is_file()
    assert (PORTAL_DIR / "keys.json").is_file()
    assert (PORTAL_DIR / "vendor" / "crypto-bundle.js").is_file()
    assert (PORTAL_DIR / "tests" / "test_runner.html").is_file()
    assert (PORTAL_DIR / "tests" / "sample_valid_cert.json").is_file()
    assert (PORTAL_DIR / "tests" / "sample_tampered_cert.json").is_file()


def test_keys_json_matches_repo_public_key():
    keys_path = PORTAL_DIR / "keys.json"
    with open(keys_path) as f:
        keys_data = json.load(f)

    assert "trusted_keys" in keys_data
    trusted = keys_data["trusted_keys"]
    assert len(trusted) >= 1

    demo_pem_path = REPO_ROOT / "core" / "keys" / "demo_issuer_public.pem"
    pub = load_public_pem(demo_pem_path)
    expected_fp = public_key_fingerprint(pub)

    # The demo key must be in the trusted keys list
    matching = [k for k in trusted if k["fingerprint"] == expected_fp]
    assert len(matching) == 1, f"Expected key fingerprint {expected_fp} in keys.json"


def test_sample_certificates_verification():
    pub = load_public_pem(REPO_ROOT / "core" / "keys" / "demo_issuer_public.pem")

    with open(PORTAL_DIR / "tests" / "sample_valid_cert.json") as f:
        valid_cert = json.load(f)

    ok, reason = verify_certificate(valid_cert, [pub])
    assert ok is True
    assert "valid Ed25519 signature" in reason

    with open(PORTAL_DIR / "tests" / "sample_tampered_cert.json") as f:
        tampered_cert = json.load(f)

    ok, reason = verify_certificate(tampered_cert, [pub])
    assert ok is False
    assert "signature does NOT match" in reason or "invalid" in reason


def test_js_canonical_json_spec_parity():
    # Verify golden vectors from core against python reference
    vectors_file = REPO_ROOT / "core" / "tests" / "data" / "canonical_vectors.json"
    with open(vectors_file) as f:
        vectors = json.load(f)["vectors"]

    for v in vectors:
        py_canon = canonicalize_str(v["input"])
        assert py_canon == v["canonical"], f"Vector {v['name']} failed"


def test_verify_js_contains_all_wipe_methods_and_tiers():
    verify_js_content = (PORTAL_DIR / "verify.js").read_text(encoding="utf-8")
    for method in WIPE_METHODS:
        assert f'"{method}"' in verify_js_content, f"Missing method {method} in verify.js"

    for tier in NIST_CATEGORIES:
        assert f'"{tier}"' in verify_js_content, f"Missing tier {tier} in verify.js"
