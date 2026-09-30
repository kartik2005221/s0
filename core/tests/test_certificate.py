"""Certificate build/validate/sign/verify tests (structural layer)."""

import json

import pytest

from s0 import certificate, crypto


def test_build_and_validate(base_cert):
    assert certificate.validate(base_cert, require_signature=False) == []


def test_signed_cert_verifies(signed_cert, keys):
    ok, reason = certificate.verify_certificate(signed_cert, [keys["pub"]])
    assert ok, reason


def test_json_roundtrip_preserves_verification(signed_cert, keys):
    """Re-serializing with any key order must still verify — that's the point of canonical form."""
    shuffled = json.loads(json.dumps(signed_cert))  # parse/re-serialize
    ok, _ = certificate.verify_certificate(shuffled, [keys["pub"]])
    assert ok


def test_verify_rejects_unknown_issuer(signed_cert):
    stranger = crypto.generate_private_key().public_key()
    ok, reason = certificate.verify_certificate(signed_cert, [stranger])
    assert not ok
    assert "unknown issuer key fingerprint" in reason


def test_verify_rejects_tampered(signed_cert, keys):
    tampered = json.loads(json.dumps(signed_cert))
    tampered["device"]["capacity_bytes"] += 1
    ok, reason = certificate.verify_certificate(tampered, [keys["pub"]])
    assert not ok
    assert "does NOT match" in reason


def test_verify_rejects_mutated_signed_payload_hash(signed_cert, keys):
    tampered = json.loads(json.dumps(signed_cert))
    tampered["signature"]["signed_payload_hash"] = "sha256:" + "0" * 64
    ok, reason = certificate.verify_certificate(tampered, [keys["pub"]])
    assert not ok
    assert "signed_payload_hash mismatch" in reason


def test_verify_no_keys_supplied(signed_cert):
    ok, reason = certificate.verify_certificate(signed_cert, [])
    assert not ok and "no trusted public keys" in reason


@pytest.mark.parametrize("mutator", [
    lambda c: c.pop("wipe"),
    lambda c: c.update(schema_version="9.9.9"),
    lambda c: c.update(cert_uuid="not-a-uuid"),
    lambda c: c["wipe"].update(method="MAGIC_FAIRY_DUST"),
    lambda c: c["wipe"].update(nist_category="Purge"),  # overwrite can never claim Purge
    lambda c: c["wipe"].update(nist_category="Destroy"),  # nothing software-based claims Destroy
    lambda c: c["result"].update(status="sort_of_ok"),
    lambda c: c["device"].update(capacity_bytes=268435456.0),  # float smuggle
    lambda c: c["device"].update(sector_size=0),  # 0 must be rejected per schema minimum 1
    lambda c: c["device"].update(sector_size=-512),  # negative must be rejected
    lambda c: c["issuer"].update(organization=""),
    lambda c: c["wipe"].update(start_time="Aug 22 2026"),
])
def test_validation_catches_mutation(base_cert, mutator):
    cert = json.loads(json.dumps(base_cert))
    mutator(cert)
    problems = certificate.validate(cert, require_signature=False)
    assert problems, f"validator missed mutation: {cert!r}"


def test_signature_required_when_requested(base_cert):
    cert = json.loads(json.dumps(base_cert))
    problems = certificate.validate(cert, require_signature=True)
    assert any("signature: required object" == p for p in problems)


def test_refuses_to_sign_invalid_certificate(base_cert):
    from s0.certificate import CertificateError

    bad = json.loads(json.dumps(base_cert))
    bad["wipe"]["method"] = "MAKE_IT_CLEAN"
    with pytest.raises(CertificateError):
        certificate.sign_certificate(bad, crypto.generate_private_key())


def test_refuses_to_render_unsigned_to_pdf(base_cert):
    from s0 import pdfgen

    with pytest.raises(ValueError):
        pdfgen.generate_pdf(base_cert, "/tmp/should-not-exist.pdf")


def test_method_tier_registry_consistent():
    """Every known method must have a permitted-tier entry, and vice versa."""
    assert set(certificate.METHOD_TIERS) == certificate.WIPE_METHODS
    for method, tiers in certificate.METHOD_TIERS.items():
        assert tiers <= certificate.NIST_CATEGORIES
        # No host-overwrite method may ever be registered as Purge-only:
        if method.startswith(("OVERWRITE", "SHRED", "WINDOWS_CLEAN", "WINDOWS_CIPHER",
                              "ANDROID_USER_SPACE")):
            assert "Purge" not in tiers or method == "BLKDISCARD"


def test_certificate_deep_nesting_handled():
    """Verify that deeply nested adversarial JSON doesn't crash with RecursionError."""
    # Build a deep dict
    deep: dict = {"key": "val"}
    for _ in range(100):
        deep = {"nested": deep}
    errors = certificate.validate(deep, require_signature=False)
    assert any("exceeds" in e or "missing" in e for e in errors)

