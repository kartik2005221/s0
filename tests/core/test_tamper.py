"""Tamper-evidence matrix: the core credibility test.

Builds one validly signed certificate, then mutates EVERY leaf field (one at a
time), plus structural attacks (remove/rename/add keys, swap the signature).
Every single mutation must break verification. This is the demoable proof that
a certificate cannot be quietly edited after issuance.
"""

import json

import pytest

from s0 import certificate, crypto


def _leaves(node, path=()):
    """Yield (path, getter, setter) for every leaf in a nested dict/list tree."""
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _leaves(v, path + (k,))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _leaves(v, path + (i,))
    else:
        yield path


def _get(node, path):
    for p in path[:-1]:
        node = node[p]
    return node, path[-1]


def _mutate(value):
    """A deterministic, type-aware single change to any leaf value."""
    if isinstance(value, bool):
        return not value
    if isinstance(value, int):
        return value + 1
    if isinstance(value, str):
        if len(value) > 8 and value.startswith("sha256:"):
            return value[:-1] + ("0" if value[-1] != "0" else "1")
        return value + "X"
    if value is None:
        return 0
    raise AssertionError(f"unhandled leaf type {type(value)}")


@pytest.fixture(scope="module")
def pristine(signed_cert):
    return signed_cert


def test_every_leaf_tamper_breaks_signature(pristine, keys):
    cert = json.loads(json.dumps(pristine))
    paths = list(_leaves({k: v for k, v in cert.items() if k != "signature"}))
    assert len(paths) >= 30, "expected a realistically-sized certificate"

    failures = []
    for path in paths:
        mutated = json.loads(json.dumps(pristine))
        container, key = _get(mutated, list(path))
        container[key] = _mutate(container[key])
        ok, _ = certificate.verify_certificate(mutated, [keys["pub"]])
        if ok:
            failures.append(".".join(str(p) for p in path))
    assert not failures, f"signature SURVIVED tampering at: {failures}"


@pytest.mark.parametrize("attack", [
    "remove_signed_field",
    "rename_signed_field",
    "add_unknown_signed_field",
    "swap_signature_value",
    "swap_fingerprint_to_other_key",
    "truncate_signature",
    "empty_signature",
])
def test_structural_attacks_break_signature(pristine, keys, attack):
    mutated = json.loads(json.dumps(pristine))
    if attack == "remove_signed_field":
        del mutated["wipe"]["bytes_processed"]
    elif attack == "rename_signed_field":
        mutated["wipe"]["bytes_processed_renamed"] = mutated["wipe"].pop("bytes_processed")
    elif attack == "add_unknown_signed_field":
        mutated["wipe"]["attacker_note"] = "nothing to see here"
    elif attack == "swap_signature_value":
        other = crypto.generate_private_key()
        mutated["signature"]["signature_base64url"] = crypto.sign_payload(
            other, b"attacker-chosen-payload")
    elif attack == "swap_fingerprint_to_other_key":
        mutated["signature"]["public_key_fingerprint"] = crypto.public_key_fingerprint(
            crypto.generate_private_key().public_key())
    elif attack == "truncate_signature":
        mutated["signature"]["signature_base64url"] = \
            mutated["signature"]["signature_base64url"][:-4]
    elif attack == "empty_signature":
        mutated["signature"]["signature_base64url"] = ""

    ok, _ = certificate.verify_certificate(mutated, [keys["pub"]])
    assert not ok, f"structural attack '{attack}' was NOT detected"


def test_resigning_after_tamper_requires_issuer_key(pristine, keys):
    """The only way to make an edited certificate verify is to re-sign it with
    the ISSUER's private key — which is exactly what an attacker must not have.
    (And a different key produces a different fingerprint, so it can't be
    smuggled past a verifier that pins the real issuer key.)"""
    edited = json.loads(json.dumps(pristine))
    edited["result"]["status"] = "success"  # imagine it said failure
    edited.pop("signature")

    attacker_key = crypto.generate_private_key()
    resigned = certificate.sign_certificate(edited, attacker_key)
    ok, reason = certificate.verify_certificate(resigned, [keys["pub"]])
    assert not ok
    assert "unknown issuer key fingerprint" in reason
