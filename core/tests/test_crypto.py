"""Crypto primitive tests: keygen, PEM round-trip, fingerprints, sign/verify."""

import pytest

from s0_core import crypto


def test_sign_verify_roundtrip(keys):
    payload = b'{"a":1,"b":"two"}'
    sig = crypto.sign_payload(keys["priv"], payload)
    assert crypto.verify_payload(keys["pub"], payload, sig) is True


def test_wrong_payload_fails(keys):
    sig = crypto.sign_payload(keys["priv"], b"payload-one")
    assert crypto.verify_payload(keys["pub"], b"payload-two", sig) is False


def test_garbage_signature_fails_not_raises(keys):
    assert crypto.verify_payload(keys["pub"], b"x", "not-base64!!!") is False
    assert crypto.verify_payload(keys["pub"], b"x", "") is False
    # A syntactically valid base64url of wrong-length bytes must also be False.
    assert crypto.verify_payload(keys["pub"], b"x", "AAAA") is False


def test_fingerprint_stable_across_pem_roundtrip(keys, tmp_path):
    pub_path = crypto.write_public_pem(keys["pub"], tmp_path / "k.pem")
    reloaded = crypto.load_public_pem(pub_path)
    fp1 = crypto.public_key_fingerprint(keys["pub"])
    fp2 = crypto.public_key_fingerprint(reloaded)
    assert fp1 == fp2
    assert fp1.startswith("sha256:")
    assert len(fp1) == len("sha256:") + 64


def test_different_keys_different_fingerprints():
    k1 = crypto.generate_private_key().public_key()
    k2 = crypto.generate_private_key().public_key()
    assert crypto.public_key_fingerprint(k1) != crypto.public_key_fingerprint(k2)


def test_private_pem_permissions(tmp_path, keys):
    p = crypto.write_private_pem(keys["priv"], tmp_path / "priv.pem")
    import os
    mode = os.stat(p).st_mode & 0o777
    assert mode == 0o600


def test_signature_is_base64url_unpadded(keys):
    sig = crypto.sign_payload(keys["priv"], b"data")
    assert "=" not in sig
    assert "+" not in sig and "/" not in sig  # urlsafe alphabet only
    # Ed25519 signatures are exactly 64 bytes -> 86 unpadded base64url chars.
    assert len(sig) == 86
