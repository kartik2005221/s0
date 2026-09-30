"""Ed25519 signing primitives for s0 certificates.

Key policy (src/s0/data/keys/README.md): private keys are generated out-of-band by the
issuing authority and NEVER ship inside any app bundle or repository. This
module is the tooling; it enforces nothing at runtime — the policy lives in
people's hands, so it is documented everywhere it matters.
"""

from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

__all__ = [
    "generate_private_key",
    "write_private_pem",
    "write_public_pem",
    "load_private_pem",
    "load_public_pem",
    "public_key_fingerprint",
    "sign_payload",
    "verify_payload",
    "payload_sha256",
    "DEMO_KEY_FINGERPRINT",
    "is_demo_key",
]

DEMO_KEY_FINGERPRINT = "sha256:8396af8c07a7d40f98ba492cf2b61e23fa768e66a9f627b02a9caff464e48c06"


def is_demo_key(key: Ed25519PrivateKey | Ed25519PublicKey | str | Path | None) -> bool:
    """Check whether a key matches the unaccredited public demonstration key."""
    if key is None:
        return True
    if isinstance(key, (str, Path)):
        p = Path(key)
        if "demo" in p.name.lower():
            return True
        if not p.exists():
            return "demo" in str(p).lower()
        try:
            priv = load_private_pem(p)
            return public_key_fingerprint(priv.public_key()) == DEMO_KEY_FINGERPRINT
        except Exception:
            try:
                pub = load_public_pem(p)
                return public_key_fingerprint(pub) == DEMO_KEY_FINGERPRINT
            except Exception:
                return "demo" in str(p).lower()
    if isinstance(key, Ed25519PrivateKey):
        return public_key_fingerprint(key.public_key()) == DEMO_KEY_FINGERPRINT
    if isinstance(key, Ed25519PublicKey):
        return public_key_fingerprint(key) == DEMO_KEY_FINGERPRINT
    return False



def generate_private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def write_private_pem(key: Ed25519PrivateKey, path: str | Path) -> Path:
    """Write an *unencrypted* PKCS#8 PEM private key with owner-only permissions.

    Unencrypted on disk is a deliberate trade-off for automated signing; if the
    issuing authority needs passphrase protection, do it with their key
    management system, not by editing this function.
    """
    path = Path(path)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.write_bytes(pem)
    os.chmod(path, 0o600)
    return path


def write_public_pem(key: Ed25519PublicKey, path: str | Path) -> Path:
    path = Path(path)
    path.write_bytes(
        key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return path


def load_private_pem(path: str | Path) -> Ed25519PrivateKey:
    data = Path(path).read_bytes()
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError(f"{path} is not an Ed25519 private key")
    return key


def load_public_pem(path: str | Path) -> Ed25519PublicKey:
    data = Path(path).read_bytes()
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, Ed25519PublicKey):
        raise TypeError(f"{path} is not an Ed25519 public key")
    return key


def _spki_der(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def public_key_fingerprint(key: Ed25519PublicKey) -> str:
    """'sha256:' + lowercase hex SHA-256 over DER SubjectPublicKeyInfo."""
    return "sha256:" + hashlib.sha256(_spki_der(key)).hexdigest()


def sign_payload(private_key: Ed25519PrivateKey, payload: bytes) -> str:
    """Pure-Ed25519 signature over *payload*, base64url, padding stripped."""
    sig = private_key.sign(payload)
    return base64.urlsafe_b64encode(sig).decode("ascii").rstrip("=")


def verify_payload(public_key: Ed25519PublicKey, payload: bytes, sig_b64url: str) -> bool:
    """Verify a signature produced by :func:`sign_payload`.

    Returns False for any invalid signature or undecodable input; raises only
    on wrong argument types.
    """
    try:
        padded = sig_b64url + "=" * (-len(sig_b64url) % 4)
        sig = base64.urlsafe_b64decode(padded.encode("ascii"))
        public_key.verify(sig, payload)
    except Exception:
        return False
    return True


def payload_sha256(payload: bytes) -> str:
    """Display annotation: 'sha256:<hex>' of the canonical payload."""
    return "sha256:" + hashlib.sha256(payload).hexdigest()
