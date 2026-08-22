"""TrustWipe shared core: canonical JSON, Ed25519 signing, wipe certificates.

The canonical-form and signing rules implemented here are specified in
core/CANONICAL_JSON.md. Every other TrustWipe component (verification portal,
Windows app, Android app) re-implements those rules and is tested against
certificates produced by this package.
"""

__version__ = "0.1.0"

from .canonical import CanonicalizationError, canonicalize, canonicalize_str
from .certificate import (
    CertificateError,
    build_certificate,
    payload_of,
    sign_certificate,
    validate,
    verify_certificate,
)
from . import crypto

__all__ = [
    "CanonicalizationError",
    "canonicalize",
    "canonicalize_str",
    "CertificateError",
    "build_certificate",
    "payload_of",
    "sign_certificate",
    "validate",
    "verify_certificate",
    "crypto",
    "__version__",
]
