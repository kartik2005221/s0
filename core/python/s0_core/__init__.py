"""s0 shared core: canonical JSON, Ed25519 signing, wipe certificates.

The canonical-form and signing rules implemented here are specified in
core/CANONICAL_JSON.md. Every other s0 component (verification portal,
Windows app, Android app) re-implements those rules and is tested against
certificates produced by this package.
"""

from .config import CONFIG

__version__ = CONFIG.get("version", "2.4.3")

from .canonical import CanonicalizationError, canonicalize, canonicalize_str
from .certificate import (
    CertificateError,
    build_certificate,
    payload_of,
    sign_certificate,
    validate,
    verify_certificate,
)
from .progress import ProgressBar
from .temperature import read_temperature
from . import crypto
from .config import CONFIG, load_config
from .validation import validate_metadata_str

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
    "validate_metadata_str",
    "ProgressBar",
    "crypto",
    "CONFIG",
    "load_config",
    "__version__",
]
