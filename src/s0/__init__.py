"""s0 (Sector Zero) — unified forensic sanitization, acquisition and recovery suite.

This is the single importable package for the whole tool. Before the repository
layout was corrected it was split across a ``s0_core`` distribution and a
``s0_cli`` distribution that the installers called "core" and "linux"; both are
now one package, ``s0``.

The canonical-form and signing rules implemented in :mod:`s0.canonical` and
:mod:`s0.crypto` are specified in ``docs/architecture/certificate-spec.md``.
Every other s0 component (verification portal, Windows and macOS wrappers)
re-implements those rules and is tested against certificates produced here.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from .config import CONFIG

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
    "read_temperature",
    "crypto",
    "CONFIG",
    "load_config",
    "__version__",
    "__version_str__",
    "__git_commit__",
]


def _distribution_version() -> str | None:
    """Version of the installed ``s0`` distribution, or ``None`` if not installed."""
    try:
        from importlib.metadata import version

        return version("s0")
    except Exception:
        return None


def _git_commit() -> str:
    """Short commit hash for the running source tree, best effort.

    The build stamps ``S0_GIT_COMMIT``; from a checkout we ask git directly.
    A wheel with neither simply reports no commit, which is better than
    inventing one.
    """
    env_commit = os.environ.get("S0_GIT_COMMIT", "").strip()
    if env_commit:
        return env_commit[:8]
    try:
        res = subprocess.run(
            ["git", "-C", str(Path(__file__).resolve().parent), "rev-parse", "--short=8", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
            timeout=2,
        )
        if res.returncode == 0 and res.stdout.strip():
            return res.stdout.strip()
    except Exception:
        pass
    return ""


#: Distribution version when installed, otherwise the packaged config's version.
__version__ = _distribution_version() or str(CONFIG.get("version", "2.4.4"))

#: Short commit hash, or ``""`` when unavailable.
__git_commit__ = _git_commit()

#: Human-facing version banner, e.g. ``2.4.4 (commit a1b2c3d4)``.
__version_str__ = f"{__version__} (commit {__git_commit__})" if __git_commit__ else str(__version__)

from . import crypto
from .canonical import CanonicalizationError, canonicalize, canonicalize_str
from .certificate import (
    CertificateError,
    build_certificate,
    payload_of,
    sign_certificate,
    validate,
    verify_certificate,
)
from .config import CONFIG, load_config
from .progress import ProgressBar
from .temperature import read_temperature
from .validation import validate_metadata_str
