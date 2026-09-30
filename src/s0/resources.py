"""Single accessor for s0 package data.

Every runtime asset s0 needs (demo keypair, certificate schema, packaged config)
is resolved here through :mod:`importlib.resources`, so a clean ``pip install``
works from any working directory with no ``sys.path`` help and no
``parents[N] / "..."`` filesystem arithmetic.

Resolution order for every asset:

1. an explicit environment variable (``S0_DEMO_PRIVATE_KEY``, ``S0_DEMO_PUBLIC_KEY``,
   ``S0_CERT_SCHEMA``, ``S0_CONFIG_PATH``) — used by operators and by tests;
2. the packaged copy inside ``s0/data/``;
3. a source checkout override, so in-tree development still works.
"""

from __future__ import annotations

import os
from importlib import resources
from pathlib import Path
from typing import Optional

__all__ = [
    "data_dir",
    "demo_private_key",
    "demo_public_key",
    "cert_schema",
    "packaged_config",
    "repo_root",
    "read_bytes",
]

_PACKAGE = "s0.data"

_DEMO_PRIVATE_KEY = "keys/demo_issuer_private.pem"
_DEMO_PUBLIC_KEY = "keys/demo_issuer_public.pem"
_CERT_SCHEMA = "cert_schema.json"
_PACKAGED_CONFIG = "s0_config.json"


def data_dir() -> Path:
    """Return the directory holding packaged data, as a real filesystem path."""
    return Path(str(resources.files(_PACKAGE)))


def read_bytes(relative: str) -> bytes:
    """Read a packaged data file by forward-slash relative path."""
    return (resources.files(_PACKAGE) / relative).read_bytes()


def _from_env(var: str) -> Optional[Path]:
    raw = os.environ.get(var, "").strip()
    if not raw:
        return None
    p = Path(raw).expanduser()
    return p if p.is_file() else None


def _packaged(relative: str) -> Optional[Path]:
    candidate = data_dir() / relative
    return candidate if candidate.is_file() else None


def repo_root() -> Optional[Path]:
    """Return the source-checkout root, or ``None`` when running from a wheel.

    A packaged install has no checkout above it, so every caller must treat this
    as optional. It exists only so that development and the release tooling can
    still find repository files that are not, and should not be, package data.
    """
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "pyproject.toml").is_file() and (parent / ".git").exists():
            return parent
    return None


def demo_private_key() -> Path:
    """Path to the DEMO issuer private key.

    Demo only. Production keys are generated out-of-band by ``s0-keygen`` and
    never live in the package; see ``docs/architecture/certificate-spec.md``.
    """
    for candidate in (
        _from_env("S0_DEMO_PRIVATE_KEY"),
        _packaged(_DEMO_PRIVATE_KEY),
        (lambda r: r / "src" / "s0" / "data" / _DEMO_PRIVATE_KEY)(repo_root()),
    ):
        if candidate is not None:
            return candidate
    raise FileNotFoundError(
        "DEMO issuer private key not found. Set S0_DEMO_PRIVATE_KEY or run from a checkout."
    )


def demo_public_key() -> Path:
    """Path to the DEMO issuer public key."""
    for candidate in (
        _from_env("S0_DEMO_PUBLIC_KEY"),
        _packaged(_DEMO_PUBLIC_KEY),
        (lambda r: r / "src" / "s0" / "data" / _DEMO_PUBLIC_KEY)(repo_root()),
    ):
        if candidate is not None:
            return candidate
    raise FileNotFoundError(
        "DEMO issuer public key not found. Set S0_DEMO_PUBLIC_KEY or run from a checkout."
    )


def cert_schema() -> Path:
    """Path to the wipe-certificate JSON schema."""
    for candidate in (
        _from_env("S0_CERT_SCHEMA"),
        _packaged(_CERT_SCHEMA),
        (lambda r: r / "src" / "s0" / "data" / _CERT_SCHEMA)(repo_root()),
    ):
        if candidate is not None:
            return candidate
    raise FileNotFoundError(
        "Certificate schema not found. Set S0_CERT_SCHEMA or run from a checkout."
    )


def packaged_config() -> Optional[Path]:
    """Path to the packaged copy of ``s0_config.json``, if one is present.

    The repository-root ``s0_config.json`` remains the release single source of
    truth; this is the copy shipped inside the wheel.
    """
    root = repo_root()
    if root is not None and (root / _PACKAGED_CONFIG).is_file():
        return root / _PACKAGED_CONFIG
    return _packaged(_PACKAGED_CONFIG)
