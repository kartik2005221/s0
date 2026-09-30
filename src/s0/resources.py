"""Single accessor for s0 package data.

Every runtime asset s0 needs (demo keypair, certificate schema, packaged config)
is resolved here through :mod:`importlib.resources`, so a clean ``pip install``
works from any working directory with no ``sys.path`` help and no
``parents[N] / "..."`` filesystem arithmetic.

Resolution order for every asset:

1. an explicit environment variable (``S0_DEMO_PRIVATE_KEY``, ``S0_DEMO_PUBLIC_KEY``,
   ``S0_CERT_SCHEMA``, ``S0_CONFIG_PATH``) — used by operators and by tests;
2. the copy packaged inside ``s0/data/``;
3. a source-checkout override, so in-tree development still works.

Step 3 is skipped entirely when there is no checkout, which is the normal case
for a pip-installed s0.
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


def repo_root() -> Optional[Path]:
    """Return the source-checkout root, or ``None`` when running from a wheel.

    A packaged install has no checkout above it, so every caller must treat this
    as optional. It exists only so that development and the release tooling can
    still find repository files that are not, and should not be, package data.
    """
    for parent in Path(__file__).resolve().parents:
        if (parent / "pyproject.toml").is_file() and (parent / ".git").exists():
            return parent
    return None


def _from_env(var: str) -> Optional[Path]:
    raw = os.environ.get(var, "").strip()
    if not raw:
        return None
    p = Path(raw).expanduser()
    return p if p.is_file() else None


def _packaged(relative: str) -> Optional[Path]:
    candidate = data_dir() / relative
    return candidate if candidate.is_file() else None


def _resolve(env_var: str, relative: str, description: str) -> Path:
    """Env override, then packaged copy, then the source checkout."""

    def from_checkout() -> Optional[Path]:
        root = repo_root()
        if root is None:
            return None
        candidate = root / "src" / "s0" / "data" / relative
        return candidate if candidate.is_file() else None

    for source in (lambda: _from_env(env_var), lambda: _packaged(relative), from_checkout):
        found = source()
        if found is not None:
            return found

    raise FileNotFoundError(
        f"{description} not found. Set {env_var} to its location, or run from a "
        f"source checkout that contains src/s0/data/{relative}."
    )


def demo_private_key() -> Path:
    """Path to the DEMO issuer private key.

    Demo only. Production keys are generated out-of-band by ``s0-keygen`` and
    never live in the package; see ``docs/architecture/certificate-spec.md``.
    """
    return _resolve("S0_DEMO_PRIVATE_KEY", _DEMO_PRIVATE_KEY, "DEMO issuer private key")


def demo_public_key() -> Path:
    """Path to the DEMO issuer public key."""
    return _resolve("S0_DEMO_PUBLIC_KEY", _DEMO_PUBLIC_KEY, "DEMO issuer public key")


def cert_schema() -> Path:
    """Path to the wipe-certificate JSON schema."""
    return _resolve("S0_CERT_SCHEMA", _CERT_SCHEMA, "Certificate schema")


def packaged_config() -> Optional[Path]:
    """Path to ``s0_config.json``: the checkout's copy if there is one, else the packaged one.

    The repository-root ``s0_config.json`` remains the release single source of
    truth; the packaged copy is what ships inside the wheel.
    """
    root = repo_root()
    if root is not None and (root / _PACKAGED_CONFIG).is_file():
        return root / _PACKAGED_CONFIG
    return _packaged(_PACKAGED_CONFIG)
