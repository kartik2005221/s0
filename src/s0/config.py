"""Central configuration loader for s0."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

from . import resources

DEFAULT_CONFIG: dict[str, Any] = {
    "version": "2.4.4",
    "tool_name": "s0",
    "tool_title": "Sector Zero — Unified Forensic & Sanitization Workstation",
    "documentation_url": "https://s0-docs.gitbook.io/",
    "verification_portal_url": "https://s0-verify.pages.dev/",
    "install_portal_url": "https://s0-install.pages.dev/",
    "github_url": "https://github.com/kartik2005221/s0",
    "default_operator": "op-forensic",
    "default_organization": "Digital Forensics & Data Sanitization Lab",
    "default_key_path": "src/s0/data/keys/demo_issuer_private.pem",
    "default_public_key_path": "src/s0/data/keys/demo_issuer_public.pem",
    "default_out_dir": "demo-out",
    "qr_url_template": "https://s0-verify.pages.dev/?cert={cert_uuid}",
    "api_port": 8669,
}


def find_config_file() -> Path | None:
    env_path = os.environ.get("S0_CONFIG_PATH")
    if env_path:
        p = Path(env_path)
        if p.is_file():
            return p

    candidates: list[Path] = []
    root = resources.repo_root()
    if root is not None:
        # Source checkout: the repo-root file is the release single source of truth.
        candidates.append(root / "s0_config.json")
    packaged = resources.packaged_config()
    if packaged is not None:
        candidates.append(packaged)
    candidates.append(Path.home() / ".s0" / "s0_config.json")
    candidates.append(Path("/etc/s0/s0_config.json"))
    for c in candidates:
        if c.is_file():
            return c
    return None


def load_config() -> dict[str, Any]:
    cfg = dict(DEFAULT_CONFIG)
    cfg_file = find_config_file()

    env_path = os.environ.get("S0_CONFIG_PATH")
    if env_path and not Path(env_path).is_file():
        # Set explicitly but pointing nowhere: that is a mistake worth naming.
        print(
            f"[s0 config]  WARNING: S0_CONFIG_PATH={env_path!r} does not exist; "
            "ignoring it and using defaults.",
            file=sys.stderr,
        )

    if cfg_file:
        try:
            with open(cfg_file, encoding="utf-8") as f:
                user_cfg = json.load(f)
        except json.JSONDecodeError as exc:
            # Previously swallowed by `except Exception: pass`, so a config with a
            # typo produced defaults and no diagnostic at all.
            print(
                f"[s0 config]  ERROR: {cfg_file} is not valid JSON ({exc}).\n"
                "             Fix the file, or unset S0_CONFIG_PATH to use defaults.\n"
                "             Continuing with built-in defaults.",
                file=sys.stderr,
            )
        except OSError as exc:
            print(
                f"[s0 config]  WARNING: cannot read {cfg_file} ({exc}); "
                "using built-in defaults.",
                file=sys.stderr,
            )
        else:
            if not isinstance(user_cfg, dict):
                print(
                    f"[s0 config]  ERROR: {cfg_file} must contain a JSON object, "
                    f"got {type(user_cfg).__name__}; using built-in defaults.",
                    file=sys.stderr,
                )
            else:
                _warn_on_type_mismatches(cfg_file, cfg, user_cfg)
                cfg.update(user_cfg)
    return cfg


def _warn_on_type_mismatches(path, defaults, supplied) -> None:
    """Flag config values whose type contradicts the built-in default.

    Values are otherwise trusted blindly, which let `{"version": {"a": 1}}` reach
    the machine-readable envelope as `"{'a': 1}"` and `{"api_port":
    "not-a-number"}` flow into `s0 web --port`. Typing them is a separate change;
    saying so is cheap and prevents the silent nonsense.
    """
    for key, value in supplied.items():
        if key not in defaults:
            print(
                f"[s0 config]  WARNING: unknown key {key!r} in {path}; it will be "
                "ignored by s0 but kept in the merged config.",
                file=sys.stderr,
            )
            continue
        expected = type(defaults[key])
        if expected is bool:
            if not isinstance(value, bool):
                print(
                    f"[s0 config]  WARNING: {key!r} should be a boolean, got "
                    f"{type(value).__name__} in {path}.",
                    file=sys.stderr,
                )
        elif isinstance(value, bool) or not isinstance(value, expected):
            print(
                f"[s0 config]  WARNING: {key!r} should be {expected.__name__}, got "
                f"{type(value).__name__} in {path}.",
                file=sys.stderr,
            )


CONFIG = load_config()
