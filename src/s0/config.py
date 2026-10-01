"""Central configuration loader for s0."""

from __future__ import annotations

import json
import os
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
    if cfg_file:
        try:
            with open(cfg_file, encoding="utf-8") as f:
                user_cfg = json.load(f)
                if isinstance(user_cfg, dict):
                    cfg.update(user_cfg)
        except Exception:
            pass
    return cfg


CONFIG = load_config()
