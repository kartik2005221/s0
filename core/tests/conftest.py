"""Shared fixtures: throwaway issuer keypair + a realistic signed demo certificate."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

CORE_PYTHON = Path(__file__).resolve().parent.parent / "python"
sys.path.insert(0, str(CORE_PYTHON))

from trustwipe_core import crypto, certificate  # noqa: E402


@pytest.fixture(scope="session")
def keys(tmp_path_factory):
    d = tmp_path_factory.mktemp("keys")
    priv = crypto.generate_private_key()
    pub_path = crypto.write_public_pem(priv.public_key(), d / "issuer_public.pem")
    return {"priv": priv, "pub": priv.public_key(), "pub_path": pub_path}


@pytest.fixture(scope="session")
def base_cert() -> dict:
    """An unsigned certificate resembling a real image-file wipe."""
    return certificate.build_certificate(
        organization="TrustWipe Demo Lab",
        operator_id="op-demo-001",
        tool_name="s0-cli",
        tool_version="0.1.0",
        platform="linux",
        device_id="sha256:" + "ab" * 32,
        device_type="image_file",
        storage_type="IMAGE_FILE",
        model="loop-test-image",
        capacity_bytes=268_435_456,
        sector_size=512,
        method="OVERWRITE_ZERO_1PASS",
        nist_category="Clear",
        pattern="zero",
        passes=1,
        start_time="2026-08-22T10:00:00Z",
        end_time="2026-08-22T10:02:31Z",
        bytes_processed=268_435_456,
        status="success",
        verification={
            "method": "sampled_readback+planted_grep",
            "samples_checked": 64,
            "sample_bytes_each": 4096,
            "all_samples_match_wipe_pattern": True,
            "planted_pattern_hits_after": 0,
            "pre_wipe_sample_hash": "sha256:" + "cd" * 32,
        },
        notes=[
            "File-backed sparse image target; real bytes on real disk.",
            "Planted known patterns at deterministic offsets; post-wipe grep found 0 hits.",
        ],
    )


@pytest.fixture(scope="session")
def signed_cert(base_cert, keys) -> dict:
    return certificate.sign_certificate(base_cert, keys["priv"])


@pytest.fixture(scope="session")
def signed_cert_file(signed_cert, tmp_path_factory) -> Path:
    p = tmp_path_factory.mktemp("certs") / "demo.signed.json"
    p.write_text(json.dumps(signed_cert, indent=2), encoding="utf-8")
    return p
