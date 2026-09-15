"""Canonical form tests against golden vectors (core/CANONICAL_JSON.md contract)."""

import json
from pathlib import Path

import pytest

from s0_core.canonical import CanonicalizationError, canonicalize, canonicalize_str

VECTORS = json.loads(
    (Path(__file__).parent / "data" / "canonical_vectors.json").read_text("utf-8")
)["vectors"]


@pytest.mark.parametrize("vector", VECTORS, ids=lambda v: v["name"])
def test_golden_vectors(vector):
    assert canonicalize_str(vector["input"]) == vector["canonical"]
    assert canonicalize(vector["input"]) == vector["canonical"].encode("utf-8")


def test_key_order_independence():
    """Re-encoding the same object with different insertion order gives identical bytes."""
    a = {"zeta": 1, "alpha": {"y": 2, "x": [3, {"k": 4}]}}
    b = {"alpha": {"x": [3, {"k": 4}], "y": 2}, "zeta": 1}
    assert canonicalize(a) == canonicalize(b)


def test_whitespace_insignificance():
    """Parsing pretty-printed JSON then canonicalizing equals compact round-trip."""
    raw = '{\n  "b" : 2 ,\n  "a": [ 1,\t{"c": "d"} ]\n}'
    parsed = json.loads(raw)
    assert canonicalize(parsed) == b'{"a":[1,{"c":"d"}],"b":2}'


def test_float_rejected():
    with pytest.raises(CanonicalizationError):
        canonicalize({"bytes_processed": 12.5})
    # Even a whole-valued float is rejected — schema says integers only.
    with pytest.raises(CanonicalizationError):
        canonicalize({"capacity_bytes": 1024.0})


def test_non_string_key_rejected():
    with pytest.raises(CanonicalizationError):
        canonicalize({1: "a"})


def test_unrepresentable_type_rejected():
    with pytest.raises(CanonicalizationError):
        canonicalize({"when": object()})


def test_canonical_json_spec_no_drift():
    """core/CANONICAL_JSON.md and docs-portal/docs/CANONICAL_JSON.md must remain bit-for-bit identical."""
    repo = Path(__file__).resolve().parents[2]
    core_spec = repo / "core" / "CANONICAL_JSON.md"
    docs_spec = repo / "docs-portal" / "docs" / "CANONICAL_JSON.md"
    assert core_spec.is_file(), f"Missing {core_spec}"
    assert docs_spec.is_file(), f"Missing {docs_spec}"
    assert core_spec.read_text(encoding="utf-8") == docs_spec.read_text(encoding="utf-8"), (
        "Specification drift detected between core/CANONICAL_JSON.md and docs-portal/docs/CANONICAL_JSON.md"
    )

