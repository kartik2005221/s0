"""Canonical form tests against golden vectors (docs/architecture/canonical-json.md contract)."""

import json
from pathlib import Path

import pytest

from s0.canonical import CanonicalizationError, canonicalize, canonicalize_str

VECTORS = json.loads((Path(__file__).parent / "data" / "canonical_vectors.json").read_text("utf-8"))[
    "vectors"
]


@pytest.mark.parametrize("vector", VECTORS, ids=lambda v: v["name"])
def test_golden_vectors(vector):
    if "error" in vector:
        # A refusal vector. Both implementations must refuse, and for the same
        # reason, or they diverge on the same bytes.
        with pytest.raises(CanonicalizationError, match=vector["error"]):
            canonicalize_str(vector["input"])
        with pytest.raises(CanonicalizationError, match=vector["error"]):
            canonicalize(vector["input"])
        return
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
    """Verify docs/architecture/canonical-json.md exists and contains the 7 canonical serialization rules."""
    repo = Path(__file__).resolve().parents[2]
    core_spec = repo / "docs" / "architecture" / "canonical-json.md"
    assert core_spec.is_file(), f"Missing {core_spec}"
    text = core_spec.read_text(encoding="utf-8")
    for rule in [
        "1. **Encoding.**",
        "2. **Objects.**",
        "3. **Whitespace.**",
        "4. **Strings.**",
        "5. **Numbers.**",
        "6. **Literals.**",
        "7. **Arrays.**",
    ]:
        assert rule in text, f"Missing rule {rule} in docs/architecture/canonical-json.md"
