"""Certificate structural validation must not be skippable by type confusion.

The bug this guards against: `validate()` read each section as
`cert.get("issuer") or {}` and then ran its field checks only
`if isinstance(issuer, dict)`. A *truthy* non-dict -- `5`, `"x"`, `True`,
`3.14`, `["a"]` -- survived the `or {}`, failed the `isinstance`, and so skipped
every check for that section while contributing **zero** errors. A certificate
with no issuer identity, no device, no wipe method and no result validated
exactly as well as a genuine one.

That is the whole attack: a signed certificate carrying no meaningful claim at
all still verified as authentic. The block hash is plain SHA-256, so the
signatures were the only authenticity available.

The identical pattern existed in the browser verifier
(`site/verify/verify.js`), so both are covered here. Node is exercised for real
when it is available, and skipped with a clear reason when it is not -- a skipped
test is visible; a missing assertion is not.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from s0.certificate import build_certificate, sign_certificate, validate
from s0.crypto import load_private_pem

REPO = Path(__file__).resolve().parent.parent.parent
JS_VERIFIER = REPO / "site" / "verify" / "verify.js"
DEMO_KEY = REPO / "src" / "s0" / "data" / "keys" / "demo_issuer_private.pem"

SECTIONS = ("issuer", "tool", "device", "wipe", "result")

#: Values that are truthy in Python but are not objects. `0`, `""`, `None`, `[]`
#: and `{}` are all falsy, so the old `or {}` caught them; these are the ones that
#: slipped through.
HOSTILE_VALUES = [5, "x", True, 3.14, ["a"], [1, 2], {"a": 1} or [1], object()]


def _baseline() -> dict:
    """A genuinely valid, signed certificate to mutate."""
    cert = build_certificate(
        organization="Acme Forensics",
        operator_id="op-1",
        tool_name="s0",
        tool_version="2.4.4",
        platform="linux",
        device_id="sha256:deadbeef",
        device_type="removable_disk",
        storage_type="HDD",
        method="OVERWRITE_ZERO_1PASS",
        nist_category="Clear",
        start_time="2026-01-01T00:00:00Z",
        end_time="2026-01-01T00:01:00Z",
        bytes_processed=4096,
        capacity_bytes=8192,
    )
    return sign_certificate(cert, load_private_pem(DEMO_KEY))


@pytest.fixture(scope="module")
def baseline() -> dict:
    cert = _baseline()
    # Guard the guard: if the baseline is not clean, every delta below is noise.
    problems = [p for p in validate(cert) if "signature" not in p]
    assert not problems, f"baseline certificate is not clean: {problems}"
    return cert


# --------------------------------------------------------------------------- #
# Python validator
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("section", SECTIONS)
@pytest.mark.parametrize("value", [5, "x", True, 3.14, ["a"]], ids=repr)
def test_hostile_section_type_is_rejected(baseline, section, value):
    cert = json.loads(json.dumps(baseline))
    cert[section] = value
    problems = validate(cert)
    assert problems, (
        f"{section} = {value!r} is not an object, but validate() reported no "
        "error at all -- the section's field checks were skipped"
    )
    assert any(section in p for p in problems), f"expected an error naming {section}, got: {problems}"


def test_all_five_sections_corrupted_at_once_is_rejected(baseline):
    """The audit's worst case: every section replaced in one certificate."""
    cert = json.loads(json.dumps(baseline))
    for section in SECTIONS:
        cert[section] = 5
    problems = validate(cert)
    assert problems
    missing = [s for s in SECTIONS if not any(s in p for p in problems)]
    assert not missing, f"these sections produced no error: {missing}"


def test_a_missing_section_is_still_reported(baseline):
    """The other half: `or {}` also masked a *missing* section as empty-but-ok."""
    cert = json.loads(json.dumps(baseline))
    del cert["issuer"]
    problems = validate(cert)
    assert any("issuer" in p for p in problems), (
        f"a certificate with no issuer at all must not validate: {problems}"
    )


def test_a_valid_certificate_still_validates(baseline):
    """The fix must not reject well-formed certificates."""
    assert [p for p in validate(baseline) if "signature" not in p] == []


def test_object_with_wrong_field_types_is_still_rejected(baseline):
    """A real dict with hostile contents must fail on the field, not the type."""
    cert = json.loads(json.dumps(baseline))
    cert["issuer"] = {"organization": 5, "operator_id": []}
    problems = validate(cert)
    assert any("issuer" in p for p in problems)


# --------------------------------------------------------------------------- #
# Browser verifier -- the same bug shipped in two implementations
# --------------------------------------------------------------------------- #


def _node_available() -> bool:
    return shutil.which("node") is not None


requires_node = pytest.mark.skipif(not _node_available(), reason="node not installed")


def _js_validate(cert: dict) -> list[str]:
    """Run site/verify/verify.js's structural validator and return its errors."""
    driver = REPO / "tests" / "portal" / "_validate_driver.cjs"
    payload = json.dumps(cert)
    result = subprocess.run(
        ["node", str(driver)],
        input=payload,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        raise AssertionError(f"driver failed: {result.stderr[-800:]}")
    return json.loads(result.stdout)["errors"]


@requires_node
@pytest.mark.parametrize("section", SECTIONS)
@pytest.mark.parametrize("value", [5, "x", True, ["a"]], ids=repr)
def test_js_verifier_rejects_hostile_section_type(baseline, section, value):
    cert = json.loads(json.dumps(baseline))
    cert[section] = value
    errors = _js_validate(cert)
    assert errors, (
        f"verify.js accepted {section} = {value!r} with no error -- the browser "
        "verifier has the same type-confusion skip the Python one had"
    )
    assert any(section in e for e in errors), f"expected an error naming {section}, got: {errors}"


@requires_node
def test_js_verifier_accepts_the_baseline(baseline):
    assert _js_validate(baseline) == []


@requires_node
def test_both_verifiers_agree_on_hostile_types(baseline):
    """Parity is the property that matters: the two must not diverge.

    The audit's deeper point was that Python and JS are shipped as
    interchangeable implementations of one spec. A type accepted by one and
    rejected by the other is a divergence regardless of which is correct.
    """
    disagreements = []
    for section in SECTIONS:
        for value in (5, "x", True, ["a"]):
            cert = json.loads(json.dumps(baseline))
            cert[section] = value
            py = [p for p in validate(cert) if "signature" not in p]
            js = _js_validate(cert)
            py_rejects = bool(py)
            js_rejects = bool(js)
            if py_rejects != js_rejects:
                disagreements.append(
                    f"{section}={value!r}: python_rejects={py_rejects} js_rejects={js_rejects}"
                )
    assert not disagreements, "the two verifiers disagree on the same signed bytes:\n  " + "\n  ".join(
        disagreements
    )


# --------------------------------------------------------------------------- #
# The JSON Schema is the third opinion
# --------------------------------------------------------------------------- #


def test_cert_schema_also_requires_objects():
    """`cert_schema.json` already rejected these; the code now matches it.

    Worth asserting explicitly: the schema was the ground truth the audit checked
    against, and the two hand-written validators had drifted away from it.
    """
    schema = json.loads((REPO / "src" / "s0" / "data" / "cert_schema.json").read_text(encoding="utf-8"))
    props = schema["properties"]
    for section in SECTIONS:
        assert props[section]["type"] == "object", (
            f"cert_schema.json says {section} must be an object; the validators must agree"
        )
