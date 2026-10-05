"""`generate_pdf` is called directly by `s0 wipe`, so it has to survive a bad certificate.

Called with anything other than a well-formed signed certificate, the renderer raised
whatever subscript it reached first, from the middle of the layout code:

    {"cert_uuid": 1, "wipe": "nope", "signature": []}  ->  KeyError: 'result'
    {k: None for k in cert}                             ->  TypeError: 'NoneType' is not
                                                              subscriptable

Neither message names a certificate field, so an operator holding a malformed artifact had
no way to tell bad input from a renderer bug.

The case that mattered more: a certificate with a `signature` but **no `wipe` record**
rendered a complete-looking PDF with an empty wipe section. The PDF was presentable and
unattested -- worse than an exception, because an exception stops the wipe from reporting
success.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

FIXTURE = Path(__file__).resolve().parents[1] / "portal" / "fixtures" / "sample_valid_cert.json"


@pytest.fixture
def cert() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_a_valid_certificate_still_renders(cert, tmp_path):
    from s0 import pdfgen

    out = pdfgen.generate_pdf(cert, tmp_path / "c.pdf")
    assert out.is_file() and out.stat().st_size > 0


def test_an_unsigned_certificate_is_still_refused(cert, tmp_path):
    from s0 import pdfgen

    unsigned = {k: v for k, v in cert.items() if k != "signature"}
    with pytest.raises(ValueError, match="UNSIGNED"):
        pdfgen.generate_pdf(unsigned, tmp_path / "c.pdf")


def test_a_missing_wipe_record_is_refused_rather_than_rendered_blank(cert, tmp_path):
    from s0 import pdfgen

    no_wipe = {k: v for k, v in cert.items() if k != "wipe"}
    out = tmp_path / "c.pdf"
    with pytest.raises(ValueError, match="wipe"):
        pdfgen.generate_pdf(no_wipe, out)
    assert not out.exists(), (
        "a PDF was produced for a certificate with no wipe record; that file looks "
        "presentable and attests to nothing"
    )


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        ("cert_uuid", None, "cert_uuid"),
        ("cert_uuid", 1, "cert_uuid"),
        ("wipe", "not a dict", "wipe"),
        ("signature", [], "signature"),
        ("result", "not a dict", "result"),
    ],
)
def test_a_wrongly_typed_field_names_itself(cert, tmp_path, field, value, expected):
    """The error has to say *which* field, or it is indistinguishable from a bug."""
    from s0 import pdfgen

    bad = {**cert, field: value}
    with pytest.raises((TypeError, ValueError), match=expected):
        pdfgen.generate_pdf(bad, tmp_path / "c.pdf")


def test_a_result_without_a_status_is_refused(cert, tmp_path):
    from s0 import pdfgen

    with pytest.raises(ValueError, match="status"):
        pdfgen.generate_pdf({**cert, "result": {}}, tmp_path / "c.pdf")


def test_a_non_dict_certificate_is_refused(tmp_path):
    from s0 import pdfgen

    with pytest.raises(TypeError, match="must be a dict"):
        pdfgen.generate_pdf([], tmp_path / "c.pdf")


def test_the_refusal_tells_you_to_reissue_not_repair(cert, tmp_path):
    """A signed certificate is tamper-evident. "Repairing" it is never the answer."""
    from s0 import pdfgen

    no_wipe = {k: v for k, v in cert.items() if k != "wipe"}
    with pytest.raises(ValueError, match="re-issue"):
        pdfgen.generate_pdf(no_wipe, tmp_path / "c.pdf")
