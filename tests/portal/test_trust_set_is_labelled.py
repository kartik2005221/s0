"""The portal's trust set is one demo key. That is a decision, and it must be visible.

`site/verify/keys.json` pins exactly one issuer: the deliberately unaccredited development
key. It is there so the portal works out of the box and so the demo path is testable. It is
not accreditation -- a certificate that verifies against it proves an Ed25519 signature is
internally consistent and nothing about who performed the sanitization.

This is an owner decision rather than a defect, so the fix is not to remove the key. It is
to make the state unmissable to whoever reads `keys.json` next, and to refuse the two
configurations that are actually dangerous: a trust set that silently claims to be
accredited while holding only the demo key, and an empty one that looks like an outage.

`verify.js` is asserted separately in `test_web_output_path_parity.py` and the portal
tests: a demo-key certificate comes back `attested: false` with `cliExitCode: 75`, matching
what `s0 verify` exits for the same file.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
KEYS = REPO_ROOT / "site" / "verify" / "keys.json"

DEMO_FINGERPRINT = "sha256:8396af8c07a7d40f98ba492cf2b61e23fa768e66a9f627b02a9caff464e48c06"


@pytest.fixture(scope="module")
def keys() -> dict:
    return json.loads(KEYS.read_text(encoding="utf-8"))


class TestTheTrustSetIsLabelled:
    def test_it_states_what_it_is(self, keys):
        assert keys.get("trust_set", {}).get("state") == "DEMO ONLY", (
            "keys.json does not say its trust set is demo-only. Anyone reading it should "
            "not have to know the project's history to see that."
        )

    def test_it_says_what_would_make_it_accredited(self, keys):
        text = keys["trust_set"]["before_you_publish_a_real_release"].lower()
        assert "state" in text and "accredited" in text, "the note does not tell the owner what to change"

    def test_it_warns_against_deleting_the_key(self, keys):
        """An empty trust set rejects genuine certificates and reads as an outage."""
        text = keys["trust_set"]["before_you_publish_a_real_release"].lower()
        assert "empty" in text and "outage" in text, (
            "the obvious wrong fix -- deleting the entry -- is not called out"
        )

    def test_it_records_the_demo_fingerprint(self, keys):
        assert keys["trust_set"]["demo_key_fingerprint"] == DEMO_FINGERPRINT, (
            "the recorded fingerprint does not match the key actually pinned; one of them is stale"
        )


class TestThePinnedKeyIsTheDemoKeyAndSaysSo:
    def test_exactly_one_key_is_pinned(self, keys):
        assert len(keys["trusted_keys"]) == 1, (
            "the trust set changed; re-read what is pinned and update trust_set.state"
        )

    def test_the_pinned_key_is_the_demo_key(self, keys):
        assert keys["trusted_keys"][0]["fingerprint"] == DEMO_FINGERPRINT

    def test_the_issuer_name_says_unaccredited(self, keys):
        """Belt and braces with the fingerprint: the name is what an operator reads."""
        issuer = keys["trusted_keys"][0]["issuer"].lower()
        assert "demo" in issuer and "unaccredited" in issuer, (
            f"the pinned issuer is named {keys['trusted_keys'][0]['issuer']!r}, which does "
            f"not say it is a demo key"
        )


class TestTheClaimAndTheContentAgree:
    """`state` is a claim someone has to keep true.

    Nothing else enforces it: `keys.json` is data, and a stale label is worse than no label
    because it is believed.
    """

    def test_demo_only_means_the_only_key_is_the_demo_key(self, keys):
        state = keys.get("trust_set", {}).get("state")
        pinned = [k["fingerprint"] for k in keys["trusted_keys"]]
        if state == "DEMO ONLY":
            assert pinned == [DEMO_FINGERPRINT], f"state says DEMO ONLY but the trust set holds {pinned}"
        elif state == "ACCREDITED":
            assert DEMO_FINGERPRINT not in pinned, (
                "state says ACCREDITED but the trust set still holds only the demo key"
            )
        else:
            pytest.fail(f"trust_set.state is {state!r}; expected DEMO ONLY or ACCREDITED")
