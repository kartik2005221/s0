"""Sanitize attestation: reading what the device says, and bounding what we sampled.

The central test in this file is a regression. The previous decoder read the
Sanitize Status field as a bit set, but bits 3:0 are a status *code*, so a
sanitize that had **failed** was decoded as completed and not failed -- a device
that refused to erase attested as erased. That is the single worst failure this
tool could have, and it was invisible without hardware, which is why the field
layout is written out and tested against synthesised log pages instead of left
implicit in a regex.
"""

from __future__ import annotations

import pytest

from s0.wipe import attest as A
from s0.wipe.methods.nvme import parse_sanitize_log

# --------------------------------------------------------------------------- #
# The regression
# --------------------------------------------------------------------------- #

class TestStatusDecoding:
    @pytest.mark.parametrize("code,completed,failed", [
        (A.SSTAT_NEVER_SANITIZED, False, False),
        (A.SSTAT_COMPLETE_SUCCESS, True, False),
        (A.SSTAT_IN_PROGRESS, False, False),
        (A.SSTAT_COMPLETED_FAILED, False, True),
    ])
    def test_each_status_code(self, code, completed, failed):
        st = A.parse_sanitize_status_log(A.build_sanitize_status_log(status=code))
        assert st.status_code == code
        assert st.completed_successfully is completed
        assert st.failed is failed
        assert st.known_status

    def test_a_failed_sanitize_is_never_reported_as_completed(self):
        """The defect. Read the assertion as the requirement, not the test."""
        for code in range(0, 16):
            st = A.parse_sanitize_status_log(A.build_sanitize_status_log(status=code))
            assert not (st.completed_successfully and st.failed)
            if code == A.SSTAT_COMPLETED_FAILED:
                assert st.failed and not st.completed_successfully

    def test_the_old_bit_set_reading_would_have_been_wrong(self):
        """Pin the specific misreading, so the reason for the test is legible."""
        success, failure = 0x0001, 0x0003
        old_completed = lambda v: bool(v & 0x2)      # noqa: E731
        old_failed = lambda v: bool(v & 0x4)         # noqa: E731
        # The old decoder called a successful sanitize "not completed"...
        assert old_completed(success) is False
        # ...and called a failed one "completed, not failed".
        assert old_completed(failure) is True
        assert old_failed(failure) is False

    def test_an_unrecognised_code_is_reported_as_such(self):
        """Mapping an unknown code onto a defined one is the failure to avoid."""
        st = A.parse_sanitize_status_log(A.build_sanitize_status_log(status=0x7))
        assert st.status_code == 0x7
        assert not st.known_status
        assert not st.completed_successfully and not st.failed
        assert "unrecognised" in st.status_text

    def test_the_text_decoder_agrees_with_the_binary_one(self):
        """One field layout, one decoder. Two disagreeing copies is how the bug
        survived."""
        for code in (0, 1, 2, 3, 0x7):
            page = A.build_sanitize_status_log(status=code, global_data_erased=True)
            binary = A.parse_sanitize_status_log(page)
            text = parse_sanitize_log(f"[SSTAT]: 0x{code | 0x100:04x}\n[SPROG]: 0%")
            assert text["status_code"] == binary.status_code
            assert text["completed"] == binary.completed_successfully
            assert text["failed"] == binary.failed
            assert text["global_data_erased"] == binary.global_data_erased


# --------------------------------------------------------------------------- #
# Global Data Erased: the strongest evidence the specification offers
# --------------------------------------------------------------------------- #

class TestGlobalDataErased:
    def test_it_is_decoded(self):
        st = A.parse_sanitize_status_log(
            A.build_sanitize_status_log(global_data_erased=True))
        assert st.global_data_erased is True
        st = A.parse_sanitize_status_log(
            A.build_sanitize_status_log(global_data_erased=False))
        assert st.global_data_erased is False

    def test_gde_set_with_a_failed_sanitize_is_still_a_failure(self):
        """A device can report the bit and still have failed.

        The bit says nothing has been written *since the last successful
        sanitize*; it does not say the last sanitize was this one. Reading it
        without the status is how a failed operation gets attested as success.
        """
        st = A.parse_sanitize_status_log(A.build_sanitize_status_log(
            status=A.SSTAT_COMPLETED_FAILED, global_data_erased=True))
        assert st.global_data_erased is True
        assert st.failed
        assert not st.completed_successfully

    def test_media_verification_canceled_is_decoded(self):
        st = A.parse_sanitize_status_log(
            A.build_sanitize_status_log(media_verification_canceled=True))
        assert st.media_verification_canceled is True

    def test_completed_passes_is_absent_unless_an_overwrite(self):
        st = A.parse_sanitize_status_log(
            A.build_sanitize_status_log(completed_passes=0))
        assert st.completed_passes is None, "a cleared field is not zero passes"
        st = A.parse_sanitize_status_log(
            A.build_sanitize_status_log(completed_passes=3))
        assert st.completed_passes == 3


# --------------------------------------------------------------------------- #
# Progress
# --------------------------------------------------------------------------- #

class TestProgress:
    def test_the_denominator_is_65536_not_100(self):
        """SPROG is a u16 over 65536. Reading it as a percentage is a 655x error
        that makes a finished sanitize look like it did 0.15% of the work."""
        st = A.parse_sanitize_status_log(A.build_sanitize_status_log(
            status=A.SSTAT_IN_PROGRESS, progress=0xFFFF))
        assert st.progress_percent == pytest.approx(100.0, abs=0.01)
        st = A.parse_sanitize_status_log(A.build_sanitize_status_log(
            status=A.SSTAT_IN_PROGRESS, progress=0x8000))
        assert st.progress_percent == pytest.approx(50.0, abs=0.01)

    def test_progress_is_absent_when_not_in_progress(self):
        """The specification sets SPROG to FFFFh unless a sanitize is running,
        so reporting it otherwise would report a meaningless 100%."""
        st = A.parse_sanitize_status_log(A.build_sanitize_status_log(
            status=A.SSTAT_COMPLETE_SUCCESS, progress=0xFFFF))
        assert st.progress_fraction is None
        assert st.progress_percent is None


# --------------------------------------------------------------------------- #
# The recorded mechanism
# --------------------------------------------------------------------------- #

class TestRecordedAction:
    @pytest.mark.parametrize("action,text", [
        (A.SANACT_BLOCK_ERASE, "block erase"),
        (A.SANACT_CRYPTO_ERASE, "crypto erase"),
        (A.SANACT_OVERWRITE, "overwrite"),
        (A.SANACT_EXIT_FAILURE, "exit failure"),
    ])
    def test_the_action_comes_from_scdw10(self, action, text):
        st = A.parse_sanitize_status_log(
            A.build_sanitize_status_log(action=action))
        assert st.action_text == text

    def test_a_zero_overwrite_pass_count_means_sixteen(self):
        """The specification's encoding, not a missing value."""
        st = A.parse_sanitize_status_log(
            A.build_sanitize_status_log(action=A.SANACT_OVERWRITE, overwrite_passes=0))
        assert st.overwrite_passes == 16

    def test_the_flags_are_decoded(self):
        st = A.parse_sanitize_status_log(A.build_sanitize_status_log())
        assert st.allow_unrestricted_exit in (True, False)
        assert st.invert_pattern_between_passes in (True, False)
        assert 0 <= st.no_deallocate <= 7

    def test_an_absent_scdw10_reads_as_unrecorded(self):
        out = A.parse_nvme_cli_output("[SSTAT]: 0x0001")
        assert "unrecorded" in out["sanitize_status"]["action"]

    def test_the_text_fallback_also_records_the_mechanism(self):
        out = A.parse_nvme_cli_output("[SSTAT]: 0x0201\n[SCDW10]: 0x00000200")
        assert out["sanitize_status"]["action"] == "block erase"


class TestSerialisation:
    def test_as_dict_is_json_serialisable_and_complete(self):
        import json
        st = A.parse_sanitize_status_log(A.build_sanitize_status_log())
        d = st.as_dict()
        json.dumps(d)
        for key in ("status_code", "status_text", "completed_successfully", "failed",
                    "global_data_erased", "scdw10", "action", "estimated_seconds"):
            assert key in d, key

    def test_a_short_page_is_refused(self):
        with pytest.raises(ValueError, match="the fields end at"):
            A.parse_sanitize_status_log(b"\x00" * 8)


# --------------------------------------------------------------------------- #
# Sampling
# --------------------------------------------------------------------------- #

class TestSamplingProof:
    def test_a_clean_sample_carries_a_bound(self):
        p = A.build_sampling_proof(1000, 1_000_000, 0, "0x5A pattern")
        assert p.clean
        assert p.observed_fraction == 0.0
        assert 0 < p.upper_bound_fraction < 1
        assert "no sampled block matched" in p.claim()

    def test_a_dirty_sample_does_not_claim_cleanliness(self):
        p = A.build_sampling_proof(100, 1000, 3, "pattern")
        assert not p.clean
        assert "is not sanitized" in p.claim()

    def test_zero_blocks_sampled_claims_nothing(self):
        p = A.build_sampling_proof(0, 1000, 0, "pattern")
        assert p.clean is True
        assert "no blocks were sampled" in p.claim(), \
            "an empty sample must not read as verification"

    def test_more_samples_means_a_tighter_bound(self):
        bounds = [A.build_sampling_proof(n, 10**9, 0, "p").upper_bound_fraction
                  for n in (100, 1000, 10_000)]
        assert bounds == sorted(bounds, reverse=True)

    @pytest.mark.parametrize("n,expected_pct", [
        (59, 5.0), (299, 1.0), (2995, 0.1),
    ])
    def test_the_k_zero_closed_form(self, n, expected_pct):
        """k = 0 has an exact closed form: 1 - alpha**(1/n).

        Checked against the rule of thumb NIST guidance quotes (3/n gives about
        95% at n = 3/p), which is what makes these numbers recognisable.
        """
        p = A.build_sampling_proof(n, 10**9, 0, "p")
        assert p.upper_bound_fraction * 100 == pytest.approx(expected_pct, rel=0.02)

    def test_the_bound_is_reported_honestly_without_scipy(self):
        """A dirty sample without SciPy is an approximation and says so."""
        p = A.build_sampling_proof(1000, 10**6, 3, "p")
        if not A._exact_bounds_available():
            # The fallback is an approximation and names itself as one, and
            # says why rather than just being quieter about it.
            assert "Wilson" in p.method
            assert "SciPy" in p.method
        else:
            assert "Clopper-Pearson" in p.method

    def test_a_clean_sample_always_claims_exactness(self):
        p = A.build_sampling_proof(1000, 10**6, 0, "p")
        assert "exact" in p.method.lower()

    def test_the_required_sample_size_is_honest_about_magnitude(self):
        """0.01% of a large drive is a lot of blocks, and saying so matters."""
        assert A.required_sample_size(0.95, 0.01) == pytest.approx(299, abs=2)
        assert A.required_sample_size(0.95, 0.0001) > 29_000
        assert A.required_sample_size(0.99, 0.0001) > A.required_sample_size(0.95, 0.0001)

    def test_sampling_more_than_exists_is_refused(self):
        with pytest.raises(ValueError, match="not possible"):
            A.build_sampling_proof(100, 50, 0, "p")

    def test_invalid_probabilities_are_refused(self):
        for bad in (0.0, 1.0, -0.1, 1.5):
            with pytest.raises(ValueError):
                A.required_sample_size(bad, 0.01)
            with pytest.raises(ValueError):
                A.required_sample_size(0.95, bad)

    def test_as_dict_carries_the_claim_not_just_the_numbers(self):
        d = A.build_sampling_proof(1000, 10**6, 0, "0x5A").as_dict()
        assert d["clean"] is True
        assert "confidence" in d["claim"]
        assert d["upper_bound_fraction"] > 0


# --------------------------------------------------------------------------- #
# Tiers and downgrade
# --------------------------------------------------------------------------- #

class TestTiers:
    @pytest.mark.parametrize("action,tier", [
        (A.SANACT_BLOCK_ERASE, "Sanitize"),
        (A.SANACT_CRYPTO_ERASE, "Sanitize"),
        (A.SANACT_OVERWRITE, "Purge"),
    ])
    def test_the_tier_an_action_supports(self, action, tier):
        assert A.tier_for_action(action) == tier

    @pytest.mark.parametrize("action", [None, A.SANACT_EXIT_FAILURE,
                                        A.SANACT_EXIT_MEDIA_VERIFICATION, 0xF])
    def test_actions_that_support_no_tier(self, action):
        assert A.tier_for_action(action) is None, \
            "a refused action must not be mapped onto the nearest tier"

    def test_a_downgrade_is_recorded_with_its_reason(self):
        r = A.refuse_downgrade("Sanitize", "Purge", "the controller offered only overwrite")
        assert r["downgraded"] is True
        assert r["requested_tier"] == "Sanitize"
        assert r["achieved_tier"] == "Purge"
        assert "NOT achieved" in r["statement"]

    def test_no_downgrade_still_records_the_achievement(self):
        r = A.refuse_downgrade("Sanitize", "Sanitize", "crypto erase completed")
        assert r["downgraded"] is False

    def test_nothing_achieved_is_stated_rounded_up(self):
        r = A.refuse_downgrade("Sanitize", None, "device does not support sanitize")
        assert r["achieved_tier"] is None
        assert "none" in r["statement"]

    def test_the_two_vocabularies_are_kept_distinct(self):
        assert "sanitize" in A.NIST_800_88_TERMS
        assert "purge" in A.NIST_800_88_TERMS
        assert "not proof of absence" in A.NIST_800_88_TERMS["verify"]


# --------------------------------------------------------------------------- #
# The bound has to reach the certificate, not just the library
# --------------------------------------------------------------------------- #

class TestBoundReachesTheCertificate:
    """The schema has carried these fields for longer than the code has used them.

    `population_blocks`, `confidence_percent` and
    `residual_fraction_upper_bound_ppm` are in `cert_schema.json` and in the
    validator's permitted set, and nothing populated them. A certificate that
    said "64 samples, all zero" and gave no bound invited the reader to treat 64
    as sufficient.
    """

    def _verify(self, tmp_path, samples):
        from s0.wipe.methods.base import Target
        from s0.wipe.planner import verify_wipe
        img = tmp_path / "v.img"
        img.write_bytes(b"\x00" * 4_000_000)
        target = Target(path=str(img), kind="image",
                        capacity_bytes=4_000_000, sector_size=512)
        verif, _post = verify_wipe(target, "zero", samples=samples,
                                   sample_bytes=4096)
        return verif

    def test_the_population_is_counted_in_sectors(self, tmp_path):
        """One read per sector-aligned offset, so the population is sectors.

        Dividing capacity by `sample_bytes` instead gives the wrong population,
        and on a small image gives a population smaller than the sample count --
        impossible, and what a test caught.
        """
        verif = self._verify(tmp_path, samples=64)
        assert verif["population_blocks"] == 4_000_000 // 512
        assert verif["population_blocks"] >= verif["samples_checked"]

    def test_a_tiny_target_does_not_produce_an_impossible_population(self, tmp_path):
        from s0.wipe.methods.base import Target
        from s0.wipe.planner import verify_wipe
        img = tmp_path / "tiny.img"
        img.write_bytes(b"\x00" * 8192)
        target = Target(path=str(img), kind="image", capacity_bytes=8192,
                        sector_size=512)
        verif, _ = verify_wipe(target, "zero", samples=8, sample_bytes=4096)
        assert verif["population_blocks"] >= verif["samples_checked"], verif

    def test_the_bound_is_64_samples_being_about_4_5_percent(self, tmp_path):
        """The number the skill previously implied was sufficient."""
        verif = self._verify(tmp_path, samples=64)
        assert verif["confidence_percent"] == 95
        ppm = verif["residual_fraction_upper_bound_ppm"]
        assert 40_000 <= ppm <= 50_000, f"expected ~4.5%, got {ppm / 10000:.2f}%"

    def test_more_samples_tighten_the_recorded_bound(self, tmp_path):
        weak = self._verify(tmp_path, samples=64)
        strong = self._verify(tmp_path, samples=3000)
        assert (strong["residual_fraction_upper_bound_ppm"]
                < weak["residual_fraction_upper_bound_ppm"])

    def test_every_field_is_schema_permitted(self, tmp_path):
        """Floats are forbidden by the schema, which is why the bound is an
        integer count of parts per million rather than a float fraction."""
        import json
        from pathlib import Path
        schema = json.loads(
            (Path(A.__file__).parent.parent / "data" / "cert_schema.json").read_text())
        allowed = set(schema["properties"]["result"]["properties"]["verification"]["properties"])
        verif = self._verify(tmp_path, samples=64)
        for key, value in verif.items():
            if value is None:
                continue
            assert key in allowed, f"{key} is not in the certificate schema"
            spec = schema["properties"]["result"]["properties"]["verification"]["properties"][key]
            if spec.get("type") == "integer":
                assert isinstance(value, int) and not isinstance(value, bool), key

    def test_a_dirty_readback_is_not_reported_as_clean(self, tmp_path):
        """A surviving needle must fail the check and count as non-matching.

        This is the case the whole bound attaches to: a sample that found
        residue cannot be summarised as a clean sample no matter how many blocks
        were read.
        """
        from s0.wipe.methods.base import Target
        from s0.wipe.planner import verify_wipe
        needle = b"NEEDLE-FORGOT-TO-ERASE"
        img = tmp_path / "d.img"
        img.write_bytes(b"\x00" * 1_000_000 + needle + b"\x00" * (1_000_000 - len(needle)))
        target = Target(path=str(img), kind="image", capacity_bytes=2_000_000,
                        sector_size=512)
        # Offsets chosen to straddle the residue.
        verif, _ = verify_wipe(target, "zero", offsets=[0, 1_000_000],
                               sample_bytes=4096, planted_needles=[needle])
        assert verif["all_samples_match_wipe_pattern"] is False
        assert verif["planted_pattern_hits_after"] >= 1
        # A failed sample is not a clean sample, so the bound is not a clean bound.
        assert "not sanitized" in verif["attestation"] or verif[
            "residual_fraction_upper_bound_ppm"] == 1_000_000
