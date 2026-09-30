"""Sanitize attestation: read what the device says, and prove what we sampled.

Why this module exists
----------------------
A wipe certificate that says "sanitized" is a claim. The only thing that makes
it evidence is what the device reported afterwards, and the one field that
matters most is NVMe's Global Data Erased bit: the controller's own statement
that no namespace logical block has been written since manufacture or since the
last successful sanitize. Everything else in a wipe report is either something
the operator asserted or something this tool inferred.

The defect this replaces
------------------------
The previous decoder read the Sanitize Status field as a set of boolean bits:
`completed = bits & 0x2`, `failed = bits & 0x4`. Those are not the field's
meaning. Bits 3:0 are a *status code* -- 0x0 never sanitized, 0x1 completed
successfully, 0x2 in progress, 0x3 failed. So the old decoder read a
**successfully completed** sanitize (SSTAT 0x0001) as not completed, and read a
**failed** sanitize (SSTAT 0x0003) as both completed and not failed. A device
that refused to erase was attested as erased. The Global Data Erased bit, the
strongest evidence the specification offers, was not decoded at all.

That is the kind of error that only shows up on hardware nobody in the
development environment had, which is exactly why the field layout is written
out here with its source and tested against synthesised log pages rather than
left implicit in a regex.

Field layout, as read
---------------------
Sanitize Status log page, log identifier 0x81, 512 bytes, little-endian, per
the NVMe Base specification and the libnvme `nvme_sanitize_log_page` structure:

    offset  size  field
    0x00    2     SPROG   sanitize progress; numerator over 65536
    0x02    2     SSTAT   sanitize status
    0x04    4     SCDW10  the Command Dword 10 that started the operation
    0x08    4     ETO     estimated seconds, overwrite
    0x0C    4     ETBE    estimated seconds, block erase
    0x10    4     ETCE    estimated seconds, crypto erase
    0x14    4     ETOND   estimated seconds, overwrite, no-deallocate
    0x18    4     ETBEND  estimated seconds, block erase, no-deallocate
    0x1C    4     ETCEND  estimated seconds, crypto erase, no-deallocate
    0x20    480   reserved

SSTAT bit assignments:

    3:0    status code
    8      Global Data Erased
    9      Media Verification Canceled
    15:12 completed passes (cleared unless the operation was an Overwrite)

Command Dword 10 for the Sanitize admin command, opcode 0x84:

    3:0    AUSE   allow unrestricted sanitize exit
    7:4    OIPBP  overwrite invert pattern between passes
    11:8   SANACT sanitize action
    14:12  OVRPAT overwrite pattern (low 12 bits shown here as recorded)
    20:15  OWPASS overwrite pass count, where 0 means 16 passes
    23:21  ND     no-deallocate / modifies media after sanitize

SANACT values: 0x1 exit failure, 0x2 block erase, 0x3 overwrite, 0x4 crypto
erase, 0x5 exit media verification.

Why the action is recorded rather than assumed
----------------------------------------------
A certificate must be able to say which mechanism was used, and the only
trustworthy source is the command the controller says it ran. Recording SCDW10
means the certificate reports the device's own account of what happened, which
is what makes it checkable against the device later.
"""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass, field

#: Sanitize admin command opcode. Not 0xF4, which is not an NVMe command; that
#: value circulates widely and is wrong.
NVME_SANITIZE_OPCODE = 0x84
#: Sanitize Status log page identifier.
NVME_LOG_SANITIZE_STATUS = 0x81
#: Every NVMe log page is 512 bytes.
NVME_LOG_PAGE_BYTES = 512

# Status codes, SSTAT bits 3:0.
SSTAT_NEVER_SANITIZED = 0x0
SSTAT_COMPLETE_SUCCESS = 0x1
SSTAT_IN_PROGRESS = 0x2
SSTAT_COMPLETED_FAILED = 0x3

SSTAT_STATUS_TEXT = {
    SSTAT_NEVER_SANITIZED: "the NVM subsystem has never been sanitized",
    SSTAT_COMPLETE_SUCCESS: "the most recent sanitize operation completed successfully",
    SSTAT_IN_PROGRESS: "a sanitize operation is currently in progress",
    SSTAT_COMPLETED_FAILED: "the most recent sanitize operation FAILED",
}

# Sanitize actions, CDW10 bits 11:8.
SANACT_EXIT_FAILURE = 0x1
SANACT_BLOCK_ERASE = 0x2
SANACT_OVERWRITE = 0x3
SANACT_CRYPTO_ERASE = 0x4
SANACT_EXIT_MEDIA_VERIFICATION = 0x5

SANACT_TEXT = {
    SANACT_EXIT_FAILURE: "exit failure",
    SANACT_BLOCK_ERASE: "block erase",
    SANACT_OVERWRITE: "overwrite",
    SANACT_CRYPTO_ERASE: "crypto erase",
    SANACT_EXIT_MEDIA_VERIFICATION: "exit media verification",
}

#: A status code outside the defined set. Reported as-is rather than coerced to
#: one of the four, because a certificate that maps an unknown code onto
#: "completed" is precisely the failure this module exists to prevent.
SSTAT_UNKNOWN = -1


@dataclass
class SanitizeStatus:
    """One device's own account of its most recent sanitize operation."""
    status_code: int
    global_data_erased: bool | None
    media_verification_canceled: bool | None
    completed_passes: int | None
    progress_fraction: float | None
    #: The raw Command Dword 10 the controller says it acted on.
    scdw10: int
    estimated_seconds: dict = field(default_factory=dict)
    raw: bytes = b""

    @property
    def status_text(self) -> str:
        return SSTAT_STATUS_TEXT.get(
            self.status_code,
            f"unrecognised status code 0x{self.status_code:x}")

    @property
    def known_status(self) -> bool:
        return self.status_code in SSTAT_STATUS_TEXT

    @property
    def completed_successfully(self) -> bool:
        return self.status_code == SSTAT_COMPLETE_SUCCESS

    @property
    def failed(self) -> bool:
        return self.status_code == SSTAT_COMPLETED_FAILED

    @property
    def in_progress(self) -> bool:
        return self.status_code == SSTAT_IN_PROGRESS

    @property
    def never_sanitized(self) -> bool:
        return self.status_code == SSTAT_NEVER_SANITIZED

    @property
    def action(self) -> int | None:
        return (self.scdw10 >> 8) & 0xF

    @property
    def action_text(self) -> str:
        act = self.action
        if act is None or act not in SANACT_TEXT:
            return "unrecorded or unrecognised"
        return SANACT_TEXT[act]

    @property
    def overwrite_passes(self) -> int:
        """Passes the device was asked for; a stored 0 means 16."""
        n = (self.scdw10 >> 15) & 0x3F
        return 16 if n == 0 else n

    @property
    def no_deallocate(self) -> int:
        return (self.scdw10 >> 21) & 0x7

    @property
    def allow_unrestricted_exit(self) -> bool:
        return bool(self.scdw10 & 0x1)

    @property
    def invert_pattern_between_passes(self) -> bool:
        return bool((self.scdw10 >> 4) & 0x1)

    @property
    def progress_percent(self) -> float | None:
        return None if self.progress_fraction is None else self.progress_fraction * 100.0

    def as_dict(self) -> dict:
        return {
            "status_code": self.status_code,
            "status_text": self.status_text,
            "status_known": self.known_status,
            "completed_successfully": self.completed_successfully,
            "failed": self.failed,
            "in_progress": self.in_progress,
            "never_sanitized": self.never_sanitized,
            "global_data_erased": self.global_data_erased,
            "media_verification_canceled": self.media_verification_canceled,
            "completed_passes": self.completed_passes,
            "progress_percent": self.progress_percent,
            "scdw10": f"0x{self.scdw10:08x}",
            "action": self.action_text,
            "overwrite_passes_requested": self.overwrite_passes,
            "no_deallocate": self.no_deallocate,
            "allow_unrestricted_exit": self.allow_unrestricted_exit,
            "invert_pattern_between_passes": self.invert_pattern_between_passes,
            "estimated_seconds": self.estimated_seconds,
        }


def parse_sanitize_status_log(page: bytes) -> SanitizeStatus:
    """Parse a raw 512-byte Sanitize Status log page.

    Every field is bounds-checked and an out-of-range status code is reported
    as unrecognised rather than mapped onto a defined one.
    """
    if len(page) < 0x20:
        raise ValueError(
            f"sanitize status log page is {len(page)} bytes; the fields end at 0x20")
    sprog, sstat, scdw10 = struct.unpack_from("<HHI", page, 0)
    eto, etbe, etce, etond, etbend, etcend = struct.unpack_from("<IIIIII", page, 0x08)
    status = sstat & 0xF
    # The completed-passes field is only meaningful for an Overwrite, and the
    # specification says it is cleared otherwise, so it is reported as absent
    # rather than as zero passes.
    passes_raw = (sstat >> 12) & 0xF
    return SanitizeStatus(
        status_code=status,
        global_data_erased=bool((sstat >> 8) & 0x1),
        media_verification_canceled=bool((sstat >> 9) & 0x1),
        completed_passes=passes_raw if passes_raw else None,
        # SPROG's denominator is 65536, not 100. Reading it as a percentage is
        # the kind of off-by-a-lot-of-factor that makes progress read 0.15%.
        progress_fraction=((sprog / 65536.0)
                        if (sstat & 0xF) == SSTAT_IN_PROGRESS else None),
        scdw10=scdw10,
        estimated_seconds={
            "overwrite": eto, "block_erase": etbe, "crypto_erase": etce,
            "overwrite_no_dealloc": etond, "block_erase_no_dealloc": etbend,
            "crypto_erase_no_dealloc": etcend,
        },
        raw=bytes(page),
    )


def build_sanitize_status_log(*, status: int = SSTAT_COMPLETE_SUCCESS,
                              global_data_erased: bool = True,
                              action: int = SANACT_BLOCK_ERASE,
                              overwrite_passes: int = 0,
                              progress: int = 0,
                              media_verification_canceled: bool = False,
                              completed_passes: int = 0) -> bytes:
    """Build a log page. Used by the tests, and to document the layout."""
    sstat = (status & 0xF)
    if global_data_erased:
        sstat |= 1 << 8
    if media_verification_canceled:
        sstat |= 1 << 9
    sstat |= (completed_passes & 0xF) << 12
    scdw10 = ((action & 0xF) << 8) | (overwrite_passes & 0x3F) << 15
    page = bytearray(NVME_LOG_PAGE_BYTES)
    struct.pack_into("<HHI", page, 0, progress & 0xFFFF, sstat, scdw10)
    return bytes(page)


def parse_nvme_cli_output(text: str) -> dict:
    """Parse `nvme sanitize-log` human output, keeping the raw values.

    The text form is a fallback for when the raw page is not available. The
    SSTAT value is kept whole and decoded with the same field layout as the raw
    page rather than through a second, independent set of bit tests -- the old
    decoder's mistake was having two places that disagreed about the bits.
    """
    import re
    out: dict = {"source": "nvme-cli text output"}
    m = re.search(r"\[SSTAT\]:\s*0x([0-9a-fA-F]+)", text)
    if not m:
        raise ValueError("no [SSTAT] in the nvme sanitize-log output")
    sstat = int(m.group(1), 16)
    status = sstat & 0xF
    scdw10 = 0
    m10 = re.search(r"\[SCDW10\]:\s*0x([0-9a-fA-F]+)", text)
    if m10:
        scdw10 = int(m10.group(1), 16)
    out["sanitize_status"] = {
        "status_code": status,
        "status_text": SSTAT_STATUS_TEXT.get(
            status, f"unrecognised status code 0x{status:x}"),
        "status_known": status in SSTAT_STATUS_TEXT,
        "completed_successfully": status == SSTAT_COMPLETE_SUCCESS,
        "failed": status == SSTAT_COMPLETED_FAILED,
        "in_progress": status == SSTAT_IN_PROGRESS,
        "never_sanitized": status == SSTAT_NEVER_SANITIZED,
        "global_data_erased": bool((sstat >> 8) & 0x1),
        "media_verification_canceled": bool((sstat >> 9) & 0x1),
        "completed_passes": ((sstat >> 12) & 0xF) or None,
        "sstat_raw": f"0x{sstat:04x}",
        "action": SANACT_TEXT.get((scdw10 >> 8) & 0xF, "unrecorded or unrecognised"),
    }
    m = re.search(r"\[SPROG\]:\s*(\d+)%", text)
    if m:
        out["sanitize_status"]["progress_percent"] = int(m.group(1))
    return out


# --------------------------------------------------------------------------- #
# Statistical sampling
# --------------------------------------------------------------------------- #

@dataclass
class SamplingProof:
    """What a sample of the medium showed, and how much that is worth.

    A sampling proof says nothing about the bytes it did not read. The value of
    one is entirely in the bound attached to it, so the bound is computed here,
    recorded here, and has to travel into the certificate. A sample count with
    no bound is not evidence of anything, and reporting it as though it were
    would be the dishonest form of this feature.
    """
    blocks_sampled: int
    blocks_total: int
    blocks_matching: int
    pattern_description: str
    confidence: float = 0.95
    #: Binomial upper bound at `confidence`, as a fraction of the medium.
    upper_bound_fraction: float = 0.0
    method: str = "one-sided Clopper-Pearson exact upper bound, k=0 closed form"

    @property
    def observed_fraction(self) -> float:
        return self.blocks_matching / self.blocks_sampled if self.blocks_sampled else 0.0

    @property
    def clean(self) -> bool:
        """True when the sample found nothing matching.

        This is the claim the certificate is allowed to make, and it is weaker
        than "the drive is clean" -- it is "nothing was found in the sample, and
        this is how much of the drive that leaves unaccounted for".
        """
        return self.blocks_matching == 0

    def as_dict(self) -> dict:
        return {
            "blocks_sampled": self.blocks_sampled,
            "blocks_total": self.blocks_total,
            "blocks_matching": self.blocks_matching,
            "pattern": self.pattern_description,
            "confidence": self.confidence,
            "method": self.method,
            "observed_fraction": self.observed_fraction,
            "upper_bound_fraction": self.upper_bound_fraction,
            "clean": self.clean,
            "claim": self.claim(),
        }

    def claim(self) -> str:
        if not self.clean:
            pct = self.observed_fraction * 100
            return (f"{self.blocks_matching} of {self.blocks_sampled} sampled blocks "
                    f"still matched the pattern ({pct:.2f}% of the sample); the medium "
                    f"is not sanitized")
        if not self.blocks_sampled:
            return "no blocks were sampled, so nothing was verified"
        bound = self.upper_bound_fraction * 100
        return (f"no sampled block matched the pattern; at {self.confidence:.0%} "
                f"confidence the fraction of the medium still matching is below "
                f"{bound:.3f}% ({self.method})")


def clopper_pearson_upper(k: int, n: int, confidence: float = 0.95) -> float:
    """One-sided exact binomial upper bound on the success probability.

    Uses the Beta quantile rather than the normal approximation, because a
    sampling proof is normally reported for k = 0, where the normal approximation
    is at its worst and the naive "3/n rule of thumb" is a rule of thumb rather
    than a bound.
    """
    if n <= 0:
        return 1.0
    if not 0.0 < confidence < 1.0:
        raise ValueError("confidence must be in (0, 1)")
    alpha = 1.0 - confidence
    if k >= n:
        return 1.0
    # Upper bound is BetaInv(1 - alpha; k + 1, n - k).
    try:
        from scipy.stats import beta as _beta
        return float(_beta.ppf(1.0 - alpha, k + 1, n - k))
    except ImportError:
        pass
    # Wilson score upper bound as a dependency-free fallback. It is not the
    # exact bound, so the method string is adjusted by the caller below.
    import math
    if k == 0:
        # The k=0 case has a closed form even without SciPy: 1 - alpha**(1/n).
        return 1.0 - alpha ** (1.0 / n)
    z = 1.6448536269514722  # one-sided 95%
    if abs(confidence - 0.95) > 1e-9:
        z = {0.90: 1.2815515655446004, 0.99: 2.3263478740408408}.get(
            round(confidence, 2), z)
    p = k / n
    denom = 1 + z * z / n
    centre = p + z * z / (2 * n)
    margin = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return max(0.0, min(1.0, (centre + margin) / denom))


def _exact_bounds_available() -> bool:
    try:
        import scipy.stats  # noqa: F401
    except ImportError:
        return False
    return True


def build_sampling_proof(blocks_sampled: int, blocks_total: int,
                         blocks_matching: int, pattern_description: str,
                         confidence: float = 0.95) -> SamplingProof:
    """Assemble a sampling proof, reporting which bound was actually computed.

    The k = 0 case -- a clean sample, which is the one a wipe certificate
    normally rests on -- has a closed form that needs no SciPy and is exact, so
    it is always labelled exact. For k > 0 the exact bound needs SciPy; without
    it the Wilson bound is an approximation, and the method string says so
    rather than claiming exactness the calculation does not have.
    """
    if blocks_sampled > blocks_total and blocks_total > 0:
        raise ValueError(
            f"sampled {blocks_sampled} blocks from a medium of {blocks_total}; "
            f"that is not possible")
    upper = clopper_pearson_upper(blocks_matching, blocks_sampled, confidence)
    if blocks_matching == 0:
        method = "one-sided Clopper-Pearson exact upper bound, k=0 closed form"
    elif _exact_bounds_available():
        method = "one-sided Clopper-Pearson (exact binomial) upper bound"
    else:
        method = ("Wilson score upper bound; the exact Clopper-Pearson bound "
                  "needs SciPy and is not strictly tighter here")
    return SamplingProof(
        blocks_sampled=blocks_sampled,
        blocks_total=blocks_total,
        blocks_matching=blocks_matching,
        pattern_description=pattern_description,
        confidence=confidence,
        upper_bound_fraction=upper,
        method=method,
    )


def required_sample_size(confidence: float = 0.95,
                         upper_fraction: float = 0.0001) -> int:
    """Blocks to sample so a clean sample bounds the residue at `upper_fraction`.

    For the k = 0 case this is the standard closed form,
    ``n >= ln(1 - confidence) / ln(1 - upper_fraction)``. It is the number an
    operator needs in order to state a bound at all, and it is large: 0.01% of
    a 1 TB disk is 10 GB, and pretending otherwise would be the whole problem
    this module is about.
    """
    if not 0.0 < confidence < 1.0:
        raise ValueError("confidence must be in (0, 1)")
    if not 0.0 < upper_fraction < 1.0:
        raise ValueError("upper_fraction must be in (0, 1)")
    return math.ceil(math.log(1.0 - confidence) / math.log(1.0 - upper_fraction))


# --------------------------------------------------------------------------- #
# Terminology
# --------------------------------------------------------------------------- #

#: NIST SP 800-88 Rev. 2 and IEEE 2883-2022 use "sanitize" for the
#: cryptographically-strong tiers and treat overwrite as a fallback with a
#: different assurance argument. Keeping the two vocabularies apart in a
#: certificate is the point: "the drive was overwritten three times" and "the
#: drive was sanitized" are different claims with different evidence.
NIST_800_88_TERMS = {
    "clear": "logical overwrite to a known state, recoverable by the operating system",
    "purge": "overwrite that addresses the medium's spare and remapped areas too",
    "destroy": "physical destruction of the medium",
    "sanitize": "cryptographic or verified media erase, as defined in SP 800-88 Rev. 2 "
                "section 2.5 and IEEE 2883-2022",
    "verify": "sampling to confirm, with a recorded bound; not proof of absence",
}


def tier_for_action(action: int | None, *, storage_type: str = "UNKNOWN") -> str | None:
    """The NIST tier a given sanitize action can support.

    Crypto erase and block erase are `Sanitize`. Overwrite is `Purge` at best,
    and only if the pass count is defensible -- which is a separate judgement
    and is not made here. `None` means the action supports no tier, and the
    caller must refuse rather than pick the nearest one.
    """
    if action in (SANACT_BLOCK_ERASE, SANACT_CRYPTO_ERASE):
        return "Sanitize"
    if action == SANACT_OVERWRITE:
        return "Purge"
    return None


def refuse_downgrade(requested: str, achieved: str | None,
                     reason: str) -> dict:
    """The record for a requested tier that was not achieved.

    Invariant 2 of the plan: never claim a tier the evidence does not support,
    and never silently downgrade. This returns the honest record, which names
    what was asked for, what was achieved, and why they differ.
    """
    return {
        "requested_tier": requested,
        "achieved_tier": achieved,
        "downgraded": achieved != requested,
        "reason": reason,
        "statement": (f"the requested {requested} tier was NOT achieved; "
                      f"the highest tier the evidence supports is "
                      f"{achieved or 'none'}"),
    }
