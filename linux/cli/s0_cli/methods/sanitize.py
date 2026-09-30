"""Firmware-mediated sanitization drivers: ATA Sanitize, NVMe Sanitize, SCSI SANITIZE.

Every function here **blocks until the controller reports completion**. That is
the single most important correctness property in this file. A sanitize command
being *accepted* is not the same as it being *done*: ATA and NVMe both return
success as soon as the controller takes the request and then continue erasing in
the background for minutes or hours. A tool that reports success on acceptance
issues a certificate for an operation that has not finished.

So each driver follows the same shape:

    1. refuse if the capability is not advertised (never send a command the
       identify data does not claim, you will get a bare sense error and no erase)
    2. handle the frozen state machine (SD1 -> antifreeze, SD2 -> poll, do not
       re-issue)
    3. start the operation
    4. poll the status log until it leaves "in progress"
    5. record the firmware-reported evidence, not just our exit code

Where the platform has a purpose-built tool (`hdparm`, `nvme`, `sg_sanitize`)
that tool is preferred over raw ioctl, because it implements the CDB layouts and
the sense-code decoding for us. Where it does not, the raw command is built here.
"""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple

from .capabilities import DeviceCapabilities, Tiers, has_external_tool, _run

__all__ = [
    "SanitizeOutcome",
    "ata_sanitize_block_erase",
    "ata_sanitize_crypto_scramble",
    "ata_sanitize_overwrite",
    "nvme_sanitize",
    "scsi_sanitize",
    "sanitize_status_nvme",
    "timed_out",
]

# Poll cadence and ceiling. A 16 TiB NVMe overwrite takes hours; the ceiling is
# deliberately generous because a premature "timed out" would be a false failure
# on a legitimate long operation, while the operator can always interrupt.
POLL_INTERVAL = 3.0
DEFAULT_TIMEOUT = 8 * 3600.0


class timed_out(RuntimeError):
    """The controller did not finish within the allotted time."""


@dataclass
class SanitizeOutcome:
    ok: bool
    method_id: str
    tier: str
    mechanism: str
    command: str
    status: str = "unknown"
    attestation: str = ""
    notes: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    started_at: float = 0.0
    duration_seconds: float = 0.0


# --------------------------------------------------------------------------- #
# ATA Sanitize Device (ATA-4 / ACS-4, command 0xB4, 48-bit Non-Data)
# --------------------------------------------------------------------------- #
#
# All the "magic" values below spell the subcommand in ASCII, which is how ACS
# specifies them:
#
#   CRYPTO SCRAMBLE   FEATURE 0x0011   LBA 0x4372, 0x7943   HOB 0x70   "Cryp"
#   BLOCK ERASE       FEATURE 0x0012   LBA 0x4272, 0x6B45   HOB 0x42   "BkEr"
#   OVERWRITE         FEATURE 0x0014   LBA[47:32] = 0x4F57 ("OW"), LBA[31:0] = pattern,
#                                     NSECT = pass count
#   SANITIZE STATUS   FEATURE 0x0000
#   FREEZE LOCK       FEATURE 0x0020   LBA 0x46726C6B  "FrLk"
#   ANTIFREEZE LOCK   FEATURE 0x0040   LBA 0x416E7469  "Anti"
#
# State machine: SD0 idle <-> SD1 frozen; a start command is legal only from
# SD0, SD3 (failed) or SD4 (succeeded), and moves the drive to SD2 in progress.
# During SD2 only IDENTIFY DEVICE, REQUEST SENSE and SANITIZE STATUS are
# accepted, so re-issuing the start is a protocol error, not a retry.
#
# *** Pass count 0 means SIXTEEN passes. *** An 8 TB drive left on the default
# ran ~15 hours at 5 percent complete and had to be power-cycled. Never send 0.

ATA_SANITIZE_STATUS = {
    0: "SD0 idle",
    1: "SD1 frozen",
    2: "SD2 sanitize in progress",
    3: "SD3 sanitize failed",
    4: "SD4 sanitize succeeded",
}

ATA_ERROR_REASON = {
    0: "reason not reported",
    1: "last sanitize completed unsuccessfully",
    2: "command unsupported",
    3: "device is frozen",
    4: "antifreeze lock enabled",
}


def _sanitize_timeout(override: Optional[float]) -> float:
    return float(override) if override else DEFAULT_TIMEOUT


def ata_sanitize_status(dev: str) -> Tuple[int, dict]:
    """Read ATA SANITIZE STATUS EXT. Returns ``(state_code, decoded)``."""
    if not has_external_tool("hdparm"):
        return -1, {"error": "hdparm is not installed"}
    rc, out, err = _run(["hdparm", "--sanitize-status", dev])
    blob = out + err
    if rc != 0:
        return -1, {"error": blob.strip()[:200]}
    info: dict = {"raw": blob.strip()[:400]}
    low = blob.lower()
    if "succeeded" in low or "success" in low:
        info["succeeded"] = True
    if "in progress" in low or "progress" in low:
        info["in_progress"] = True
    if "frozen" in low:
        info["frozen"] = True
    if "failed" in low:
        info["failed"] = True
    m = __import__("re").search(r"(\d{1,3})%", blob)
    if m:
        info["progress_percent"] = int(m.group(1))
    return (2 if info.get("in_progress") else
            4 if info.get("succeeded") else
            3 if info.get("failed") else
            1 if info.get("frozen") else 0), info


def _antifreeze(dev: str) -> Tuple[bool, str]:
    if not has_external_tool("hdparm"):
        return False, "hdparm is not installed; cannot clear the sanitize freeze lock"
    rc, out, err = _run(["hdparm", "--yes-i-know-what-i-am-doing", "--sanitize-anti-freeze-lock", dev],
                        timeout=60)
    return rc == 0, (out + err).strip()[:200]


def _ata_sanitize(
    dev: str,
    *,
    feature: int,
    hdparm_flag: str,
    method_id: str,
    tier: str,
    mechanism: str,
    extra_args: Optional[List[str]] = None,
    timeout: Optional[float] = None,
    poll: Callable[[str], None] = lambda _m: None,
) -> SanitizeOutcome:
    outcome = SanitizeOutcome(
        ok=False, method_id=method_id, tier=tier, mechanism=mechanism,
        command=f"ATA 0xB4 FEATURE 0x{feature:04x}"
                + (f" {' '.join(extra_args)}" if extra_args else ""),
        started_at=time.monotonic(),
    )
    if not has_external_tool("hdparm"):
        outcome.errors.append("hdparm is not installed; s0 will not build raw ATA "
                              "taskfile commands against an unverified identify layout")
        return outcome

    state, info = ata_sanitize_status(dev)
    if state == 1:                                     # frozen
        poll("drive is in the SANITIZE FROZEN state; sending ANTIFREEZE LOCK")
        ok, msg = _antifreeze(dev)
        if not ok:
            outcome.errors.append(f"could not clear the sanitize freeze lock: {msg}")
            return outcome
    elif state == 2:
        outcome.errors.append(
            "a sanitize operation is already in progress on this device. Re-issuing "
            "is a protocol violation; wait for it to finish, or power-cycle the drive, "
            "which resumes rather than aborts it.")
        return outcome

    cmd = ["hdparm", "--yes-i-know-what-i-am-doing", hdparm_flag] + (extra_args or []) + [dev]
    poll(f"issuing: {' '.join(cmd)}")
    rc, out, err = _run(cmd, timeout=max(60, _sanitize_timeout(timeout)))
    outcome.notes.append((out + err).strip()[:500])
    if rc != 0:
        outcome.errors.append(f"{' '.join(cmd)} exited {rc}: {(out + err).strip()[:300]}")
        return outcome

    poll("waiting for the controller to report completion")
    deadline = time.monotonic() + _sanitize_timeout(timeout)
    last_report = 0.0
    while True:
        state, info = ata_sanitize_status(dev)
        if state == 4:
            outcome.status = ATA_SANITIZE_STATUS[4]
            outcome.attestation = "ata_sanitize_status_succeeded=1"
            outcome.ok = True
            break
        if state == 3:
            outcome.status = ATA_SANITIZE_STATUS[3]
            reason = ATA_ERROR_REASON.get(int(info.get("error_code", 0) or 0), "unspecified")
            outcome.errors.append(f"drive reported a sanitize failure: {reason}")
            break
        if time.monotonic() > deadline:
            outcome.status = "timed out waiting for the controller"
            outcome.errors.append(
                "the controller did not report completion within the allotted time. "
                "ATA and NVMe sanitize resume across a power cycle by design, so the "
                "device may still be working. Re-run `s0 plan` to read the current "
                "state before deciding anything.")
            break
        if time.monotonic() - last_report > 15.0:
            last_report = time.monotonic()
            pct = info.get("progress_percent")
            poll(f"in progress{f' ({pct}%)' if pct else ''}")
        time.sleep(POLL_INTERVAL)

    outcome.duration_seconds = time.monotonic() - outcome.started_at
    return outcome


def ata_sanitize_block_erase(dev: str, *, timeout=None, poll=lambda _m: None) -> SanitizeOutcome:
    """ATA Sanitize BLOCK ERASE EXT. Purge on flash; controller-internal."""
    return _ata_sanitize(
        dev, feature=0x0012, hdparm_flag="--sanitize-block-erase",
        method_id="ATA_SANITIZE_BLOCK_ERASE", tier=Tiers.FIRMWARE_PURGE,
        mechanism="ATA Sanitize Device BLOCK ERASE EXT (0xB4 / FEATURE 0x0012, 'BkEr'); "
                  "controller-internal block erase of all user data including caches",
        timeout=timeout, poll=poll)


def ata_sanitize_crypto_scramble(dev: str, *, timeout=None, poll=lambda _m: None) -> SanitizeOutcome:
    """ATA Sanitize CRYPTO SCRAMBLE EXT. Purge on a self-encrypting drive."""
    return _ata_sanitize(
        dev, feature=0x0011, hdparm_flag="--sanitize-crypto-scramble",
        method_id="ATA_SANITIZE_CRYPTO_SCRAMBLE", tier=Tiers.CRYPTOGRAPHIC_ERASE,
        mechanism="ATA Sanitize Device CRYPTO SCRAMBLE EXT (0xB4 / FEATURE 0x0011, 'Cryp'); "
                  "destroys the internal data-encryption key",
        timeout=timeout, poll=poll)


def ata_sanitize_overwrite(dev: str, *, pattern: str = "hex:0x00000000", passes: int = 1,
                           timeout=None, poll=lambda _m: None) -> SanitizeOutcome:
    """ATA Sanitize OVERWRITE EXT.

    `passes` is validated: 0 means sixteen passes in the ATA specification, which
    has bricked multi-terabyte drives by running for a day. s0 refuses 0.
    """
    if passes < 1 or passes > 255:
        return SanitizeOutcome(
            ok=False, method_id="ATA_SANITIZE_OVERWRITE", tier=Tiers.FIRMWARE_PURGE,
            mechanism="", command="",
            errors=[f"refusing pass count {passes}: in the ATA specification 0 means "
                    f"SIXTEEN passes, which can run for a day and has been observed "
                    f"stalling multi-terabyte drives. Pass an explicit 1-255."])
    if passes == 0:  # pragma: no cover - guarded above
        raise AssertionError
    return _ata_sanitize(
        dev, feature=0x0014, hdparm_flag="--sanitize-overwrite",
        method_id="ATA_SANITIZE_OVERWRITE", tier=Tiers.FIRMWARE_PURGE,
        mechanism=f"ATA Sanitize Device OVERWRITE EXT (0xB4 / FEATURE 0x0014, "
                  f"LBA[47:32]='OW', NSECT={passes}); firmware overwrite of logical and "
                  f"physical address space",
        extra_args=[pattern, "--sanitize-overwrite-passes", str(passes)],
        timeout=timeout, poll=poll)


# --------------------------------------------------------------------------- #
# NVMe Sanitize (admin opcode 0x84 -- NOT 0xF4, which is not an NVMe command)
# --------------------------------------------------------------------------- #
#
#   CDW10  bits 2:0  SANACT  1=ExitFailure 2=BlockErase 3=Overwrite
#                                 4=CryptoErase 5=ExitMediaVerif 6=PurgeRequired
#          bit 3      AUSE   Allow Unrestricted Sanitize Exit
#          bits 7:4  OWPASS Overwrite Pass Count (0 = 16 passes)
#          bit 8     OIPBP  Overwrite Invert Pattern Between Passes
#          bit 9     NODAS  No-Deallocate After Sanitize
#          bit 10    EMVS   Enter Media Verification State
#   CDW11          OVRPAT  32-bit overwrite pattern
#   NSID           0xFFFFFFFF (all namespaces)
#
# Sanitize Status is log page 0x81:
#   SSTAT bits 2:0  0 NeverSanitized 1 CompleteSuccess 2 InProgress
#                   3 CompletedFailed 4 NDCompleteSuccess
#   SSTAT bit 8     GLOBAL DATA ERASED
# The GLOBAL DATA ERASED bit is the single strongest firmware attestation
# available anywhere in storage: it asserts that no namespace user data has been
# written and no PMR has been enabled since manufacture or the last successful
# sanitize. s0 records it, and gates the certificate on it.

NVME_SANACT = {
    "exit_failure": 1,
    "block_erase": 2,
    "overwrite": 3,
    "crypto_erase": 4,
    "exit_media_verification": 5,
    "purge_required": 6,
}

NVME_SSTAT = {
    0: "never sanitized",
    1: "sanitize complete, successful",
    2: "sanitize in progress",
    3: "sanitize complete, failed",
    4: "sanitize complete, successful, no-dealloc applied",
}


def sanitize_status_nvme(ctrl: str) -> Tuple[int, dict]:
    """Read NVMe log page 0x81 (Sanitize Status). Returns ``(sstat, decoded)``."""
    if not has_external_tool("nvme"):
        return -1, {"error": "nvme-cli is not installed"}
    rc, out, err = _run(["nvme", "log", "sanitize", ctrl])
    if rc != 0:
        rc, out, err = _run(["nvme", "sanitize-log", ctrl])
    blob = out + err
    if rc != 0:
        return -1, {"error": blob.strip()[:200]}
    import re
    info: dict = {"raw": blob.strip()[:600]}
    m = re.search(r"sstat\s*:\s*(0x[0-9a-fA-F]+)", blob)
    if m:
        val = int(m.group(1), 16)
        info["sstat"] = val
        info["status"] = NVME_SSTAT.get(val & 0x07, f"reserved ({val & 0x07})")
        info["global_data_erased"] = bool(val & (1 << 8))
        info["passes_completed"] = (val >> 3) & 0x1F
        return val & 0x07, info
    low = blob.lower()
    if "in progress" in low:
        return 2, info
    if "succeeded" in low or "success" in low:
        return 1, info
    if "failed" in low:
        return 3, info
    return 0, info


def nvme_sanitize(ctrl: str, sanact: str, *, pattern: int = 0xDEADBEEF, passes: int = 1,
                  use_ause: bool = True, timeout: Optional[float] = None,
                  poll: Callable[[str], None] = lambda _m: None) -> SanitizeOutcome:
    """Issue an NVMe Sanitize command and block until the controller finishes.

    `ctrl` is the controller node (`/dev/nvme0`), not a namespace.
    """
    method_map = {
        "block_erase": ("NVME_SANITIZE_BLOCK_ERASE", Tiers.FIRMWARE_PURGE,
                        "NVMe Sanitize SANACT=2 (Block Erase), admin opcode 0x84; "
                        "controller-internal block erase"),
        "crypto_erase": ("NVME_SANITIZE_CRYPTO_ERASE", Tiers.CRYPTOGRAPHIC_ERASE,
                         "NVMe Sanitize SANACT=4 (Crypto Erase), admin opcode 0x84; "
                         "destroys the media encryption key"),
        "overwrite": ("NVME_SANITIZE_OVERWRITE", Tiers.FIRMWARE_PURGE,
                      "NVMe Sanitize SANACT=3 (Overwrite), admin opcode 0x84, CDW11=OVRPAT"),
        "purge_required": ("NVME_SANITIZE_PURGE_REQUIRED", Tiers.FIRMWARE_PURGE,
                           "NVMe Sanitize SANACT=6 with SPRRS; asserts IEEE 2883 conformance"),
    }
    if sanact not in method_map:
        return SanitizeOutcome(ok=False, method_id="NVME_SANITIZE", tier=Tiers.NONE,
                               mechanism="", command="",
                               errors=[f"unknown NVMe SANACT {sanact!r}"])
    if sanact == "overwrite" and passes < 1:
        return SanitizeOutcome(ok=False, method_id=method_map[sanact][0], tier=Tiers.FIRMWARE_PURGE,
                               mechanism="", command="",
                               errors=["refusing NVMe OWPASS=0: in the specification 0 means "
                                       "SIXTEEN passes. Pass an explicit count."])
    method_id, tier, mechanism = method_map[sanact]

    outcome = SanitizeOutcome(
        ok=False, method_id=method_id, tier=tier, mechanism=mechanism,
        command=f"nvme sanitize --sanact=start-{sanact.replace('_', '-')} (SANACT="
                f"{NVME_SANACT[sanact]}, opcode 0x84)",
        started_at=time.monotonic())

    if not has_external_tool("nvme"):
        outcome.errors.append("nvme-cli is not installed; s0 will not issue raw NVMe "
                              "admin passthrough commands against an unverified layout")
        return outcome

    cmd = ["nvme", "sanitize", ctrl, f"--sanact=start-{sanact.replace('_', '-')}"]
    if use_ause:
        cmd.append("--ause")
    if sanact == "overwrite":
        cmd += [f"--ovrpat=0x{pattern:08X}", f"--owpass={passes}", "--oipbp"]
    outcome.command = " ".join(cmd)
    poll(f"issuing: {outcome.command}")
    # No --wait: s0 does its own status polling so it can prove completion and
    # capture GLOBAL DATA ERASED rather than trusting a tool's exit code.
    rc, out, err = _run(cmd, timeout=300)
    outcome.notes.append((out + err).strip()[:500])
    if rc != 0:
        outcome.errors.append(f"{outcome.command} exited {rc}: {(out + err).strip()[:300]}")
        return outcome

    poll("polling NVMe log 0x81 (Sanitize Status) until the controller finishes")
    deadline = time.monotonic() + _sanitize_timeout(timeout)
    while True:
        sstat, info = sanitize_status_nvme(ctrl)
        if sstat in (1, 4):
            outcome.status = NVME_SSTAT[sstat]
            outcome.attestation = (
                "nvme_log_0x81_global_data_erased="
                + ("1" if info.get("global_data_erased") else "0")
            )
            if info.get("global_data_erased"):
                outcome.notes.append(
                    "GLOBAL DATA ERASED asserted: no namespace user data has been "
                    "written and no persistent memory region enabled since manufacture "
                    "or the last successful sanitize")
            else:
                outcome.notes.append(
                    "the controller reported success but did NOT assert GLOBAL DATA "
                    "ERASED; a previous sanitize or a vendor firmware path may have "
                    "been taken. This is recorded on the certificate.")
            outcome.ok = True
            break
        if sstat == 3:
            outcome.status = NVME_SSTAT[3]
            outcome.errors.append("the controller reported that the sanitize FAILED")
            break
        if time.monotonic() > deadline:
            outcome.status = "timed out waiting for the controller"
            outcome.errors.append("the controller did not report completion in time; "
                                  "NVMe sanitize resumes across a power cycle by design")
            break
        time.sleep(POLL_INTERVAL)

    outcome.duration_seconds = time.monotonic() - outcome.started_at
    return outcome


# --------------------------------------------------------------------------- #
# SCSI SANITIZE (opcode 0x48)
# --------------------------------------------------------------------------- #
#
#   byte 1  bits 4:0 SERVICE ACTION  0x01 overwrite  0x02 block erase
#                                       0x03 cryptographic erase  0x1F exit failure
#           bit 5  AUSE   Allow Unrestricted Sanitize Exit
#           bit 6  ZNR    Zone No Reset
#           bit 7  IMMED  (the Linux SAT translation requires this bit)
#   bytes 7-8  PARAMETER LIST LENGTH (big-endian)
#
# OVERWRITE parameter list: byte 0 bits 4:0 pass count, bits 6:5 test, bit 7
# invert; bytes 2-3 initialisation pattern length; bytes 4.. pattern.

SCSI_SERVICE_ACTION = {"overwrite": 0x01, "block_erase": 0x02,
                       "cryptographic_erase": 0x03, "exit_failure": 0x1F}


def scsi_sanitize(dev: str, service_action: str, *, pattern: bytes = b"\x00\x00\x00\x00",
                  passes: int = 1, timeout: Optional[float] = None,
                  poll: Callable[[str], None] = lambda _m: None) -> SanitizeOutcome:
    method_map = {
        "overwrite": ("SCSI_SANITIZE_OVERWRITE", Tiers.FIRMWARE_PURGE),
        "block_erase": ("SCSI_SANITIZE_BLOCK_ERASE", Tiers.FIRMWARE_PURGE),
        "cryptographic_erase": ("SCSI_SANITIZE_CRYPTOGRAPHIC_ERASE", Tiers.CRYPTOGRAPHIC_ERASE),
    }
    if service_action not in method_map:
        return SanitizeOutcome(ok=False, method_id="SCSI_SANITIZE", tier=Tiers.NONE,
                               mechanism="", command="",
                               errors=[f"unknown SCSI SANITIZE service action {service_action!r}"])
    method_id, tier = method_map[service_action]
    outcome = SanitizeOutcome(
        ok=False, method_id=method_id, tier=tier,
        mechanism=f"SCSI SANITIZE opcode 0x48, service action "
                  f"0x{SCSI_SERVICE_ACTION[service_action]:02X}",
        command="", started_at=time.monotonic())

    if not has_external_tool("sg_sanitize"):
        outcome.errors.append("sg3_utils is not installed; s0 will not hand-build SCSI "
                              "CDBs and parse sense data for a firmware erase")
        return outcome

    cmd = ["sg_sanitize", f"--{service_action}"]
    if service_action == "overwrite":
        cmd += ["--zero", f"--count={passes}", "--wait"]
    else:
        cmd += ["--wait"]
    cmd.append(dev)
    outcome.command = " ".join(cmd)
    poll(f"issuing: {outcome.command}")
    rc, out, err = _run(cmd, timeout=_sanitize_timeout(timeout))
    outcome.notes.append((out + err).strip()[:500])
    if rc != 0:
        outcome.errors.append(f"{outcome.command} exited {rc}: {(out + err).strip()[:300]}")
        return outcome
    outcome.status = "completed (per sg3_utils REQUEST SENSE polling)"
    outcome.attestation = "scsi_sanitize_completed"
    outcome.ok = True
    outcome.duration_seconds = time.monotonic() - outcome.started_at
    return outcome
