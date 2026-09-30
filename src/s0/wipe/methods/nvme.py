"""NVMe Sanitize / Format-NVM via nvme-cli — firmware-level Purge.

VALIDATION STATUS: command construction follows the NVM Express 1.4 spec and
nvme-cli usage; parsing is fixture-tested. No NVMe controller existed in the
development environment (and QEMU's emulated controller does not implement
Sanitize), so real-firmware behavior — Sanitize Progress reporting, actual
media erasure semantics, crypto-erase availability per drive — is NOT
validated here. Certificates from this path say so in notes.

Methods, strongest-first:
  * nvme sanitize --crypto-erase : firmware destroys the encryption key
    (SED-capable drives) -> Purge, near-instant.
  * nvme sanitize --block-erase  : firmware internally erases all blocks,
    including overprovisioned area -> Purge.
  * nvme format -s 1 (user data erase) / -s 2 (crypto erase): format-level
    equivalents; -s 2 requires the drive to be SED-capable.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import time

from .base import MethodResult, Plan, ProgressFn, Target, WipeMethod


def _run(cmd: list[str], timeout: int | None = None) -> tuple[int, str, str]:
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    return proc.returncode, proc.stdout, proc.stderr


class NvmeMethod(WipeMethod):
    def __init__(self, variant: str) -> None:
        # variant in: sanitize_crypto | sanitize_block | format_user | format_crypto
        self.variant = variant
        self.id = {
            "sanitize_crypto": "NVME_SANITIZE_CRYPTO_ERASE",
            "sanitize_block": "NVME_SANITIZE_BLOCK_ERASE",
            "format_user": "NVME_FORMAT_USER_DATA_ERASE",
            "format_crypto": "NVME_FORMAT_CRYPTO_ERASE",
        }[variant]
        self.nist_category = "Purge"

    def applies_to(self, target: Target) -> bool:
        return target.kind == "block" and target.path.startswith("/dev/nvme") \
            and shutil.which("nvme") is not None

    def plan(self, target: Target) -> Plan:
        cmds = {
            "sanitize_crypto": [f"nvme sanitize {target.path} --crypto-erase --no-dealloc=no"],
            "sanitize_block": [f"nvme sanitize {target.path} --block-erase --no-dealloc=no"],
            "format_user": [f"nvme format {target.path} -s 1"],
            "format_crypto": [f"nvme format {target.path} -s 2"],
        }[self.variant]
        return Plan(
            method_id=self.id,
            nist_category=self.nist_category,
            summary=f"NVMe {self.variant.replace('_', ' ')} executed by controller firmware",
            commands=cmds + [f"nvme sanitize-log {target.path}  # poll until finished"],
            warnings=[
                "Crypto-erase variants require an SED-capable drive; the controller "
                "must report support or the command fails (we check first).",
                "DEVELOPMENT NOTE: fixture-tested only — no NVMe controller was "
                "available in this project's environment.",
            ],
        )

    def crypto_erase_capable(self, target: Target) -> bool | None:
        """Best-effort probe of `nvme id-ctrl` OACS/FNA fields. None = unknown."""
        code, out, _ = _run(["nvme", "id-ctrl", target.path], timeout=20)
        if code != 0:
            return None
        m = re.search(r"oacs\s*=\s*0x([0-9a-f]+)", out)
        if not m:
            return None
        oacs = int(m.group(1), 16)
        return bool(oacs & 0x10)  # bit 4: Sanitize capability (NVM Express 1.4 §5.8)

    def run(self, target: Target, progress: ProgressFn) -> MethodResult:
        result = MethodResult(status="success")
        if self.variant == "format_crypto" and self.crypto_erase_capable(target) is False:
            result.status = "failure"
            result.errors.append(
                "controller does not report sanitize/crypto capability; refusing to "
                "claim a crypto erase it may not perform — use sanitize_block instead"
            )
            return result

        cmds = {
            "sanitize_crypto": ["nvme", "sanitize", target.path, "--crypto-erase"],
            "sanitize_block": ["nvme", "sanitize", target.path, "--block-erase"],
            "format_user": ["nvme", "format", target.path, "-s", "1"],
            "format_crypto": ["nvme", "format", target.path, "-s", "2"],
        }[self.variant]
        progress(f"issuing: {' '.join(cmds)}")
        try:
            code, out, err = _run(cmds)
        except subprocess.TimeoutExpired:
            result.status = "failure"
            result.errors.append("command timed out")
            return result
        if code != 0:
            result.status = "failure"
            result.errors.append((err or out).strip())
            return result

        if self.variant.startswith("sanitize"):
            ok, detail = self._wait_for_sanitize(target, progress)
            if not ok:
                result.status = "partial"
                result.errors.append(detail)
        result.bytes_processed = target.capacity_bytes
        result.notes.append(
            "NVMe firmware command issued and completion polled via nvme-cli. "
            "Not hardware-validated during this project's development."
        )
        return result

    def _wait_for_sanitize(self, target: Target, progress: ProgressFn,
                           poll_seconds: int = 15, max_polls: int = 720) -> tuple[bool, str]:
        """Poll `nvme sanitize-log` until completion. Parsing is fixture-tested."""
        for _ in range(max_polls):
            code, out, _ = _run(["nvme", "sanitize-log", target.path], timeout=20)
            if code != 0:
                return False, "sanitize-log poll failed"
            state = parse_sanitize_log(out)
            if state.get("progress_pct") is not None:
                progress(f"sanitize progress: {state['progress_pct']}%")
                if state["progress_pct"] >= 100:
                    return True, "sanitize complete"
            if state.get("completed"):
                return True, "sanitize complete (SSTAT)"
            if state.get("failed"):
                return False, "controller reports sanitize FAILED (SSTAT)"
            time.sleep(poll_seconds)
        return False, "sanitize did not complete within the polling window"


def parse_sanitize_log(out: str) -> dict:
    """Parse `nvme sanitize-log` human output into status flags.

    The SSTAT field is decoded by :mod:`s0.wipe.attest`, which is the single
    place the field layout is written down. This function used to test the raw
    value as a bit set -- ``completed = bits & 0x2``, ``failed = bits & 0x4`` --
    which is not what the field means. Bits 3:0 are a status code, so that
    decoder read a *successfully completed* sanitize (0x0001) as not completed
    and a *failed* one (0x0003) as completed and not failed: a device that
    refused to erase was attested as erased. There is now one decoder, and it
    is the tested one.
    """
    from s0.wipe import attest

    state: dict = {"progress_pct": None, "completed": False, "failed": False}
    m = re.search(r"\[SPROG\]:\s*(\d+)%", out)
    if m:
        state["progress_pct"] = int(m.group(1))
    m = re.search(r"\[SSTAT\]:\s*0x([0-9a-fA-F]+)", out)
    if m:
        sstat = int(m.group(1), 16)
        status = sstat & 0xF
        state["status_code"] = status
        state["status_known"] = status in attest.SSTAT_STATUS_TEXT
        state["completed"] = status == attest.SSTAT_COMPLETE_SUCCESS
        state["failed"] = status == attest.SSTAT_COMPLETED_FAILED
        state["in_progress"] = status == attest.SSTAT_IN_PROGRESS
        state["never_sanitized"] = status == attest.SSTAT_NEVER_SANITIZED
        # Global Data Erased is the controller's own statement that nothing has
        # been written since the last successful sanitize. It was not decoded
        # here at all, which is the strongest evidence the specification offers.
        state["global_data_erased"] = bool((sstat >> 8) & 0x1)
        state["media_verification_canceled"] = bool((sstat >> 9) & 0x1)
        state["sstat_raw"] = f"0x{sstat:04x}"
    return state
