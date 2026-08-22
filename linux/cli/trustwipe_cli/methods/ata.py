"""ATA Security Erase via hdparm — firmware-level Purge for SATA drives.

VALIDATION STATUS (be honest, always): the command sequences below follow the
hdparm/ATA-8 documented workflow and are unit-tested against recorded output
fixtures. Their *real-firmware* behavior — erase timing, completion semantics,
frozen-drive states — was NOT observable in the development environment, which
has no SATA hardware. Every certificate produced via this path carries a note
saying exactly that.

Workflow per hdparm docs:
  1. `hdparm -I <dev>`          -> confirm "Security Erase" supported; detect
                                   "frozen" state (must not be frozen).
  2. `--security-set-pass`      -> set a temporary password (mode 'u' = user +
                                   master level so master can still clear).
  3. `--security-erase`         -> firmware erases ALL user data incl.
                                   reallocated sectors. Enhanced variant also
                                   erases bad/retired blocks deterministically.
  4. `--security-disable`       -> remove the temporary password afterwards.

A drive frozen by the BIOS cannot accept security commands; the standard fix
is a warm sleep/resume cycle before booting the wipe tool. The CLI detects and
reports this instead of failing mysteriously.
"""

from __future__ import annotations

import re
import shutil
import subprocess

from .base import MethodResult, Plan, ProgressFn, Target, WipeMethod

TEMP_PASSWORD = "TrustWipeEraseTemp2026"


def _run(cmd: list[str], timeout: int | None = None) -> tuple[int, str, str]:
    proc = subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout, check=False
    )
    return proc.returncode, proc.stdout, proc.stderr


class AtaSecureEraseMethod(WipeMethod):
    """hdparm --security-erase / --security-erase-enhanced."""

    def __init__(self, enhanced: bool) -> None:
        self.enhanced = enhanced
        self.id = "ATA_SECURE_ERASE_ENHANCED" if enhanced else "ATA_SECURE_ERASE"
        self.nist_category = "Purge"

    def applies_to(self, target: Target) -> bool:
        return target.kind == "block" and shutil.which("hdparm") is not None \
            and not target.path.startswith("/dev/nvme")

    def plan(self, target: Target) -> Plan:
        variant = "enhanced " if self.enhanced else ""
        return Plan(
            method_id=self.id,
            nist_category=self.nist_category,
            summary=f"ATA {variant}Security Erase executed by the drive firmware",
            commands=[
                f"hdparm -I {target.path}",
                f"hdparm --user-master u --security-set-pass {TEMP_PASSWORD} {target.path}",
                f"hdparm --user-master u --security-erase{'-enhanced' if self.enhanced else ''} "
                f"{TEMP_PASSWORD} {target.path}",
                f"hdparm --user-master u --security-disable {TEMP_PASSWORD} {target.path}",
            ],
            warnings=[
                "Firmware erase may take hours on large drives; do not interrupt power.",
                "DEVELOPMENT NOTE: this path is fixture-tested but NOT validated "
                "against real ATA firmware in this project's environment.",
            ],
        )

    # ---------------------------------------------------------------- probe #
    def probe(self, target: Target) -> dict:
        """Parse `hdparm -I` for ATA security state. Regexes are anchored to
        hdparm's documented output shapes and fixture-tested (see tests)."""
        info = {"supported": False, "enhanced_supported": False, "frozen": False,
                "enabled": False, "error": None}
        code, out, err = _run(["hdparm", "-I", target.path], timeout=30)
        if code != 0:
            info["error"] = (err or f"hdparm -I exited {code}").strip()
            return info
        sec = _security_block(out)

        # Capability lines look like:  "supported: Security Erase"
        #                              "supported: enhanced erase"
        # under the tab-indented Security: block. Enhanced implies standard.
        info["enhanced_supported"] = bool(re.search(
            r"^\s+supported:\s*enhanced erase\s*$", sec, re.M))
        info["supported"] = info["enhanced_supported"] or bool(re.search(
            r"^\s+supported:\s*Security Erase\s*$", sec, re.M))
        # State words appear as bare indented tokens; 'not' prefixes negate:
        #   "not	enabled", "frozen", "not	locked"
        info["enabled"] = not re.search(r"^\s*not\s+enabled\s*$", sec, re.M) and \
            bool(re.search(r"^\s*(not\s+)?(enabled|locked)\s*$", sec, re.M))
        info["frozen"] = bool(re.search(r"^\s+frozen\s*$", sec, re.M))
        return info

    def run(self, target: Target, progress: ProgressFn) -> MethodResult:
        result = MethodResult(status="success")
        info = self.probe(target)
        if info.get("error"):
            result.status = "failure"
            result.errors.append(f"cannot read drive security state: {info['error']}")
            return result
        if info.get("frozen"):
            result.status = "failure"
            result.errors.append(
                "drive security state is FROZEN — BIOS froze it to block hot-attach "
                "attacks; warm-sleep/resume (suspend the machine, resume) then retry"
            )
            return result
        if self.enhanced and not info.get("enhanced_supported"):
            result.notes.append("enhanced erase unsupported; falling back to standard erase")
            fallback = AtaSecureEraseMethod(enhanced=False)
            fb = fallback.run(target, progress)
            fb.errors.extend(result.errors)
            return fb
        if not info.get("supported") and not info.get("enabled"):
            result.status = "failure"
            result.errors.append("drive does not advertise Security Erase support")
            return result

        flag = "--security-erase-enhanced" if self.enhanced else "--security-erase"
        steps = [
            ["hdparm", "--user-master", "u", "--security-set-pass", TEMP_PASSWORD, target.path],
            ["hdparm", "--user-master", "u", flag, TEMP_PASSWORD, target.path],
            ["hdparm", "--user-master", "u", "--security-disable", TEMP_PASSWORD, target.path],
        ]
        labels = ["setting temporary security password",
                  "firmware erase RUNNING — this can take hours; do not cut power",
                  "removing temporary password"]
        for step, label in zip(steps, labels):
            progress(label)
            try:
                code, out, err = _run(step)
            except subprocess.TimeoutExpired:
                result.status = "partial"
                result.errors.append(f"'{label}' timed out")
                return result
            if code != 0:
                # If we failed after setting a password, TRY to remove it so we
                # don't leave the user's drive locked behind our temp password.
                if label != labels[-1]:
                    _run(["hdparm", "--user-master", "u", "--security-disable",
                          TEMP_PASSWORD, target.path])
                result.status = "failure"
                result.errors.append(f"{label}: {(err or out).strip()}")
                return result
            if "SS" in out and "complete" in out.lower():
                progress(out.strip().splitlines()[-1])

        result.bytes_processed = target.capacity_bytes
        result.notes.append(
            "ATA Security Erase issued via hdparm; firmware-reported completion. "
            "Not hardware-validated during this project's development."
        )
        return result


def _context(text: str, phrase: str) -> str:
    """Text from the first occurrence of *phrase* onward (small helper)."""
    i = text.find(phrase)
    return text[i:i + 120] if i >= 0 else ""


def _security_block(hdparm_i_output: str) -> str:
    """Return the indented block following the 'Security:' heading.

    Real hdparm indents the header one tab; we accept any indentation so the
    parser survives cosmetic changes between hdparm versions.
    """
    lines = hdparm_i_output.splitlines()
    start = next((i for i, l in enumerate(lines) if l.strip() == "Security:"), None)
    if start is None:
        return ""
    block = []
    for line in lines[start + 1:]:
        if line and not line[0].isspace():  # next unindented section begins
            break
        block.append(line)
        if re.search(r"\d+\s*min.*SECURITY ERASE", line):
            break  # duration line terminates the block
    return "\n".join(block)


def hpa_dco_report(target: Target) -> dict:
    """Detect HPA/DCO on ATA drives via `hdparm -N` / `--dco-identify`.

    hdparm -N output shape:
        max sectors   = 78165360/78140376, HPA is enabled
                                        (visible / native)

    Loop devices and image files never exhibit HPA/DCO — this returns
    {'note': ...} for them. Real-firmware behavior was not observable during
    development; detection/removal commands are fixture-tested only.
    """
    report = {"hpa_present": None, "dco_present": None, "native_max": None,
              "visible_max": None, "restore_command": None, "note": None}
    if not shutil.which("hdparm") or target.kind != "block":
        report["note"] = "HPA/DCO detection requires a real ATA block device"
        return report

    code, out, _ = _run(["hdparm", "-N", target.path], timeout=20)
    if code == 0:
        m = re.search(r"max sectors\s*=\s*(\d+)/(\d+)", out)
        if m:
            visible, native = int(m.group(1)), int(m.group(2))
            report.update(visible_max=visible, native_max=native,
                          hpa_present=native > visible)
            if native > visible:
                report["restore_command"] = f"hdparm -N p{native} {target.path}"

    code, out, _ = _run(["hdparm", "--dco-identify", target.path], timeout=20)
    if code == 0:
        m = re.search(r"real max sectors\s*=\s*(\d+)", out)
        if m and report["visible_max"] is not None:
            real = int(m.group(1))
            report["dco_present"] = real > report["visible_max"]
            if real > report["visible_max"]:
                report.setdefault("restore_command", f"hdparm --dco-restore {target.path}")
    return report
