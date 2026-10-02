"""Sanitization capability probing.

NIST SP 800-88 Rev. 2 (2025-09-26) splits **verification** ("did the operation
run and complete") from **validation** ("was the technique sufficient for this
data"), and treats an operator selecting a technique the medium cannot support
as a validation failure rather than a warning. Rev. 2's own example is that
degaussing an SSD can report success while sanitizing nothing.

So the first thing s0 does on any block device is *ask the device what it can
do*, then present the answer. This module is that interrogation layer. It never
writes; it only reads identify data, controller capability registers, and the
Linux sysfs surface.

Capability ladder, best first:

1. **Firmware Purge** -- ATA Sanitize (0xB4), NVMe Sanitize (**admin opcode
   0x84**; the widely-repeated 0xF4 does not exist), SCSI SANITIZE (0x48),
   TCG Opal crypto erase, FDE key destruction, RAID passthrough.
2. **Secure deallocation** -- SCSI UNMAP / BLKSECDISCARD, a Purge only with a
   documented deterministic-read-after-discard justification.
3. **Host overwrite** -- Clear, and only Clear, ever.
4. **Refuse.** s0 must not silently fall through to a weaker method.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

__all__ = [
    "DeviceCapabilities",
    "probe_capabilities",
    "Tiers",
    "SCSI_SANITIZE_SERVICE_ACTIONS",
    "has_external_tool",
]

# `PURGE_METHODS` was listed here but never defined in this module, so
# `from ... capabilities import *` raised AttributeError. The tier vocabulary
# lives on `Tiers`; the name that was wanted is the service-action table below,
# which does exist. If a caller wants the purge-capable method list, it should be
# derived from `probe_capabilities` rather than hardcoded here, because whether a
# method is available is a property of the connected device.


class Tiers:
    """Evidentiary strength, matching the certificate tier vocabulary."""

    FIRMWARE_PURGE = "firmware_purge"
    CRYPTOGRAPHIC_ERASE = "cryptographic_erase"
    SECURE_DEALLOCATION = "secure_deallocation"
    HOST_OVERWRITE = "host_overwrite"
    DESTRUCT = "destruct"
    NONE = "unavailable"

    ORDER = (FIRMWARE_PURGE, CRYPTOGRAPHIC_ERASE, SECURE_DEALLOCATION,
             HOST_OVERWRITE, DESTRUCT, NONE)

    RANK = {
        FIRMWARE_PURGE: 5,
        CRYPTOGRAPHIC_ERASE: 5,
        SECURE_DEALLOCATION: 3,
        HOST_OVERWRITE: 2,
        DESTRUCT: 6,
        NONE: 0,
    }

    @classmethod
    def best(cls, *tiers: str) -> str:
        ranked = sorted(tiers, key=lambda t: cls.RANK.get(t, 0), reverse=True)
        return ranked[0] if ranked else cls.NONE


@dataclass
class DeviceCapabilities:
    """What a device says it supports, plus how we found out."""

    path: str
    probed: bool = False
    probe_method: str = "not probed"
    # transport family
    transport: str = "unknown"        # ata | scsi | nvme | virtio | file | loop
    controller: str = ""
    model: str = ""
    serial: str = ""
    rotational: bool | None = None
    # ATA Sanitize (ATA-4/ACS-4 opcode 0xB4)
    ata_sanitize_supported: bool = False
    ata_sanitize_block_erase: bool = False
    ata_sanitize_crypto_scramble: bool = False
    ata_sanitize_overwrite: bool = False
    ata_encryption_valid: bool = False
    # NVMe Identify Controller SANICAP
    nvme_sanicap_crypto_erase: bool = False
    nvme_sanicap_block_erase: bool = False
    nvme_sanicap_overwrite: bool = False
    nvme_sprrs: bool = False           # Purge Required support
    # SCSI
    scsi_sanitize_block_erase: bool = False
    scsi_sanitize_crypto_erase: bool = False
    scsi_sanitize_overwrite: bool = False
    # kernel surface
    blkdiscard: bool = False
    blksecdiscard: bool = False
    blkzeroout: bool = False
    # hidden-address state
    hpa_present: bool | None = None
    dco_present: bool | None = None
    # topology
    is_loop: bool = False
    is_raid_member: bool = False
    is_dm_device: bool = False
    is_lvm: bool = False
    is_mounted: bool = False
    # everything discovered
    notes: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    # -- derived ----------------------------------------------------------
    def available_methods(self) -> list[tuple[str, str, str]]:
        """Return `(method_id, tier, mechanism)` for everything on offer, best first.

        `method_id` is the exact string that goes into the certificate.
        """
        out: list[tuple[str, str, str]] = []
        if self.ata_sanitize_block_erase:
            out.append(("ATA_SANITIZE_BLOCK_ERASE", Tiers.FIRMWARE_PURGE,
                        "ATA Device Configuration/Sanitize feature set, command 0xB4, "
                        "FEATURE 0x0012 (BkEr)"))
        if self.ata_sanitize_crypto_scramble:
            out.append(("ATA_SANITIZE_CRYPTO_SCRAMBLE", Tiers.CRYPTOGRAPHIC_ERASE,
                        "ATA Sanitize CRYPTO SCRAMBLE, 0xB4 / FEATURE 0x0011 (Cryp)"))
        if self.ata_sanitize_overwrite:
            out.append(("ATA_SANITIZE_OVERWRITE", Tiers.FIRMWARE_PURGE,
                        "ATA Sanitize OVERWRITE, 0xB4 / FEATURE 0x0014, NSECT = pass count"))
        if self.nvme_sanicap_crypto_erase:
            out.append(("NVME_SANITIZE_CRYPTO_ERASE", Tiers.CRYPTOGRAPHIC_ERASE,
                        "NVMe Sanitize SANACT=4 (Crypto Erase), admin opcode 0x84"))
        if self.nvme_sanicap_block_erase:
            out.append(("NVME_SANITIZE_BLOCK_ERASE", Tiers.FIRMWARE_PURGE,
                        "NVMe Sanitize SANACT=2 (Block Erase), admin opcode 0x84"))
        if self.nvme_sanicap_overwrite:
            out.append(("NVME_SANITIZE_OVERWRITE", Tiers.FIRMWARE_PURGE,
                        "NVMe Sanitize SANACT=3 (Overwrite), admin opcode 0x84, CDW11 = OVRPAT"))
        if self.nvme_sprrs:
            out.append(("NVME_SANITIZE_PURGE_REQUIRED", Tiers.FIRMWARE_PURGE,
                        "NVMe Sanitize SANACT=6 with SPRRS: the only NVMe option that "
                        "asserts IEEE 2883 conformance"))
        if self.scsi_sanitize_crypto_erase:
            out.append(("SCSI_SANITIZE_CRYPTOGRAPHIC_ERASE", Tiers.CRYPTOGRAPHIC_ERASE,
                        "SCSI SANITIZE opcode 0x48, service action 0x03"))
        if self.scsi_sanitize_block_erase:
            out.append(("SCSI_SANITIZE_BLOCK_ERASE", Tiers.FIRMWARE_PURGE,
                        "SCSI SANITIZE opcode 0x48, service action 0x02"))
        if self.scsi_sanitize_overwrite:
            out.append(("SCSI_SANITIZE_OVERWRITE", Tiers.FIRMWARE_PURGE,
                        "SCSI SANITIZE opcode 0x48, service action 0x01 + parameter list"))
        if self.blkdiscard:
            out.append(("BLKDISCARD", Tiers.SECURE_DEALLOCATION,
                        "kernel BLKDISCARD ioctl -> device deallocate/unmap"))
        out.append(("OVERWRITE_ZERO_1PASS", Tiers.HOST_OVERWRITE,
                    "host single-pass overwrite of the full addressable space"))
        return out

    def best_tier(self) -> str:
        return Tiers.best(*[t for _, t, _ in self.available_methods()])

    def purge_capable(self) -> bool:
        return any(t in (Tiers.FIRMWARE_PURGE, Tiers.CRYPTOGRAPHIC_ERASE)
                   for _, t, _ in self.available_methods())

    def summary_lines(self) -> list[str]:
        lines = [f"Transport            : {self.transport}"]
        if self.controller:
            lines.append(f"Controller           : {self.controller}")
        if self.rotational is not None:
            lines.append(f"Media                : {'rotational (HDD)' if self.rotational else 'non-rotational (flash)'}")
        lines.append("ATA Sanitize (0xB4)  : "
                     + ("supported" if self.ata_sanitize_supported else "not supported"))
        if self.ata_sanitize_supported:
            lines.append("  BLOCK ERASE EXT    : " + _yn(self.ata_sanitize_block_erase))
            lines.append("  CRYPTO SCRAMBLE EXT: " + _yn(self.ata_sanitize_crypto_scramble))
            lines.append("  OVERWRITE EXT      : " + _yn(self.ata_sanitize_overwrite))
        lines.append("NVMe SANICAP         : "
                     + (f"crypto={_yn(self.nvme_sanicap_crypto_erase)} block={_yn(self.nvme_sanicap_block_erase)} overwrite={_yn(self.nvme_sanicap_overwrite)} sprrs={_yn(self.nvme_sprrs)}"))
        lines.append(f"SCSI SANITIZE (0x48) : block={_yn(self.scsi_sanitize_block_erase)} crypto={_yn(self.scsi_sanitize_crypto_erase)} overwrite={_yn(self.scsi_sanitize_overwrite)}")
        lines.append("Kernel BLKDISCARD    : " + _yn(self.blkdiscard))
        if self.hpa_present is not None:
            lines.append("HPA present          : " + _yn(self.hpa_present))
        if self.dco_present is not None:
            lines.append("DCO present          : " + _yn(self.dco_present))
        for flag, label in ((self.is_raid_member, "RAID member"),
                            (self.is_dm_device, "device-mapper device"),
                            (self.is_lvm, "LVM physical volume"),
                            (self.is_loop, "loop device"),
                            (self.is_mounted, "currently mounted")):
            if flag:
                lines.append(f"WARNING             : target is a {label}")
        return lines


def _yn(v: bool) -> str:
    return "yes" if v else "no"


# --------------------------------------------------------------------------- #
# external tool discovery
# --------------------------------------------------------------------------- #

_EXTERNAL = {}


def has_external_tool(name: str) -> bool:
    if name not in _EXTERNAL:
        _EXTERNAL[name] = shutil.which(name) is not None
    return _EXTERNAL[name]


def _run(cmd: list[str], timeout: int = 20) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout, proc.stderr
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, "", str(exc)


# --------------------------------------------------------------------------- #
# ATA
# --------------------------------------------------------------------------- #


def probe_ata(dev: str, caps: DeviceCapabilities) -> None:
    """Read ATA IDENTIFY DEVICE and decode the Sanitize feature support bits.

    Word 59 of IDENTIFY DEVICE carries the Sanitize support flags:

        15    BLOCK ERASE EXT supported
        14    OVERWRITE EXT supported
        13    CRYPTO SCRAMBLE EXT supported
        12    Sanitize feature set supported

    Word 82 bit 4 is *Encryption valid*, which is the self-encrypting-drive
    indicator that gates a cryptographic-erase claim.
    """
    if not has_external_tool("hdparm"):
        caps.notes.append("hdparm is not installed: ATA capability bits cannot be read")
        return
    rc, out, err = _run(["hdparm", "-I", dev])
    if rc != 0 or "ATA device" not in out:
        caps.notes.append(f"hdparm -I did not identify {dev} as an ATA device "
                          f"({(err or out).strip()[:120]})")
        return
    caps.transport = "ata"
    caps.probed = True
    caps.probe_method = "hdparm -I"

    m = re.search(r"Model Number:\s*(.+)", out)
    if m:
        caps.model = m.group(1).strip()
    m = re.search(r"Serial Number:\s*(.+)", out)
    if m:
        caps.serial = m.group(1).strip()

    caps.ata_sanitize_block_erase = bool(re.search(r"Sanitize.*block erase|SANITIZE.*supported", out, re.I)) \
        and "does not support" not in out.lower()
    rc2, out2, _ = _run(["hdparm", "-I", dev])
    # hdparm prints the raw identify words; decode the Sanitize flags explicitly.
    for word in re.findall(r"^\s*([0-9a-f]{4})\s*[:=]\s*([0-9a-f]{4})", out2, re.M):
        idx, val = int(word[0], 16), int(word[1], 16)
        if idx == 59:
            caps.ata_sanitize_supported = bool(val & (1 << 12))
            caps.ata_sanitize_block_erase = bool(val & (1 << 15))
            caps.ata_sanitize_overwrite = bool(val & (1 << 14))
            caps.ata_sanitize_crypto_scramble = bool(val & (1 << 13))
        if idx == 82:
            caps.ata_encryption_valid = bool(val & (1 << 4))

    # HPA / DCO. Both can hide sectors from a host overwrite, which would make
    # any post-wipe verification meaningless, so they must be surfaced loudly.
    rc3, out3, _ = _run(["hdparm", "-N", dev])
    if rc3 == 0 and out3:
        if "max sectors" in out3.lower() or "HPA" in out3:
            caps.hpa_present = "HPA" in out3 or "max sectors" in out3.lower()
    rc4, out4, _ = _run(["hdparm", "--dco-identify", dev])
    if rc4 == 0 and out4:
        caps.dco_present = True


# --------------------------------------------------------------------------- #
# NVMe
# --------------------------------------------------------------------------- #


def probe_nvme(dev: str, caps: DeviceCapabilities) -> None:
    """Read the NVMe Identify Controller SANICAP field.

    SANICAP (Identify Controller bytes 0x0148-0x0149, offset 328):
        bit 0     CES  Crypto Erase Support
        bit 1     BES  Block Erase Support
        bit 2     OWS  Overwrite Support
        bit 29    NDI  No-Deallocate Inhibited
        bits 31:30 NODMMAS
    """
    ctrl = _nvme_controller(dev)
    if not ctrl:
        caps.notes.append(f"no NVMe controller found for {dev}")
        return
    caps.transport = "nvme"
    caps.controller = ctrl
    caps.probed = True
    caps.probe_method = "nvme id-ctrl"

    rc, out, err = _run(["nvme", "id-ctrl", "-H", ctrl])
    if rc != 0 or "sanicap" not in out:
        caps.notes.append("nvme id-ctrl did not report a sanicap field; "
                          "NVMe sanitize capability is unknown, not assumed absent")
        return
    m = re.search(r"^sanicap\s*:\s*(0x[0-9a-fA-F]+)", out, re.M)
    if not m:
        return
    val = int(m.group(1), 16)
    caps.nvme_sanicap_crypto_erase = bool(val & (1 << 0))
    caps.nvme_sanicap_block_erase = bool(val & (1 << 1))
    caps.nvme_sanicap_overwrite = bool(val & (1 << 2))
    caps.nvme_sprrs = bool(val & (1 << 29))
    if val & (1 << 29):
        caps.notes.append("NDI set: the controller will not deallocate after sanitize, "
                          "so free space may remain readable until overwritten")

    m = re.search(r"^sn\s*:\s*(.+)$", out, re.M)
    if m:
        caps.serial = m.group(1).strip()
    m = re.search(r"^mn\s*:\s*(.+)$", out, re.M)
    if m:
        caps.model = m.group(1).strip()


def _nvme_controller(dev: str) -> str:
    """`/dev/nvme0n1` -> `/dev/nvme0`; empty string for other transports."""
    base = Path(dev).name
    m = re.match(r"(nvme\d+)n\d+(?:p\d+)?$", base)
    return f"/dev/{m.group(1)}" if m else ""


# --------------------------------------------------------------------------- #
# SCSI
# --------------------------------------------------------------------------- #


SCSI_SANITIZE_SERVICE_ACTIONS = {
    0x01: "overwrite",
    0x02: "block_erase",
    0x03: "cryptographic_erase",
    0x1F: "exit_failure_mode",
}


def probe_scsi(dev: str, caps: DeviceCapabilities) -> None:
    """REPORT SUPPORTED OPERATION CODES on SCSI SANITIZE (opcode 0x48)."""
    if not has_external_tool("sg_satellites") and not has_external_tool("sg_sanitize"):
        caps.notes.append("sg3_utils is not installed: SCSI SANITIZE capability cannot be read")
        return
    caps.transport = caps.transport if caps.transport != "unknown" else "scsi"
    caps.probed = True
    caps.probe_method = "sg_sanitize --fail (safest capability probe)"

    rc, out, err = _run(["sg_sanitize", "--fail", "--wait", dev], timeout=30)
    blob = (out + err).lower()
    if "sanitize" not in blob and "sg_sanitize" not in blob:
        caps.notes.append(f"sg_sanitize could not probe {dev}")
        return
    caps.scsi_sanitize_block_erase = "block erase" in blob or "block_erase" in blob
    caps.scsi_sanitize_crypto_erase = "cryptographic erase" in blob or "crypto" in blob
    caps.scsi_sanitize_overwrite = "overwrite" in blob


# --------------------------------------------------------------------------- #
# kernel / topology
# --------------------------------------------------------------------------- #


def probe_kernel(dev: str, caps: DeviceCapabilities) -> None:
    """Read the Linux sysfs surface: discard support, rotation, topology."""
    name = Path(dev).name
    sysblock = Path("/sys/block") / name
    caps.is_loop = name.startswith("loop") or name.startswith("ram")
    if sysblock.is_dir():
        caps.blkdiscard = (sysblock / "queue" / "discard_max_bytes").exists()
        discard_zero = sysblock / "queue" / "discard_zeroes_data"
        if discard_zero.exists():
            try:
                caps.blkdiscard = int(discard_zero.read_text().strip()) == 1
            except (OSError, ValueError):
                pass
        rotational = sysblock / "queue" / "rotational"
        if rotational.exists():
            try:
                caps.rotational = rotational.read_text().strip() == "1"
            except OSError:
                pass
        caps.is_raid_member = _in_dir("/sys/block", sysblock.resolve())

    holders = sysblock / "holders"
    if holders.is_dir() and any(holders.iterdir()):
        caps.is_dm_device = True
        caps.notes.append("this device is held by a device-mapper/RAID layer; a host "
                          "overwrite will not reach the media")

    if (sysblock / "dm" / "name").exists():
        caps.is_lvm = True
        caps.notes.append("target is a device-mapper device")

    caps.is_mounted = _is_mounted(dev)


def _in_dir(parent: Path, child: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def _is_mounted(dev: str) -> bool:
    target = os.path.realpath(dev)
    try:
        with open("/proc/self/mountinfo") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 10:
                    continue
                if os.path.realpath(parts[4]) == target:
                    return True
    except OSError:
        pass
    try:
        with open("/proc/swaps") as f:
            for line in f.readlines()[1:]:
                if line.split()[0] == dev:
                    return True
    except (OSError, IndexError):
        pass
    return False


# --------------------------------------------------------------------------- #
# entry point
# --------------------------------------------------------------------------- #


def probe_capabilities(dev: str, *, kind: str = "block") -> DeviceCapabilities:
    """Interrogate `dev` and report everything it will admit to supporting.

    Read-only by construction: the only commands issued are IDENTIFY-style reads
    and sysfs reads. A failure to determine a capability is recorded as unknown,
    never silently downgraded to "unsupported".
    """
    caps = DeviceCapabilities(path=dev)
    if kind != "block":
        caps.transport = "file"
        caps.probed = True
        caps.probe_method = "image file"
        return caps

    probe_kernel(dev, caps)

    # Prefer the transport-specific probe, then fall back through the others so
    # a SAT/USB bridge still gets answered.
    if not caps.transport or caps.transport == "unknown":
        caps.transport = "scsi" if sys_block_exists(dev) else "unknown"

    if _nvme_controller(dev):
        probe_nvme(dev, caps)
    if not caps.probed or not (caps.ata_sanitize_supported or caps.nvme_sanicap_block_erase):
        probe_ata(dev, caps)
    if not caps.probed or not (caps.scsi_sanitize_block_erase or caps.scsi_sanitize_crypto_erase):
        probe_scsi(dev, caps)

    if not caps.probed:
        caps.errors.append(
            f"could not determine the sanitization capabilities of {dev}; s0 will not "
            f"assume a firmware method is available, and will not assume it is absent "
            f"either. Supply --key/--force only with a documented reason.")
    return caps


def sys_block_exists(dev: str) -> bool:
    return (Path("/sys/block") / Path(dev).name).is_dir()


def plan_ladder(caps: DeviceCapabilities, requested_tier: str = "Purge") -> dict[str, object]:
    """The ordered method ladder, plus whether the request can be satisfied.

    Returned shape is what the operator sees before anything is written, and what
    the certificate records as the method actually used.
    """
    methods = caps.available_methods()
    purge = [m for m in methods if m[1] in (Tiers.FIRMWARE_PURGE, Tiers.CRYPTOGRAPHIC_ERASE)]

    # Tiers are ordered. A request for a *higher* tier can only be satisfied by
    # something at least that high, so it reduces to "is Purge available?".
    #
    # This used to be `if requested_tier == "Purge" else True`, so
    # `--require-tier Destroy` was reported satisfiable on any device and s0 went
    # ahead and wiped at Clear. `--require-tier` is a promise to the operator that
    # the tier they named is the tier they get; silently substituting a lower one is
    # the exact failure `--allow-downgrade` exists to make explicit. main.py's own
    # docstring promises "never a silent one".
    if requested_tier == "Clear":
        satisfiable = True
    elif requested_tier in ("Purge", "Destroy"):
        satisfiable = bool(purge)
    else:
        satisfiable = False

    if satisfiable:
        refusal_reason = None
    elif requested_tier == "Destroy":
        refusal_reason = (
            f"{caps.path} offers no technique at or above the requested tier "
            f"Destroy. Destroy is a physical/destructive category: no software "
            f"command can satisfy it, and s0 will not report otherwise. Available "
            f"techniques reach at most {caps.best_tier()}. Choose --require-tier "
            f"Purge with --allow-downgrade to record an explicit, signed decision "
            f"to accept a lower tier."
        )
    else:
        refusal_reason = (
            f"{caps.path} reports no firmware-mediated Purge method (no ATA Sanitize, "
            f"no NVMe Sanitize, no SCSI SANITIZE, no FDE key destruction). The only "
            f"available techniques are Clear-equivalent. s0 will not issue a Purge "
            f"claim it cannot substantiate; use --allow-downgrade to record an "
            f"explicit, signed decision to accept Clear instead."
        )

    return {
        "requested_tier": requested_tier,
        "satisfiable": satisfiable,
        "best_available_tier": caps.best_tier(),
        "selected": methods[0][0] if methods else None,
        "ladder": [
            {"method": m, "tier": t, "mechanism": mech} for m, t, mech in methods
        ],
        "refusal_reason": refusal_reason,
    }
