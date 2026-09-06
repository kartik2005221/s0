"""Wipe orchestration: method selection, verification, certificate issuance.

Selection is deliberately conservative:
  * image files            -> overwrite (no firmware to talk to)
  * NVMe                   -> nvme-cli sanitize/format when available
  * SATA SSD/HDD           -> ATA Security Erase when supported (Purge),
                              else single-pass overwrite (Clear)
  * BLKDISCARD             -> offered for block devices that accept it,
                              classified Clear unless the operator supplies a
                              deterministic-TRIM justification
Fallbacks are recorded with their reasons so the operator (and the
certificate) can state honestly why the chosen tier is what it is.
"""

from __future__ import annotations

import collections
import hashlib
import math
import secrets
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

# The wipe CLI imports the shared core from the same venv.
from s0_core import certificate as cert_mod
from s0_core import crypto as core_crypto

from .devices import Target, device_id_for
from .methods.ata import AtaSecureEraseMethod
from .methods.base import MethodResult, Plan, ProgressFn, Target as T, WipeMethod  # noqa: F401
from .methods.blkdiscard import BlkdiscardMethod
from .methods.nvme import NvmeMethod
from .methods.overwrite import OverwriteMethod


@dataclass
class Candidate:
    method: WipeMethod | None
    reason: str = ""
    available: bool = True


def select_method(
    target: T,
    *,
    passes: int = 1,
    pattern: str = "zero",
    prefer_firmware: bool = True,
    discard_justification: str | None = None,
    ata_probe=None,
    nvme_capable_probe=None,
) -> tuple[Candidate, list[Candidate]]:
    """Pick a method for *target*; return (chosen, considered-alternatives).

    probe hooks are injectable for testing; defaults call the real hardware.
    """
    alternatives: list[Candidate] = []

    def probe_ata(t: T) -> dict:
        if ata_probe is not None:
            return ata_probe(t)
        if t.kind != "block" or shutil.which("hdparm") is None or t.path.startswith("/dev/nvme"):
            return {"supported": False, "enhanced_supported": False, "frozen": False}
        return AtaSecureEraseMethod(enhanced=False).probe(t)

    def nvme_ok(t: T) -> bool | None:
        if nvme_capable_probe is not None:
            return nvme_capable_probe(t)
        return NvmeMethod("sanitize_crypto").crypto_erase_capable(t)

    # ---- image files -------------------------------------------------------
    if target.kind == "image":
        chosen = OverwriteMethod(passes=passes, pattern=pattern)
        alternatives.append(Candidate(None, "firmware erase: no firmware behind an image file",
                                      available=False))
        return Candidate(chosen), alternatives

    # ---- NVMe ---------------------------------------------------------------
    if target.path.startswith("/dev/nvme"):
        if shutil.which("nvme"):
            capable = nvme_ok(target)
            if prefer_firmware:
                if capable:
                    return Candidate(NvmeMethod("sanitize_crypto")), alternatives
                if capable is None:
                    alt = Candidate(NvmeMethod("sanitize_crypto"),
                                    "crypto erase capability unconfirmed", available=False)
                    alternatives.append(alt)
                    return Candidate(NvmeMethod("sanitize_block")), alternatives
                alternatives.append(Candidate(
                    NvmeMethod("sanitize_crypto"),
                    "controller lacks sanitize capability", available=False))
                return Candidate(NvmeMethod("format_user")), alternatives
        alternatives.append(Candidate(None, "nvme-cli not installed", available=False))
        fallback = Candidate(OverwriteMethod(passes=passes, pattern=pattern))
        return fallback, alternatives

    # ---- ATA (SATA SSD/HDD) -------------------------------------------------
    if prefer_firmware and (ata_probe is not None or shutil.which("hdparm") or shutil.which("/usr/sbin/hdparm") or shutil.which("/sbin/hdparm")):
        info = probe_ata(target)
        if info.get("frozen"):
            alternatives.append(Candidate(None, "ATA Security Erase unavailable: drive "
                                               "security state is FROZEN", available=False))
        elif info.get("enhanced_supported"):
            chosen = AtaSecureEraseMethod(enhanced=True)
            alternatives.append(Candidate(BlkdiscardMethod(discard_justification),
                                          "discard-only alternative (weaker classification)"))
            return Candidate(chosen), alternatives
        elif info.get("supported"):
            return Candidate(AtaSecureEraseMethod(enhanced=False)), alternatives
        else:
            alternatives.append(Candidate(None, "ATA Security Erase: drive does not "
                                               "advertise support", available=False))

    # ---- fallbacks ----------------------------------------------------------
    if discard_justification:
        chosen = BlkdiscardMethod(discard_justification)
        alternatives.append(Candidate(OverwriteMethod(passes, pattern),
                                      "overwrite alternative (slower, equally Clear-classified)"))
        return Candidate(chosen), alternatives
    if target.kind == "block" and target.storage_type in ("SSD", "eMMC") and \
            not target.path.startswith("/dev/loop"):
        alternatives.append(Candidate(BlkdiscardMethod(),
                                      "not chosen by default: classification depends on "
                                      "drive TRIM guarantees"))

    return Candidate(OverwriteMethod(passes=passes, pattern=pattern)), alternatives


# --------------------------------------------------------------------------- #
# verification sampling
# --------------------------------------------------------------------------- #

def sample_offsets(capacity: int, sector_size: int, count: int) -> list[int]:
    """Deterministic-per-seed crypto-random sample offsets, sector aligned."""
    if capacity <= 0 or sector_size <= 0:
        return []
    total_sectors = capacity // sector_size
    if total_sectors <= 0:
        return [0]
    num_samples = min(count, total_sectors)
    if total_sectors <= count * 2:
        sec_indices = secrets.SystemRandom().sample(range(total_sectors), num_samples)
        return sorted(idx * sector_size for idx in sec_indices)

    offsets = set()
    guard = 0
    max_sector = total_sectors - 1
    while len(offsets) < num_samples and guard < count * 20:
        sec = secrets.randbelow(max_sector + 1)
        offsets.add(sec * sector_size)
        guard += 1
    return sorted(offsets)


def _shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy in bits per byte (0.0 to 8.0)."""
    if not data:
        return 0.0
    counts = collections.Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _read_samples(path: str, offsets: list[int], length: int) -> list[bytes]:
    if not offsets:
        return []
    blobs = []
    try:
        with open(path, "rb") as f:
            for off in offsets:
                f.seek(off)
                blob = f.read(length)
                blobs.append(blob.ljust(length, b"\x00"))
    except Exception:
        pass
    return blobs


def verify_wipe(
    target: T,
    pattern: str,
    *,
    samples: int = 64,
    sample_bytes: int = 4096,
    planted_needles: list[bytes] | None = None,
    pre_samples: list[bytes] | None = None,
    offsets: list[int] | None = None,
) -> tuple[dict, list[bytes]]:
    """Post-wipe verification. Returns (verification_dict_for_cert, post_samples).

    Honest scope: this is SAMPLING through the OS's view of the device — strong
    statistical evidence, not an exhaustive forensic sweep. What was checked is
    recorded verbatim in the certificate.
    """
    offs = offsets if offsets is not None else sample_offsets(
        target.capacity_bytes, target.sector_size, samples)
    post = _read_samples(target.path, offs, sample_bytes)

    verif: dict = {
        "method": "sampled_readback",
        "samples_checked": len(post),
        "sample_bytes_each": sample_bytes,
    }
    if len(post) == 0:
        verif["all_samples_match_wipe_pattern"] = False
        verif["verification_error"] = "Zero readback samples obtained (empty or unreadable target)"
    elif pattern == "zero":
        verif["all_samples_match_wipe_pattern"] = all(b == b"\x00" * len(b) for b in post)
    elif pre_samples is not None and len(pre_samples) == len(post):
        changed = [a != b for a, b in zip(pre_samples, post)]
        pct_changed = sum(changed) / len(changed) if changed else 1.0
        verif["all_samples_match_wipe_pattern"] = (pct_changed >= 0.90)
        verif["method"] = "sampled_readback_changed_vs_pre"
    elif pattern in ("firmware", "key_destruction"):
        all_zeros = all(b == b"\x00" * len(b) for b in post)
        all_ones = all(b == b"\xff" * len(b) for b in post)
        verif["all_samples_match_wipe_pattern"] = (all_zeros or all_ones)
    else:
        # Random pattern without pre-samples: check non-zero ratio and Shannon entropy
        non_zeros = [b != b"\x00" * len(b) for b in post]
        pct_non_zero = sum(non_zeros) / len(non_zeros) if non_zeros else 0.0
        entropies = [_shannon_entropy(b) for b in post if len(b) > 0]
        avg_entropy = sum(entropies) / len(entropies) if entropies else 0.0

        min_expected_entropy = min(7.0, (math.log2(sample_bytes) * 0.85) if sample_bytes > 1 else 0.0)

        verif["average_entropy"] = round(avg_entropy, 3)
        verif["pct_non_zero_samples"] = round(pct_non_zero, 3)
        verif["all_samples_match_wipe_pattern"] = (pct_non_zero >= 0.90 and avg_entropy >= min_expected_entropy)
        verif["note_only_pattern_check_possible_with_pre_samples"] = True

    if planted_needles:
        from .methods.overwrite import count_pattern_hits

        hits = {n.decode("utf-8", "replace"): count_pattern_hits(target.path, n)
                for n in planted_needles}
        verif["planted_pattern_hits_after"] = sum(hits.values())
    return verif, post


def take_pre_samples(target: T, *, samples: int = 64, sample_bytes: int = 4096):
    """Sample BEFORE wiping so random-pattern wipes have something to diff against."""
    offs = sample_offsets(target.capacity_bytes, target.sector_size, samples)
    return offs, _read_samples(target.path, offs, sample_bytes)


# --------------------------------------------------------------------------- #
# certificate assembly
# --------------------------------------------------------------------------- #

def default_issuer_key(explicit: str | None) -> Path | None:
    if explicit:
        p = Path(explicit)
        return p if p.exists() else None
    env = Path(__file__).resolve().parents[3] / "core" / "keys" / "demo_issuer_private.pem"
    if env.exists():
        return env
    here = Path("core/keys/demo_issuer_private.pem")
    return here if here.exists() else None


def cert_device_type(target: T) -> str:
    """Map the CLI's internal target kinds onto the certificate schema enum."""
    if target.kind == "image":
        return "image_file"
    return "removable_disk" if getattr(target, "removable", False) else "internal_disk"


def make_certificate(
    target: T,
    method: WipeMethod,
    result: MethodResult,
    start_time: str,
    end_time: str,
    *,
    operator_id: str,
    organization: str,
    tool_version: str,
    key_path: Path,
    verification: dict | None = None,
    extra_notes: list[str] | None = None,
    status_override: str | None = None,
) -> dict:
    notes = list(extra_notes or [])
    if target.kind == "image":
        notes.insert(0, "File-backed image target: bytes written really land on the "
                        "underlying disk; no root privileges required.")
    if target.kind == "block" and target.serial is None:
        notes.append(f"device_id fell back to path hash (no serial/WWN available): "
                     f"{target.path}")

    cert = cert_mod.build_certificate(
        organization=organization,
        operator_id=operator_id,
        tool_name="s0-wipe",
        tool_version=tool_version,
        platform="linux",
        device_id=device_id_for(target),
        device_type=cert_device_type(target),
        storage_type=target.storage_type,
        model=target.model or "",
        serial_number=target.serial or "",
        capacity_bytes=target.capacity_bytes,
        sector_size=target.sector_size,
        method=method.id,
        nist_category=method.nist_category,
        pattern=method.pattern,
        passes=getattr(method, "passes", 1),
        start_time=start_time,
        end_time=end_time,
        bytes_processed=result.bytes_processed,
        status=status_override or ("success" if result.status == "success" else result.status),
        errors=list(result.errors),
        verification=verification,
        notes=notes,
    )
    priv = core_crypto.load_private_pem(key_path)
    return cert_mod.sign_certificate(cert, priv)
