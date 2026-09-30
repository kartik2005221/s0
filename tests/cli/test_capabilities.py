"""Sanitization capability probing and the refuse-to-downgrade rule.

NIST SP 800-88 Rev. 2 splits *verification* ("did it run") from *validation*
("was it enough") and treats selecting a technique the medium cannot support as
a validation failure. These tests pin the behaviour that follows from that: s0
asks the device what it can do, and never claims a tier it cannot substantiate.
"""

from __future__ import annotations

import pytest

from s0.wipe.methods import capabilities as cap
from s0.wipe.methods import sanitize as san
from s0.wipe.methods.capabilities import DeviceCapabilities, Tiers, plan_ladder


# --------------------------------------------------------------------------- #
# the ladder
# --------------------------------------------------------------------------- #


def _ata(**kw):
    c = DeviceCapabilities(path="/dev/sdX", probed=True)
    for k, v in kw.items():
        setattr(c, k, v)
    return c


def test_host_overwrite_is_always_the_last_resort():
    methods = DeviceCapabilities(path="/dev/sdX").available_methods()
    assert methods[-1][0] == "OVERWRITE_ZERO_1PASS"
    assert methods[-1][1] == Tiers.HOST_OVERWRITE


def test_ata_sanitize_flags_produce_the_right_methods():
    c = _ata(ata_sanitize_supported=True, ata_sanitize_block_erase=True,
             ata_sanitize_crypto_scramble=True, ata_sanitize_overwrite=True)
    ids = [m[0] for m in c.available_methods()]
    assert "ATA_SANITIZE_BLOCK_ERASE" in ids
    assert "ATA_SANITIZE_CRYPTO_SCRAMBLE" in ids
    assert "ATA_SANITIZE_OVERWRITE" in ids
    assert c.purge_capable()
    assert c.best_tier() in (Tiers.FIRMWARE_PURGE, Tiers.CRYPTOGRAPHIC_ERASE)


def test_nvme_sanicap_flags_produce_the_right_methods():
    c = _ata(nvme_sanicap_crypto_erase=True, nvme_sanicap_block_erase=True,
             nvme_sanicap_overwrite=True, nvme_sprrs=True)
    ids = [m[0] for m in c.available_methods()]
    assert "NVME_SANITIZE_CRYPTO_ERASE" in ids
    assert "NVME_SANITIZE_BLOCK_ERASE" in ids
    assert "NVME_SANITIZE_OVERWRITE" in ids
    assert "NVME_SANITIZE_PURGE_REQUIRED" in ids


def test_scsi_sanitize_flags_produce_the_right_methods():
    c = _ata(scsi_sanitize_block_erase=True, scsi_sanitize_crypto_erase=True,
             scsi_sanitize_overwrite=True)
    ids = [m[0] for m in c.available_methods()]
    for expected in ("SCSI_SANITIZE_BLOCK_ERASE",
                     "SCSI_SANITIZE_CRYPTOGRAPHIC_ERASE",
                     "SCSI_SANITIZE_OVERWRITE"):
        assert expected in ids
    assert ids[-1] == "OVERWRITE_ZERO_1PASS"
    assert ids.index("SCSI_SANITIZE_BLOCK_ERASE") < ids.index("SCSI_SANITIZE_OVERWRITE")


def test_mechanism_strings_carry_the_actual_opcode():
    """The certificate must name the mechanism, not a marketing label."""
    c = _ata(nvme_sanicap_block_erase=True)
    mech = [m[2] for m in c.available_methods() if m[0] == "NVME_SANITIZE_BLOCK_ERASE"][0]
    assert "0x84" in mech
    assert "0xF4" not in mech, "0xF4 is not an NVMe admin opcode; several sources are wrong"


def test_clear_only_device_cannot_satisfy_a_purge_request():
    c = DeviceCapabilities(path="/dev/sdX", probed=True)
    plan = plan_ladder(c, "Purge")
    assert plan["satisfiable"] is False
    assert plan["refusal_reason"]
    assert "Clear" in plan["refusal_reason"]
    assert "allow-downgrade" in plan["refusal_reason"]


def test_clear_request_is_always_satisfiable():
    plan = plan_ladder(DeviceCapabilities(path="/dev/sdX", probed=True), "Clear")
    assert plan["satisfiable"] is True


def test_ladder_is_ordered_best_first():
    c = _ata(ata_sanitize_block_erase=True, nvme_sanicap_crypto_erase=True, blkdiscard=True)
    ranks = [Tiers.RANK[t] for _, t, _ in c.available_methods()]
    assert ranks == sorted(ranks, reverse=True)


# --------------------------------------------------------------------------- #
# probe honesty
# --------------------------------------------------------------------------- #


def test_unknown_capability_is_recorded_as_unknown_not_absent(monkeypatch):
    """A probe that cannot reach the device must not silently read as 'no Purge'."""
    c = DeviceCapabilities(path="/dev/nvme9")
    monkeypatch.setattr(cap, "_nvme_controller", lambda _d: "/dev/nvme9")
    monkeypatch.setattr(cap, "has_external_tool", lambda _n: False)
    cap.probe_nvme("/dev/nvme9", c)
    assert c.notes, "an undeterminable capability must leave a note"
    assert any("unknown" in n or "not assumed" in n for n in c.notes)
    assert not c.nvme_sanicap_block_erase


def test_probe_never_writes():
    """Constructing a plan must not open the device for writing."""
    issued = []

    def fake_run(cmd, timeout=20):
        issued.append(cmd)
        return 0, "", ""

    import unittest.mock as mock
    with mock.patch.object(cap, "_run", fake_run), \
         mock.patch.object(cap, "has_external_tool", lambda _n: True):
        cap.probe_capabilities("/dev/sdX", kind="block")
    mutating = ("--sanitize-block-erase", "--sanitize-crypto-scramble",
                "--sanitize-overwrite", "--security-erase", "format",
                "--wipe", "shred", "clean all")
    for cmd in issued:
        joined = " ".join(cmd)
        for verb in mutating:
            assert verb not in joined, f"capability probe issued a mutating command: {joined}"


# --------------------------------------------------------------------------- #
# sanitize drivers
# --------------------------------------------------------------------------- #


def test_ata_overwrite_refuses_pass_count_zero():
    """0 means SIXTEEN passes in ACS-4, which has stalled multi-TB drives."""
    out = san.ata_sanitize_overwrite("/dev/sdX", passes=0)
    assert out.ok is False
    assert any("SIXTEEN" in e for e in out.errors)


def test_nvme_overwrite_refuses_pass_count_zero():
    out = san.nvme_sanitize("/dev/nvme0", "overwrite", passes=0)
    assert out.ok is False
    assert any("SIXTEEN" in e for e in out.errors)


def test_ata_block_erase_reports_the_exact_cdb():
    out = san.ata_sanitize_block_erase("/dev/sdX")
    assert "0xB4" in out.command and "0x0012" in out.command
    from s0.certificate import METHOD_TIERS
    assert METHOD_TIERS[out.method_id] == {"Purge"}


def test_nvme_crypto_erase_uses_opcode_0x84():
    out = san.nvme_sanitize("/dev/nvme0", "crypto_erase")
    assert "0x84" in out.command
    assert out.method_id == "NVME_SANITIZE_CRYPTO_ERASE"
    assert out.tier == Tiers.CRYPTOGRAPHIC_ERASE
    from s0.certificate import METHOD_TIERS
    assert METHOD_TIERS[out.method_id] == {"Purge"}


def test_scsi_block_erase_reports_the_exact_opcode():
    out = san.scsi_sanitize("/dev/sdX", "block_erase")
    assert "0x48" in out.mechanism and "0x02" in out.mechanism
    assert out.method_id == "SCSI_SANITIZE_BLOCK_ERASE"


def test_drivers_refuse_without_their_platform_tool(monkeypatch):
    """s0 does not hand-build firmware CDBs when the vendor tooling is absent."""
    monkeypatch.setattr(san, "has_external_tool", lambda _n: False)
    for out in (san.ata_sanitize_block_erase("/dev/sdX"),
                san.nvme_sanitize("/dev/nvme0", "block_erase"),
                san.scsi_sanitize("/dev/sdX", "block_erase")):
        assert out.ok is False
        assert out.errors


def test_unknown_sanitize_action_is_rejected():
    assert san.nvme_sanitize("/dev/nvme0", "definitely_not_a_sanact").ok is False
    assert san.scsi_sanitize("/dev/sdX", "explode").ok is False


def test_ata_overwrite_passes_zero_and_nvme_owpass_zero_are_the_same_trap():
    """Both specifications read a zero pass count as sixteen."""
    assert any("SIXTEEN" in e for e in san.ata_sanitize_overwrite("/dev/sdX", passes=0).errors)
    assert any("SIXTEEN" in e for e in san.nvme_sanitize("/dev/nvme0", "overwrite", passes=0).errors)


# --------------------------------------------------------------------------- #
# tier vocabulary
# --------------------------------------------------------------------------- #


def test_every_purge_capable_method_is_registered_in_the_certificate_schema():
    """A method the engine can run must be a method a certificate may name."""
    from s0.certificate import METHOD_TIERS, WIPE_METHODS
    for method_id, _tier, _mech in DeviceCapabilities(
            path="/dev/sdX", probed=True,
            ata_sanitize_block_erase=True, ata_sanitize_crypto_scramble=True,
            ata_sanitize_overwrite=True, nvme_sanicap_block_erase=True,
            nvme_sanicap_crypto_erase=True, nvme_sanicap_overwrite=True,
            nvme_sprrs=True, scsi_sanitize_block_erase=True,
            scsi_sanitize_crypto_erase=True, scsi_sanitize_overwrite=True,
            blkdiscard=True).available_methods():
        if method_id == "OVERWRITE_ZERO_1PASS":
            continue
        assert method_id in WIPE_METHODS, f"{method_id} is runnable but not in the schema"
        assert method_id in METHOD_TIERS, f"{method_id} has no NIST tier mapping"
