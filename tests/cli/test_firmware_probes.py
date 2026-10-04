"""Fixture-driven tests for the firmware methods we CANNOT exercise on real
hardware here (ATA Security Erase, NVMe sanitize, BLKDISCARD-on-block).

These tests pin command construction and output parsing against recorded /
documented output shapes. They prove the code is correct against the SPEC —
they do NOT prove real firmware behaves this way, which is exactly why
LIMITATIONS.md and the certificate notes say "not hardware-validated".
"""

from s0.cli.devices import Target
from s0.wipe.methods import ata as ata_mod

BLOCK = Target(
    path="/dev/sda",
    kind="block",
    capacity_bytes=500 * 2**30,
    storage_type="HDD",
    model="ST500LT012",
    serial="S0VWXYZ",
)

# --- hdparm -I fixtures (shapes per hdparm documentation) --------------------
# Written out explicitly per scenario — no replace() chains, which silently
# no-op when the pattern doesn't match (that bug shipped once already).

HDPARM_I_ENHANCED_FROZEN = """\
/dev/sda:

ATA device, with non-removable media
Commands/features:
	Enabled	Supported:
	   *	SMART feature set
	   *	Security Mode feature set
	Security:
		Master password revision code = 65534
			supported
		not	enabled
		not	locked
			frozen
		not	expired: security count
			supported: enhanced erase
		2min for SECURITY ERASE UNIT.
Logical Unit WWN Device Identifier: 5000c500abcdefff
"""

HDPARM_I_STD_NOT_FROZEN = """\
/dev/sda:

ATA device, with non-removable media
Commands/features:
	Enabled	Supported:
	   *	SMART feature set
	   *	Security Mode feature set
	Security:
		Master password revision code = 65534
			supported
		not	enabled
		not	locked
		not	expired: security count
			supported: Security Erase
		84min for SECURITY ERASE UNIT.
"""

HDPARM_I_NO_SUPPORT = """\
/dev/sda:
Commands/features:
	Enabled	Supported:
	   *	SMART feature set
	Security:
		Master password revision code = 65534
			supported
		not	enabled
"""


def fake_hdparm(monkeypatch, outputs):
    """Replace ata_mod._run with a fixture responder keyed by command prefix."""

    def _run(cmd, timeout=None):
        for key, out in outputs.items():
            if key in cmd:
                return 0, out, ""
        return 0, "", ""

    monkeypatch.setattr(ata_mod, "_run", _run)


def test_probe_detects_frozen_and_enhanced_support(monkeypatch):
    method = ata_mod.AtaSecureEraseMethod(enhanced=True)
    fake_hdparm(monkeypatch, {"-I": HDPARM_I_ENHANCED_FROZEN})
    info = method.probe(BLOCK)
    assert info["supported"] is True  # enhanced implies standard support
    assert info["enhanced_supported"] is True
    assert info["frozen"] is True
    assert info["enabled"] is False


def test_probe_standard_erase_only_not_frozen(monkeypatch):
    method = ata_mod.AtaSecureEraseMethod(enhanced=False)
    fake_hdparm(monkeypatch, {"-I": HDPARM_I_STD_NOT_FROZEN})
    info = method.probe(BLOCK)
    assert info["supported"] is True
    assert info["enhanced_supported"] is False
    assert info["frozen"] is False


def test_probe_no_security_support(monkeypatch):
    method = ata_mod.AtaSecureEraseMethod(enhanced=False)
    fake_hdparm(monkeypatch, {"-I": HDPARM_I_NO_SUPPORT})
    info = method.probe(BLOCK)
    assert info["supported"] is False
    assert info["enhanced_supported"] is False


def test_run_refuses_frozen_drive_before_touching_data(monkeypatch):
    method = ata_mod.AtaSecureEraseMethod(enhanced=True)
    called = {"setpass": 0}

    def scripted(cmd, timeout=None):
        joined = " ".join(cmd)
        if "--security-set-pass" in joined:
            called["setpass"] += 1
        if "-I" in cmd:  # probe must see the frozen drive state
            return 0, HDPARM_I_ENHANCED_FROZEN, ""
        return 0, "", ""

    monkeypatch.setattr(ata_mod, "_run", scripted)
    result = method.run(BLOCK, lambda m: None)
    assert result.status == "failure"
    assert "FROZEN" in result.errors[0]
    assert called["setpass"] == 0  # never set a password on a frozen drive


def test_run_sets_then_disables_temp_password(monkeypatch):
    seq = []

    def scripted(cmd, timeout=None):
        seq.append(" ".join(cmd))
        return 0, "", ""

    monkeypatch.setattr(ata_mod, "_run", scripted)
    monkeypatch.setattr(
        method := ata_mod.AtaSecureEraseMethod(enhanced=True),
        "probe",
        lambda t: {"supported": True, "enhanced_supported": True, "frozen": False},
    )
    result = method.run(BLOCK, lambda m: None)
    assert result.status == "success", result.errors
    assert any("--security-set-pass" in s for s in seq)
    assert any("--security-erase-enhanced" in s for s in seq)
    # The temp password must be removed afterwards:
    assert any("--security-disable" in s for s in seq)
    assert result.notes and "hardware-validated" in result.notes[-1].lower()


# --- hdparm -N / --dco-identify (HPA/DCO) -----------------------------------


def test_hpa_detection_when_native_exceeds_visible(monkeypatch):
    outputs = {
        "-N": "/dev/sda:\n max sectors   = 488397168/500118192, HPA is enabled\n",
        "--dco-identify": "DCO Revision: 0x0001\n real max sectors  = 500118192\n",
    }
    fake_hdparm(monkeypatch, outputs)
    rep = ata_mod.hpa_dco_report(BLOCK)
    assert rep["hpa_present"] is True
    assert rep["native_max"] == 500118192
    assert rep["visible_max"] == 488397168
    assert rep["restore_command"] == "hdparm -N p500118192 /dev/sda"
    assert rep["dco_present"] is True


def test_hpa_absent_on_normal_drive(monkeypatch):
    fake_hdparm(
        monkeypatch,
        {
            "-N": "/dev/sda:\n max sectors   = 500118192/500118192, HPA is disabled\n",
            "--dco-identify": "DCO Revision: 0x0001\n real max sectors  = 500118192\n",
        },
    )
    rep = ata_mod.hpa_dco_report(BLOCK)
    assert rep["hpa_present"] is False
    assert rep["dco_present"] is False
    assert rep["restore_command"] is None


def test_image_targets_report_hpa_check_unavailable():
    img = Target(path="/x/y.img", kind="image", capacity_bytes=1024, storage_type="IMAGE_FILE")
    rep = ata_mod.hpa_dco_report(img)
    assert rep["note"] and "real ATA block device" in rep["note"]


# --- NVMe -------------------------------------------------------------------

from s0.wipe.methods.nvme import NvmeMethod, parse_sanitize_log  # noqa: E402

NVME_DEV = Target(
    path="/dev/nvme0n1", kind="block", capacity_bytes=1024**3, storage_type="NVMe", model="QEMU NVMe Ctrl"
)


def test_parse_sanitize_log_states():
    """SSTAT bits 3:0 are a status *code*, not a set of flags.

    The values here changed, and that is the point. This test previously read
    `0x0` as "running", `0x2` as "completed" and `0x6` as "failed" -- so a
    sanitize that was still in progress (0x2) was asserted complete, and 0x6
    is not a defined status code at all. The test was pinning the misreading
    rather than the specification.
    """
    never = parse_sanitize_log("[SSTAT]: 0x0\n")
    assert never["never_sanitized"] and not never["completed"] and not never["failed"]

    running = parse_sanitize_log("[SPROG]: 37%\n[SSTAT]: 0x2\n")
    assert running["in_progress"] and running["progress_pct"] == 37
    assert not running["completed"], "a sanitize in progress is not complete"

    done = parse_sanitize_log("[SPROG]: 100%\n[SSTAT]: 0x1\n")
    assert done["completed"] and done["progress_pct"] == 100
    assert not done["failed"]

    failed = parse_sanitize_log("[SSTAT]: 0x3\n")
    assert failed["failed"] and not failed["completed"]

    # Global Data Erased is the controller's own statement that nothing has
    # been written since the last successful sanitize. It was not read at all.
    gde = parse_sanitize_log("[SSTAT]: 0x0101\n")
    assert gde["completed"] and gde["global_data_erased"] is True

    unknown = parse_sanitize_log("[SSTAT]: 0x6\n")
    assert unknown["status_known"] is False
    assert not unknown["completed"] and not unknown["failed"]


def test_nvme_plan_commands_follow_spec():
    plan = NvmeMethod("sanitize_crypto").plan(NVME_DEV)
    assert plan.nist_category == "Purge"
    assert any("--crypto-erase" in c for c in plan.commands)
    assert any("sanitize-log" in c for c in plan.commands)


def test_format_crypto_refused_without_capability(monkeypatch):
    m = NvmeMethod("format_crypto")
    monkeypatch.setattr(m, "crypto_erase_capable", lambda t: False)
    result = m.run(NVME_DEV, lambda msg: None)
    assert result.status == "failure"
    assert "refusing to claim a crypto erase" in result.errors[0]


def test_blkdiscard_rejects_non_block_target(tmp_path):
    from s0.wipe.methods.blkdiscard import BlkdiscardMethod

    img = tmp_path / "a.img"
    img.write_bytes(b"\x00" * 4096)
    from s0.cli.devices import image_target

    result = BlkdiscardMethod().run(image_target(str(img)), lambda m: None)
    assert result.status == "failure"
    assert "requires a block device" in result.errors[0]
