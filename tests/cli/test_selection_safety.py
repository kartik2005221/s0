"""Method-selection matrix + safety-refusal tests (injected probes, no real HW)."""

import json
import subprocess
from types import SimpleNamespace

import pytest

from s0.terminal import EX_USAGE

import s0.wipe.planner as wipe_mod
from s0.cli.devices import SafetyError, Target, check_safety, device_id_for
from s0.wipe.methods.overwrite import OverwriteMethod
from s0.wipe.planner import select_method

IMG = Target(path="/tmp/x.img", kind="image", capacity_bytes=2**20,
             storage_type="IMAGE_FILE")
NVME = Target(path="/dev/nvme0n1", kind="block", capacity_bytes=2**30,
              storage_type="NVMe")
SSD = Target(path="/dev/sda", kind="block", capacity_bytes=2**30,
             storage_type="SSD", serial="SER-123")
HDD = Target(path="/dev/sdb", kind="block", capacity_bytes=2**30,
             storage_type="HDD")


def without_binary(binary):
    """Patch wipe_mod's shutil view so `which(binary)` returns None."""
    real_which = wipe_mod.shutil.which

    def fake(cmd):
        return None if cmd == binary else real_which(cmd)
    return SimpleNamespace(which=fake)


def with_binary(binary, path="/usr/bin/fake-" + "x"):
    """Patch wipe_mod's shutil view so `which(binary)` reports present.

    Needed because this VM has hdparm but not nvme-cli; tests for the NVMe
    selection path must not depend on the host's installed packages.
    """
    real_which = wipe_mod.shutil.which

    def fake(cmd):
        return path if cmd == binary else real_which(cmd)
    return SimpleNamespace(which=fake)


def test_image_gets_overwrite_and_clear():
    chosen, alts = select_method(IMG)
    assert isinstance(chosen.method, OverwriteMethod)
    assert chosen.method.nist_category == "Clear"
    assert chosen.available


def test_nvme_without_cli_falls_back_to_overwrite_with_reason(monkeypatch):
    monkeypatch.setattr(wipe_mod, "shutil", without_binary("nvme"))
    chosen, alts = select_method(NVME)
    assert isinstance(chosen.method, OverwriteMethod)
    assert any("nvme-cli not installed" in a.reason for a in alts)


def test_nvme_capable_controller_prefers_crypto_erase(monkeypatch):
    monkeypatch.setattr(wipe_mod, "shutil", with_binary("nvme"))
    chosen, _ = select_method(NVME, nvme_capable_probe=lambda t: True)
    assert chosen.method.id == "NVME_SANITIZE_CRYPTO_ERASE"
    assert chosen.method.nist_category == "Purge"


def test_nvme_uncapable_gets_block_erase_and_records_crypto_unavailable(monkeypatch):
    monkeypatch.setattr(wipe_mod, "shutil", with_binary("nvme"))
    chosen, alts = select_method(NVME, nvme_capable_probe=lambda t: False)
    assert chosen.method.id == "NVME_FORMAT_USER_DATA_ERASE"
    assert any("lacks sanitize capability" in a.reason for a in alts)


def test_ata_enhanced_support_selects_purge():
    probe = lambda t: {"supported": True, "enhanced_supported": True, "frozen": False}
    chosen, _ = select_method(HDD, ata_probe=probe)
    assert chosen.method.id == "ATA_SECURE_ERASE_ENHANCED"
    assert chosen.method.nist_category == "Purge"


def test_ata_standard_support_selects_standard_erase():
    probe = lambda t: {"supported": True, "enhanced_supported": False, "frozen": False}
    chosen, _ = select_method(HDD, ata_probe=probe)
    assert chosen.method.id == "ATA_SECURE_ERASE"


def test_ata_unsupported_falls_back_to_clear_overwrite():
    probe = lambda t: {"supported": False, "enhanced_supported": False, "frozen": False}
    chosen, alts = select_method(SSD, ata_probe=probe)
    assert isinstance(chosen.method, OverwriteMethod)
    assert chosen.method.nist_category == "Clear"
    assert any("does not advertise" in a.reason for a in alts)


def test_frozen_drive_never_gets_ata_path():
    probe = lambda t: {"supported": True, "enhanced_supported": True, "frozen": True}
    chosen, alts = select_method(HDD, ata_probe=probe)
    assert isinstance(chosen.method, OverwriteMethod)
    assert any("FROZEN" in a.reason for a in alts)


def test_no_hdparm_binary_skips_firmware_path(monkeypatch):
    monkeypatch.setattr(wipe_mod, "shutil", without_binary("hdparm"))
    chosen, alts = select_method(HDD)  # no ata_probe needed; binary missing short-circuits
    assert isinstance(chosen.method, OverwriteMethod)


def test_discard_justification_promotes_blkdiscard_to_purge():
    chosen, _ = select_method(
        SSD, discard_justification="Vendor spec guarantees DRAT/RZAT (rev 3.1 §4.2)")
    assert chosen.method.id == "BLKDISCARD"
    assert chosen.method.nist_category == "Purge"


# --------------------------------------------------------------------------- #
# safety refusals
# --------------------------------------------------------------------------- #

@pytest.fixture
def block_dev(tmp_path):
    return Target(path=str(tmp_path / "sdx"), kind="block", capacity_bytes=2**20,
                  storage_type="SSD", serial="SER-9")


def test_refuses_mounted_device_without_force(block_dev, monkeypatch):
    monkeypatch.setattr("s0.cli.devices._mounted_paths",
                        lambda: {block_dev.path + "1"})
    with pytest.raises(SafetyError, match="mounted filesystems"):
        check_safety(block_dev, force=False)


def test_force_downgrades_mount_refusal_to_warning(block_dev, monkeypatch):
    monkeypatch.setattr("s0.cli.devices._mounted_paths",
                        lambda: {block_dev.path + "1"})
    warnings = check_safety(block_dev, force=True)
    assert any("WITH MOUNTED FILESYSTEMS" in w for w in warnings)


def test_refuses_running_root_filesystem(block_dev, monkeypatch):
    monkeypatch.setattr("s0.cli.devices._mounted_paths", lambda: set())

    class FakeProc:
        returncode = 0
        stdout = block_dev.path + "\n"

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: FakeProc())
    with pytest.raises(SafetyError, match="ROOT filesystem"):
        check_safety(block_dev, force=False)


def test_image_targets_are_always_safe():
    assert check_safety(IMG) == []


def test_device_id_prefers_serial_then_hash():
    assert device_id_for(SSD) == "SER-123"
    fallback = device_id_for(Target(path="/dev/sdz", kind="block",
                                    capacity_bytes=1, storage_type="UNKNOWN"))
    import hashlib

    assert fallback == "sha256:" + hashlib.sha256(b"/dev/sdz").hexdigest()


def test_root_disk_protection_falls_back_to_proc_mounts(block_dev, monkeypatch):
    monkeypatch.setattr("s0.cli.devices._mounted_paths", lambda: set())
    # findmnt fails
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(FileNotFoundError("findmnt not found")))
    # /proc/mounts returns block_dev.path as root
    import io
    fake_mounts = f"{block_dev.path}2 / ext4 rw,relatime 0 0\n"
    import builtins
    real_open = builtins.open
    def mock_open(path, *a, **k):
        if str(path) == "/proc/mounts":
            return io.StringIO(fake_mounts)
        return real_open(path, *a, **k)

    monkeypatch.setattr(builtins, "open", mock_open)
    with pytest.raises(SafetyError, match="ROOT filesystem"):
        check_safety(block_dev, force=False)


def test_root_disk_protection_fails_closed_when_indeterminate(block_dev, monkeypatch):
    monkeypatch.setattr("s0.cli.devices._mounted_paths", lambda: set())
    # Both findmnt and /proc/mounts fail to resolve
    monkeypatch.setattr("s0.cli.devices._get_root_mount_source", lambda: None)
    with pytest.raises(SafetyError, match="Cannot verify whether"):
        check_safety(block_dev, force=False)

    warnings = check_safety(block_dev, force=True)
    assert any("could not verify whether target hosts the root filesystem" in w for w in warnings)


def test_is_os_device_detection(monkeypatch):
    from s0.cli.devices import is_os_device
    monkeypatch.setattr("s0.cli.devices._get_root_mount_source", lambda: "/dev/sda2")
    assert is_os_device("/dev/sda2") is True
    assert is_os_device("/dev/sda") is True
    assert is_os_device("/dev/sdb") is False
    assert is_os_device("") is False

    # Fedora LUKS encrypted root test (mapper device backed by nvme partition)
    monkeypatch.setattr("s0.cli.devices._get_root_mount_source", lambda: "/dev/mapper/luks-fedora-root")
    monkeypatch.setattr("s0.cli.devices._get_underlying_devices", lambda src: {"/dev/mapper/luks-fedora-root", "/dev/nvme0n1p3"})
    assert is_os_device("/dev/mapper/luks-fedora-root") is True
    assert is_os_device("/dev/nvme0n1p3") is True
    assert is_os_device("/dev/nvme0n1") is True
    assert is_os_device("/dev/sdb") is False


def test_cmd_wipe_rejects_block_device_in_targets(monkeypatch, capsys):
    from types import SimpleNamespace
    from pathlib import Path
    import s0.cli.main as main_mod

    args = SimpleNamespace(
        targets=["/dev/sdb"],
        target=None,
        yes=True,
        key=None,
        out_dir=".",
        operator="test",
        organization="test",
    )
    monkeypatch.setattr(Path, "is_block_device", lambda self: True)
    rc = main_mod.cmd_wipe(args)
    # sysexits: passing a block device to --targets is a usage error (64),
    # not a generic failure (1) or argparse's 2.
    assert rc == EX_USAGE
    captured = capsys.readouterr()
    assert "is a block storage device" in captured.err

