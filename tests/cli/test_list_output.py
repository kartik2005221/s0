"""`s0 list`: OS detection and table geometry.

Two board bugs, one module:

* OS DRIVE read "-" forever on Fedora/openSUSE because findmnt reports the btrfs
  root as ``/dev/sda2[/@]`` and the bracketed subvolume suffix survived into
  matching, where it matched nothing. Also: on the Live ISO the running root is
  the live overlay, so *no* disk could ever be flagged -- hence the LIKELY
  heuristic (an EFI System Partition on the disk), display-only.
* Long NVMe model names cut their own vendor prefix off (the MODEL column used
  the left-ellipsis reserved for identifiers) and pushed the right-hand columns
  off a 100-column terminal, because the renderer had no total-width budget.
"""

from __future__ import annotations

from s0.cli import devices as devices_mod
from s0.cli.devices import (
    EFI_SYSTEM_PARTITION_GUID,
    is_likely_os_device,
    is_os_device,
)

# --------------------------------------------------------------------------- #
# btrfs subvolume suffix
# --------------------------------------------------------------------------- #


def test_root_mount_source_strips_btrfs_subvolume_suffix(monkeypatch):
    """`findmnt -o SOURCE /` on Fedora/openSUSE prints /dev/sda2[/@]; the
    literal bracketed string realpath()s to itself and matches no device."""
    import subprocess as sp

    class FakeProc:
        returncode = 0
        stdout = "/dev/sda2[/@]\n"

    monkeypatch.setattr(sp, "run", lambda *a, **k: FakeProc())
    monkeypatch.setattr("os.path.realpath", lambda p: p)  # nothing exists at that name
    assert devices_mod._get_root_mount_source() == "/dev/sda2"


def test_btrfs_root_disk_is_flagged_as_os_device(monkeypatch):
    """Through is_os_device: with the root resolved from a subvolume-suffixed
    source and the underlying walk naming sda2, the disk must be flagged --
    the SafetyError message users actually see."""
    import subprocess as sp

    class FakeFindmnt:
        returncode = 0
        stdout = "/dev/sda2[/@]\n"

    def fake_run(cmd, *a, **k):
        if cmd[:2] == ["lsblk", "-s"]:
            return sp.CompletedProcess(cmd, 1, "", "no lsblk in sandbox")
        return FakeFindmnt()

    monkeypatch.setattr(sp, "run", fake_run)
    monkeypatch.setattr("os.path.realpath", lambda p: p)  # nothing exists at that name
    assert devices_mod._get_root_mount_source() == "/dev/sda2"
    # The resolved source itself is an underlying device, so the disk and the
    # subvolume's partition are both flagged the moment the suffix is stripped:
    assert is_os_device("/dev/sda") is True
    assert is_os_device("/dev/sda2") is True
    assert is_os_device("/dev/sdb") is False


# --------------------------------------------------------------------------- #
# LIKELY heuristic (EFI System Partition)
# --------------------------------------------------------------------------- #


PARTTABLE = {
    "sda": "",
    "sda1": EFI_SYSTEM_PARTITION_GUID,  # ESP
    "sda2": "0fc63daf-8483-4772-8e79-3d69d8477de4",  # linux fs
    "sdb": "",
    "sdb1": "0fc63daf-8483-4772-8e79-3d69d8477de4",
}


def test_likely_os_via_esp_on_whole_disk(monkeypatch):
    monkeypatch.setattr(devices_mod, "partition_type_map", lambda: dict(PARTTABLE))
    assert is_likely_os_device("/dev/sda") is True


def test_likely_os_via_esp_partition_itself(monkeypatch):
    monkeypatch.setattr(devices_mod, "partition_type_map", lambda: dict(PARTTABLE))
    assert is_likely_os_device("/dev/sda1") is True


def test_data_disk_without_esp_is_not_likely_os(monkeypatch):
    monkeypatch.setattr(devices_mod, "partition_type_map", lambda: dict(PARTTABLE))
    assert is_likely_os_device("/dev/sdb") is False


def test_siblings_of_same_prefix_do_not_leak(monkeypatch):
    """/dev/sda1 being an ESP must not make /dev/sdb likely (name regex)."""
    table = dict(PARTTABLE)
    table["sdb"] = ""
    monkeypatch.setattr(devices_mod, "partition_type_map", lambda: table)
    assert is_likely_os_device("/dev/sdb") is False
    # sda10-style suffixes must still be attributed to sda:
    table["sda10"] = EFI_SYSTEM_PARTITION_GUID
    assert is_likely_os_device("/dev/sda") is True


def test_nvme_p_separator_is_matched(monkeypatch):
    table = {"nvme0n1": "", "nvme0n1p1": EFI_SYSTEM_PARTITION_GUID}
    monkeypatch.setattr(devices_mod, "partition_type_map", lambda: table)
    assert is_likely_os_device("/dev/nvme0n1") is True


def test_empty_table_is_not_likely(monkeypatch):
    monkeypatch.setattr(devices_mod, "partition_type_map", lambda: {})
    assert is_likely_os_device("/dev/sda") is False


def test_windows_is_never_likely(monkeypatch):
    monkeypatch.setattr(devices_mod.sys, "platform", "win32")
    monkeypatch.setattr(devices_mod, "partition_type_map", lambda: dict(PARTTABLE))
    assert is_likely_os_device("/dev/sda") is False


# --------------------------------------------------------------------------- #
# Table geometry
# --------------------------------------------------------------------------- #


def _render(policy, rows):
    from s0.terminal import Column, render_table

    render_table(
        policy,
        [
            Column("PATH", max_width=28),
            Column("TYPE"),
            Column("STORAGE"),
            Column("CAPACITY", align="r"),
            Column("MODEL", max_width=24, tail=False),
            Column("SERIAL", max_width=18),
            Column("MOUNTED", align="r"),
            Column("OS DRIVE", align="r"),
        ],
        rows,
    )


def test_model_is_truncated_from_the_right_keeping_the_vendor(capsys):
    """KIOXIA's vendor prefix used to be cut off by the identifier-style
    left-ellipsis; a model name is prose and cut from the right."""
    from s0.terminal import OutputPolicy

    policy = OutputPolicy()
    _render(
        policy,
        [
            [
                "/dev/sda",
                "disk",
                "SSD",
                "1 TB",
                "KIOXIA-EXCERIA_PLUS_G3_SSD_2TB_SUPER_LONG_MODEL_XYZ",
                "SER123",
                "-",
                "-",
            ]
        ],
    )
    err = capsys.readouterr().err
    assert "KIOXIA-EXCERIA_PLUS_G" in err, "the vendor prefix must survive: " + err
    assert "R_LONG" not in err, "the tail (right-hand characters) must be what gets cut from a model: " + err


def test_table_never_exceeds_the_terminal_width(capsys, monkeypatch):
    """The right-hand columns (MOUNTED, OS DRIVE) must survive on a narrow
    terminal instead of wrapping off-screen."""
    from s0.terminal import OutputPolicy

    monkeypatch.setattr(OutputPolicy, "width", property(lambda self: 100))
    policy = OutputPolicy()
    long_model = "SAMSUNG_990_PRO_WITH_AN_EXTREMELY_LONG_NVME_MODEL_NAME_STRING"[:60]
    _render(
        policy,
        [
            ["/dev/nvme0n1", "disk", "SSD", "1 TB", long_model, "S5XBNX0T123456", "-", "-"],
            ["/dev/nvme0n1p1", "part", "UNKNOWN", "500 MB", "—", "—", "YES", "LIKELY"],
        ],
    )
    err = capsys.readouterr().err
    lines = [ln for ln in err.splitlines() if ln.startswith("  /dev")]
    assert lines, err
    for ln in lines:
        assert len(ln.rstrip()) <= 100, f"table row overflows a 100-column terminal:\n{ln}"


def test_columns_never_shrink_below_their_caption(capsys, monkeypatch):
    from s0.terminal import OutputPolicy

    monkeypatch.setattr(OutputPolicy, "width", property(lambda self: 60))
    policy = OutputPolicy()
    _render(
        policy, [["/dev/sda", "disk", "SSD", "1 TB", "LONG_MODEL_NAME_HERE_XYZ", "SER12345678", "-", "-"]]
    )
    err = capsys.readouterr().err
    assert "MODEL" in err and "OS DRIVE" in err, "captions must survive the shrink: " + err
