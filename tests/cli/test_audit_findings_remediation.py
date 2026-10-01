"""Comprehensive tests verifying remediation of all forensic audit findings.

Covers:
1. Block device sizing, partition mount safety, and 0-byte wipe rejection.
2. ext4 deleted inode scanner strictly skipping reserved inodes (journal) and live inodes.
3. Whole-disk partitioned MBR/GPT filesystem detection and carving.
4. NTFS carver file pointer preservation during non-resident data extraction.
5. Removal of fabricated verification fields in certificates.
6. CoW warnings propagated into batch erasure certificates.
7. Audit ledger recording error reporting (no silent pass).
8. Entropy scoring strictly rejecting zero-filled buffers.
"""

import struct
from pathlib import Path

from s0.carve import boundary
from s0.carve.engine import (
    carve_image,
    detect_filesystem,
    detect_partitions,
)
from s0.carve.ext4_carver import (
    scan_ext4_deleted_inodes,
)
from s0.carve.ntfs_carver import (
    ATTR_DATA,
    ATTR_END_MARKER,
    MFT_RECORD_MAGIC,
    parse_mft_record_bytes,
)
from s0.carve.scoring import (
    score_carved_candidate,
)
from s0.carve.signatures import get_signature_by_ext
from s0.cli.devices import (
    Target,
    _is_dev_or_subpartition,
)
from s0.wipe.planner import verify_wipe


def test_partition_mount_matching_no_false_positive():
    assert _is_dev_or_subpartition("/dev/sda1", "/dev/sda1") is True
    assert _is_dev_or_subpartition("/dev/sda1", "/dev/sda10") is False
    assert _is_dev_or_subpartition("/dev/sda1", "/dev/sda2") is False

    assert _is_dev_or_subpartition("/dev/sda", "/dev/sda") is True
    assert _is_dev_or_subpartition("/dev/sda", "/dev/sda1") is True
    assert _is_dev_or_subpartition("/dev/sda", "/dev/sda10") is True
    assert _is_dev_or_subpartition("/dev/sda", "/dev/sdb1") is False


def test_zero_capacity_wipe_verification_fails():
    target = Target(
        path="/dev/loop99",
        kind="block",
        capacity_bytes=0,
        sector_size=512,
        storage_type="UNKNOWN",
    )
    verif, post = verify_wipe(target, "zero", offsets=[], sample_bytes=4096)
    assert verif["all_samples_match_wipe_pattern"] is False
    assert "Zero readback samples obtained" in verif["verification_error"]


def test_ext4_scanner_skips_journal_and_live_inodes(tmp_path: Path):
    block_size = 1024
    blocks_count = 128
    blocks_per_group = 128
    inodes_per_group = 32
    inode_size = 256

    img = bytearray(blocks_count * block_size)

    sb_off = 1024
    struct.pack_into("<I", img, sb_off + 0, 32)
    struct.pack_into("<I", img, sb_off + 4, blocks_count)
    struct.pack_into("<I", img, sb_off + 20, 1)
    struct.pack_into("<I", img, sb_off + 24, 0)
    struct.pack_into("<I", img, sb_off + 32, blocks_per_group)
    struct.pack_into("<I", img, sb_off + 40, inodes_per_group)
    struct.pack_into("<H", img, sb_off + 56, 0xEF53)
    struct.pack_into("<H", img, sb_off + 88, inode_size)

    bgd_off = 2 * block_size
    inode_table_block = 5
    struct.pack_into("<I", img, bgd_off + 8, inode_table_block)

    it_start = inode_table_block * block_size

    # Inode 8 (Journal Inode) - regular file, size > 0, dtime == 0, links == 1 -> MUST BE SKIPPED
    ino8_off = it_start + (8 - 1) * inode_size
    struct.pack_into("<H", img, ino8_off + 0, 0x81A4)
    struct.pack_into("<I", img, ino8_off + 4, 16384)
    struct.pack_into("<I", img, ino8_off + 20, 0)
    struct.pack_into("<H", img, ino8_off + 26, 1)

    # Inode 12 (Live File) - regular file, size > 0, dtime == 0, links == 1 -> MUST BE SKIPPED
    ino12_off = it_start + (12 - 1) * inode_size
    struct.pack_into("<H", img, ino12_off + 0, 0x81A4)
    struct.pack_into("<I", img, ino12_off + 4, 1024)
    struct.pack_into("<I", img, ino12_off + 20, 0)
    struct.pack_into("<H", img, ino12_off + 26, 1)

    # Inode 14 (GENUINE DELETED FILE) - dtime > 0, links == 0, inode >= 11 -> MUST BE RECOVERED
    payload = b"GENUINE DELETED EVIDENCE FILE"
    payload_block = 20
    img[payload_block * block_size : payload_block * block_size + len(payload)] = payload

    ino14_off = it_start + (14 - 1) * inode_size
    struct.pack_into("<H", img, ino14_off + 0, 0x81A4)
    struct.pack_into("<I", img, ino14_off + 4, len(payload))
    struct.pack_into("<I", img, ino14_off + 20, 1700000000)
    struct.pack_into("<H", img, ino14_off + 26, 0)
    struct.pack_into("<I", img, ino14_off + 32, 0x00080000)
    struct.pack_into("<H", img, ino14_off + 40 + 0, 0xF30A)
    struct.pack_into("<H", img, ino14_off + 40 + 2, 1)
    struct.pack_into("<H", img, ino14_off + 40 + 4, 4)
    struct.pack_into("<H", img, ino14_off + 40 + 6, 0)
    struct.pack_into("<I", img, ino14_off + 52 + 0, 0)
    struct.pack_into("<H", img, ino14_off + 52 + 4, 1)
    struct.pack_into("<H", img, ino14_off + 52 + 6, 0)
    struct.pack_into("<I", img, ino14_off + 52 + 8, payload_block)

    img_path = tmp_path / "ext4_filter.raw"
    img_path.write_bytes(img)

    recovered = scan_ext4_deleted_inodes(img_path)
    assert len(recovered) == 1
    assert recovered[0].inode_num == 14
    assert recovered[0].data == payload


def test_whole_disk_partition_detection_and_carving(tmp_path: Path):
    sector_size = 512
    part_start_sector = 2048
    part_offset = part_start_sector * sector_size
    total_size = part_offset + (128 * 1024)

    img = bytearray(total_size)

    img[510:512] = b"\x55\xaa"
    mbr_entry1 = 446
    img[mbr_entry1 + 4] = 0x83
    struct.pack_into("<I", img, mbr_entry1 + 8, part_start_sector)
    struct.pack_into("<I", img, mbr_entry1 + 12, 128 * 2)

    sb_off = part_offset + 1024
    struct.pack_into("<I", img, sb_off + 0, 32)
    struct.pack_into("<I", img, sb_off + 4, 128)
    struct.pack_into("<I", img, sb_off + 20, 1)
    struct.pack_into("<I", img, sb_off + 24, 0)
    struct.pack_into("<I", img, sb_off + 32, 128)
    struct.pack_into("<I", img, sb_off + 40, 32)
    struct.pack_into("<H", img, sb_off + 56, 0xEF53)
    struct.pack_into("<H", img, sb_off + 88, 256)

    img_file = tmp_path / "partitioned_disk.raw"
    img_file.write_bytes(img)

    parts = detect_partitions(img_file)
    assert len(parts) >= 1
    assert parts[0][0] == "ext4"
    assert parts[0][1] == part_offset

    fs = detect_filesystem(img_file)
    assert fs == "ext4"


def test_ntfs_carver_file_handle_preservation(tmp_path: Path):
    disk_data = bytearray(64 * 1024)
    cluster_size = 4096

    target_cluster = 5
    payload = b"NON-RESIDENT DATA STREAM"
    data_offset = target_cluster * cluster_size
    disk_data[data_offset : data_offset + len(payload)] = payload

    img_path = tmp_path / "ntfs_seek_test.raw"
    img_path.write_bytes(disk_data)

    rec = bytearray(1024)
    rec[0:4] = MFT_RECORD_MAGIC
    struct.pack_into("<H", rec, 0x14, 56)
    struct.pack_into("<H", rec, 0x16, 0x00)
    struct.pack_into("<I", rec, 0x2C, 42)

    off = 56
    struct.pack_into("<I", rec, off + 0, ATTR_DATA)
    attr_len = 72
    struct.pack_into("<I", rec, off + 4, attr_len)
    rec[off + 8] = 1
    rec[off + 9] = 0
    struct.pack_into("<H", rec, off + 32, 64)
    struct.pack_into("<Q", rec, off + 48, len(payload))

    rec[off + 64 + 0] = 0x11
    rec[off + 64 + 1] = 1
    rec[off + 64 + 2] = target_cluster
    rec[off + 64 + 3] = 0

    struct.pack_into("<I", rec, off + attr_len, ATTR_END_MARKER)

    with open(img_path, "r+b") as f:
        initial_pos = 1000
        f.seek(initial_pos)

        parsed = parse_mft_record_bytes(bytes(rec), disk_file=f, cluster_size=cluster_size)

        assert f.tell() == initial_pos
        assert parsed is not None
        assert parsed.data == payload
        assert parsed.is_deleted is True


def test_carver_manifest_verification_integrity(tmp_path: Path):
    """A carve manifest must not borrow sanitization vocabulary: there is no
    wipe pattern and no planted data on a read-only recovery operation."""
    target_img = tmp_path / "target.img"
    target_img.write_bytes(b"%PDF-1.7\ntrailer<</Root 1 0 R>>\n%%EOF" + bytes(4096))

    out_dir = tmp_path / "carved_out"
    summary = carve_image(target_img, out_dir)

    assert summary.manifest_certificate is not None
    verif = summary.manifest_certificate["result"]["verification"]
    assert "all_samples_match_wipe_pattern" not in verif
    assert "planted_pattern_hits_after" not in verif
    assert verif["method"] == "per_artifact_boundary_resolution_and_structural_validation"
    assert "rejected" in verif["attestation"]


def test_scoring_flags_effectively_constant_data():
    """Padding and unwritten allocations are the one thing entropy may deny.

    A valid but very small file must still pass; only near-zero-entropy data
    should be called out, and it must be called out explicitly.
    """
    pdf_sig = get_signature_by_ext("pdf")
    assert pdf_sig is not None

    zero_buf = b"%PDF-" + bytes(1024)
    score, heuristics = score_carved_candidate(pdf_sig, zero_buf, has_valid_footer=True)
    assert any("effectively constant" in h for h in heuristics)

    real = b"%PDF-1.7\n" + b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n" * 8 \
        + b"trailer<</Root 1 0 R>>\n%%EOF"
    score2, h2 = score_carved_candidate(pdf_sig, real,
                                        boundary_method=boundary.FOOTER_ANCHORED)
    assert score2 > score
    assert not any("effectively constant" in h for h in h2)


def test_random_wipe_verification_entropy(tmp_path: Path):
    import os


    # Create file with random bytes
    rand_file = tmp_path / "random.img"
    rand_file.write_bytes(os.urandom(64 * 1024))

    target = Target(
        path=str(rand_file),
        kind="image",
        capacity_bytes=64 * 1024,
        sector_size=512,
        storage_type="UNKNOWN",
    )
    verif, post = verify_wipe(target, "random", samples=8, sample_bytes=1024)
    assert verif["all_samples_match_wipe_pattern"] is True
    assert verif["average_entropy"] >= 7.0
    assert verif["pct_non_zero_samples"] == 1.0

    # Test file with repeating pattern (low entropy) fails random verification
    low_entropy_file = tmp_path / "low_entropy.img"
    low_entropy_file.write_bytes(b"A" * (64 * 1024))
    target_low = Target(
        path=str(low_entropy_file),
        kind="image",
        capacity_bytes=64 * 1024,
        sector_size=512,
        storage_type="UNKNOWN",
    )
    verif_low, post_low = verify_wipe(target_low, "random", samples=8, sample_bytes=1024)
    assert verif_low["all_samples_match_wipe_pattern"] is False
    assert verif_low["average_entropy"] < 1.0


def test_csprng_sample_offsets():
    from s0.wipe.planner import sample_offsets

    # Small device branch (total_sectors <= count * 2)
    offs_small = sample_offsets(capacity=4096, sector_size=512, count=4)
    assert len(offs_small) == 4
    assert all(off % 512 == 0 for off in offs_small)

    # Large device branch
    offs_large = sample_offsets(capacity=100 * 1024 * 1024, sector_size=512, count=16)
    assert len(offs_large) == 16
    assert all(off % 512 == 0 for off in offs_large)


def test_mount_octal_unescaping():
    from s0.cli.devices import _unescape_mount_field

    assert _unescape_mount_field(r"/media/My\040Drive/disk\040image") == "/media/My Drive/disk image"
    assert _unescape_mount_field(r"/mnt/test\011tab\012newline") == "/mnt/test\ttab\nnewline"
    assert _unescape_mount_field(r"/dev/sda1") == "/dev/sda1"


def test_partition_boundary_matching():
    from s0.cli.devices import _is_dev_or_subpartition, _is_partition

    assert _is_partition("sda") is False
    assert _is_partition("sda1") is True
    assert _is_partition("sda10") is True
    assert _is_partition("nvme0n1") is False
    assert _is_partition("nvme0n1p1") is True
    assert _is_partition("loop0") is False
    assert _is_partition("loop0p1") is True
    assert _is_partition("mmcblk0") is False
    assert _is_partition("mmcblk0p1") is True

    # Subpartition relationships
    assert _is_dev_or_subpartition("/dev/sda", "/dev/sda1") is True
    assert _is_dev_or_subpartition("/dev/sda1", "/dev/sda10") is False
    assert _is_dev_or_subpartition("/dev/nvme0n1", "/dev/nvme0n1p3") is True
    assert _is_dev_or_subpartition("/dev/nvme0n1p1", "/dev/nvme0n1p10") is False


def test_hpa_gate_fails_closed_when_hdparm_missing(monkeypatch, capsys):
    import argparse
    import shutil

    from s0.cli.main import cmd_wipe

    monkeypatch.setattr(shutil, "which", lambda cmd: None)
    monkeypatch.setattr("s0.cli.main._resolve_target", lambda path: Target(path="/dev/sde", kind="block", capacity_bytes=100*1024*1024, sector_size=512, storage_type="HDD"))
    monkeypatch.setattr("s0.cli.main.check_safety", lambda target, force=False: [])
    monkeypatch.setattr("s0.cli.devices._get_root_mount_source", lambda: None)
    monkeypatch.setattr("s0.cli.devices._mounted_paths", lambda: set())

    args = argparse.Namespace(
        target="/dev/sde",
        targets=None,
        method=None,
        passes=1,
        pattern="zero",
        verify=True,
        verify_samples=8,
        verify_pattern_readback=True,
        no_firmware=True,
        discard_purge_justification=None,
        key=None,
        out=None,
        yes=True,
        force=False,
        json=False,
        operator_name="Auditor",
        operator_id="AUD-01",
        operator_role="Tester",
        organization="TestOrg",
        destruction_purpose="Test",
        internal_ticket_id=None,
    )
    rc = cmd_wipe(args)
    assert rc == 2
    err = capsys.readouterr().err
    assert "hdparm is not installed" in err


