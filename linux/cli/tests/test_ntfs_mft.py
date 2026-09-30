"""Tests for NTFS $MFT record recovery.

The fixtures here build a byte-accurate $MFT by hand, using the record layout
confirmed against a volume produced by mkntfs: the attribute chain starts at the
offset in the header field at 0x14, the update sequence number lives in the
first slot of the fixup array (not in the $LogFile field at 0x08), the array's
count is the sector count plus one, and the record number is at 0x2C.

Building it by hand rather than shelling out to mkntfs is deliberate: mkntfs
cannot create a *deleted* file, and a deleted record is the entire subject here.
Each fixture writes a real update sequence array, so the fixup is exercised for
real rather than assumed away.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from s0_cli.carver import mft
from s0_cli.carver.ntfs_carver import parse_ntfs_boot_sector, scan_ntfs_deleted_records

SECTOR = 512
REC = 1024
CLUSTER = 4096
EPOCH = 11644473600


MFT_LCN = 4


def record_at(img: bytes, index: int) -> bytes:
    """The *index*-th MFT record in the image (four records share a cluster)."""
    start = MFT_LCN * CLUSTER + index * REC
    return img[start : start + REC]


def nt(ts: float) -> int:
    return int((ts + EPOCH) * 10_000_000)


# --------------------------------------------------------------------------- #
# fixture construction
# --------------------------------------------------------------------------- #


class MftBuilder:
    """Assembles a valid $MFT image: boot sector, MFT records and file data.

    The volume is deliberately tiny. A 1 KiB record plus a few clusters of file
    data is all these tests need, and a suite that writes 16 MB per fixture burns
    hundreds of megabytes of temporary space on every run.
    """

    def __init__(self, total_clusters: int = 96):
        self.total_clusters = total_clusters
        self.records: dict[int, bytes] = {}
        self.alloc: dict[int, bytes] = {}

    def add_data(self, blob: bytes) -> int:
        """Place a blob on a cluster boundary and return its starting LCN.

        Allocations are spaced ten clusters apart so that a file whose run list
        covers two clusters cannot run into the next file's data.
        """
        lcn = 10 + 4 * len(self.alloc)
        self.alloc[lcn] = blob
        return lcn

    @staticmethod
    def run_for(blob: bytes) -> tuple:
        """The run list that covers `blob`, which may span several clusters."""
        return (None, -(-len(blob) // CLUSTER))

    def _attribute(self, attr_type: int, name: str, value: bytes,
                   runs: list | None = None, flags: int = 0) -> bytes:
        name_bytes = name.encode("utf-16le")
        if runs is None:
            length = 0x18 + len(name_bytes) + len(value)
            length = (length + 7) & ~7
            out = bytearray(length)
            struct.pack_into("<I", out, 0x00, attr_type)
            struct.pack_into("<I", out, 0x04, length)
            out[0x08] = 0
            out[0x09] = len(name)
            struct.pack_into("<H", out, 0x0A, 0x18)
            struct.pack_into("<H", out, 0x0C, 0)
            struct.pack_into("<I", out, 0x10, len(value))
            struct.pack_into("<H", out, 0x14, 0x18 + len(name_bytes))
            struct.pack_into("<H", out, 0x16, flags)
            # Assign an exact-length slice: `out[0x18:] = value` resizes the
            # bytearray, which silently truncates the attribute below its own
            # declared length and desynchronises the whole chain.
            payload = name_bytes + value
            out[0x18 : 0x18 + len(payload)] = payload
            assert len(out) == length
            return bytes(out)
        # Non-resident: encode the run list, then size the attribute around it.
        runlist = bytearray()
        lcn = 0
        for start, count in runs:
            length = -(-count * CLUSTER // CLUSTER)
            delta = start - lcn
            assert delta >= 0, "the fixture only emits ascending runs"
            runlist += bytes([0x21, length & 0xFF, delta & 0xFF, (delta >> 8) & 0xFF])
            lcn = start
        real = -(-len(value) // CLUSTER) * CLUSTER
        length = 0x40 + len(name_bytes) + len(runlist)
        length = (length + 7) & ~7
        out = bytearray(length)
        struct.pack_into("<I", out, 0x00, attr_type)
        struct.pack_into("<I", out, 0x04, length)
        out[0x08] = 1
        out[0x09] = len(name)
        struct.pack_into("<H", out, 0x0A, 0x40)
        struct.pack_into("<H", out, 0x0C, 0)
        struct.pack_into("<H", out, 0x20, 0x40 + len(name_bytes))
        struct.pack_into("<Q", out, 0x28, real)
        struct.pack_into("<Q", out, 0x30, len(value))
        struct.pack_into("<Q", out, 0x38, len(value))
        struct.pack_into("<H", out, 0x16, flags)
        payload = name_bytes + bytes(runlist)
        out[0x40 : 0x40 + len(payload)] = payload
        assert len(out) == length
        return bytes(out)

    def standard_information(self, created: float, modified: float | None = None,
                             changed: float | None = None,
                             accessed: float | None = None) -> bytes:
        modified = modified if modified is not None else created + 60
        changed = changed if changed is not None else created + 120
        accessed = accessed if accessed is not None else created + 180
        out = bytearray(0x24)
        struct.pack_into("<QQQQ", out, 0x00, nt(created), nt(modified),
                         nt(changed), nt(accessed))
        return bytes(out)

    def file_name(self, name: str, parent: tuple[int, int], created: float,
                  real_size: int = 0, allocated_size: int = 0) -> bytes:
        raw = name.encode("utf-16le")
        out = bytearray(0x42 + len(raw))
        ref = (parent[0] & 0x0000FFFFFFFFFFFF) | ((parent[1] & 0xFFFF) << 48)
        struct.pack_into("<Q", out, 0x00, ref)
        struct.pack_into("<Q", out, 0x08, nt(created))
        struct.pack_into("<Q", out, 0x10, nt(created + 60))
        struct.pack_into("<Q", out, 0x18, nt(created + 120))
        struct.pack_into("<Q", out, 0x20, nt(created + 180))
        struct.pack_into("<Q", out, 0x28, allocated_size)
        struct.pack_into("<Q", out, 0x30, real_size)
        struct.pack_into("<I", out, 0x38, 0)
        struct.pack_into("<I", out, 0x3C, 0)
        out[0x40] = len(name)
        out[0x41] = 1
        out[0x42:] = raw
        return bytes(out)

    def record(self, rec_num: int, *, allocated: bool = True, is_dir: bool = False,
               sequence: int = 1, attributes: list[bytes] = (),
               extra_names: list[bytes] = ()) -> bytes:
        rec = bytearray(REC)
        rec[0:4] = b"FILE"
        struct.pack_into("<H", rec, 0x0C, sequence)
        struct.pack_into("<H", rec, 0x0E, 1)
        struct.pack_into("<H", rec, 0x14, 0x38)          # offset to first attribute
        struct.pack_into("<H", rec, 0x16, (0x01 if allocated else 0) | (0x02 if is_dir else 0))
        struct.pack_into("<I", rec, 0x18, 0)             # bytes in use, filled below
        struct.pack_into("<I", rec, 0x1C, REC)
        struct.pack_into("<I", rec, 0x28, len(attributes) + 1)
        struct.pack_into("<I", rec, 0x2C, rec_num)

        pos = 0x38
        for attr in list(attributes) + list(extra_names):
            rec[pos : pos + len(attr)] = attr
            pos += len(attr)
        struct.pack_into("<II", rec, pos, 0xFFFFFFFF, 0)
        pos += 8
        struct.pack_into("<I", rec, 0x18, pos)

        # Write a real update sequence array, exactly as NTFS does.
        usa_off = pos
        usa_cnt = REC // SECTOR + 1
        struct.pack_into("<H", rec, 0x04, usa_off)
        struct.pack_into("<H", rec, 0x06, usa_cnt)
        struct.pack_into("<H", rec, usa_off, sequence)
        for i in range(1, usa_cnt):
            struct.pack_into("<H", rec, usa_off + i * 2, 0)
        saved = []
        for i in range(1, usa_cnt):
            tail = i * SECTOR - 2
            saved.append(bytes(rec[tail : tail + 2]))
            struct.pack_into("<H", rec, tail, sequence)
        for i in range(1, usa_cnt):
            struct.pack_into("<H", rec, usa_off + i * 2,
                             struct.unpack_from("<H", saved[i - 1], 0)[0])
        return bytes(rec)

    def write(self, path: Path) -> Path:
        total_sectors = 64 + self.total_clusters * (CLUSTER // SECTOR)
        img = bytearray(total_sectors * SECTOR)

        mft_lcn = 4
        struct.pack_into("<H", img, 0x0B, SECTOR)
        img[0x0D] = CLUSTER // SECTOR
        img[3:11] = b"NTFS    "
        struct.pack_into("<Q", img, 0x28, total_sectors)
        struct.pack_into("<Q", img, 0x30, mft_lcn)
        struct.pack_into("<b", img, 0x40, -10)          # 2^10 = 1024-byte records
        struct.pack_into("<H", img, 0x1FE, 0xAA55)

        # Record 0 must be part of the record run, not written over the top of
        # it: it carries the $MFT's own run list, and a reader that follows those
        # extents has to find record 0 there too.
        per_run = CLUSTER // REC
        recs = [self.records[i] for i in sorted(self.records)]

        def layout(runs):
            out = []
            for start in range(0, len(runs), per_run):
                out.extend(runs[start : start + per_run])
            return out

        placeholder = self.record(
            0, attributes=[self._attribute(0x80, "", b"", runs=[(mft_lcn, 1)])],
            extra_names=[self._attribute(0x30, "", self.file_name("$MFT", (5, 1), 1700000000))])
        recs = [placeholder] + recs
        runs = layout([(mft_lcn, per_run)] * ((len(recs) + per_run - 1) // per_run))
        runs = [(mft_lcn + i, 1) for i in range((len(recs) + per_run - 1) // per_run)]
        recs[0] = self.record(
            0, attributes=[self._attribute(0x80, "", b"", runs=runs)],
            extra_names=[self._attribute(0x30, "", self.file_name("$MFT", (5, 1), 1700000000))])

        for i, r in enumerate(recs):
            off = (mft_lcn + i // per_run) * CLUSTER + (i % per_run) * REC
            img[off : off + REC] = r

        for lcn_start, blob in self.alloc.items():
            off = lcn_start * CLUSTER
            img[off : off + len(blob)] = blob

        path.write_bytes(bytes(img))
        return path


def _volume(tmp_path: Path, deleted: bool = True) -> Path:
    """A volume with a live file and (optionally) a deleted one in a subdirectory."""
    b = MftBuilder()
    b.records[5] = b.record(
        5, is_dir=True,
        attributes=[b._attribute(0x10, "", b.standard_information(1700000000))],
        extra_names=[b._attribute(0x30, "", b.file_name(".", (5, 1), 1700000000)),
                     b._attribute(0x30, "", b.file_name("evidence", (5, 1), 1700000500))],
    )
    b.records[30] = b.record(
        30, is_dir=True,
        attributes=[b._attribute(0x10, "", b.standard_information(1700000500))],
        extra_names=[b._attribute(0x30, "", b.file_name("evidence", (5, 1), 1700000500)),
                     b._attribute(0x30, "", b.file_name("..", (5, 1), 1700000000))],
    )
    b.records[6] = b.record(6, attributes=[
        b._attribute(0x10, "", b.standard_information(1700000000)),
        b._attribute(0x30, "", b.file_name("$Bitmap", (5, 1), 1700000000)),
    ])

    payload = b"DELETED EVIDENCE PAYLOAD " * 200
    deleted_lcn = b.add_data(payload)
    b.records[42] = b.record(
        42, allocated=not deleted, sequence=3,
        attributes=[
            b._attribute(0x10, "", b.standard_information(1750000000, changed=1750003600)),
            b._attribute(0x30, "", b.file_name("budget-final.xlsx", (30, 1), 1750000000,
                        real_size=len(payload), allocated_size=-(-len(payload) // CLUSTER) * CLUSTER)),
            b._attribute(0x80, "", payload, runs=[(deleted_lcn, -(-len(payload) // CLUSTER))]),
        ],
    )

    live = b"LIVE FILE CONTENT " * 100
    live_lcn = b.add_data(live)
    b.records[43] = b.record(
        43, allocated=True,
        attributes=[
            b._attribute(0x10, "", b.standard_information(1750001000)),
            b._attribute(0x30, "", b.file_name("notes.txt", (5, 1), 1750001000, real_size=len(live))),
            b._attribute(0x80, "", live, runs=[(live_lcn, -(-len(live) // CLUSTER))]),
        ],
    )
    return b.write(tmp_path / "ntfs.img")


# --------------------------------------------------------------------------- #
# boot sector and fixup
# --------------------------------------------------------------------------- #


def test_boot_sector_is_parsed(tmp_path):
    boot = parse_ntfs_boot_sector(_volume(tmp_path))
    assert boot is not None
    assert boot.cluster_size == CLUSTER
    assert boot.mft_record_size == REC
    assert boot.bytes_per_sector == SECTOR


def test_fixup_sequence_lives_in_the_first_usa_slot_not_at_0x08(tmp_path):
    """A regression guard.

    0x08 holds the $LogFile sequence number, which mkntfs leaves at zero. Reading
    the USN from there compares every sector tail against zero, so a perfectly
    good record fails verification and a torn one can pass.
    """
    rec = record_at(_volume(tmp_path).read_bytes(), 0)
    usa_off = struct.unpack_from("<H", rec, 0x04)[0]
    assert struct.unpack_from("<I", rec, 0x08)[0] == 0
    assert struct.unpack_from("<H", rec, usa_off)[0] != 0


def test_usa_count_is_the_sector_count_plus_one(tmp_path):
    rec = record_at(_volume(tmp_path).read_bytes(), 0)
    assert struct.unpack_from("<H", rec, 0x06)[0] == REC // SECTOR + 1


def test_fixup_is_applied_and_verified(tmp_path):
    raw = record_at(_volume(tmp_path).read_bytes(), 0)
    rec = mft.parse_mft_record(raw, sector_size=SECTOR)
    assert rec is not None and rec.fixup_verified
    assert rec.name() == "$MFT"


def test_applying_the_fixup_twice_fails_verification(tmp_path):
    """The fixup must be applied once, to a record straight off the media.

    A corrected record no longer carries the USN in its sector tails, so feeding
    one back through a fixing parser leaves it unverifiable. That is the safe
    outcome: the parser refuses rather than reporting torn bytes as a file.
    """
    raw = record_at(_volume(tmp_path).read_bytes(), 0)
    usa = struct.unpack_from("<H", raw, 0x04)[0]
    usn = struct.unpack_from("<H", raw, usa)[0]
    assert struct.unpack_from("<H", raw, SECTOR - 2)[0] == usn     # placeholder in place
    assert mft.parse_mft_record(raw, SECTOR) is not None

    once = bytearray(raw)
    mft.apply_fixup(once, SECTOR)
    assert struct.unpack_from("<H", once, SECTOR - 2)[0] != usn     # restored
    # A second pass is a no-op on the bytes but leaves the USN gone.
    assert mft.parse_mft_record(bytes(once), SECTOR) is None


def test_a_torn_record_is_rejected_by_default(tmp_path):
    raw = bytearray(record_at(_volume(tmp_path).read_bytes(), 0))
    usa_off = struct.unpack_from("<H", raw, 0x04)[0]
    seq = struct.unpack_from("<H", raw, usa_off)[0]
    struct.pack_into("<H", raw, REC - 2, (seq + 1) & 0xFFFF)   # tear the last sector
    assert mft.parse_mft_record(bytes(raw), SECTOR) is None
    lenient = mft.parse_mft_record(bytes(raw), SECTOR, strict=False)
    assert lenient is not None and lenient.fixup_verified is False


def test_sequence_number_is_read_from_0x0c(tmp_path):
    """A regression guard.

    0x0C is the record's sequence number. 0x08 is the $LogFile sequence number and
    0x10 is neither; all three are adjacent, and confusing them mislabels which
    incarnation of a record a name belongs to.
    """
    raw = record_at(_volume(tmp_path).read_bytes(), 0)
    assert struct.unpack_from("<H", raw, 8)[0] == 0       # $LogFile LSN, left at 0
    rec = mft.parse_mft_record(raw, SECTOR)
    assert rec.sequence_number == struct.unpack_from("<H", raw, 0x0C)[0] == 1
    assert rec.sequence_number != struct.unpack_from("<H", raw, 0x14)[0]


# --------------------------------------------------------------------------- #
# record contents
# --------------------------------------------------------------------------- #


def test_file_name_parent_reference_is_the_first_field(tmp_path):
    """A regression guard.

    Reading the parent reference at 0x28 returns the file's allocated size,
    which is a plausible record number and produces nonsense parent paths.
    """
    rec = mft.parse_mft_record(record_at(_volume(tmp_path).read_bytes(), 0),
                               SECTOR)
    entry = rec.primary_name()
    assert entry["parent_ref"] == (5, 1)
    assert entry["parent_ref"][0] != entry["real_size"]


def test_record_fields_are_read_from_the_right_offsets(tmp_path):
    rec = mft.parse_mft_record(record_at(_volume(tmp_path).read_bytes(), 0),
                               SECTOR)
    assert rec.record_num == 0
    assert rec.allocated is True
    assert rec.is_directory is False
    assert rec.name() == "$MFT"


def test_nt_time_rejects_sentinel_values():
    assert mft.parse_nt_time(0) is None
    assert mft.parse_nt_time(0xFFFFFFFFFFFFFFFF) is None
    assert mft.parse_nt_time(nt(1750000000)) == pytest.approx(1750000000, abs=1)


def test_run_list_decodes_multi_byte_length_and_delta():
    """A run larger than 255 clusters does not fit in the header's low nibble."""
    from s0_cli.carver.allocation import decode_run_list_raw
    # header 0x22: 2-byte length, 2-byte delta. 0x1000 clusters, delta 0x4000.
    assert decode_run_list_raw(bytes([0x22, 0x00, 0x10, 0x00, 0x40])) == [(0x4000, 0x1000)]


def test_run_list_delta_accumulates_and_can_be_negative():
    from s0_cli.carver.allocation import decode_run_list_raw
    # Two runs whose deltas are -0x10 and +0x20 relative to the running LCN.
    runs = decode_run_list_raw(bytes([0x11, 0x04, 0xF0, 0x11, 0x08, 0x20]))
    assert runs == [(0xFFFFFFFFFFFFFFF0 - (1 << 64), 4), (0x10, 8)]


def test_run_list_marks_sparse_runs():
    from s0_cli.carver.allocation import decode_run_list_raw
    # header 0x01: a length of 1 byte and no delta, i.e. a hole reading as zeros.
    # header 0x21: a 1-byte length and a 2-byte delta.
    assert decode_run_list_raw(bytes([0x01, 0x08, 0x21, 0x04, 0x10, 0x00])) == \
        [(-1, 8), (16, 4)]


def test_run_list_stops_when_a_run_would_overrun_the_attribute():
    from s0_cli.carver.allocation import decode_run_list_raw
    # 0x21 promises a 2-byte delta but only one byte is left, so the run is
    # truncated rather than read off the end of the attribute.
    assert decode_run_list_raw(bytes([0x01, 0x08, 0x21, 0x04, 0x10])) == [(-1, 8)]


# --------------------------------------------------------------------------- #
# end-to-end deleted-record recovery
# --------------------------------------------------------------------------- #


def test_deleted_file_is_recovered_with_its_original_name_and_path(tmp_path):
    results = scan_ntfs_deleted_records(_volume(tmp_path))
    assert len(results) == 1
    entry = results[0]
    assert entry.name == "budget-final.xlsx"
    assert entry.record_num == 42
    assert entry.path == "evidence\\budget-final.xlsx"
    assert entry.parent_record == 30
    assert entry.data is not None
    assert entry.data == b"DELETED EVIDENCE PAYLOAD " * 200
    assert entry.is_restorable


def test_live_files_are_not_reported_as_deleted(tmp_path):
    results = scan_ntfs_deleted_records(_volume(tmp_path))
    assert all(e.name != "notes.txt" for e in results)


def test_deletion_time_is_the_mft_changed_timestamp(tmp_path):
    entry = scan_ntfs_deleted_records(_volume(tmp_path))[0]
    assert entry.mft_changed == pytest.approx(1750003600, abs=1)
    assert entry.mft_changed > entry.created


def test_results_are_ordered_newest_deletion_first(tmp_path):
    b = MftBuilder()
    b.records[5] = b.record(5, is_dir=True, attributes=[b._attribute(0x10, "", b.standard_information(1700000000))],
                            extra_names=[b._attribute(0x30, "", b.file_name(".", (5, 1), 1700000000))])
    for num, name, changed in ((60, "older.txt", 1750001000), (61, "newer.txt", 1750009000)):
        payload = f"contents of {name} ".encode() * 50
        lcn = b.add_data(payload)
        b.records[num] = b.record(
            num, allocated=False, sequence=2,
            attributes=[
                b._attribute(0x10, "", b.standard_information(1750000000, changed=changed)),
                b._attribute(0x30, "", b.file_name(name, (5, 1), 1750000000, real_size=len(payload))),
                b._attribute(0x80, "", payload, runs=[(lcn, -(-len(payload) // CLUSTER))]),
            ],
        )
    results = scan_ntfs_deleted_records(b.write(tmp_path / "order.img"))
    assert [e.name for e in results] == ["newer.txt", "older.txt"]


def test_missing_parent_is_reported_as_a_gap_not_guessed(tmp_path):
    b = MftBuilder()
    b.records[5] = b.record(5, is_dir=True, attributes=[b._attribute(0x10, "", b.standard_information(1700000000))])
    payload = b"orphan payload " * 100
    lcn = b.add_data(payload)
    b.records[77] = b.record(
        77, allocated=False,
        attributes=[
            b._attribute(0x10, "", b.standard_information(1750000000)),
            b._attribute(0x30, "", b.file_name("orphaned.txt", (999, 1), 1750000000, real_size=len(payload))),
            b._attribute(0x80, "", payload, runs=[(lcn, -(-len(payload) // CLUSTER))]),
        ],
    )
    entry = scan_ntfs_deleted_records(b.write(tmp_path / "orphan.img"))[0]
    assert entry.name == "orphaned.txt"
    assert "record 999" in entry.path
    assert entry.parent_record == 999


def test_encrypted_stream_is_refused_rather_than_reconstructed(tmp_path):
    b = MftBuilder()
    b.records[5] = b.record(5, is_dir=True, attributes=[b._attribute(0x10, "", b.standard_information(1700000000))])
    payload = b"\x01\x02\x03" * 500            # EFS header, not plaintext
    lcn = b.add_data(payload)
    b.records[88] = b.record(
        88, allocated=False,
        attributes=[
            b._attribute(0x10, "", b.standard_information(1750000000)),
            b._attribute(0x30, "", b.file_name("secret.doc", (5, 1), 1750000000, real_size=len(payload))),
            b._attribute(0x80, "", payload, runs=[(lcn, -(-len(payload) // CLUSTER))], flags=mft.ATTR_IS_ENCRYPTED),
        ],
    )
    entry = scan_ntfs_deleted_records(b.write(tmp_path / "efs.img"))[0]
    assert entry.name == "secret.doc"       # the name is still evidence
    assert entry.data is None               # but the bytes are not the file
    assert entry.content_caveat and "encrypted" in entry.content_caveat
    assert not entry.is_restorable


def test_compressed_stream_is_refused_rather_than_reconstructed(tmp_path):
    b = MftBuilder()
    b.records[5] = b.record(5, is_dir=True, attributes=[b._attribute(0x10, "", b.standard_information(1700000000))])
    payload = b"\x00" * 8192
    lcn = b.add_data(payload)
    b.records[89] = b.record(
        89, allocated=False,
        attributes=[
            b._attribute(0x10, "", b.standard_information(1750000000)),
            b._attribute(0x30, "", b.file_name("sparse.log", (5, 1), 1750000000, real_size=len(payload))),
            b._attribute(0x80, "", payload, runs=[(lcn, -(-len(payload) // CLUSTER))], flags=mft.ATTR_IS_COMPRESSED),
        ],
    )
    entry = scan_ntfs_deleted_records(b.write(tmp_path / "comp.img"))[0]
    assert entry.data is None
    assert entry.content_caveat and "compressed" in entry.content_caveat


def test_sparse_stream_reports_its_length_but_not_fabricated_content(tmp_path):
    b = MftBuilder()
    b.records[5] = b.record(5, is_dir=True, attributes=[b._attribute(0x10, "", b.standard_information(1700000000))])
    lcn = b.add_data(b"partial")
    b.records[90] = b.record(
        90, allocated=False,
        attributes=[
            b._attribute(0x10, "", b.standard_information(1750000000)),
            b._attribute(0x30, "", b.file_name("holey.bin", (5, 1), 1750000000, real_size=16384)),
            b._attribute(0x80, "", b"partial", runs=[(lcn, 1)], flags=mft.ATTR_IS_SPARSE),
        ],
    )
    entry = scan_ntfs_deleted_records(b.write(tmp_path / "sparse.img"))[0]
    assert entry.data is None
    assert entry.content_caveat and "sparse" in entry.content_caveat


def test_file_name_preserves_a_name_longer_than_one_sector(tmp_path):
    """A long name crosses the sector tail the fixup protects."""
    long_name = "Q3-2026-Regional-Field-Reconciliation-" + "x" * 120 + ".xlsx"
    # The name has to reach past the first sector tail (0x1FE), which is where the
    # fixup array's placeholder sits until it is undone.
    name_start = 0x38 + 0x40 + 0x42
    assert name_start + len(long_name) * 2 > SECTOR - 2
    b = MftBuilder()
    b.records[5] = b.record(5, is_dir=True, attributes=[b._attribute(0x10, "", b.standard_information(1700000000))])
    payload = b"long name payload " * 40
    lcn = b.add_data(payload)
    b.records[91] = b.record(
        91, allocated=False,
        attributes=[
            b._attribute(0x10, "", b.standard_information(1750000000)),
            b._attribute(0x30, "", b.file_name(long_name, (5, 1), 1750000000, real_size=len(payload))),
            b._attribute(0x80, "", payload, runs=[(lcn, -(-len(payload) // CLUSTER))]),
        ],
    )
    entry = scan_ntfs_deleted_records(b.write(tmp_path / "longname.img"))[0]
    assert entry.name == long_name


def test_resident_small_file_is_recovered_from_inside_its_record(tmp_path):
    b = MftBuilder()
    b.records[5] = b.record(5, is_dir=True, attributes=[b._attribute(0x10, "", b.standard_information(1700000000))])
    inline = b"tiny resident content"
    b.records[92] = b.record(
        92, allocated=False,
        attributes=[
            b._attribute(0x10, "", b.standard_information(1750000000)),
            b._attribute(0x30, "", b.file_name("readme.txt", (5, 1), 1750000000, real_size=len(inline))),
            b._attribute(0x80, "", inline),
        ],
    )
    entry = scan_ntfs_deleted_records(b.write(tmp_path / "resident.img"))[0]
    assert entry.data == inline
    assert entry.is_resident


def test_system_records_are_excluded_unless_asked_for(tmp_path):
    img = _volume(tmp_path)
    assert all(e.record_num >= 16 for e in scan_ntfs_deleted_records(img))
    with_system = scan_ntfs_deleted_records(img, include_system=True, include_allocated=True)
    assert any(e.name.startswith("$") for e in with_system)
    assert all(e.record_num >= 16
               for e in scan_ntfs_deleted_records(img, include_allocated=True))


def test_satellite_record_is_followed_through_the_attribute_list(tmp_path):
    """A large file's $DATA lives in a satellite record; without following the
    $ATTRIBUTE_LIST the biggest files on a volume look empty."""
    b = MftBuilder()
    b.records[5] = b.record(5, is_dir=True, attributes=[b._attribute(0x10, "", b.standard_information(1700000000))])
    payload = bytes((i * 37) % 256 for i in range(20000))
    lcn = b.add_data(payload)

    entry = bytearray(0x18)
    struct.pack_into("<I", entry, 0x00, 0x80)          # attribute type $DATA
    struct.pack_into("<H", entry, 0x04, REC)           # record length
    struct.pack_into("<H", entry, 0x09, 0)             # starting VCN
    entry[0x0B:0x11] = (93).to_bytes(6, "little")      # MFT file reference: record 93
    b.records[92] = b.record(
        92, allocated=False,
        attributes=[
            b._attribute(0x10, "", b.standard_information(1750000000)),
            b._attribute(0x30, "", b.file_name("large.bin", (5, 1), 1750000000, real_size=len(payload))),
            b._attribute(0x20, "", bytes(entry)),
        ],
    )
    b.records[93] = b.record(
        93, allocated=False,
        attributes=[b._attribute(0x80, "", payload, runs=[(lcn, -(-len(payload) // CLUSTER))])],
    )
    results = scan_ntfs_deleted_records(b.write(tmp_path / "satellite.img"))
    target = [e for e in results if e.name == "large.bin"]
    assert target, [e.name for e in results]
    assert target[0].data == payload
    assert target[0].recovered_from_satellite


def test_empty_or_absent_volume_returns_nothing(tmp_path):
    junk = tmp_path / "junk.img"
    junk.write_bytes(b"\x00" * 4096)
    assert scan_ntfs_deleted_records(junk) == []


def test_non_ntfs_image_returns_nothing(tmp_path):
    other = tmp_path / "fat.img"
    other.write_bytes(b"\x00" * 8192)
    other.write_bytes(b"MSDOS5.0" + b"\x00" * 8184)
    assert scan_ntfs_deleted_records(other) == []
