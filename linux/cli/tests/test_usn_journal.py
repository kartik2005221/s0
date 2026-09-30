"""Tests for $UsnJrnl parsing.

The fixtures encode USN records byte by byte, which is the point: the reason
this module is easy to get wrong is that a misread offset yields a plausible
record. A timestamp shifted by two bytes is still a plausible timestamp, a
128-bit reference read as 48-bit is still a plausible number, and a reason mask
read from the wrong field is still a valid mask. Every test here pins a specific
field to a specific offset by giving it a value that could not be confused with
its neighbour.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from s0.carve import usn
from s0.carve.usn import (
    REASON_FILE_CREATE,
    REASON_FILE_DELETE,
    REASON_RENAME_NEW,
    REASON_RENAME_OLD,
    USN_RECORD_V2,
    USN_RECORD_V4,
    build_timeline,
    decode_reasons,
    parse_usn_journal,
    parse_usn_record,
    parse_usn_time,
    summarize,
)


def nt(ts: float) -> int:
    return int((ts + 11644473600) * 10_000_000)


def ordinal(entry: int, sequence: int = 1) -> int:
    """A FILEORDINAL: 48 bits of MFT entry number, then a 16-bit sequence.

    Written as a function so the layout is stated once. A hex literal like
    ordinal(0x2A, 1) looks like "entry 1, sequence 2A" and is neither:
    the sequence lives in bits 48-63, so that value has sequence 0 and entry
    0x100000000002A.
    """
    return ((sequence & 0xFFFF) << 48) | (entry & 0x0000FFFFFFFFFFFF)


def make_record(name: str, *, usn_value: int = 0x1000, timestamp: float = 1_760_000_000.0,
                reason: int = REASON_FILE_CREATE, file_ref: int = 0,
                parent_ref: int = 0, attributes: int = 0x20,
                version: int = usn.USN_RECORD_V2) -> bytes:
    """Encode a USN_RECORD_V2 or V3.

    The two are byte-identical apart from the version field: RecordLength,
    version, two 8-byte FILEORDINALs (48-bit entry then 16-bit sequence), the
    USN, a timestamp, reason, source, security id and attributes, then the name
    length, the name offset, and the name.
    """
    assert version in (usn.USN_RECORD_V2, usn.USN_RECORD_V3), \
        "V4 is a different structure with no file name; build it explicitly"
    file_ref = file_ref or ordinal(0x2A, 5)
    parent_ref = parent_ref or ordinal(5, 5)

    raw = name.encode("utf-16le")
    fixed = usn._V2_FIXED_LENGTH

    # The record is the fixed header plus the name, rounded up to 8 bytes, which
    # is what the format requires and what the parser's alignment check demands.
    length = (fixed + len(raw) + 7) & ~7
    out = bytearray(length)
    struct.pack_into("<I", out, usn._OFF_RECORD_LENGTH, length)
    struct.pack_into("<H", out, usn._OFF_MAJOR, version)
    struct.pack_into("<H", out, usn._OFF_MAJOR + 2, 0)
    struct.pack_into("<Q", out, 0x08, file_ref)
    struct.pack_into("<Q", out, 0x10, parent_ref)
    struct.pack_into("<Q", out, 0x18, usn_value)
    struct.pack_into("<Q", out, 0x20, nt(timestamp))
    struct.pack_into("<I", out, 0x28, reason)
    struct.pack_into("<I", out, 0x2C, 1)          # source info
    struct.pack_into("<I", out, 0x30, 256)        # security id
    struct.pack_into("<I", out, 0x34, attributes)
    struct.pack_into("<H", out, usn._OFF_NAME_LENGTH, len(raw))
    struct.pack_into("<H", out, usn._OFF_NAME_OFFSET, fixed)
    out[fixed : fixed + len(raw)] = raw
    return bytes(out)


# --------------------------------------------------------------------------- #
# individual records
# --------------------------------------------------------------------------- #


def test_v2_record_round_trips():
    rec = parse_usn_record(make_record("budget-final.xlsx"))
    assert rec is not None
    assert rec.version == USN_RECORD_V2
    assert rec.name == "budget-final.xlsx"
    assert rec.mft_entry == 0x2A
    assert rec.sequence == 5
    assert rec.parent_mft_entry == 5
    assert rec.usn == 0x1000
    assert rec.timestamp == pytest.approx(1_760_000_000, abs=1)
    assert rec.reason_mask == REASON_FILE_CREATE
    assert rec.reasons == ["FILE_CREATE"]
    assert rec.establishes_existence


def test_v2_and_v3_are_byte_identical_apart_from_the_version():
    fields = dict(usn_value=0x2000, timestamp=1_750_000_000.0,
                  reason=REASON_FILE_DELETE, file_ref=ordinal(0x2A, 5),
                  parent_ref=ordinal(5, 5))
    v2 = parse_usn_record(make_record("evidence.zip", version=2, **fields))
    v3 = parse_usn_record(make_record("evidence.zip", version=3, **fields))
    for rec in (v2, v3):
        assert rec is not None
        assert rec.name == "evidence.zip"
        assert rec.mft_entry == 0x2A
        assert rec.parent_mft_entry == 5
        assert rec.usn == 0x2000
        assert rec.timestamp == pytest.approx(1_750_000_000, abs=1)
        assert rec.reason_mask == REASON_FILE_DELETE


def test_v4_records_are_skipped_rather_than_read_as_names():
    """A regression guard, and the one that matters most here.

    USN_RECORD_V4 is a different structure: it reports which byte ranges of a
    file changed, using 128-bit file references, and carries no timestamp, no
    attributes and no file name. Windows emits one or more V4 records and then a
    V3 record with USN_REASON_CLOSE that does carry the name.

    Read with the V2 layout, a V4 record yields a name assembled out of its
    extent list -- plausible, wrong, and attributed to a file that may not
    exist. It must be recognised and skipped instead.
    """
    # A minimal V4-shaped record: 128-bit references, then an extent list.
    out = bytearray(0x4C)
    struct.pack_into("<I", out, 0x00, 0x4C)
    struct.pack_into("<H", out, usn._OFF_MAJOR, usn.USN_RECORD_V4)
    struct.pack_into("<H", out, usn._OFF_MAJOR + 2, 0)
    out[0x08:0x18] = (0x2A).to_bytes(16, "little")
    out[0x18:0x28] = (5).to_bytes(16, "little")
    struct.pack_into("<Q", out, 0x28, 0x3000)
    struct.pack_into("<I", out, 0x30, REASON_FILE_DELETE)
    assert parse_usn_record(bytes(out)) is None


def test_both_references_use_the_same_ordinal_layout():
    """A FILEORDINAL is 48 bits of entry number then 16 bits of sequence.

    Reading the low 48 bits of a value whose sequence sits in the high half keeps
    the sequence and loses the entry, which is backwards: every MFT entry number
    would come back as the ordinal itself.
    """
    rec = parse_usn_record(make_record(
        "ordinal.bin", file_ref=ordinal(0x2A, 5), parent_ref=ordinal(5, 5)))
    assert rec.mft_entry == 0x2A
    assert rec.sequence == 5
    assert rec.parent_mft_entry == 5


def test_directory_attribute_is_recognised():
    rec = parse_usn_record(make_record("Projects", attributes=0x10 | 0x20))
    assert rec.is_directory
    assert not parse_usn_record(make_record("notes.txt", attributes=0x20)).is_directory


def test_reason_mask_expands_to_named_operations():
    names = decode_reasons(REASON_FILE_CREATE | REASON_FILE_DELETE)
    assert set(names) == {"FILE_CREATE", "FILE_DELETE"}
    assert decode_reasons(0) == []


def test_establishes_existence_distinguishes_data_writes():
    """A data-overwrite entry is not evidence a name ever existed."""
    create = parse_usn_record(make_record("a.txt", reason=REASON_FILE_CREATE))
    assert create.establishes_existence
    write = parse_usn_record(make_record("a.txt", reason=usn.USN_REASONS and 0x00000001))
    assert not write.establishes_existence
    assert write.reasons == ["DATA_OVERWRITE"]


# --------------------------------------------------------------------------- #
# rejection of junk
# --------------------------------------------------------------------------- #


def test_zero_length_record_is_rejected():
    """A zero length would let the scanner advance by nothing and loop forever."""
    blob = bytearray(make_record("x.txt"))
    struct.pack_into("<I", blob, usn._OFF_RECORD_LENGTH, 0)
    assert parse_usn_record(bytes(blob)) is None


def test_record_longer_than_the_buffer_is_rejected():
    blob = bytearray(make_record("x.txt"))
    struct.pack_into("<I", blob, 0, 0xFFFF)
    assert parse_usn_record(bytes(blob)) is None


def test_unaligned_record_length_is_rejected():
    blob = bytearray(make_record("x.txt"))
    length = struct.unpack_from("<I", blob, 0)[0]
    struct.pack_into("<I", blob, 0, length - 1)      # not 4- or 8-byte aligned
    assert parse_usn_record(bytes(blob)) is None


@pytest.mark.parametrize("version", [0, 1, 5, 99])
def test_unknown_version_is_rejected(version):
    blob = bytearray(make_record("x.txt"))
    struct.pack_into("<H", blob, usn._OFF_MAJOR, version)
    assert parse_usn_record(bytes(blob)) is None


def test_name_length_of_zero_is_rejected():
    blob = bytearray(make_record("x.txt"))
    struct.pack_into("<H", blob, usn._OFF_NAME_LENGTH, 0)
    assert parse_usn_record(bytes(blob)) is None


def test_odd_name_length_is_rejected():
    blob = bytearray(make_record("x.txt"))
    struct.pack_into("<H", blob, usn._OFF_NAME_LENGTH, 3)           # UTF-16 cannot be 3 bytes
    assert parse_usn_record(bytes(blob)) is None


def test_name_offset_outside_the_record_is_rejected():
    blob = bytearray(make_record("x.txt"))
    length = struct.unpack_from("<I", blob, 0)[0]
    struct.pack_into("<H", blob, usn._OFF_NAME_OFFSET, length)      # offset + length overruns
    assert parse_usn_record(bytes(blob)) is None


def test_whitespace_only_name_is_rejected():
    blob = bytearray(make_record(" "))
    assert parse_usn_record(bytes(blob)) is None


def test_a_name_made_only_of_dots_is_kept():
    """"." is a real journal entry for a directory, not junk."""
    rec = parse_usn_record(make_record("."))
    assert rec is not None and rec.name == "."


def test_name_containing_a_nul_is_rejected():
    blob = bytearray(make_record("x.txt"))
    no = struct.unpack_from("<H", blob, usn._OFF_NAME_OFFSET)[0]
    blob[no : no + 2] = "\x00".encode("utf-16le")
    assert parse_usn_record(bytes(blob)) is None


def test_garbage_does_not_parse_as_a_record():
    assert parse_usn_record(bytes(64)) is None
    assert parse_usn_record(b"\xff" * 128) is None
    assert parse_usn_record(b"") is None
    assert parse_usn_record(b"short") is None


def test_unset_timestamps_are_not_rendered_as_dates():
    """A sentinel must read as unknown, not as 1601 or the year 30828."""
    assert parse_usn_time(0) is None
    assert parse_usn_time(0xFFFFFFFFFFFFFFFF) is None
    assert parse_usn_time(0x7FFFFFFFFFFFFFFF) is None
    assert parse_usn_time(0xFFFFFFFF00000000) is None
    assert parse_usn_time(nt(1_700_000_000)) == pytest.approx(1_700_000_000, abs=1)


def test_record_with_a_sentinel_timestamp_still_parses():
    blob = bytearray(make_record("stamp.txt"))
    struct.pack_into("<Q", blob, 0x20, 0xFFFFFFFFFFFFFFFF)   # V2 timestamp field
    rec = parse_usn_record(bytes(blob))
    assert rec is not None
    assert rec.name == "stamp.txt"
    assert rec.timestamp is None


# --------------------------------------------------------------------------- #
# journal scanning
# --------------------------------------------------------------------------- #


def test_journal_of_several_records_is_read_in_usn_order():
    journal = b"".join([
        make_record("first.txt", usn_value=0x1000, reason=REASON_FILE_CREATE),
        make_record("second.txt", usn_value=0x2000, reason=REASON_FILE_CREATE),
        make_record("second.txt", usn_value=0x3000, reason=REASON_FILE_DELETE),
    ])
    records = parse_usn_journal(journal)
    assert [r.usn for r in records] == [0x1000, 0x2000, 0x3000]
    assert records[-1].reasons == ["FILE_DELETE"]


def test_records_written_out_of_order_are_sorted_by_usn():
    """The journal is a ring buffer, so physical order is not chronological.

    The USN is a monotonic counter, so it orders records correctly even when the
    buffer wraps or was written out of order. A filesystem timestamp cannot: the
    clock can be set backwards.
    """
    journal = b"".join([
        make_record("late.txt", usn_value=0x9000, timestamp=1_760_000_000.0),
        make_record("early.txt", usn_value=0x1000, timestamp=1_750_000_000.0),
        make_record("middle.txt", usn_value=0x5000, timestamp=1_755_000_000.0),
    ])
    records = parse_usn_journal(journal)
    assert [r.name for r in records] == ["early.txt", "middle.txt", "late.txt"]


def test_scanner_resynchronises_across_junk():
    journal = (
        b"\x00" * 64
        + make_record("kept.txt", usn_value=0x1000)
        + b"\xff" * 40
        + make_record("also-kept.txt", usn_value=0x2000)
    )
    names = [r.name for r in parse_usn_journal(journal)]
    assert "kept.txt" in names
    assert "also-kept.txt" in names


def test_duplicates_are_collapsed():
    blob = make_record("dup.txt", usn_value=0x1000)
    records = parse_usn_journal(blob + blob)
    assert len(records) == 1


def test_max_records_is_honoured():
    journal = b"".join(
        make_record(f"f{i}.txt", usn_value=0x1000 + i) for i in range(20)
    )
    assert len(parse_usn_journal(journal, max_records=5)) == 5


def test_empty_journal_yields_nothing():
    assert parse_usn_journal(b"") == []
    assert parse_usn_journal(bytes(4096)) == []


# --------------------------------------------------------------------------- #
# timeline
# --------------------------------------------------------------------------- #


def test_timeline_reports_deletion_time_for_a_deleted_file():
    records = parse_usn_journal(b"".join([
        make_record("report.docx", usn_value=0x1000, timestamp=1_760_000_000.0,
                    reason=REASON_FILE_CREATE),
        make_record("report.docx", usn_value=0x2000, timestamp=1_760_003_600.0,
                    reason=REASON_FILE_DELETE),
    ]))
    timeline = build_timeline(records)
    assert len(timeline) == 1
    entry = timeline[0]
    assert entry.name == "report.docx"
    assert entry.was_deleted
    assert entry.created_at == pytest.approx(1_760_000_000, abs=1)
    assert entry.deleted_at == pytest.approx(1_760_003_600, abs=1)
    assert entry.event_count == 2


def test_timeline_collapses_data_writes_into_one_entry():
    """A busy file produces many journal entries and exactly one timeline row.

    Reporting each revision separately would bury the single fact that matters
    -- that the file was deleted, and when.
    """
    records = parse_usn_journal(b"".join(
        [make_record("busy.log", usn_value=0x1000 + i, timestamp=1_760_000_000.0 + i,
                     reason=0x00000001)          # DATA_OVERWRITE
         for i in range(50)]
        + [make_record("busy.log", usn_value=0x2000, timestamp=1_760_001_000.0,
                       reason=REASON_FILE_DELETE)]
    ))
    timeline = build_timeline(records)
    assert len(timeline) == 1
    assert timeline[0].event_count == 51
    assert timeline[0].was_deleted
    assert "DATA_OVERWRITE" in timeline[0].reasons
    assert "FILE_DELETE" in timeline[0].reasons


def test_rename_records_the_previous_name():
    records = parse_usn_journal(b"".join([
        make_record("draft.txt", usn_value=0x1000, reason=REASON_RENAME_OLD),
        make_record("final.txt", usn_value=0x2000, reason=REASON_RENAME_NEW),
    ]))
    entry = build_timeline(records)[0]
    assert entry.name == "final.txt"
    assert entry.renamed_from == "draft.txt"
    assert entry.renamed


def test_timeline_is_ordered_newest_deletion_first():
    records = parse_usn_journal(b"".join([
        make_record("old.bin", usn_value=0x1000, timestamp=1_700_000_000.0,
                    reason=REASON_FILE_DELETE, file_ref=ordinal(0x31, 1)),
        make_record("new.bin", usn_value=0x2000, timestamp=1_760_000_000.0,
                    reason=REASON_FILE_DELETE, file_ref=ordinal(0x32, 1)),
        make_record("mid.bin", usn_value=0x3000, timestamp=1_730_000_000.0,
                    reason=REASON_FILE_DELETE, file_ref=ordinal(0x33, 1)),
    ]))
    assert [e.name for e in build_timeline(records)] == ["new.bin", "mid.bin", "old.bin"]


def test_a_file_reference_is_kept_distinct_from_another():
    """A reused MFT entry is a different file with a different sequence number."""
    records = parse_usn_journal(b"".join([
        make_record("first.txt", usn_value=0x1000, file_ref=ordinal(0x2A, 1)),
        make_record("second.txt", usn_value=0x2000, file_ref=ordinal(0x2A, 2)),
    ]))
    timeline = build_timeline(records)
    assert len(timeline) == 2
    assert sorted(e.name for e in timeline) == ["first.txt", "second.txt"]
    assert all(e.mft_entry == 0x2A for e in timeline)


def test_summarize_counts_the_distinctive_facts():
    records = parse_usn_journal(b"".join([
        make_record("gone.txt", usn_value=0x1000, reason=REASON_FILE_DELETE,
                    file_ref=ordinal(0x41, 1)),
        make_record("here.txt", usn_value=0x2000, reason=REASON_FILE_CREATE,
                    file_ref=ordinal(0x42, 1)),
        make_record("dir", usn_value=0x3000, reason=REASON_FILE_CREATE,
                    attributes=0x10, file_ref=ordinal(0x43, 1)),
    ]))
    stats = summarize(build_timeline(records))
    assert stats["files_tracked"] == 3
    assert stats["deleted"] == 1
    assert stats["directories"] == 1


def test_name_fills_in_a_placeholder_journal_name_from_the_mft():
    """Some records carry a placeholder name; the MFT's is better.

    A journal entry for a directory rename can record "." , which is true but
    useless. When the MFT still has the real name, it takes precedence.
    """
    records = parse_usn_journal(make_record(".", usn_value=0x1000, file_ref=ordinal(0x51, 1)))
    assert build_timeline(records)[0].name == "."
    hinted = build_timeline(records, name_hint={records[0].file_reference: "real.txt"})
    assert hinted[0].name == "real.txt"


def test_timeline_of_nothing_is_empty():
    assert build_timeline([]) == []
    assert summarize([])["files_tracked"] == 0
