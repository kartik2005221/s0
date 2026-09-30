"""$UsnJrnl parsing: the change journal NTFS keeps about its own operations.

The MFT keeps the last state of a file. When a file is deleted, that state is
overwritten or the record is reused, and what is left is a name with no content
and no timestamp of its own. The change journal is the other half of the story:
every create, rename and delete is appended there with the file's reference
number, its parent, the reason, and the exact moment. A name recovered from the
journal is a name that is *known to have existed*, with a time attached, and
that is a materially stronger claim than a signature match on some bytes.

This matters most for the case record-level recovery cannot cover: a file that
was deleted, whose MFT record has since been reused by a new file, whose
clusters have been reused again. The content is gone, but the journal still
lists the name and says when it was deleted. That is the difference between
reporting nothing and reporting a lead.

The journal is sparse, circular and rewritten constantly. Entries past the
current position are stale, and the same file appears many times as it is
modified. So the output is a deduplicated timeline, ordered by USN, which is a
monotonically increasing counter of the change -- more reliable than a timestamp
for ordering, and unaffected by clock changes.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# USN_RECORD versions. V2 is Windows XP; V3 is Vista onward and is byte-identical
# to V2, differing only in the version field. V4 is a different structure entirely
# and carries no file name at all -- see _V4_NOT_A_NAME_RECORD.
USN_RECORD_V2 = 2
USN_RECORD_V3 = 3
USN_RECORD_V4 = 4

# Reason flags, from the WinNT header. Several can be set at once.
USN_REASONS = {
    0x00000001: "DATA_OVERWRITE",
    0x00000002: "DATA_EXTEND",
    0x00000004: "DATA_TRUNCATION",
    0x00000010: "NAMED_DATA_OVERWRITE",
    0x00000020: "NAMED_DATA_EXTEND",
    0x00000040: "NAMED_DATA_TRUNCATION",
    0x00000100: "FILE_CREATE",
    0x00000200: "FILE_DELETE",
    0x00000400: "EA_CHANGE",
    0x00000800: "SECURITY_CHANGE",
    0x00001000: "RENAME_OLD_NAME",
    0x00002000: "RENAME_NEW_NAME",
    0x00004000: "RENAME_DOS_NAME",
    0x00008000: "FILE_DELETE_CHAMPION",
    0x00010000: "CLOSE_APPLICATION",
    0x00020000: "CLOSE_WRITER",
    0x00040000: "CLOSE_SERVER",
    0x00080000: "DATA_SET_LENGTH",
    0x00100000: "DATA_PROTECTION",
    0x00200000: "DUPLICATE_INCREASE",
    0x00400000: "DUPLICATE_DECREASE",
    0x00800000: "INTEGRITY_OVERWRITE",
    0x02000000: "CLOSE_USER",
    0x04000000: "CLOSE_TRANSMIT",
    0x10000000: "DESIRED_DROP",
}

# Reasons that establish that a name existed at a time, versus reasons that
# only say a byte range changed.
REASON_FILE_CREATE = 0x00000100
REASON_FILE_DELETE = 0x00000200
REASON_RENAME_OLD = 0x00001000
REASON_RENAME_NEW = 0x00002000

# Header offsets shared by all three versions.
_OFF_RECORD_LENGTH = 0x00
_OFF_MAJOR = 0x04
_OFF_FILE_REF = 0x08
_OFF_PARENT_REF = 0x10
_OFF_USN = 0x18
_OFF_TIMESTAMP = 0x20
_OFF_REASON = 0x28
_OFF_SOURCE = 0x2C
_OFF_SECURITY_ID = 0x30
_OFF_ATTRIBUTES = 0x34
_OFF_NAME_LENGTH = 0x38
_OFF_NAME_OFFSET = 0x3A
# Where the file name begins. In both V2 and V3 the name-length and name-offset
# fields sit at 0x38 and 0x3A, so the fixed header is 0x3C bytes and the name
# follows. Reading the name from 0x3A instead starts it on top of the offset
# field that describes it, and every character after the first is wrong.
_V2_FIXED_LENGTH = 0x3C
_V3_FIXED_LENGTH = 0x3C

# USN_RECORD_V4 is not a name record. It reports which byte ranges of a file
# changed, using 128-bit file references, and holds no timestamp, no attributes
# and no file name; Windows always follows it with a V3 record carrying
# USN_REASON_CLOSE that does carry the name. Parsing a V4 record with the V2
# layout yields a plausible-looking name that is really a fragment of an extent
# list, so V4 records are recognised and skipped rather than misread.
_V4_NOT_A_NAME_RECORD = True

# Minimum plausible values, used to reject garbage before it is interpreted.
_MIN_RECORD_LENGTH = 0x3C

# Records are 8-byte aligned within the journal. When the scanner hits something
# that is not a record -- the ring buffer holds fragments and stale bytes -- it
# must resynchronise on that same stride: stepping by the record length instead
# lands on an odd offset, where a valid record never begins, and the rest of the
# journal is missed.
_ALIGNMENT = 8
_MIN_REASON = 0
_MAX_REASON = 0x20000000

# A 64-bit NT FILETIME beyond this is not a real instant; the 0xFFFFFFFF...
# sentinel means "not set" and must not be rendered as a date.
_MAX_FILETIME = 2650467744000000000


def decode_reasons(mask: int) -> List[str]:
    """Expand a reason bitmask into the named operations it represents."""
    if not mask:
        return []
    return [name for bit, name in USN_REASONS.items() if mask & bit]


def parse_usn_time(value: int) -> Optional[float]:
    """Convert an NT FILETIME (100ns ticks since 1601-01-01) to a UNIX timestamp.

    Returns None rather than a nonsense date when the value is one of NTFS's
    "unset" sentinels, or falls outside a believable range.
    """
    if value in (0, 0xFFFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF):
        return None
    if value > _MAX_FILETIME:
        return None
    seconds = value / 10_000_000 - 11644473600
    if seconds < 0 or seconds > 4_102_444_800:        # past 2100
        return None
    return seconds


@dataclass
class UsnRecord:
    version: int
    usn: int
    timestamp: Optional[float]
    reason_mask: int
    file_reference: int
    parent_reference: int
    file_attributes: int
    source_info: int
    name: str

    @property
    def reasons(self) -> List[str]:
        return decode_reasons(self.reason_mask)

    @property
    def sequence(self) -> int:
        """16-bit sequence number, distinguishing reuse of an MFT entry."""
        return (self.file_reference >> 48) & 0xFFFF

    @property
    def mft_entry(self) -> int:
        """48-bit MFT entry number, in the low half of the ordinal."""
        return self.file_reference & 0x0000FFFFFFFFFFFF

    @property
    def parent_mft_entry(self) -> int:
        return self.parent_reference & 0x0000FFFFFFFFFFFF

    @property
    def is_directory(self) -> bool:
        return bool(self.file_attributes & 0x10)

    @property
    def establishes_existence(self) -> bool:
        """True when this entry is evidence the named object existed.

        A data-overwrite reason only says some bytes changed within a file that
        already existed. A create, a delete or a rename is a statement about the
        name itself, and is what a reconstruction of what was on the volume is
        built from.
        """
        return bool(
            self.reason_mask
            & (REASON_FILE_CREATE | REASON_FILE_DELETE
               | REASON_RENAME_OLD | REASON_RENAME_NEW)
        )


def parse_usn_record(blob: bytes) -> Optional[UsnRecord]:
    """Parse one USN_RECORD from the head of `blob`.

    Returns None if the record is not plausibly a USN record. The journal is
    reused space, so the region past the write position contains old entries,
    fragments of entries, and arbitrary bytes that can look almost right; every
    structural field is checked before anything is interpreted.
    """
    if len(blob) < _MIN_RECORD_LENGTH:
        return None
    record_length = struct.unpack_from("<I", blob, _OFF_RECORD_LENGTH)[0]
    if record_length < _MIN_RECORD_LENGTH or record_length > len(blob):
        return None
    if (record_length & 7) != 0 or (record_length & 3) != 0:
        return None

    major = struct.unpack_from("<H", blob, _OFF_MAJOR)[0]
    minor = struct.unpack_from("<H", blob, _OFF_MAJOR + 2)[0]
    if major == USN_RECORD_V4:
        # A V4 record describes changed byte ranges and has no file name. Windows
        # emits one or more V4 records and then a V3 record with USN_REASON_CLOSE
        # that does name the file, so skipping V4 loses nothing and reading it
        # with the V2 layout would invent a name out of an extent list.
        return None
    if major not in (USN_RECORD_V2, USN_RECORD_V3):
        return None
    if major == USN_RECORD_V2 and minor not in (0, 1, 2):
        return None

    # V2 and V3 are byte-identical apart from the version field.
    fixed = _V2_FIXED_LENGTH
    usn_off, time_off, reason_off = 0x18, 0x20, 0x28
    source_off, security_off, attr_off = 0x2C, 0x30, 0x34
    name_len_off, name_off_off = 0x38, 0x3A

    if record_length < fixed:
        return None

    # Both references are 8 bytes holding a 64-bit FILEORDINAL: the 48-bit MFT
    # entry number in the LOW half and a 16-bit sequence number in the HIGH half.
    # Masking the low 48 bits of a value whose sequence was placed in the high
    # half therefore keeps the sequence and loses the entry, which is exactly
    # backwards -- so the split is done here, once, with the layout stated.
    file_ref = struct.unpack_from("<Q", blob, 0x08)[0]
    parent_ref = struct.unpack_from("<Q", blob, 0x10)[0]

    usn = struct.unpack_from("<Q", blob, usn_off)[0]
    timestamp_raw = struct.unpack_from("<Q", blob, time_off)[0]
    reason = struct.unpack_from("<I", blob, reason_off)[0]
    source = struct.unpack_from("<I", blob, source_off)[0]
    security = struct.unpack_from("<I", blob, security_off)[0]
    attributes = struct.unpack_from("<I", blob, attr_off)[0]
    name_length = struct.unpack_from("<H", blob, name_len_off)[0]
    name_offset = struct.unpack_from("<H", blob, name_off_off)[0]

    if reason < _MIN_REASON or reason > _MAX_REASON:
        return None
    if name_length == 0 or name_length % 2:
        return None
    if name_offset < fixed or name_offset + name_length > record_length:
        return None

    raw_name = blob[name_offset : name_offset + name_length]
    try:
        name = raw_name.decode("utf-16le")
    except UnicodeDecodeError:
        return None
    if "\x00" in name or not name.strip():
        return None

    return UsnRecord(
        version=major,
        usn=usn,
        timestamp=parse_usn_time(timestamp_raw),
        reason_mask=reason,
        file_reference=file_ref,
        parent_reference=parent_ref,
        file_attributes=attributes,
        source_info=source,
        name=name,
    )


@dataclass
class UsnTimelineEntry:
    """One file's history, folded out of the journal's many revisions."""
    mft_entry: int
    name: str
    parent_mft_entry: int
    created_at: Optional[float] = None
    deleted_at: Optional[float] = None
    renamed_from: Optional[str] = None
    is_directory: bool = False
    last_usn: int = 0
    event_count: int = 0
    reasons: List[str] = field(default_factory=list)
    renamed: bool = False

    @property
    def was_deleted(self) -> bool:
        return self.deleted_at is not None

    @property
    def last_seen_at(self) -> Optional[float]:
        return self.deleted_at or self.created_at


def parse_usn_journal(
    data: bytes,
    start_usn: int = 0,
    max_records: int = 500_000,
) -> List[UsnRecord]:
    """Read a USN journal image into a list of records, in USN order.

    `data` is the raw content of the $J stream, which is a ring buffer: the bytes
    between the write position and the end are whatever the next pass will
    overwrite, not valid history. Rather than trust a journal header that may
    itself be stale, every candidate offset is attempted and the results are
    ordered by USN, which is monotonic in real time and so cannot be spoofed by
    a clock change.
    """
    records: List[UsnRecord] = []
    seen: set = set()
    pos = 0
    limit = len(data)
    while pos + _MIN_RECORD_LENGTH <= limit and len(records) < max_records:
        rec = parse_usn_record(data[pos:])
        if rec is None:
            pos += _ALIGNMENT
            continue
        key = (rec.usn, rec.file_reference, rec.name)
        if key not in seen:
            seen.add(key)
            records.append(rec)
        # Advance by the record's own length, which is 8-byte aligned.
        advance = struct.unpack_from("<I", data, pos + _OFF_RECORD_LENGTH)[0]
        pos += max(advance, _ALIGNMENT)

    records.sort(key=lambda r: (r.usn, r.file_reference))
    return records


def build_timeline(
    records: List[UsnRecord],
    name_hint: Optional[Dict[int, str]] = None,
) -> List[UsnTimelineEntry]:
    """Fold journal records into one entry per file reference.

    A single file appears many times in the journal, once per operation, and its
    name changes on rename. Reporting each revision separately would bury the one
    fact that matters -- that it was deleted, and when -- under dozens of
    data-overwrite entries. Ordering is by USN throughout, since it is monotonic
    where a filesystem timestamp is not.
    """
    name_hint = name_hint or {}
    by_ref: Dict[int, UsnTimelineEntry] = {}

    # Records arrive sorted by USN, so the first create or rename for a reference
    # is that file's earliest known event and the last delete is its last.
    for rec in records:
        entry = by_ref.get(rec.file_reference)
        if entry is None:
            entry = UsnTimelineEntry(
                mft_entry=rec.mft_entry,
                name=rec.name,
                parent_mft_entry=rec.parent_mft_entry,
                is_directory=rec.is_directory,
            )
            by_ref[rec.file_reference] = entry
        elif rec.reason_mask & REASON_RENAME_NEW and rec.name != entry.name:
            entry.renamed_from = entry.name
            entry.renamed = True
            entry.name = rec.name

        if entry.created_at is None and rec.establishes_existence:
            entry.created_at = rec.timestamp
        if rec.reason_mask & REASON_FILE_DELETE:
            entry.deleted_at = rec.timestamp

        entry.last_usn = max(entry.last_usn, rec.usn)
        entry.event_count += 1
        for reason in rec.reasons:
            if reason not in entry.reasons:
                entry.reasons.append(reason)

    for ref, entry in by_ref.items():
        if entry.name in ("", ".") and ref in name_hint:
            entry.name = name_hint[ref]

    # Newest deletion first: what a reviewer needs is the recent past, and a
    # volume's entire history is not what they are looking for.
    return sorted(
        by_ref.values(),
        key=lambda e: (-(e.deleted_at or 0.0), -e.last_usn, e.name),
    )


def summarize(entries: List[UsnTimelineEntry]) -> Dict[str, int]:
    """Counts for a report, so a journal scan is legible without reading it."""
    return {
        "files_tracked": len(entries),
        "deleted": sum(1 for e in entries if e.was_deleted),
        "renamed": sum(1 for e in entries if e.renamed),
        "directories": sum(1 for e in entries if e.is_directory),
        "named_no_mft_entry": sum(1 for e in entries if e.mft_entry == 0),
    }
