"""Master File Table record primitives for NTFS.

The three things that make an MFT record hard to read correctly, and that a
forensic tool gets wrong if it ignores them:

**The update sequence array (fixup).** Every MFT record is protected the way the
BIOS protects the boot sector. The last two bytes of each sector-sized chunk of
the record are overwritten with a sequence number, and the values they displaced
are stored in a "fixup" array at the end of the record. A parser that reads the
record without undoing this sees two corrupt bytes at the end of every sector. In
a 1024-byte record with 512-byte sectors that means bytes 510-511 and 1022-1023
are wrong -- which is enough to corrupt a run list or a filename, and it looks
like plausible data rather than an error.

**The $MFT is itself a non-resident file.** It is not guaranteed to be
contiguous. On any volume that has been busy the MFT has been extended more than
once and record 6, record 30, and everything after them can be somewhere else
entirely. Walking `mft_start + n * record_size` finds the first few records and
then silently stops yielding data.

**Records are reused.** A deleted record is not zeroed. Its $FILE_NAME
attribute still holds the original name, its run list still points at whatever
clusters it held, and its $STANDARD_INFORMATION still carries the timestamp at
which it was deleted. That is the whole reason deleted-record recovery is worth
doing, and it is the only place the original name survives at all once a file's
directory entry is gone.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

MFT_RECORD_MAGIC = b"FILE"
MFT_END_MARKER = 0xFFFFFFFF

ATTR_STANDARD_INFORMATION = 0x10
ATTR_ATTRIBUTE_LIST = 0x20
ATTR_FILE_NAME = 0x30
ATTR_OBJECT_ID = 0x40
ATTR_DATA = 0x80

# $DATA / $ATTRIBUTE_LIST attribute flags.
ATTR_IS_COMPRESSED = 0x0001
ATTR_IS_ENCRYPTED = 0x4000
ATTR_IS_SPARSE = 0x8000

# $STANDARD_INFORMATION header flags.
SI_FLAG_DIRECTORY = 0x10000000

# Well-known MFT record numbers. Below 16 the records are metadata files, and
# they must never be reported as recovered user content.
SYSTEM_RECORDS = frozenset(range(0, 16))
ROOT_DIRECTORY_RECORD = 5

# NTFS epoch is 1601-01-01; 100ns intervals.
_EPOCH_DELTA = 11644473600


class FixupError(Exception):
    """The record's update sequence array does not verify."""


def parse_nt_time(value: int) -> float | None:
    """Convert an NT FILETIME (100ns ticks since 1601-01-01) to a UNIX timestamp.

    Returns None for values that are not a real instant -- 0 and 0xFFFFFFFFFFFF
    are both used by NTFS to mean "never" or "unknown", and rendering either as
    1601 or as year 30828 would be worse than reporting nothing.
    """
    if value in (0, 0xFFFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF):
        return None
    seconds = value / 10_000_000 - _EPOCH_DELTA
    if seconds < 0 or seconds > 4_102_444_800:      # beyond year 2100
        return None
    return seconds


def apply_fixup(record: bytearray, sector_size: int) -> tuple[bool, int]:
    """Undo the update sequence array, in place.

    Returns (verified, sequence_number). Raises FixupError if the record's
    structure is too short to carry a fixup array at all; returns (False, 0) if
    the array is structurally present but its trailing copies do not match, which
    means the sector was torn by a crash and the record cannot be trusted.
    """
    if len(record) < 48:
        raise FixupError("record too short to hold a fixup array")

    usa_offset = struct.unpack_from("<H", record, 0x04)[0]
    usa_count = struct.unpack_from("<H", record, 0x06)[0]

    if usa_count == 0:
        raise FixupError("update sequence array is empty")
    if usa_offset < 0x2A or usa_offset + usa_count * 2 > len(record):
        raise FixupError("update sequence array points outside the record")
    if sector_size == 0 or sector_size & (sector_size - 1):
        raise FixupError(f"implausible sector size {sector_size}")

    # The update sequence number is the first slot of the array. The 2-byte field
    # at 0x08 is the $LogFile sequence number, which is a different thing and is
    # routinely zero on a volume that has not been mounted and written.
    sequence = struct.unpack_from("<H", record, usa_offset)[0]

    # The array holds one slot for the sequence number itself plus one per
    # sector, so its count is always the sector count plus one.
    sectors = (len(record) + sector_size - 1) // sector_size
    if usa_count != sectors + 1:
        raise FixupError(
            f"update sequence array claims {usa_count - 1} sectors but the record "
            f"spans {sectors}"
        )

    verified = True
    for i in range(1, usa_count):
        # The value the sector's last two bytes originally held.
        saved = struct.unpack_from("<H", record, usa_offset + i * 2)[0]
        tail = i * sector_size - 2
        if tail < 0 or tail + 2 > len(record):
            raise FixupError(f"sector {i} tail falls outside the record")
        present = struct.unpack_from("<H", record, tail)[0]
        if present != sequence:
            verified = False
        struct.pack_into("<H", record, tail, saved)
    return verified, sequence


@dataclass
class MftAttribute:
    """One attribute as it appears on disk, with its value already fixup-corrected."""
    type: int
    name: str
    non_resident: bool
    resident_value: bytes = b""
    runs: list[tuple[int, int]] = field(default_factory=list)   # (lcn, length)
    allocated_size: int = 0
    real_size: int = 0
    initialized_size: int = 0
    flags: int = 0
    start_vcn: int = 0
    last_vcn: int = 0

    @property
    def is_primary_stream(self) -> bool:
        return self.name == ""

    @property
    def is_compressed(self) -> bool:
        return bool(self.flags & ATTR_IS_COMPRESSED)

    @property
    def is_encrypted(self) -> bool:
        return bool(self.flags & ATTR_IS_ENCRYPTED)

    @property
    def is_sparse(self) -> bool:
        return bool(self.flags & ATTR_IS_SPARSE)

    @property
    def content_is_plaintext(self) -> bool:
        """True when the run list yields the file's actual bytes.

        A compressed, encrypted or sparse $DATA stream does not read back as the
        file's contents. Reconstructing it and presenting the result as a
        recovered file would be a serious forensic error, so callers must refuse
        these rather than write out garbage.
        """
        return not (self.is_compressed or self.is_encrypted or self.is_sparse)

    @property
    def fragmented(self) -> bool:
        return len([r for r in self.runs if r[1] > 0]) > 1


@dataclass
class MftRecord:
    record_num: int
    sequence_number: int
    allocated: bool
    is_directory: bool
    base_record: int
    next_attr_id: int
    fixup_verified: bool
    sector_size: int
    bytes_in_use: int = 0
    attributes: list[MftAttribute] = field(default_factory=list)
    # Populated from $STANDARD_INFORMATION.
    created: float | None = None
    modified: float | None = None
    mft_changed: float | None = None
    accessed: float | None = None
    # Populated from $FILE_NAME. A record can carry several, one per hard link,
    # and for a directory one per .. entry.
    names: list[dict] = field(default_factory=list)
    # Raw $ATTRIBUTE_LIST payloads, followed on demand to find satellite records.
    attribute_lists: list[bytes] = field(default_factory=list)

    @property
    def real_size(self) -> int:
        """File size in bytes.

        Taken from the primary $DATA stream when it survives, and otherwise from
        $FILE_NAME, which keeps the size of a deleted file whose $DATA attribute
        has been overwritten. That size is often the only surviving evidence that
        a file ever existed at a given name.
        """
        for attr in self.attributes:
            if attr.type == ATTR_DATA and attr.is_primary_stream:
                return attr.real_size
        entry = self.primary_name()
        if entry:
            return int(entry.get("real_size") or 0)
        return 0

    @property
    def content_is_plaintext(self) -> bool:
        """False when the primary stream is compressed, encrypted or sparse.

        Reconstructing such a stream and presenting the bytes as the file's
        contents would be a serious forensic error: the output would be
        self-consistent and completely wrong.
        """
        for attr in self.attributes:
            if attr.type == ATTR_DATA and attr.is_primary_stream:
                return attr.content_is_plaintext
        # No surviving $DATA: there is nothing to misreport.
        return True

    @property
    def cannot_restore_reason(self) -> str | None:
        """Why this record's content cannot be reconstructed, if it cannot."""
        for attr in self.attributes:
            if attr.type == ATTR_DATA and not attr.is_primary_stream:
                continue
            if attr.type != ATTR_DATA:
                continue
            if attr.is_encrypted:
                return "the $DATA stream is EFS-encrypted; the plaintext is not on the volume"
            if attr.is_compressed:
                return "the $DATA stream is NTFS-compressed; the on-disk bytes are not the file"
            if attr.is_sparse:
                return "the $DATA stream is sparse; holes read as zeros, not as file content"
        return None

    @property
    def deleted(self) -> bool:
        return not self.allocated

    def primary_name(self) -> dict | None:
        """The $FILE_NAME entry that is not a hard link or a .. reference.

        Windows stores up to 20 $FILE_NAME attributes per directory and one per
        hard link. The namespace/parent flag distinguishes the entry that actually
        names this object from the "." and ".." links of a directory, which all
        share the record number.
        """
        best = None
        for entry in self.names:
            if entry.get("namespace") not in (1, 3):        # $FILE_NAME_NAMESPACE_DOS/Win32
                continue
            if entry.get("is_dot") or entry.get("is_dotdot"):
                continue
            if best is None or entry.get("is_primary", False):
                best = entry
                if entry.get("is_primary", False):
                    break
        return best or (self.names[0] if self.names else None)

    def name(self) -> str:
        entry = self.primary_name()
        return entry["name"] if entry else ""

    def parent(self) -> tuple[int, int] | None:
        """The (record, sequence) of the directory containing this object."""
        entry = self.primary_name()
        if not entry:
            return None
        ref = entry.get("parent_ref")
        return ref if ref else None

    def timestamps(self) -> dict[str, float | None]:
        return {
            "created": self.created,
            "modified": self.modified,
            "mft_changed": self.mft_changed,
            "accessed": self.accessed,
        }


def _first_attribute_offset(record: bytes) -> int | None:
    """Locate the start of the attribute chain.

    The header field for this lives at 0x14, which is what ntfs-3g writes and
    what 0x18a2 offset records carry. Some references document the chain as
    starting at 0x10, so rather than trust one layout the value is validated: a
    real attribute has a known type and a length that is a multiple of 8 and
    fits inside the record. If 0x14 does not hold that, the record is scanned for
    the first offset that does, which is cheap and only ever runs on records that
    the documented layout would have mis-parsed.
    """
    def valid(offset: int) -> bool:
        if offset < 0x2A or offset + 8 > len(record):
            return False
        attr_type = struct.unpack_from("<I", record, offset)[0]
        if attr_type in (0, MFT_END_MARKER) or attr_type > 0xFF:
            return False
        attr_len = struct.unpack_from("<I", record, offset + 4)[0]
        return attr_len >= 16 and attr_len % 8 == 0 and offset + attr_len <= len(record)

    candidate = struct.unpack_from("<H", record, 0x14)[0]
    if valid(candidate):
        return candidate
    # Fall back to a scan, honouring the 8-byte alignment the format requires.
    start = (0x30 + 7) & ~7
    for offset in range(start, len(record) - 8, 8):
        if valid(offset):
            return offset
    return None


def _iter_attributes(record: bytes):
    """Yield (offset, type, length, non_resident, name_len, name) for each attribute."""
    first = _first_attribute_offset(record)
    if first is None:
        return
    offset = first
    limit = len(record)
    while offset + 16 <= limit:
        attr_type = struct.unpack_from("<I", record, offset)[0]
        if attr_type in (0, MFT_END_MARKER):
            return
        attr_len = struct.unpack_from("<I", record, offset + 0x04)[0]
        if attr_len < 16 or offset + attr_len > limit:
            return
        non_resident = record[offset + 0x08]
        name_len = record[offset + 0x09]
        name_off = struct.unpack_from("<H", record, offset + 0x0A)[0]
        name = ""
        if name_len:
            start = offset + name_off
            if start + name_len * 2 <= offset + attr_len:
                name = record[start : start + name_len * 2].decode("utf-16le", "replace")
        yield offset, attr_type, attr_len, non_resident, name
        offset += attr_len


def _parse_attribute_list(blob: bytes) -> list[tuple[int, int, int]]:
    """Decode $ATTRIBUTE_LIST into [(type, start_vcn, satellite_record_number)].

    Each 0x18-byte entry names the attribute type, the VCN it starts at, and the
    MFT record that actually holds it. A file whose $DATA does not fit in its own
    record stores it in a satellite record that only this list points to, so
    without following it the largest files on a volume look empty.

    Entry layout:
      0x00  4  attribute type        0x04  2  record length
      0x06  2  attribute name offset 0x07 1  name length
      0x08  1  name namespace       0x09  2  starting VCN
      0x0B  6  MFT file reference (6-byte entry number, no sequence)
      0x11  2  attribute id         0x13  2  attribute name
    """
    out: list[tuple[int, int, int]] = []
    for i in range(0, max(0, len(blob) - 0x17), 0x18):
        if blob[i] == 0:
            break
        attr_type = struct.unpack_from("<I", blob, i)[0]
        if attr_type in (0, MFT_END_MARKER):
            break
        start_vcn = struct.unpack_from("<H", blob, i + 0x09)[0]
        entry = int.from_bytes(blob[i + 0x0B : i + 0x11], "little")
        if entry < 16:
            continue
        out.append((attr_type, start_vcn, entry))
    return out


def satellite_records(rec: MftRecord, limit: int = 64) -> list[int]:
    """Record numbers holding this file's data, per its $ATTRIBUTE_LIST."""
    out: list[int] = []
    for blob in rec.attribute_lists:
        for attr_type, _vcn, entry in _parse_attribute_list(blob):
            if attr_type == ATTR_DATA and entry not in out and entry != rec.record_num:
                out.append(entry)
                if len(out) >= limit:
                    return out
    return out


def merge_satellite(target: MftRecord, satellite: MftRecord) -> None:
    """Copy a satellite record's non-resident $DATA onto its owner.

    Attributes are kept in VCN order so reassembly can walk them from the start
    rather than assuming the owner record holds the first extent.
    """
    existing = {(a.type, a.name, a.start_vcn) for a in target.attributes}
    for attr in sorted(satellite.attributes, key=lambda a: (a.type, a.start_vcn)):
        if attr.type != ATTR_DATA:
            continue
        key = (attr.type, attr.name, attr.start_vcn)
        if key in existing:
            continue
        target.attributes.append(attr)
        existing.add(key)
    return None


def parse_mft_record(
    raw: bytes,
    sector_size: int = 512,
    strict: bool = True,
) -> MftRecord | None:
    """Parse one fixup-corrected MFT record.

    `strict` rejects a record whose update sequence array does not verify. A
    record that fails verification was being written when the machine lost power;
    its contents are a mixture of two versions and cannot be presented as
    evidence. With strict=False the record is still parsed -- which is useful for
    *searching* an image -- but `fixup_verified` is False so a report can say so.
    """
    if len(raw) < 48 or raw[0:4] != MFT_RECORD_MAGIC:
        return None

    buf = bytearray(raw)
    try:
        verified, sequence = apply_fixup(buf, sector_size)
    except FixupError:
        return None
    if strict and not verified:
        return None
    record = bytes(buf)

    flags = struct.unpack_from("<H", record, 0x16)[0]
    attrs: list[MftAttribute] = []
    std: dict | None = None
    names: list[dict] = []
    attr_lists: list[bytes] = []

    for offset, attr_type, attr_len, non_resident, name in _iter_attributes(record):
        if attr_type == ATTR_STANDARD_INFORMATION and not non_resident:
            value_off = struct.unpack_from("<H", record, offset + 0x14)[0]
            value_len = struct.unpack_from("<I", record, offset + 0x10)[0]
            blob = record[offset + value_off : offset + value_off + value_len]
            if len(blob) >= 0x24:
                std = {
                    "created": parse_nt_time(struct.unpack_from("<Q", blob, 0x00)[0]),
                    "modified": parse_nt_time(struct.unpack_from("<Q", blob, 0x08)[0]),
                    "mft_changed": parse_nt_time(struct.unpack_from("<Q", blob, 0x10)[0]),
                    "accessed": parse_nt_time(struct.unpack_from("<Q", blob, 0x18)[0]),
                }

        elif attr_type == ATTR_FILE_NAME and not non_resident:
            value_off = struct.unpack_from("<H", record, offset + 0x14)[0]
            value_len = struct.unpack_from("<I", record, offset + 0x10)[0]
            blob = record[offset + value_off : offset + value_off + value_len]
            # $FILE_NAME value layout:
            #   0x00  8  parent directory reference (MFT entry : sequence)
            #   0x08  8  created      0x10 8 modified     0x18 8 mft changed
            #   0x20  8  accessed     0x28 8 allocated size   0x30 8 real size
            #   0x38  4  flags        0x3C 4 reparse value
            #   0x40  1  name length  0x41 1 namespace    0x42 .. name
            # The parent reference is the *first* field. Reading offset 0x28 here
            # returns the file's allocated size, which is a plausible-looking
            # record number and silently produces nonsense parent paths.
            if len(blob) < 0x42:
                continue
            name_len = blob[0x40]
            if 0x42 + name_len * 2 > len(blob):
                continue
            raw_name = blob[0x42 : 0x42 + name_len * 2]
            # The name is UTF-16, but a few historic writers stored one byte per
            # character, in which case the declared length is half the byte length.
            try:
                decoded = raw_name.decode("utf-16le")
            except UnicodeDecodeError:
                decoded = raw_name.decode("latin-1", "replace")
            parent_entry = struct.unpack_from("<Q", blob, 0x00)[0]
            fn_flags = struct.unpack_from("<I", blob, 0x38)[0] if len(blob) >= 0x3C else 0
            names.append({
                "name": decoded,
                "namespace": blob[0x41],
                "parent_ref": (parent_entry & 0x0000FFFFFFFFFFFF,
                               (parent_entry >> 48) & 0xFFFF),
                "is_dot": decoded == ".",
                "is_dotdot": decoded == "..",
                "allocated_size": (struct.unpack_from("<Q", blob, 0x28)[0]
                                   if len(blob) >= 0x30 else 0),
                "real_size": (struct.unpack_from("<Q", blob, 0x30)[0]
                              if len(blob) >= 0x38 else 0),
                "flags": fn_flags,
                # A $FILE_NAME entry marked directory with a matching record
                # number is the "." link of a directory; the one whose parent
                # differs is "..". Neither names the object.
                "is_primary": decoded not in (".", ".."),
            })

        elif attr_type == ATTR_DATA and not non_resident:
            value_off = struct.unpack_from("<H", record, offset + 0x14)[0]
            value_len = struct.unpack_from("<I", record, offset + 0x10)[0]
            attrs.append(MftAttribute(
                type=attr_type, name=name, non_resident=False,
                resident_value=record[offset + value_off : offset + value_off + value_len],
                real_size=value_len, allocated_size=value_len, initialized_size=value_len,
                flags=struct.unpack_from("<H", record, offset + 0x16)[0],
            ))

        elif attr_type == ATTR_DATA and non_resident:
            run_off = struct.unpack_from("<H", record, offset + 0x20)[0]
            alloc = struct.unpack_from("<Q", record, offset + 0x28)[0]
            real = struct.unpack_from("<Q", record, offset + 0x30)[0]
            init = struct.unpack_from("<Q", record, offset + 0x38)[0]
            blob = record[offset + run_off : offset + attr_len]
            from .allocation import decode_run_list_raw
            attrs.append(MftAttribute(
                type=attr_type, name=name, non_resident=True,
                runs=decode_run_list_raw(blob),
                allocated_size=alloc, real_size=real, initialized_size=init,
                flags=struct.unpack_from("<H", record, offset + 0x16)[0],
                start_vcn=struct.unpack_from("<Q", record, offset + 0x10)[0],
                last_vcn=struct.unpack_from("<Q", record, offset + 0x18)[0],
            ))

        elif attr_type == ATTR_ATTRIBUTE_LIST and not non_resident:
            value_off = struct.unpack_from("<H", record, offset + 0x14)[0]
            value_len = struct.unpack_from("<I", record, offset + 0x10)[0]
            attr_lists.append(record[offset + value_off : offset + value_off + value_len])

    return MftRecord(
        record_num=struct.unpack_from("<I", record, 0x2C)[0],
        # The record's sequence number, not the $LogFile LSN, and not the
        # first-attribute offset at 0x10. These are all adjacent 2-byte fields
        # and confusing them silently mislabels every record's incarnation.
        sequence_number=struct.unpack_from("<H", record, 0x0C)[0],
        allocated=bool(flags & 0x0001),
        is_directory=bool(flags & 0x0002),
        base_record=struct.unpack_from("<I", record, 0x20)[0],
        next_attr_id=struct.unpack_from("<H", record, 0x28)[0],
        bytes_in_use=struct.unpack_from("<I", record, 0x18)[0],
        fixup_verified=verified,
        sector_size=sector_size,
        attributes=attrs,
        created=(std or {}).get("created"),
        modified=(std or {}).get("modified"),
        mft_changed=(std or {}).get("mft_changed"),
        accessed=(std or {}).get("accessed"),
        names=names,
        attribute_lists=attr_lists,
    )


def read_data(spans: list[tuple[int, int, bool]], handle, partition_offset: int,
              limit_bytes: int) -> bytes:
    """Read reconstructed file content from a list of byte spans.

    Sparse spans are emitted as real zero bytes rather than skipped, because the
    file's byte offsets depend on them being present.
    """
    out: list[bytes] = []
    remaining = limit_bytes
    for offset, length, sparse in spans:
        if remaining <= 0:
            break
        if sparse:
            out.append(bytes(min(length, remaining)))
            remaining -= min(length, remaining)
            continue
        handle.seek(partition_offset + offset)
        chunk = handle.read(min(length, remaining))
        if not chunk:
            break
        out.append(chunk)
        remaining -= len(chunk)
    return b"".join(out)


def runs_to_byte_spans(runs: list[tuple[int, int]], cluster_size: int,
                       limit_bytes: int) -> list[tuple[int, int, bool]]:
    """Turn cluster runs into (byte_offset, length, is_sparse) spans.

    `limit_bytes` caps the total so a corrupt or hostile run list -- a
    fragment count of 2^64 clusters -- cannot ask for an unbounded read.
    """
    spans: list[tuple[int, int, bool]] = []
    remaining = limit_bytes
    for lcn, length in runs:
        if remaining <= 0:
            break
        size = min(length * cluster_size, remaining)
        if size <= 0:
            continue
        if lcn < 0:
            spans.append((0, size, True))
        else:
            spans.append((lcn * cluster_size, size, False))
        remaining -= size
    return spans
