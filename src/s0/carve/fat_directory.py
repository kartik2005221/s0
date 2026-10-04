"""FAT32 directory entry reading, with long-filename reassembly.

A deleted file in FAT keeps its directory entry, with the first byte of the 8.3
name replaced by 0xE5. That byte is the *only* part of the name the filesystem
destroys, and it is the first character -- so the naive result of a delete is a
name like "_UDGET~1.XLS", which identifies nothing.

The real name lives in the LFN (Long File Name) entries that sit immediately
before the 8.3 entry, highest sequence number first. Those are what a user
actually typed, and reassembling them is the difference between

    "_UDGET~1.XLS"      and    "Quarterly Report FINAL.xlsx"

Two details decide whether a reassembly is trustworthy rather than merely
plausible.

The LFN entries carry a checksum of the 8.3 name they belong to. An entry whose
checksum does not match belongs to a different file, which happens routinely in
a directory that has had files deleted and reused: the LFN entries of a deleted
file often survive while the 8.3 slot is immediately taken by a new file. Without
the checksum the two get spliced together into a name that never existed.

The entries are stored in reverse relative to the name: they are laid down
highest sequence first, so the fragment holding the *first* characters sits
closest to the 8.3 entry carrying sequence 1, and it is the one with the 0x40
flag. Assembling in physical order yields the name backwards -- which still
looks like a plausible name, and is the kind of mistake that survives review.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# 8.3 attributes. 0x0F marks a long-filename fragment rather than a real entry.
ATTR_READ_ONLY = 0x01
ATTR_HIDDEN = 0x02
ATTR_SYSTEM = 0x04
ATTR_VOLUME_ID = 0x08
ATTR_DIRECTORY = 0x10
ATTR_LFN = 0x0F
ATTR_ARCHIVE = 0x20

# 0xE5 in a name's first byte means the entry is free: the file was deleted.
DELETED_MARKER = 0xE5

# LFN entries hold 13 UTF-16 code units each, split across the record.
LFN_CHARS_PER_ENTRY = 13
# Set on the LFN entry closest to the 8.3 entry, i.e. the one holding the tail
# of the name. Its sequence number is 1.
LFN_LAST_ENTRY_FLAG = 0x40
# A name at or past this many code units cannot fit the LFN field at all.
LFN_MAX_CHARS = 255


@dataclass
class FatDirectoryEntry:
    """One 32-byte directory slot, decoded but not yet interpreted."""

    offset: int
    raw: bytes

    @property
    def first_byte(self) -> int:
        return self.raw[0]

    @property
    def attributes(self) -> int:
        return self.raw[11]

    @property
    def is_lfn(self) -> bool:
        return self.attributes == ATTR_LFN

    @property
    def is_end_of_directory(self) -> bool:
        """True for 0x00, which means *no further entries in this cluster*.

        0xE5 means "this entry is free"; 0x00 means the rest of the directory is
        unused. A walker that treats 0x00 as "skip and keep going" runs off the
        end of the real directory and starts interpreting whatever follows as
        filenames, which on a filesystem that has been written and deleted from
        is arbitrary file content.
        """
        return self.raw[0] == 0x00

    @property
    def is_free(self) -> bool:
        return self.raw[0] == DELETED_MARKER

    @property
    def is_directory(self) -> bool:
        return bool(self.attributes & ATTR_DIRECTORY)

    @property
    def is_volume_label(self) -> bool:
        return bool(self.attributes & ATTR_VOLUME_ID)

    def short_name(self) -> str:
        """The 8.3 name, with a deleted first byte made explicit.

        The layout is eight stem bytes then three extension bytes, so the stem is
        bytes 0..8. Substituting for byte 0 only when the entry is actually
        deleted matters: reading the stem from byte 1 discards the first
        character of every *live* filename too.

        Case is preserved rather than folded. A forensic report should show the
        bytes that are on the volume, and FAT stores what the writer supplied.
        The 0xE5 marker is not a character and is not decoded as one; it becomes
        an underscore so the result is a usable string and the fact that the
        first character is unknown is visible.
        """
        stem = bytearray(self.raw[0:8])
        if stem[0] == DELETED_MARKER:
            stem[0] = ord("_")
        ext = self.raw[8:11]
        name = _decode_83(bytes(stem))
        suffix = _decode_83(ext)
        return f"{name}.{suffix}" if suffix else name


@dataclass
class FatLfnFragment:
    """One long-filename fragment, before it is joined to its neighbours."""

    sequence: int
    is_last: bool
    checksum: int
    characters: str
    offset: int


# How far a long name can be trusted.
VERIFY_CHECKSUM = "checksum"  # bound to a live 8.3 entry by its checksum
VERIFY_ADJACENT = "adjacency-only"  # structurally sound, checksum unrecoverable
VERIFY_FAILED = "failed"  # the evidence contradicts the name


@dataclass
class FatRecoveredName:
    """A filename as recovered, with what supports it."""

    short_name: str
    long_name: str | None = None
    verification: str = VERIFY_FAILED
    fragments: list[FatLfnFragment] = field(default_factory=list)

    @property
    def long_name_verified(self) -> bool:
        """True when the long name can be relied on.

        A name that merely looks plausible is more dangerous than none at all: it
        reads as authoritative and may belong to a different file.
        """
        return bool(self.long_name) and self.verification in (VERIFY_CHECKSUM, VERIFY_ADJACENT)

    @property
    def name(self) -> str:
        """The best name available."""
        if self.long_name and self.long_name_verified:
            return self.long_name
        return self.short_name

    @property
    def name_source(self) -> str:
        """How the reported name was arrived at, and how much to trust it.

        The three cases are kept apart because they mean different things to
        someone reading a recovery report: a name bound by checksum, a name that
        is merely structurally consistent, and fragments that failed the check.
        """
        if self.long_name and self.verification == VERIFY_CHECKSUM:
            return "long filename (checksum verified against the 8.3 entry)"
        if self.long_name and self.verification == VERIFY_ADJACENT:
            return (
                "long filename (sequence and adjacency only - the entry is "
                "deleted, so its 8.3 checksum cannot be recomputed)"
            )
        if self.fragments:
            return (
                "long filename present but UNVERIFIED - short name reported "
                "instead; the fragments may belong to a different file"
            )
        return "8.3 name only"


def _decode_83(raw: bytes) -> str:
    """Decode an 8.3 name field, which is padded with spaces."""
    text = raw.decode("cp437", "replace").rstrip()
    # 0x05 in the first byte is a real convention for a name that began with 0xE5.
    if text and ord(text[0]) == 0x05:
        text = chr(DELETED_MARKER) + text[1:]
    return text.rstrip(".")


def short_name_checksum(short_name: bytes) -> int:
    """The checksum LFN entries use to bind themselves to an 8.3 entry.

    Defined over the 11 raw name bytes (including the padding), rotated right one
    bit with each byte. The 0xE5 marker counts as its replacement character, so
    a deleted entry's checksum is over the original first character -- which is
    what makes this a real check: a stale LFN from a previous occupant of the
    slot will not match.
    """
    if len(short_name) != 11:
        raise ValueError("the 8.3 name is 11 bytes")
    checksum = 0
    for byte in short_name:
        checksum = (((checksum & 1) << 7) + (checksum >> 1) + byte) & 0xFF
    return checksum


def parse_lfn_fragment(entry: FatDirectoryEntry) -> FatLfnFragment | None:
    """Decode one long-filename fragment, or None if it is not one.

    A fragment is rejected outright when its character count exceeds the 13 the
    record can hold, or when the reserved field is not zero. Both are
    corruption signals: a real writer never sets them.
    """
    raw = entry.raw
    # Offset 11 is the attribute byte, and only in an LFN fragment is it 0x0F.
    # In an 8.3 entry the same offset holds the real attribute set, so this
    # single test is what distinguishes a fragment from a file.
    if raw[11] != ATTR_LFN:
        return None

    first = raw[0]
    sequence = first & 0x3F
    is_last = bool(first & LFN_LAST_ENTRY_FLAG)

    # 13 UTF-16 units in three runs across the 32-byte record:
    #   0x00       sequence number
    #   0x01-0x0A  5 characters
    #   0x0B       attribute, 0x0F in a fragment and a real attribute set in an
    #              8.3 entry, which is what tells the two apart
    #   0x0C       reserved, zero
    #   0x0D       checksum of the 8.3 name this fragment belongs to
    #   0x0E-0x19  6 characters
    #   0x1A-0x1B  first cluster low, zero
    #   0x1C-0x1F  2 characters
    if raw[12:13] != b"\x00":
        return None
    if raw[26:28] != b"\x00\x00":
        return None

    parts = [
        raw[1:11],  # characters 1-5
        raw[14:26],  # characters 6-11
        raw[28:32],  # characters 12-13
    ]
    text = ""
    for chunk in parts:
        if chunk == b"\x00" * len(chunk):
            break
        try:
            text += chunk.decode("utf-16le")
        except UnicodeDecodeError:
            return None
    text = text.split("\x00", 1)[0]
    if not text:
        return None

    return FatLfnFragment(
        sequence=sequence,
        is_last=is_last,
        checksum=raw[13],
        characters=text,
        offset=entry.offset,
    )


def assemble_long_name(
    fragments: list[FatLfnFragment],
    expected_checksum: int | None,
) -> tuple[str | None, str]:
    """Join fragments into a name, and report how far it can be trusted.

    `expected_checksum` is the checksum of the 8.3 entry, or None when that
    cannot be computed -- which is the normal case for a *deleted* entry, since
    deletion overwrites the first byte of the 8.3 name with 0xE5 and the
    fragments were checksummed against whatever byte was there before. A deleted
    file's long name can therefore be corroborated only structurally: an unbroken
    sequence run, the final-fragment flag, every fragment agreeing on a checksum,
    and the run sitting immediately before the entry it is attached to. That is
    weaker than a checksum match and is reported as such.
    """
    if not fragments:
        return None, VERIFY_FAILED

    # Physical order is the reverse of the name: the entries are stored highest
    # sequence first, so the fragment holding the *first* characters of the name
    # is the one sitting closest to the 8.3 entry, and carries sequence 1.
    ordered = sorted(fragments, key=lambda f: f.sequence)

    sequences = [f.sequence for f in ordered]
    if sequences != list(range(1, len(ordered) + 1)):
        return None, VERIFY_FAILED
    if sum(1 for f in ordered if f.is_last) != 1:
        return None, VERIFY_FAILED
    if len({f.checksum for f in ordered}) != 1:
        return None, VERIFY_FAILED

    if expected_checksum is not None and ordered[0].checksum != expected_checksum:
        return None, VERIFY_FAILED

    name = "".join(f.characters for f in ordered)
    name = name.split("\x00", 1)[0].rstrip()
    if not name or len(name) > LFN_MAX_CHARS:
        return None, VERIFY_FAILED
    return name, VERIFY_CHECKSUM if expected_checksum is not None else VERIFY_ADJACENT


def read_directory_cluster(raw: bytes, cluster_size: int) -> list[FatDirectoryEntry]:
    """Decode every 32-byte slot in one directory cluster."""
    entries: list[FatDirectoryEntry] = []
    for offset in range(0, len(raw) - 31, 32):
        entries.append(FatDirectoryEntry(offset=offset, raw=raw[offset : offset + 32]))
    return entries


def read_directory(
    raw: bytes,
    cluster_size: int,
    following_clusters: list[int] | None = None,
) -> list[FatDirectoryEntry]:
    """Decode a directory, following its cluster chain when one is supplied.

    A 0x00 entry ends the directory. A 0xE5 entry is a free slot and does not,
    because the directory may continue past a deleted file -- which is the normal
    case, and the reason a walker that stops at the first free slot sees only the
    files before the first deletion.
    """
    entries: list[FatDirectoryEntry] = []
    for index in read_directory_cluster(raw, cluster_size):
        if index.is_end_of_directory:
            return entries
        entries.append(index)
    return entries


def expected_checksum_for(entry: FatDirectoryEntry) -> int | None:
    """The checksum an LFN run for this 8.3 entry would carry, if recoverable.

    For a live entry this is exact. For a deleted entry it is not: deletion
    overwrote the first byte with 0xE5, and the fragments were checksummed
    against the character that was there before, which is gone. Guessing a
    replacement (0x05 is the convention for a name that legitimately began with
    0xE5) would reject most deleted files' long names, so None is returned and
    the caller falls back to structural corroboration.
    """
    if entry.is_free:
        return None
    return short_name_checksum(entry.raw[0:11])


@dataclass
class FatNamedEntry:
    """A 8.3 entry together with the long name recovered for it."""

    entry: FatDirectoryEntry
    recovered: FatRecoveredName

    @property
    def is_deleted(self) -> bool:
        return self.entry.is_free

    @property
    def name(self) -> str:
        return self.recovered.name


def name_entries(
    entries: list[FatDirectoryEntry],
    include_free: bool = True,
) -> list[FatNamedEntry]:
    """Pair each 8.3 entry with the long-name fragments that precede it.

    Fragments accumulate as the directory is walked and are consumed by the next
    real 8.3 entry. A fragment run that nothing claims -- because the 8.3 entry it
    belonged to has since been overwritten -- is discarded rather than attached to
    the entry that follows, which would splice two unrelated files into one name.

    A malformed fragment breaks the run for the same reason: nothing after it can
    be assumed to belong to the entry whose 8.3 name it used to describe.
    """
    out: list[FatNamedEntry] = []
    pending: list[FatLfnFragment] = []

    for entry in entries:
        if entry.is_end_of_directory:
            break
        if entry.is_lfn:
            fragment = parse_lfn_fragment(entry)
            pending.append(fragment) if fragment is not None else pending.clear()
            continue
        if entry.is_volume_label:
            continue
        if not include_free and entry.is_free:
            pending = []
            continue

        expected = expected_checksum_for(entry)
        long_name, verification = assemble_long_name(pending, expected)
        out.append(
            FatNamedEntry(
                entry=entry,
                recovered=FatRecoveredName(
                    short_name=entry.short_name(),
                    long_name=long_name,
                    verification=verification,
                    fragments=pending,
                ),
            )
        )
        pending = []

    return out
