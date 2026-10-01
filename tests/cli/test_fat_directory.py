"""Tests for FAT32 directory reading and long-filename reassembly.

The point of these fixtures is the *deleted* filename. When FAT deletes a file
it replaces the first byte of the 8.3 name with 0xE5, so the naive reading of
"budget-final.xlsx" after deletion is "_UDGET~1.XLS" -- which identifies nothing.
The real name lives in the LFN entries that precede the 8.3 entry, and those
entries also carry a checksum that binds them to it. Every test below is about
whether that binding is honoured, because a long name attached to the wrong 8.3
entry is worse than no long name at all: it looks authoritative and is fiction.
"""

from __future__ import annotations

import struct

import pytest

from s0.carve import fat_directory as fd

# --------------------------------------------------------------------------- #
# entry construction
# --------------------------------------------------------------------------- #


def name83(stem: str, extension: str = "") -> bytes:
    """The 11 raw bytes of an 8.3 name: 8 of stem, 3 of extension.

    Built from the two parts so a name can never come out the wrong length, which
    is the sort of mistake a hand-counted literal makes and then the parser gets
    blamed for.
    """
    raw = stem.encode("ascii")[:8].ljust(8, b" ") + extension.encode("ascii")[:3].ljust(3, b" ")
    assert len(raw) == 11
    return raw


def make_short_entry(raw_name: bytes, *, first_cluster: int = 5, size: int = 4096,
                     attributes: int = fd.ATTR_ARCHIVE) -> bytes:
    assert len(raw_name) == 11, f"8.3 name must be 11 bytes, got {len(raw_name)}"
    out = bytearray(32)
    out[0:11] = raw_name
    out[11] = attributes
    struct.pack_into("<H", out, 20, (first_cluster >> 16) & 0xFFFF)
    struct.pack_into("<H", out, 26, first_cluster & 0xFFFF)
    struct.pack_into("<I", out, 28, size)
    return bytes(out)


def make_lfn_entry(sequence: int, characters: str, checksum: int,
                   is_last: bool = False) -> bytes:
    out = bytearray(32)
    out[0] = (sequence & 0x3F) | (fd.LFN_LAST_ENTRY_FLAG if is_last else 0)
    # 13 UTF-16 units, 26 bytes, split 5 / 6 / 2 across the record.
    encoded = characters.encode("utf-16le")[:26].ljust(26, b"\x00")
    out[1:11] = encoded[0:10]        # 0x01-0x0A  characters 1-5
    out[11] = fd.ATTR_LFN            # 0x0B       attribute
    out[12] = 0                      # 0x0C       reserved
    out[13] = checksum               # 0x0D       8.3 name checksum
    out[14:26] = encoded[10:22]      # 0x0E-0x19  characters 6-11
    out[26:28] = b"\x00\x00"        # 0x1A-0x1B  first cluster low
    out[28:32] = encoded[22:26]      # 0x1C-0x1F  characters 12-13
    return bytes(out)


def deleted_name83(stem: str, extension: str = "") -> bytes:
    """The 11 on-disk bytes of an 8.3 name after deletion: first byte 0xE5.

    This is what the writer hashed as 0x05, so the checksum of *these* bytes is
    what an LFN fragment for this entry carries.
    """
    return bytes([fd.DELETED_MARKER]) + name83(stem, extension)[1:]


def deleted_short_entry(on_disk_name: bytes, **kwargs) -> bytes:
    """An 8.3 entry as FAT leaves it after deletion (first byte 0xE5)."""
    raw = bytearray(make_short_entry(on_disk_name, **kwargs))
    raw[0] = fd.DELETED_MARKER
    return bytes(raw)


def long_name_for(short83: bytes, long_name: str) -> list:
    """Build the LFN run a real writer would leave before an 8.3 entry.

    Fragments are emitted in reverse order, highest sequence first, which is how
    FAT stores them; the entry nearest the 8.3 entry holds the tail of the name
    and carries the 0x40 flag.
    """
    stem = bytearray(short83[:11])
    if stem[0] == fd.DELETED_MARKER:
        stem[0] = 0x05
    checksum = fd.short_name_checksum(bytes(stem))

    units = [long_name[i : i + 13] for i in range(0, len(long_name), 13)]
    units = [u.ljust(13, "\x00") for u in units]
    out = []
    for i, chunk in enumerate(units, start=1):
        out.append(make_lfn_entry(i, chunk, checksum, is_last=(i == 1)))
    return list(reversed(out))       # reverse order on disk


# --------------------------------------------------------------------------- #
# 8.3 decoding
# --------------------------------------------------------------------------- #


def test_short_name_is_decoded_and_padding_stripped():
    entry = fd.FatDirectoryEntry(0, make_short_entry(name83("BUDGET", "XLS")))
    assert entry.short_name() == "BUDGET.XLS"


def test_a_deleted_name_reports_the_unknown_first_character():
    """0xE5 is a marker, not a character, and must not be decoded as one."""
    entry = fd.FatDirectoryEntry(0, deleted_short_entry(name83("BUDGET~1", "XLS")))
    assert entry.short_name() == "_UDGET~1.XLS"
    assert entry.is_free
    assert chr(0xE5) not in entry.short_name()


def test_end_of_directory_is_distinguished_from_a_free_slot():
    end = fd.FatDirectoryEntry(0, bytes(32))
    free = fd.FatDirectoryEntry(0, deleted_short_entry(b"FILE    TXT"))
    assert end.is_end_of_directory and not end.is_free
    assert free.is_free and not free.is_end_of_directory


# --------------------------------------------------------------------------- #
# long name reassembly
# --------------------------------------------------------------------------- #


def test_long_name_is_reassembled_from_fragments_in_reverse_order():
    short = deleted_name83("BUDGET~1", "XLS")
    long_name = "Quarterly Report FINAL.xlsx"
    blob = b"".join(long_name_for(short, long_name)) + deleted_short_entry(short)
    entries = fd.read_directory_cluster(blob, 512)
    named = fd.name_entries(entries)
    assert len(named) == 1
    assert named[0].name == long_name, "fragments were joined in the wrong order"
    assert named[0].recovered.long_name_verified
    assert named[0].is_deleted


def test_a_name_longer_than_one_fragment_survives():
    short = deleted_name83("VERYLONG~", "1X")
    long_name = "a-really-quite-long-filename-that-needs-three-fragments.txt"
    assert len(long_name) > fd.LFN_CHARS_PER_ENTRY * 2
    blob = b"".join(long_name_for(short, long_name)) + deleted_short_entry(short)
    named = fd.name_entries(fd.read_directory_cluster(blob, 512))
    assert named[0].name == long_name


def test_fragments_with_a_wrong_checksum_are_rejected():
    """The core safety property.

    LFN entries outlive the 8.3 entry they describe: delete a file and the slot
    is immediately reused. Without the checksum the stale fragments get attached
    to the new file, producing a name that never existed.
    """
    short = deleted_name83("OLDNAM~1", "TXT")
    blob = b"".join(long_name_for(short, "Original Document.docx"))
    blob += make_short_entry(name83("NEWFILE~", "TXT"))      # different name, slot reused
    named = fd.name_entries(fd.read_directory_cluster(blob, 512))
    assert named[0].name == "NEWFILE~.TXT", "a stale long name was trusted"
    assert not named[0].recovered.long_name_verified
    assert "UNVERIFIED" in named[0].recovered.name_source


def test_a_gap_in_the_sequence_numbers_is_rejected():
    short = deleted_name83("LONGREP1", "DO")
    frags = long_name_for(short, "Quarterly Reconciliation Report For The Region.docx")
    assert len(frags) >= 3, "needs three fragments for a gap to be detectable"
    # Remove the middle fragment, leaving sequence 1 and 3 with nothing at 2.
    seqs = [fd.parse_lfn_fragment(fd.FatDirectoryEntry(0, f)).sequence for f in frags]
    frags.pop(seqs.index(2))
    blob = b"".join(frags) + deleted_short_entry(short)
    named = fd.name_entries(fd.read_directory_cluster(blob, 512))
    # Sequence 1 and 3 with nothing at 2 is a gap the run cannot span.
    assert named[0].name == "_ONGREP1.DO"
    assert not named[0].recovered.long_name_verified


def test_a_malformed_fragment_breaks_the_run():
    """A corrupt fragment must not be spliced onto the following entry."""
    short = deleted_name83("GOODNAM~", "1T")
    frags = long_name_for(short, "Good Name.txt")
    bad = bytearray(frags[0])
    bad[26:28] = b"\xff\xff"                         # reserved field must be zero
    blob = bytes(bad) + b"".join(frags[1:]) + deleted_short_entry(short)
    named = fd.name_entries(fd.read_directory_cluster(blob, 512))
    assert named[0].name == "_OODNAM~.1T"
    assert not named[0].recovered.long_name_verified


def test_unclaimed_fragments_are_discarded_not_attached_to_the_next_file():
    """A run whose 8.3 entry is gone must not migrate to the following entry."""
    orphan = b"".join(long_name_for(deleted_name83("GONEONE~", "1T"), "Deleted Long Ago.txt"))
    following = make_short_entry(name83("KEEPFIL", "1TX"))
    named = fd.name_entries(fd.read_directory_cluster(orphan + following, 512))
    assert named[0].name == "KEEPFIL.1TX"


def test_a_run_without_the_final_entry_flag_is_rejected():
    short = deleted_name83("NOFLAG~", "1TX")
    frags = long_name_for(short, "No Flag Set.txt")
    flagged = [f for f in frags
               if fd.parse_lfn_fragment(fd.FatDirectoryEntry(0, f)).is_last]
    assert len(flagged) == 1
    stripped = bytearray(flagged[0])
    stripped[0] &= 0x3F                               # clear the 0x40 flag
    assert fd.parse_lfn_fragment(fd.FatDirectoryEntry(0, bytes(stripped))).is_last is False
    frags = [bytes(stripped) if f is flagged[0] else f for f in frags]
    blob = bytes(stripped) + b"".join(frags[1:]) + deleted_short_entry(short)
    named = fd.name_entries(fd.read_directory_cluster(blob, 512))
    assert not named[0].recovered.long_name_verified
    assert named[0].name == "_OFLAG~.1TX"


def test_unicode_names_are_recovered():
    short = deleted_name83("REPORT~1", "TX")
    long_name = "Jahresbericht Übersicht – Q3.pdf"
    blob = b"".join(long_name_for(short, long_name)) + deleted_short_entry(short)
    named = fd.name_entries(fd.read_directory_cluster(blob, 512))
    assert named[0].name == long_name


def test_a_live_file_also_gets_its_long_name():
    short = name83("PRESENT~", "1T")
    long_name = "Still Here.txt"
    blob = b"".join(long_name_for(short, long_name)) + make_short_entry(short)
    named = fd.name_entries(fd.read_directory_cluster(blob, 512))
    assert named[0].name == long_name
    assert not named[0].is_deleted


# --------------------------------------------------------------------------- #
# directory walking
# --------------------------------------------------------------------------- #


def test_a_free_slot_does_not_end_the_directory():
    """A walker that stops at the first deletion sees only files before it.

    That is the normal state of a directory that has had anything deleted from
    it, so it would hide most of the directory.
    """
    blob = (make_short_entry(name83("FIRST", "TXT"))
            + deleted_short_entry(name83("DELETED", "TXT"))
            + make_short_entry(name83("THIRD", "TXT")))
    named = fd.name_entries(fd.read_directory_cluster(blob, 512))
    assert [n.name for n in named] == ["FIRST.TXT", "_ELETED.TXT", "THIRD.TXT"]


def test_a_zero_entry_does_end_the_directory():
    blob = (make_short_entry(name83("REALFILE", "TXT"))
            + bytes(32)
            + make_short_entry(name83("BOGUS", "TXT")))
    named = fd.name_entries(fd.read_directory_cluster(blob, 512))
    assert [n.name for n in named] == ["REALFILE.TXT"]


def test_the_volume_label_is_not_a_file():
    label = bytearray(32)
    label[0:11] = b"S0FIX      "
    label[11] = fd.ATTR_VOLUME_ID
    blob = bytes(label) + make_short_entry(name83("AFTERLBL", "TXT"))
    named = fd.name_entries(fd.read_directory_cluster(blob, 512))
    assert [n.name for n in named] == ["AFTERLBL.TXT"]


def test_directory_entries_are_skipped_when_not_requested():
    blob = make_short_entry(name83("LIVE", "TXT")) + deleted_short_entry(name83("DEAD", "TXT"))
    entries = fd.read_directory_cluster(blob, 512)
    assert len(fd.name_entries(entries, include_free=False)) == 1


# --------------------------------------------------------------------------- #
# checksum
# --------------------------------------------------------------------------- #


def test_a_deleted_entry_has_no_recomputable_checksum():
    """Why deleted long names are corroborated structurally rather than by hash.

    Deletion overwrites the first byte of the 8.3 name with 0xE5. The fragments
    were checksummed against the character that was there before, and that
    character is gone -- 0x05 is the convention for a filename that genuinely
    began with 0xE5, not the placeholder for a deleted one. Substituting it
    would make the checksum disagree for essentially every deleted file and
    silently degrade every recovered long name to the useless 8.3 form, so the
    parser reports "adjacency only" instead of claiming a match.
    """
    deleted = fd.FatDirectoryEntry(0, deleted_short_entry(name83("BUDGET~1", "XLS")))
    assert deleted.is_free
    assert fd.expected_checksum_for(deleted) is None
    live = fd.FatDirectoryEntry(0, make_short_entry(name83("BUDGET~1", "XLS")))
    assert fd.expected_checksum_for(live) is not None


def test_checksum_rejects_a_wrong_length_name():
    with pytest.raises(ValueError):
        fd.short_name_checksum(b"TOOSHORT")


def test_checksum_is_rotation_not_addition():
    """Order matters: two different 11-byte names with the same bytes shuffled
    produce different checksums, which is what stops a misplaced LFN run."""
    a = fd.short_name_checksum(b"ABCDEFGHIJK")
    b = fd.short_name_checksum(b"BCDEFGHIJKA")
    assert a != b


# --------------------------------------------------------------------------- #
# end-to-end: the scanner uses the reassembly
# --------------------------------------------------------------------------- #


def test_scanner_recovers_a_long_name_for_a_deleted_entry(tmp_path, monkeypatch):
    """The reassembly has to be reached from scan_fat32_deleted_files, not just exist.

    A unit test on the reassembler proves nothing if the carver still parses
    entries one at a time, which is exactly how it behaved before.
    """
    from s0.carve import fat_carver

    boot_bytes = bytearray(512)
    boot_bytes[0x03:0x0B] = b"FAT32   "
    struct.pack_into("<H", boot_bytes, 0x0B, 512)      # bytes per sector
    boot_bytes[0x0D] = 4                                # sectors per cluster (2 KiB)
    struct.pack_into("<H", boot_bytes, 0x0E, 32)         # reserved sectors
    boot_bytes[0x10] = 2                                 # FAT count
    struct.pack_into("<H", boot_bytes, 0x11, 0)          # root entries (FAT32)
    struct.pack_into("<H", boot_bytes, 0x13, 4096)       # total sectors 16
    struct.pack_into("<I", boot_bytes, 0x24, 32)         # sectors per FAT
    struct.pack_into("<I", boot_bytes, 0x2C, 3)          # root cluster
    boot_bytes[0x1FE:0x200] = b"\x55\xaa"

    cluster_bytes = 2048
    short = deleted_name83("BUDGET~1", "XLS")
    cluster = b"".join(long_name_for(short, "Quarterly Report FINAL.xlsx"))
    cluster += deleted_short_entry(short, first_cluster=3, size=64)
    cluster += bytes(cluster_bytes - len(cluster))

    # The boot sector is the first sector *of the reserved region*, so the layout
    # is reserved (32 sectors, boot included), then both FATs, then the data area
    # where cluster 2 is the root directory and cluster 3 is the file's data.
    image = tmp_path / "fat.img"
    image.write_bytes(
        bytes(boot_bytes)
        + bytes(31 * 512)          # rest of the reserved region
        + bytes(32 * 512)          # FAT #1
        + bytes(32 * 512)          # FAT #2
        + cluster
        + bytes(cluster_bytes * 2)
    )
    # Mark cluster 3 as allocated so the data offset is inside the image.
    fat_off = 32 * 512
    data = bytearray(image.read_bytes())
    struct.pack_into("<I", data, fat_off + 3 * 4, 0x0FFFFFFF)
    image.write_bytes(bytes(data))

    results = fat_carver.scan_fat32_deleted_files(str(image))
    found = [r for r in results if r.is_deleted]
    assert found, "no deleted entry was reported"
    assert found[0].filename == "Quarterly Report FINAL.xlsx"
    assert found[0].name_source.startswith("long filename")
    # A deleted entry cannot be checksummed, and the report must say so.
    assert found[0].name_verification == fd.VERIFY_ADJACENT
    assert "adjacency" in found[0].name_source
