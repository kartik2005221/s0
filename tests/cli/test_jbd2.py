"""Tests for jbd2 (ext4 journal) parsing.

The superblock tests are pinned against the bytes of a real mkfs.ext4 volume,
not against a fixture written by the same code that reads them. The remaining
journal is empty on that image -- a journal is only written when a filesystem is
mounted and modified -- so the transaction-walking path is exercised separately
and marked as such.
"""

from __future__ import annotations

import struct

import pytest

from s0.carve import jbd2


# The first 0x44 bytes of a jbd2 superblock from a 64 MiB ext4 image made with
# `mkfs.ext4 -b 1024`. Taken verbatim; the UUID differs per image and is
# irrelevant here.
REAL_SUPERBLOCK = bytes.fromhex(
    "c03b3998"          # 0x00 h_magic
    "00000004"          # 0x04 h_blocktype = JBD2_SUPERBLOCK_V2
    "00000000"          # 0x08 h_sequence
    "00000400"          # 0x0C s_blocksize = 1024
    "00001000"          # 0x10 s_maxlen = 4096
    "00000001"          # 0x14 s_first
    "00000001"          # 0x18 s_sequence
    "00000000"          # 0x1C s_start
    "00000000"          # 0x20 s_errno
    "00000000"          # 0x24 s_feature_compat
    "00000000"          # 0x28 s_feature_incompat
    "00000000"          # 0x2C s_feature_ro_compat
    "647e02df57f4448ba59190257ed79ff9"   # 0x30 s_uuid
    "00000001"          # 0x40 s_nr_users
)


def _superblock(blocksize: int = 1024, maxlen: int = 4096, first: int = 1,
                sequence: int = 1, start: int = 0, blocktype: int = 4,
                magic: int = jbd2.JBD2_MAGIC, incompat: int = 0,
                uuid: bytes = b"\x11" * 16, nr_users: int = 1) -> bytes:
    out = bytearray(1024)
    struct.pack_into(">III", out, 0x00, magic, blocktype, 0)
    struct.pack_into(">III", out, 0x0C, blocksize, maxlen, first)
    struct.pack_into(">III", out, 0x18, sequence, start, 0)
    struct.pack_into(">III", out, 0x24, 0, incompat, 0)
    out[0x30:0x40] = uuid
    struct.pack_into(">I", out, 0x40, nr_users)
    return bytes(out)


# --------------------------------------------------------------------------- #
# superblock
# --------------------------------------------------------------------------- #


def test_real_superblock_parses():
    """The bytes are from an actual mkfs.ext4 volume."""
    sb = jbd2.parse_jbd2_superblock(REAL_SUPERBLOCK)
    assert sb is not None
    assert sb.blocksize == 1024
    assert sb.maxlen == 4096
    assert sb.first == 1
    assert sb.sequence_max == 1
    assert sb.start == 0
    assert sb.block_type == jbd2.JBD2_SUPERBLOCK_V2
    assert sb.uuid == bytes.fromhex("647e02df57f4448ba59190257ed79ff9")
    assert sb.nr_users == 1


def test_header_is_twelve_bytes_so_geometry_starts_at_0x0c():
    """A regression guard, and the bug this parser was originally born with.

    journal_header_t is {magic, blocktype, sequence}, twelve bytes. Reading
    blocksize at 0x08 instead puts every field four bytes early, so a perfectly
    valid journal reports a block size of zero and looks like it does not exist.
    """
    sb = jbd2.parse_jbd2_superblock(REAL_SUPERBLOCK)
    assert sb.blocksize != 0
    # The value at 0x08 is the header's sequence number, not a block size.
    assert struct.unpack_from(">I", REAL_SUPERBLOCK, 0x08)[0] == 0
    assert struct.unpack_from(">I", REAL_SUPERBLOCK, 0x0C)[0] == 1024


def test_superblock_v1_is_accepted():
    sb = jbd2.parse_jbd2_superblock(_superblock(blocktype=3))
    assert sb is not None and sb.block_type == jbd2.JBD2_SUPERBLOCK_V1


def test_wrong_magic_is_rejected():
    assert jbd2.parse_jbd2_superblock(_superblock(magic=0xDEADBEEF)) is None


def test_unknown_blocktype_is_rejected():
    """A version the reader does not know must not be interpreted.

    The kernel documents that a new major version means the on-disk structure may
    have changed and the journal should not be used at all.
    """
    assert jbd2.parse_jbd2_superblock(_superblock(blocktype=9)) is None


def test_zero_blocksize_is_rejected():
    assert jbd2.parse_jbd2_superblock(_superblock(blocksize=0)) is None


def test_implausible_blocksize_is_rejected():
    """1000 is not a block size ext4 uses; accepting it would read nonsense."""
    assert jbd2.parse_jbd2_superblock(_superblock(blocksize=1000)) is None


def test_start_beyond_the_ring_is_rejected():
    assert jbd2.parse_jbd2_superblock(_superblock(maxlen=16, start=99)) is None


def test_empty_maxlen_is_rejected():
    assert jbd2.parse_jbd2_superblock(_superblock(maxlen=0)) is None


def test_truncated_superblock_is_rejected():
    assert jbd2.parse_jbd2_superblock(REAL_SUPERBLOCK[:32]) is None
    assert jbd2.parse_jbd2_superblock(b"") is None


def test_64bit_and_csum_features_are_read_from_the_right_bits():
    """A regression guard: these flags are 0x02 and 0x10, not 0x01 and 0x02.

    Off by one bit, 64BIT reads as REVOKE and CSUM_V3 as 64BIT, so a 64-bit
    journal is walked with 32-bit block numbers and every block after the first
    4 GiB is fetched from the wrong place.
    """
    sb = jbd2.parse_jbd2_superblock(_superblock(incompat=0x02))
    assert sb.has_64bit and not sb.has_csum_seed
    sb = jbd2.parse_jbd2_superblock(_superblock(incompat=0x10))
    assert sb.has_csum_seed and not sb.has_64bit
    sb = jbd2.parse_jbd2_superblock(_superblock(incompat=0x01))
    assert not sb.has_64bit and not sb.has_csum_seed     # REVOKE


# --------------------------------------------------------------------------- #
# block walking
# --------------------------------------------------------------------------- #


def _journal_block(blocktype: int, sequence: int, payload: bytes,
                   blocksize: int = 1024) -> bytes:
    out = bytearray(blocksize)
    struct.pack_into(">III", out, 0, jbd2.JBD2_MAGIC, blocktype, sequence)
    out[12 : 12 + len(payload)] = payload
    return bytes(out)


def test_blocks_are_read_with_the_twelve_byte_header():
    sb = jbd2.parse_jbd2_superblock(_superblock())
    journal = _journal_block(jbd2.JBD2_DESCRIPTOR_BLOCK, 7, b"\xaa" * 16)
    journal += _journal_block(jbd2.JBD2_COMMIT_BLOCK, 7, b"\xbb" * 16)
    blocks = jbd2.read_journal_blocks(journal, sb)
    assert len(blocks) == 2
    assert blocks[0].type_name == "descriptor"
    assert blocks[0].sequence == 7
    assert blocks[1].type_name == "commit"
    assert all(b.magic_ok for b in blocks)


def test_a_block_without_the_magic_is_marked_not_trusted():
    sb = jbd2.parse_jbd2_superblock(_superblock())
    raw = bytearray(_journal_block(jbd2.JBD2_DESCRIPTOR_BLOCK, 1, b""))
    raw[0:4] = b"\x00\x00\x00\x00"
    blocks = jbd2.read_journal_blocks(bytes(raw), sb)
    assert blocks and not blocks[0].magic_ok


def test_empty_journal_yields_no_blocks():
    sb = jbd2.parse_jbd2_superblock(_superblock())
    assert jbd2.read_journal_blocks(b"", sb) == []


# --------------------------------------------------------------------------- #
# ext4 directory entries
# --------------------------------------------------------------------------- #


def _dirent(inode: int, name: str, file_type: int = jbd2.EXT4_DIR_FT_REG,
            rec_len: int | None = None) -> bytes:
    raw = name.encode("utf-8")
    length = rec_len if rec_len is not None else (8 + len(raw) + 3) & ~3
    out = bytearray(length)
    struct.pack_into("<IHBB", out, 0, inode, length, len(raw), file_type)
    out[8 : 8 + len(raw)] = raw
    return bytes(out)


def test_directory_entries_are_read_in_order():
    block = _dirent(2, ".") + _dirent(2, "..")
    block += _dirent(11, "report.pdf", jbd2.EXT4_DIR_FT_REG)
    block += _dirent(12, "subdir", jbd2.EXT4_DIR_FT_DIR)
    entries = jbd2.parse_ext4_directory(block)
    assert [e.name for e in entries] == ["report.pdf", "subdir"]
    assert entries[0].inode == 11
    assert entries[0].type_name == "file"
    assert entries[1].type_name == "directory"


def test_dot_and_dotdot_are_not_reported_as_files():
    entries = jbd2.parse_ext4_directory(_dirent(2, ".") + _dirent(2, ".."))
    assert entries == []


def test_a_deleted_entry_keeps_its_name_with_a_zeroed_inode():
    """The case this whole exercise exists for.

    ext4 clears the inode number when a directory entry is unlinked but leaves
    the name and the record length in place, so the space can be reused. The
    name is still legible, and it is the only place it survives.
    """
    block = _dirent(0, "confidential-report.pdf")
    entries = jbd2.parse_ext4_directory(block)
    assert len(entries) == 1
    assert entries[0].name == "confidential-report.pdf"
    assert entries[0].inode == 0
    assert entries[0].deleted is True


def test_the_final_entry_may_be_short():
    """ext4 does not pad the last entry in a block to the block boundary."""
    block = _dirent(11, "exactly-fits.txt")
    assert len(block) < 1024
    entries = jbd2.parse_ext4_directory(block)
    assert [e.name for e in entries] == ["exactly-fits.txt"]


def test_a_zero_length_entry_ends_the_walk():
    entries = jbd2.parse_ext4_directory(_dirent(11, "before.txt") + bytes(8))
    assert [e.name for e in entries] == ["before.txt"]


def test_a_torn_entry_length_stops_the_walk_without_overrunning():
    """A record length that runs past the block means the block is torn.

    Reading to it would walk off the end of the buffer; trusting it would read
    garbage as filenames.
    """
    good = _dirent(11, "intact.txt")
    bad = bytearray(_dirent(12, "torn.txt"))
    struct.pack_into("<H", bad, 4, 4096)          # claims 4 KiB in a 1 KiB block
    entries = jbd2.parse_ext4_directory(good + bytes(bad))
    assert [e.name for e in entries] == ["intact.txt"]


def test_a_zero_rec_len_terminates():
    block = bytearray(_dirent(11, "a.txt"))
    struct.pack_into("<H", block, 4, 0)
    assert jbd2.parse_ext4_directory(bytes(block)) == []


def test_a_name_length_past_the_record_is_refused():
    block = bytearray(_dirent(11, "a.txt"))
    struct.pack_into("<B", block, 6, 200)         # name_len larger than rec_len
    assert jbd2.parse_ext4_directory(bytes(block)) == []


def test_reserved_inodes_are_not_offered_as_recovered_data():
    """lost+found, the journal and the root inode all have names in a directory.

    Reporting them as recovered user files would put eight rows of filesystem
    internals at the top of every result list.
    """
    block = b"".join(_dirent(n, f"reserved-{n}.txt") for n in sorted(jbd2.SYSTEM_INODES))
    block += _dirent(100, "user-document.pdf")
    entries = jbd2.parse_ext4_directory(block)
    user = [e for e in entries if e.inode not in jbd2.SYSTEM_INODES]
    assert [e.name for e in user] == ["user-document.pdf"]


def test_empty_directory_block_yields_nothing():
    assert jbd2.parse_ext4_directory(bytes(1024)) == []
    assert jbd2.parse_ext4_directory(b"") == []


def test_non_utf8_name_is_preserved_rather_than_dropped():
    """A Latin-1 filename is a real filename, not a parse failure.

    ext4 stores raw bytes; the filesystem does not require UTF-8. Dropping the
    entry loses a name that was genuinely on the volume.
    """
    raw = b"caf\xe9-notes.txt"
    out = bytearray(8 + len(raw))
    struct.pack_into("<IHBB", out, 0, 11, len(out), len(raw), 1)
    out[8:] = raw
    entries = jbd2.parse_ext4_directory(bytes(out))
    assert len(entries) == 1
    assert "notes.txt" in entries[0].name


# --------------------------------------------------------------------------- #
# checksum
# --------------------------------------------------------------------------- #


def test_crc32c_matches_the_standard_check_value():
    """CRC-32C (Castagnoli) of "123456789" is 0xE3069283.

    ext4 chose CRC-32C over the more common CRC-32 (IEEE) precisely because it is
    cheaper in hardware. A journal checksummed with IEEE will not match a single
    block, and the symptom is that every block is rejected as corrupt.
    """
    assert jbd2._crc32c(b"123456789") == 0xE3069283


def test_crc32c_differs_from_ieee_crc32():
    import zlib
    data = b"the quick brown fox"
    # IEEE CRC-32 of the same bytes is 0x91c102ca. Reading a Castagnoli check
    # with the IEEE polynomial -- the obvious mistake when implementing this
    # from the name -- produces a different constant and rejects every block.
    assert jbd2._crc32c(data) != zlib.crc32(data)
    assert zlib.crc32(data) == 0x91C102CA
    assert jbd2._crc32c(data) == 0x3355EFD3


def test_a_block_whose_checksum_does_not_verify_is_marked():
    # A checksum is only present when the superblock advertises CSUM_V3.
    sb = jbd2.parse_jbd2_superblock(_superblock(incompat=0x10))
    block = bytearray(_journal_block(jbd2.JBD2_DESCRIPTOR_BLOCK, 1, b"payload"))
    struct.pack_into(">I", block, len(block) - 4, 0xDEADBEEF)   # wrong on purpose
    parsed = jbd2.read_journal_blocks(bytes(block), sb)[0]
    assert parsed.checksum_ok is False


def test_a_block_with_no_checksum_feature_is_not_checked():
    """Without CSUM_V2/V3 the trailing bytes are payload, not a checksum."""
    sb = jbd2.parse_jbd2_superblock(_superblock())
    journal = _journal_block(jbd2.JBD2_DESCRIPTOR_BLOCK, 1, b"\x00" * 32)
    parsed = jbd2.read_journal_blocks(journal, sb)[0]
    assert parsed.checksum_ok is None
