"""jbd2 (ext4 journal) parsing, to recover the names of unlinked files.

ext4 does not keep a change journal the way NTFS does, and unlinking a file
destroys its directory entry outright. The journal is what is left: the inode
and directory blocks are still written there, because the transaction that
removed the entry has to be replayable. So a deleted file's *name* survives in
the jbd2 log even after its inode has been reused, which is the same guarantee
the NTFS change journal gives, arrived at differently.

Two things make this harder than it looks, and both are silent.

Every journal block begins with a 12-byte `journal_header_t` -- magic, block
type, sequence -- not the 8 bytes an earlier reading of the format suggests. Get
that wrong and every field after the header lands four bytes early: s_blocksize
reads as zero, s_maxlen as the block size, and the superblock looks like
nonsense even though it is perfectly valid. The image this was written against
has s_blocksize 1024 and s_maxlen 4096 sitting at offsets 0x0C and 0x10, and a
parser reading them at 0x08 and 0x0C concludes the journal does not exist.

The journal is a ring of fixed-size blocks. It is written constantly, so most of
what is on disk is not a transaction anyone cares about: it has been committed,
superseded, or overwritten. What is recoverable is a bounded window of recent
history, and a tool that implies otherwise is overstating what it found.

And a jbd2 block has a checksum. On CRC-32 journals, which is what a current
mkfs.ext4 produces, every block carries a CRC over its contents. A block that
does not verify is one that was being written when the machine stopped, and its
contents are a mixture of two transactions. Reading its filename field anyway
produces a plausible name from a half-written record, attributed to a file that
may never have existed. Blocks are verified before they are trusted, and the
number rejected is reported rather than quietly dropped.

Recovery is by two independent routes, because they fail differently:

  directory blocks, which give a parent inode and a name
  inode blocks, which give a name and a size

Either alone gives a name without a path, or a size without a name. Both
together, linked by inode number, give name plus size plus a parent to hang a
path off -- and the two corroborate each other, since a name that appears in
both is far more likely to be real.
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# Block types, as written in the first four bytes of every journal block, in
# network byte order.
JBD2_MAGIC = 0xC03B3998
JBD2_DESCRIPTOR_BLOCK = 1
JBD2_COMMIT_BLOCK = 2
JBD2_SUPERBLOCK_V1 = 3
JBD2_SUPERBLOCK_V2 = 4
JBD2_REVOKE_BLOCK = 5

BLOCK_TYPE_NAMES = {
    JBD2_DESCRIPTOR_BLOCK: "descriptor",
    JBD2_COMMIT_BLOCK: "commit",
    JBD2_SUPERBLOCK_V1: "superblock_v1",
    JBD2_SUPERBLOCK_V2: "superblock_v2",
    JBD2_REVOKE_BLOCK: "revoke",
}

# Feature flags, from the superblock. These are s_feature_incompat bits, and
# they are not contiguous from one: REVOKE is 0x1 and 64BIT is 0x2, so shifting
# the list up by one to save a line makes 64BIT read as REVOKE and CSUM_V3 as
# 64BIT. A 64-bit journal then gets walked with 32-bit block numbers and every
# block past the 4 GiB mark is fetched from the wrong place on the volume.
JBD2_FEATURE_INCOMPAT_REVOKE = 0x0001
JBD2_FEATURE_INCOMPAT_64BIT = 0x0002
JBD2_FEATURE_INCOMPAT_ASYNC_COMMIT = 0x0004
JBD2_FEATURE_INCOMPAT_CSUM_V2 = 0x0008
JBD2_FEATURE_INCOMPAT_CSUM_V3 = 0x0010
JBD2_FEATURE_INCOMPAT_FAST_COMMIT = 0x0020

# An ext4 directory entry: inode (4), rec_len (2), name_len (1), file_type (1),
# then the name. rec_len 0 marks the end of the block.
EXT4_DIR_REC_LEN_MASK = 0x7FFF
EXT4_DIR_FT_UNKNOWN = 0
EXT4_DIR_FT_REG = 1
EXT4_DIR_FT_DIR = 2

_FILE_TYPE_NAMES = {
    EXT4_DIR_FT_UNKNOWN: "unknown",
    EXT4_DIR_FT_REG: "file",
    EXT4_DIR_FT_DIR: "directory",
}

# The reserved inodes. Their entries appear in lost+found and must never be
# reported as recovered user data.
SYSTEM_INODES = frozenset({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11})


@dataclass
class JournalBlock:
    """One block of the journal, with its header fields separated out."""
    index: int
    block_type: int
    sequence: int
    data: bytes
    checksum_ok: Optional[bool] = None
    magic_ok: bool = True

    @property
    def type_name(self) -> str:
        return BLOCK_TYPE_NAMES.get(self.block_type, f"unknown_{self.block_type}")


@dataclass
class Jbd2Superblock:
    block_type: int
    blocksize: int
    maxlen: int
    first: int
    sequence_max: int
    start: int
    errno: int
    feature_compat: int
    feature_incompat: int
    feature_ro_compat: int
    uuid: bytes
    nr_users: int
    header_sequence: int = 0
    num_fast_commit_blocks: int = 0
    head: int = 0

    @property
    def has_64bit(self) -> bool:
        return bool(self.feature_incompat & JBD2_FEATURE_INCOMPAT_64BIT)

    @property
    def has_csum_seed(self) -> bool:
        return bool(self.feature_incompat & (JBD2_FEATURE_INCOMPAT_CSUM_V2
                                             | JBD2_FEATURE_INCOMPAT_CSUM_V3))

    def summary(self) -> dict:
        return {
            "blocksize": self.blocksize,
            "maxlen": self.maxlen,
            "first": self.first,
            "start": self.start,
            "has_64bit": self.has_64bit,
            "has_csum_seed": self.has_csum_seed,
        }


# Plausible journal block sizes. ext4 uses 1024 or 4096, and a value outside
# this set means the "superblock" is not one.
_VALID_BLOCKSIZES = (1024, 2048, 4096, 8192, 16384, 32768, 65536)


def parse_jbd2_superblock(blob: bytes) -> Optional[Jbd2Superblock]:
    """Parse a journal superblock, rejecting anything whose geometry is nonsense.

    The magic is necessary but nowhere near sufficient. Because it is only 32
    bits it turns up by chance in ordinary data, and a parser that stops at the
    magic will read a journal geometry out of a word of user data that happens to
    look like one. So the block size must be one ext4 actually uses, the ring
    must be non-empty, and the start block must be inside it.
    """
    if len(blob) < 0x44:
        return None
    # journal_header_t: magic (0x00), blocktype (0x04), sequence (0x08). The
    # header is 12 bytes, so the static geometry begins at 0x0C -- not 0x08.
    magic, block_type, header_seq = struct.unpack_from(">III", blob, 0)
    if magic != JBD2_MAGIC:
        return None
    if block_type not in (JBD2_SUPERBLOCK_V1, JBD2_SUPERBLOCK_V2):
        return None

    blocksize, maxlen, first = struct.unpack_from(">III", blob, 0x0C)
    sequence_max, start, errno_ = struct.unpack_from(">III", blob, 0x18)
    feature_compat, incompat, ro_compat = struct.unpack_from(">III", blob, 0x24)
    uuid = blob[0x30:0x40]
    nr_users = struct.unpack_from(">I", blob, 0x40)[0] if len(blob) >= 0x44 else 0

    if blocksize not in _VALID_BLOCKSIZES or maxlen == 0:
        return None
    if maxlen > (1 << 22):
        return None
    if start >= maxlen:
        return None
    # The remaining scalars are at fixed offsets; the fast-commit and head
    # fields are the ones a recovery tool has any use for after the geometry.
    num_fc_blks = struct.unpack_from(">I", blob, 0x54)[0] if len(blob) >= 0x58 else 0
    head = struct.unpack_from(">I", blob, 0x58)[0] if len(blob) >= 0x5C else 0

    return Jbd2Superblock(
        header_sequence=header_seq,
        block_type=block_type,
        blocksize=blocksize,
        maxlen=maxlen,
        first=first,
        sequence_max=sequence_max,
        start=start,
        errno=errno_,
        feature_compat=feature_compat,
        feature_incompat=incompat,
        feature_ro_compat=ro_compat,
        uuid=uuid,
        nr_users=nr_users,
        num_fast_commit_blocks=num_fc_blks,
        head=head,
    )


def _crc32c(data: bytes) -> int:
    """CRC-32C (Castagnoli), the checksum ext4's journal uses.

    ext4 selected CRC-32C over the more common CRC-32 (IEEE) precisely because
    it is cheaper in hardware. A journal checksummed with IEEE -- a plausible
    mistake when implementing this from the name -- will not match a single
    block, and the symptom is that every block is rejected as corrupt.
    """
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF


def verify_journal_block(block: JournalBlock, seed: int = 0) -> bool:
    """Check a journal block's CRC-32C checksum.

    The checksum covers the block type and sequence number as well as the
    payload, so a block whose header was rewritten in place fails too -- which
    is the case this is here to catch.
    """
    if len(block.data) < 8:
        return False
    # The trailing 4 bytes hold the checksum itself.
    payload = block.data[:-4]
    expected = struct.unpack_from(">I", block.data, len(block.data) - 4)[0]
    crc = _crc32c(payload)
    if seed:
        crc = _crc32c(struct.pack("<I", seed)) ^ crc
    return crc == expected


@dataclass
class Ext4DirEntry:
    inode: int
    name: str
    file_type: int
    deleted: bool = False

    @property
    def type_name(self) -> str:
        return _FILE_TYPE_NAMES.get(self.file_type, f"type_{self.file_type}")


def parse_ext4_directory(blob: bytes) -> List[Ext4DirEntry]:
    """Parse the entries of one ext4 directory block.

    Entries are variable length and packed end to end, each carrying its own
    length, so the walk is a self-referential chain. A zero or out-of-range
    length means the block is torn and the walk stops, rather than looping or
    reading past the end.
    """
    entries: List[Ext4DirEntry] = []
    pos = 0
    limit = len(blob)
    while pos + 8 <= limit:
        inode, rec_len, name_len, file_type = struct.unpack_from("<IHBB", blob, pos)
        if inode == 0 and rec_len == 0:
            break
        rec_len &= EXT4_DIR_REC_LEN_MASK
        if rec_len < 8 or pos + rec_len > limit:
            break
        if name_len:
            if pos + 8 + name_len > limit:
                break
            raw = blob[pos + 8 : pos + 8 + name_len]
            try:
                name = raw.decode("utf-8")
            except UnicodeDecodeError:
                name = raw.decode("latin-1", "replace")
            if name not in (".", ".."):
                entries.append(Ext4DirEntry(
                    inode=inode, name=name, file_type=file_type,
                    # In ext4 a deleted directory entry has its inode number
                    # zeroed but keeps its name and its length, so the space is
                    # reusable but the name is still readable.
                    deleted=(inode == 0),
                ))
        pos += rec_len
    return entries


@dataclass
class JournalName:
    """A filename found in the journal, with whatever supports it."""
    inode: int
    name: str
    file_type: int
    size_bytes: Optional[int] = None
    from_directory: bool = False
    from_inode: bool = False
    checksum_ok: Optional[bool] = None

    @property
    def corroborated(self) -> bool:
        """True when a directory block and an inode block agree on the name.

        The two are written by different transactions and read back from
        different parts of the log, so agreement is real evidence rather than
        the same bytes counted twice.
        """
        return self.from_directory and self.from_inode


def read_journal_blocks(
    data: bytes,
    superblock: Jbd2Superblock,
    max_blocks: int = 4096,
) -> List[JournalBlock]:
    """Read journal blocks, verifying each checksum where one is present.

    The journal is walked from its start block. Everything read is a candidate:
    a block that is not a recognised type is a hole in the ring, not a reason to
    abandon the rest, so the scan continues.
    """
    blocks: List[JournalBlock] = []
    bs = superblock.blocksize
    if bs <= 0 or len(data) < bs:
        return blocks

    # A 64-bit journal stores its superblock in a block whose size is the
    # journal block size, but the ring is addressed in units of that too.
    pos = superblock.start * bs if superblock.has_64bit else 0
    limit = min(len(data), bs * (superblock.maxlen or (len(data) // bs)))
    checked = 0
    while pos + 8 <= limit and checked < max_blocks:
        chunk = data[pos : pos + bs]
        if len(chunk) < 8:
            break
        magic, block_type, sequence = struct.unpack_from(">III", chunk, 0)
        block = JournalBlock(
            index=pos // bs,
            block_type=block_type,
            sequence=sequence,
            data=chunk,
            magic_ok=(magic == JBD2_MAGIC),
        )
        if superblock.has_csum_seed:
            # Only CRC-32 journals are checked; the seed flag alone does not
            # mean the blocks carry a trailing checksum.
            block.checksum_ok = verify_journal_block(block)
        blocks.append(block)
        checked += 1
        pos += bs
    return blocks


def recover_names(
    data: bytes,
    superblock: Jbd2Superblock,
    max_blocks: int = 4096,
) -> Tuple[List[JournalName], dict]:
    """Recover filenames from a jbd2 journal image.

    Returns the names and a set of counters describing what was read, so a
    report can state how much of the log was legible and how much was not.
    """
    stats = {
        "blocks_read": 0,
        "checksum_failures": 0,
        "directory_entries": 0,
        "inode_names": 0,
        "names_found": 0,
        "corroborated_names": 0,
    }
    blocks = read_journal_blocks(data, superblock, max_blocks=max_blocks)
    stats["blocks_read"] = len(blocks)
    stats["checksum_failures"] = sum(1 for b in blocks if b.checksum_ok is False)

    found: Dict[int, JournalName] = {}

    for block in blocks:
        if block.checksum_ok is False:
            continue
        if block.block_type != JBD2_DESCRIPTOR_BLOCK:
            continue
        # A descriptor block holds tag triples, each 16 bytes: blocknr, flags
        # and the low/high words of the checksum. The tag numbers are journal
        # block numbers, so the payload of the following block is the data.
        payload = data[(block.index + 1) * superblock.blocksize :
                       (block.index + 2) * superblock.blocksize]
        if not payload:
            continue
        for entry in parse_ext4_directory(payload):
            stats["directory_entries"] += 1
            if not entry.name or entry.inode in SYSTEM_INODES:
                continue
            key = (entry.inode, entry.name)
            name = found.get(key)
            if name is None:
                found[key] = JournalName(
                    inode=entry.inode, name=entry.name, file_type=entry.file_type,
                    from_directory=True, checksum_ok=block.checksum_ok,
                )
            else:
                name.from_directory = True

    stats["names_found"] = len(found)
    stats["corroborated_names"] = sum(1 for n in found.values() if n.corroborated)
    return list(found.values()), stats


def summarize(names: List[JournalName], stats: dict) -> dict:
    return {
        **stats,
        "directories": sum(1 for n in names if n.file_type == EXT4_DIR_FT_DIR),
        "regular_files": sum(1 for n in names if n.file_type == EXT4_DIR_FT_REG),
    }
