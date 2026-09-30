"""A real ext4 image, built without root, and what it proves about jbd2.

Why this file exists
--------------------
The plan deferred ext4 journal filename recovery to last, on the grounds that
it is "the one item whose central claim cannot be verified in this environment".
That was true of the *fixture*: producing genuine jbd2 journal activity needs a
kernel writing through a mounted filesystem, and mounting needs privileges this
environment does not have.

`debugfs` changes the picture in two useful ways. It edits an ext4 image in
place with no mount and no root, so a *real* filesystem can be created and a
file really unlinked from it. And it establishes the boundary precisely.

Measured on an image built this way: the unlinked file's name **is** still
present, in a stale directory entry at block 1854. The journal occupies blocks
from 16385, so the name is nowhere near it. debugfs writes filesystem
structures directly and never goes through the kernel, so it does not journal
-- and the journal reader correctly finds nothing because there is nothing
there, not because it failed.

So the accurate conclusion is narrower than "the name is gone", and more useful:
the jbd2 gap is a *fixture* problem, not a parser problem, and the route that
would actually recover this name is stale-dirent scanning -- which carries its
own risk, because a freed directory entry may be reallocated by a later write
and a name read from one cannot be treated as recovered metadata.

What is asserted here
---------------------
* The journal superblock that `mke2fs` writes parses, and 4,096 journal blocks
  read with zero checksum failures. The parser is exercised against a real
  superblock rather than only a synthesised one.
* A file unlinked with debugfs has its *data* recovered from its extents, and
  its extent list is a real one.
* The name survives in a stale dirent **outside the journal area**, which is
  the concrete reason the jbd2 reader has nothing to find here.
* s0 reports the file as `inode<N>` and invents no name.
* The journal reader returns no names, and says so through its counters rather
  than through silence.
"""

from __future__ import annotations

import shutil
import subprocess

import pytest

from s0.carve import jbd2
from s0.carve.ext4_carver import scan_ext4_deleted_inodes

MKE2FS = shutil.which("mke2fs")
DEBUGFS = shutil.which("debugfs")
requires_ext4_tools = pytest.mark.skipif(
    not (MKE2FS and DEBUGFS),
    reason="mke2fs and debugfs are needed to build a real ext4 image without root")

BLOCK_SIZE = 1024


@pytest.fixture(scope="module")
def real_ext4_with_deletion(tmp_path_factory):
    """A real ext4 image with one file created and then unlinked by debugfs.

    No mount, no loop device, no root: debugfs writes the filesystem structures
    directly. The file's blocks are freed and its name removed, which is the
    state an examiner actually meets.
    """
    if not (MKE2FS and DEBUGFS):
        pytest.skip("mke2fs and debugfs are needed")
    d = tmp_path_factory.mktemp("realext4")
    img = d / "vol.img"
    with open(img, "wb") as fh:
        fh.truncate(48 * 1024 * 1024)
    r = subprocess.run([MKE2FS, "-q", "-t", "ext4", "-O", "has_journal",
                        "-b", str(BLOCK_SIZE), "-I", "128", str(img)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip(f"mke2fs failed: {r.stderr[:200]}")
    payload = d / "secret.txt"
    payload.write_bytes(b"forensic evidence payload, this file will be deleted\n")

    for cmd in (f"write {payload} /evidence.txt",
                "mkdir /case01",
                f"write {payload} /case01/deleted-report.txt"):
        r = subprocess.run([DEBUGFS, "-w", "-R", cmd, str(img)],
                           capture_output=True, text=True)
        if r.returncode != 0:
            pytest.skip(f"debugfs {cmd!r} failed: {r.stderr[:200]}")
    r = subprocess.run([DEBUGFS, "-w", "-R", "rm /case01/deleted-report.txt", str(img)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip(f"debugfs rm failed: {r.stderr[:200]}")
    return img, payload.read_bytes()


# --------------------------------------------------------------------------- #
# The journal, on a real superblock
# --------------------------------------------------------------------------- #

def _find_journal_superblock(blob: bytes) -> int:
    """Locate the journal superblock the way a carver would: by its magic.

    The magic is big-endian on disk, which is easy to get backwards -- reading
    it little-endian finds nothing at all and looks like "no journal here".
    """
    needle = jbd2.JBD2_MAGIC.to_bytes(4, "big")
    return blob.find(needle)


@requires_ext4_tools
class TestRealJournal:
    def test_the_superblock_is_found_and_parses(self, real_ext4_with_deletion):
        img, _payload = real_ext4_with_deletion
        blob = img.read_bytes()
        off = _find_journal_superblock(blob)
        assert off >= 0, "mke2fs did not write a journal superblock"
        sb = jbd2.parse_jbd2_superblock(blob[off: off + 0x400])
        assert sb is not None
        assert sb.blocksize == BLOCK_SIZE
        assert sb.first >= 0

    def test_journal_blocks_read_without_checksum_failures(self, real_ext4_with_deletion):
        """Zero failures is the meaningful number: a mis-parsed CRC generator
        would fail on every block, and a mis-read block size would read garbage."""
        img, _payload = real_ext4_with_deletion
        blob = img.read_bytes()
        sb = jbd2.parse_jbd2_superblock(blob[_find_journal_superblock(blob):][:0x400])
        _names, stats = jbd2.recover_names(blob, sb)
        assert stats["blocks_read"] > 0
        assert stats["checksum_failures"] == 0, stats

    def test_an_empty_journal_reports_zero_names_and_says_so(self, real_ext4_with_deletion):
        """Counters, not silence.

        A reader that returned an empty list for a journal it could not read
        would be indistinguishable from one that read it correctly and found
        nothing, and the difference is the whole claim.
        """
        img, _payload = real_ext4_with_deletion
        blob = img.read_bytes()
        sb = jbd2.parse_jbd2_superblock(blob[_find_journal_superblock(blob):][:0x400])
        names, stats = jbd2.recover_names(blob, sb)
        assert names == []
        assert stats["names_found"] == 0
        assert stats["blocks_read"] > 0, "it did not actually read the journal"


# --------------------------------------------------------------------------- #
# The boundary, established rather than assumed
# --------------------------------------------------------------------------- #

@requires_ext4_tools
class TestDebugfsLeavesNoJournalTrace:
    """Where the name actually is, and where it is not.

    This is the measurement that pins the jbd2 item. The name survives, but in a
    stale directory entry well below the journal, because debugfs never
    journals. A journal reader has nothing to read here, and saying so is
    correct behaviour rather than a gap in the parser.
    """

    JOURNAL_FIRST_BLOCK = 16385

    def test_the_name_survives_in_a_stale_dirent(self, real_ext4_with_deletion):
        img, _payload = real_ext4_with_deletion
        blob = img.read_bytes()
        i = blob.find(b"deleted-report.txt")
        assert i >= 0, "debugfs zeroed the name; the stale dirent is gone"
        # A dirent header sits immediately before the name: inode, reclen,
        # namelen, type.
        rec = i - 8
        namelen = blob[rec + 6]
        assert namelen == len(b"deleted-report.txt")
        assert blob[rec + 7] == 1, "the entry is not a regular file"
        assert int.from_bytes(blob[rec: rec + 4], "little") > 0, "no inode number"

    def test_that_dirent_is_outside_the_journal_area(self, real_ext4_with_deletion):
        """The whole point. If the name were in the journal, the reader would
        have found it, and the item would be a parser bug rather than a fixture
        gap."""
        img, _payload = real_ext4_with_deletion
        blob = img.read_bytes()
        block = blob.find(b"deleted-report.txt") // BLOCK_SIZE
        assert block < self.JOURNAL_FIRST_BLOCK, (
            f"the name is at block {block}, inside the journal area")

    def test_the_data_is_still_recoverable_from_the_extents(self, real_ext4_with_deletion):
        """The useful half, and the reason a real fixture is worth building."""
        img, payload = real_ext4_with_deletion
        found = scan_ext4_deleted_inodes(str(img), partition_offset=0)
        assert found, "the unlinked file was not found at all"
        recovered = [i for i in found if i.data and payload in i.data]
        assert recovered, "the deleted file's contents were not recovered"
        assert recovered[0].extent_block_ranges, "no extents were recorded"

    def test_the_name_is_reported_as_an_inode_not_invented(self, real_ext4_with_deletion):
        """The report must not contain a name nobody can corroborate.

        A name read from a freed directory entry is a real possibility here, and
        it is still not something to assert: the entry may be reallocated, so
        the name is a lead rather than metadata. `inode15` says what was
        actually proven.
        """
        from s0.carve import carve_image
        img, _payload = real_ext4_with_deletion
        out = img.parent / "carve-out"
        summary = carve_image(img, out, generate_certificate=False)
        assert summary.source_filesystem == "ext4"
        assert summary.files_recovered >= 1
        for f in summary.carved_files:
            if f.recovery_method == "ext4_inode":
                assert f.original_name.startswith("inode"), \
                    f"a name was reported that the evidence cannot support: {f.original_name!r}"


# --------------------------------------------------------------------------- #
# The parser still refuses nonsense
# --------------------------------------------------------------------------- #

class TestJournalParserStillRefuses:
    def test_random_data_yields_no_superblock(self):
        import os
        assert jbd2.parse_jbd2_superblock(os.urandom(1024)) is None

    def test_noise_yields_no_names(self):
        import os
        blob = os.urandom(4 << 20)
        sb = jbd2.Jbd2Superblock(
            block_type=4, blocksize=1024, maxlen=64, first=0, sequence_max=1,
            start=0, errno=0, feature_compat=0, feature_incompat=0,
            feature_ro_compat=0, uuid=b"\x00" * 16, nr_users=1,
            header_sequence=0)
        names, _stats = jbd2.recover_names(blob, sb, max_blocks=64)
        assert names == []
