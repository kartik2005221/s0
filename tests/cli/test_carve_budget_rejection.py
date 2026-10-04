"""Hitting a carving budget cap must not cost you the evidence.

Two crashes lived here, both of which fire on a *successful* carve rather than a
malformed one, which is why they survived a large green test suite.

**The recovery-cap crash.** Filesystem-native recovery returns
``(recovered, timeline)``. On the budget-rejection path it returned the bare
``recovered`` list instead. The only caller unpacks two values, so the moment a
volume held more deleted files than the per-extension cap -- 32 by default, which
any real disk exceeds -- carver raised ``ValueError: not enough values to
unpack`` *after* writing the files it had already recovered. The crash discarded
the manifest, the hashes and the audit-ledger entry, so the outcome was the worst
of both: files on disk with no chain of custody. If the list happened to hold
exactly two items the unpack silently succeeded with the wrong objects, which is
worse still.

**The truncated-JPEG hang.** ``_skip_entropy`` re-read the final byte of a window
whenever a JPEG scan reached the end of the readable range without finding a
marker, because it advanced by ``n - 1`` and a one-byte window makes that zero.
Truncated JPEGs are routine in forensic recovery, so the common case was an
uninterruptible hang.

Both tests here are deliberately written to fail loudly rather than to be
satisfied by a plausible-looking value.
"""

from __future__ import annotations

import shutil
import signal
import subprocess

import pytest

from s0.carve.boundary import _skip_entropy
from s0.carve.engine import _recover_from_filesystem
from s0.carve.policy import CarveBudget, CarvePolicy


def _fresh_counters() -> dict:
    """The counter dict the real caller pre-seeds at engine.py:1183."""
    return {
        "candidates": 0,
        "accepted": 0,
        "rejected": 0,
        "rejected_bytes": 0,
        "duplicate": 0,
        "filtered": 0,
        "bytes_recovered": 0,
        "structure_candidates": 0,
        "structure_accepted": 0,
        "structure_filtered": 0,
        "budget_stops": 0,
        "rejected_samples": [],
    }


MKE2FS = shutil.which("mke2fs")
DEBUGFS = shutil.which("debugfs")
requires_ext4_tools = pytest.mark.skipif(
    not (MKE2FS and DEBUGFS), reason="mke2fs and debugfs are needed to build a real ext4 image without root"
)

BLOCK_SIZE = 1024


# --------------------------------------------------------------------------- #
# The recovery-cap crash
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def ext4_with_many_deletions(tmp_path_factory):
    """An ext4 image with 40 deleted text files -- more than the per-extension cap.

    40 is chosen to sit above the default 32-file cap for a single extension, so
    an ordinary carve of this volume reaches the rejection path without any
    non-default policy.
    """
    if not (MKE2FS and DEBUGFS):
        pytest.skip("mke2fs and debugfs are needed")
    d = tmp_path_factory.mktemp("cap-ext4")
    img = d / "vol.img"
    with open(img, "wb") as fh:
        fh.truncate(48 * 1024 * 1024)
    r = subprocess.run(
        [MKE2FS, "-q", "-t", "ext4", "-O", "has_journal", "-b", str(BLOCK_SIZE), "-I", "128", str(img)],
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        pytest.skip(f"mke2fs failed: {r.stderr[:200]}")

    payload = d / "seed.txt"
    payload.write_bytes(b"deleted evidence payload\n" * 8)
    r = subprocess.run([DEBUGFS, "-w", "-R", "mkdir /case", str(img)], capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip(f"debugfs mkdir failed: {r.stderr[:200]}")
    # One -R per command: newline-separated commands in a single -R are not
    # executed, which silently produces an image with nothing deleted.
    for i in range(40):
        r = subprocess.run(
            [DEBUGFS, "-w", "-R", f"write {payload} /case/deleted-{i:03d}.txt", str(img)],
            capture_output=True,
            text=True,
        )
        if r.returncode != 0:
            pytest.skip(f"debugfs write failed: {r.stderr[:200]}")
    for i in range(40):
        subprocess.run(
            [DEBUGFS, "-w", "-R", f"rm /case/deleted-{i:03d}.txt", str(img)], capture_output=True, text=True
        )
    return img


@requires_ext4_tools
class TestRecoveryCapReturnsBothValues:
    def test_rejection_path_returns_a_two_tuple(self, ext4_with_many_deletions, tmp_path):
        """Every return path must match the annotated two-value signature.

        The budget here rejects the very first candidate, so this hits the
        rejection branch directly and cheaply -- no need to actually fill a cap.

        No extension filter is passed: a deleted inode's name is ``inode<N>``, so
        the extension comes from content sniffing, and plain text sniffs to
        ``bin``. Filtering on ``txt`` would drop all 40 candidates at the
        extension check and never reach the budget at all.
        """
        policy = CarvePolicy.for_target(48 * 1024 * 1024)
        policy.max_files_per_extension = 0  # deny immediately
        budget = CarveBudget(policy=policy)
        warnings: list[str] = []
        counters = _fresh_counters()

        result = _recover_from_filesystem(
            ext4_with_many_deletions,
            tmp_path,
            [("ext4", 0)],
            [],
            budget,
            warnings,
            counters,
            {},
            {},
        )

        # This single unpacking statement is the assertion that matters: it is
        # exactly what the real caller at engine.py:1209 does, and exactly what
        # raised ValueError before the fix.
        recovered, timeline = result

        assert isinstance(recovered, list)
        assert isinstance(timeline, list)
        # A denial must be reported, not swallowed: the examiner has to be able to
        # tell "nothing was deleted" from "we stopped looking".
        assert any("Stopped writing filesystem recoveries" in w for w in warnings)

    def test_two_element_cap_does_not_unpack_into_the_wrong_objects(self, tmp_path):
        """The silent-corruption variant of the same bug.

        If the rejected list happened to hold exactly two items, the old code's
        bare-list return unpacked *successfully* and the caller bound
        ``recovered`` to a CarvedFile and ``timeline`` to a CarvedFile. Nothing
        raised; the report was quietly wrong. Asserting the second element is a
        list of dicts pins that down.
        """
        policy = CarvePolicy.for_target(1024 * 1024)
        policy.max_files_per_extension = 0
        budget = CarveBudget(policy=policy)
        result = _recover_from_filesystem(
            tmp_path / "does-not-exist.img",
            tmp_path,
            [("ext4", 0)],
            ["txt"],
            budget,
            [],
            _fresh_counters(),
            {},
            {},
        )
        _recovered, timeline = result
        assert all(isinstance(entry, dict) for entry in timeline), (
            "the second return value is the journal-name timeline, which is a "
            "list of dicts -- never CarvedFile objects"
        )


# --------------------------------------------------------------------------- #
# The truncated-JPEG hang
# --------------------------------------------------------------------------- #


class _Timeout(Exception):
    pass


def _alarm(_signum, _frame):
    raise _Timeout("call did not terminate")


class _BytesSource:
    """Minimal ByteSource over an in-memory buffer."""

    def __init__(self, data: bytes) -> None:
        self.data = data

    def read(self, offset: int, length: int) -> bytes:
        return self.data[offset : offset + length]

    def size(self) -> int:
        return len(self.data)


@pytest.fixture
def hard_timeout():
    """Fail instead of hanging. A hanging test is worse than no test."""

    def _run(fn, *args):
        previous = signal.signal(signal.SIGALRM, _alarm)
        signal.setitimer(signal.ITIMER_REAL, 5.0)
        try:
            return fn(*args)
        except _Timeout:
            pytest.fail("call did not terminate within 5s: it is looping")
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)

    return _run


# The four inputs from the report. The last two contain no trailing 0xFF at all,
# which is the point: a control case that also hangs proves the failure is
# unconditional termination failure, not marker-detection logic.
HANG_CASES = [
    pytest.param(b"\x01\x02\x03\xff", id="ends-on-ff"),
    pytest.param(b"\xff", id="single-ff-byte"),
    pytest.param(b"\x01\x02\x03\x04", id="no-ff-at-all"),
    pytest.param(b"\x01\x02\xff\x00", id="stuffed-byte-at-end"),
    pytest.param(b"", id="empty"),
    pytest.param(b"\xff\xff", id="two-ff-bytes"),
]


class TestSkipEntropyTerminates:
    @pytest.mark.parametrize("data", HANG_CASES)
    def test_returns_without_looping(self, data, hard_timeout):
        """A scan that runs off the end must return -1, as documented."""
        assert hard_timeout(_skip_entropy, _BytesSource(data), 0, len(data)) == -1

    @pytest.mark.parametrize("data", HANG_CASES)
    def test_terminates_with_a_zero_length_limit(self, data, hard_timeout):
        assert hard_timeout(_skip_entropy, _BytesSource(data), 0, 0) == -1

    def test_still_finds_a_real_marker(self, hard_timeout):
        """The hang fix must not have broken detection."""
        # 0xFF 0xDB is a real marker; scan must stop at its offset.
        assert hard_timeout(_skip_entropy, _BytesSource(b"\x01\x02\xff\xdb\x00"), 0, 5) == 2

    def test_still_skips_stuffed_bytes(self, hard_timeout):
        """0xFF 0x00 is a stuffed byte, not a marker: scanning continues."""
        src = _BytesSource(b"\xff\x00\x11\x22\xff\xd9")
        assert hard_timeout(_skip_entropy, src, 0, 6) == 4
