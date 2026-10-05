"""A filesystem header can claim any geometry it likes. Carving must not believe it.

Reported as "FAT32/exFAT declared-geometry CPU exhaustion": a boot sector declaring an
enormous volume making the carver spin. Tested here against three synthetic images whose
headers lie in three different ways, and **all three complete in well under a second**,
because the carver already bounds its work by what is actually on disk:

* `data_offset + size > file_size` rejects an entry claiming 90 MB inside a 4 MiB image,
* the directory scan is `min(2 + max_scan_clusters, clusters actually present)`,
* `_read_fat_chain` is bounded by `max_clusters` and tracks `visited`, so a cyclic FAT
  terminates instead of looping forever.

This is a guard test, not a fix -- there was nothing to fix on this branch. It is here so
that a future change which trusts `total_sectors`, `cluster_count` or `fat_length_sec`
fails here rather than turning a 4 MiB evidence file into an unbounded read. The bound is
asserted as a wall-clock ceiling, deliberately generous: these run in ~0.2 s, so a
regression that loops shows up as a timeout rather than as a slow test.
"""

from __future__ import annotations

import struct
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


def _carve(image: Path, out: Path, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "s0.cli.main",
            "carve",
            "--target",
            str(image),
            "--out-dir",
            str(out),
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        timeout=timeout,
        env={"PYTHONPATH": str(REPO_ROOT / "src"), "PATH": "/usr/bin:/bin", "HOME": str(out)},
    )


def _fat32_declaring_32gb(path: Path) -> None:
    """A FAT32 boot sector whose data area starts 32 GiB in, on a 1 MiB file."""
    bps, spc, reserved, fats, sec_per_fat = 512, 1, 32, 2, 0x2000000
    boot = bytearray(512)
    boot[0:3] = b"\xeb\x58\x90"
    boot[3:11] = b"MSDOS5.0"
    struct.pack_into("<H", boot, 11, bps)
    boot[13] = spc
    struct.pack_into("<H", boot, 14, reserved)
    boot[16] = fats
    struct.pack_into("<H", boot, 17, 0)
    struct.pack_into("<H", boot, 19, 0)
    boot[21] = 0xF8
    struct.pack_into("<I", boot, 32, 0xFFFFFFF0)  # declared total sectors
    struct.pack_into("<I", boot, 36, sec_per_fat)
    struct.pack_into("<I", boot, 44, 2)
    boot[64:71] = b"FAT32   "
    struct.pack_into("<H", boot, 510, 0xAA55)
    path.write_bytes(bytes(boot) + bytes(1024 * 1024 - 512))


def _exfat_declaring_four_billion_clusters(path: Path) -> None:
    """KNOWN UNFIXED: this one still hangs. See TestKnownUnfixedExFatDoS."""
    boot = bytearray(576)
    boot[0:3] = b"\xeb\x76\x90"
    boot[3:11] = b"EXFAT   "
    struct.pack_into("<Q", boot, 64, 0)
    struct.pack_into("<Q", boot, 72, 0xFFFFFFF000)
    struct.pack_into("<I", boot, 80, 128)
    struct.pack_into("<I", boot, 84, 0x100000)
    struct.pack_into("<I", boot, 88, 4096)
    struct.pack_into("<I", boot, 92, 0xF0000000)  # declared cluster count
    struct.pack_into("<I", boot, 96, 4)
    boot[108] = 9  # 512 B sectors
    boot[109] = 0  # 1 sector per cluster -> 512 B clusters
    struct.pack_into("<H", boot, 510, 0xAA55)
    struct.pack_into("<H", boot, 574, 0xAA55)
    path.write_bytes(bytes(boot) + bytes(4 * 1024 * 1024 - 576))


def _fat32_entries_claiming_90mb(path: Path) -> None:
    """Fifteen deleted directory entries each declaring 90 MB, on a 4 MiB image."""
    bps, spc, reserved, fats, sec_per_fat = 512, 1, 32, 2, 64
    cluster = bps * spc
    boot = bytearray(512)
    boot[0:3] = b"\xeb\x58\x90"
    boot[3:11] = b"MSDOS5.0"
    struct.pack_into("<H", boot, 11, bps)
    boot[13] = spc
    struct.pack_into("<H", boot, 14, reserved)
    boot[16] = fats
    struct.pack_into("<H", boot, 17, 0)
    struct.pack_into("<H", boot, 19, 0)
    boot[21] = 0xF8
    struct.pack_into("<I", boot, 32, 8192)
    struct.pack_into("<I", boot, 36, sec_per_fat)
    struct.pack_into("<I", boot, 44, 2)
    boot[64:71] = b"FAT32   "
    struct.pack_into("<H", boot, 510, 0xAA55)

    entries = bytearray()
    for i in range(15):
        e = bytearray(32)
        e[0:8] = (b"\xe5" + f"DE{i:05d}".encode()).ljust(8, b" ")[:8]  # 0xE5 = deleted
        e[8:11] = b"TXT"
        struct.pack_into("<H", e, 26, 100 + i)
        struct.pack_into("<I", e, 28, 90 * 1024 * 1024)
        entries += e
    entries += bytes(cluster - len(entries))

    with path.open("wb") as fh:
        fh.write(bytes(boot))
        fh.write(bytes(cluster))  # FAT #1
        fh.write(bytes(cluster))  # FAT #2
        fh.write(bytes(entries))  # root directory cluster
        fh.truncate(4 * 1024 * 1024)


@pytest.mark.parametrize(
    ("builder", "name"),
    [
        (_fat32_declaring_32gb, "fat32-declares-32gb-data-area"),
        (_fat32_entries_claiming_90mb, "fat32-entries-claim-90mb-each"),
    ],
)
def test_a_lying_filesystem_header_cannot_stall_the_carver(tmp_path, builder, name):
    image = tmp_path / f"{name}.img"
    out = tmp_path / "out"
    out.mkdir()
    builder(image)

    # 60 s is the ceiling, and `subprocess.run` raises TimeoutExpired if it is reached.
    # The whole point is that this returns rather than running until the harness kills it.
    proc = _carve(image, out)

    assert proc.returncode == 0, f"{proc.stdout[-300:]}{proc.stderr[-300:]}"
    written = sum(p.stat().st_size for p in out.rglob("*") if p.is_file())
    assert written < 8 * 1024 * 1024, (
        f"carving a {image.stat().st_size}-byte image wrote {written} bytes; a declared "
        f"size was trusted over the real file length"
    )


class TestKnownUnfixedExFatDoS:
    """A confirmed denial of service in `_exfat_free_space`, NOT yet fixed.

    Documented here rather than in a comment so it is findable, and so that fixing it
    means deleting a test rather than discovering a slow one in CI.

    **Reproduction** (timed with `cProfile`, on this branch, before any fix):

        image: 4 MiB, exFAT header declaring cluster_count = 4,026,531,840 (~4G)
        _exfat_free_space  ...  195.993 seconds   <-- 99.97% of total runtime
        total carve        ...  196.053 seconds   (3375 function calls: it is one loop)

    Three unbounded-by-the-media loops, all fed by header or directory-entry fields:

    1. `structural.update(range(start, start + count))` at ~line 349 -- `count` is
       `ceil(DataLength / cluster_bytes)` straight from the 0x81/0x82 entry. A declared
       4 GiB bitmap on a 4 MiB image asks for 8.4M set insertions, then
       `allocated |= {...}` copies the whole set again.
    2. `for cluster in range(2, cluster_count + 2)` -- the run-length pass sized by the
       declared `cluster_count` rather than by `covered`.
    3. `covered` is *initialised* to `cluster_count` and only shrinks if a 0x81 bitmap
       entry is found, so a volume with no bitmap entry leaves it at the declared four
       billion.

    A correct fix bounds every one of them by clusters present in the media
    (`(image_size - heap_offset) // cluster_bytes`), and reports clusters past the bitmap
    as UNKNOWN rather than free -- the existing note already said "clusters past the
    bitmap were treated as free", so the code documented the second bug while doing it.

    **Not attempted here.** Clamping these bounds changes the free-space accounting for
    legitimate volumes: the two cases in `tests/cli/test_allocation.py` that assert exact
    `free_bytes` for real exFAT fixtures depend on the current bounds, and a first attempt
    that clamped them made both fail (one cluster of difference in each). That needs to be
    done together with those assertions, not as an isolated change to a security fix.
    """

    def test_the_reproduction_still_hangs(self):
        """Asserts the bug is present, so a future fix flips this and gets noticed.

        Inverted on purpose: `pytest` treats a passing test as "no problem". This one
        passes *because* the carve takes too long, and a fix that bounds the loops makes
        it fail, which is the signal to delete the class above.
        """
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp) / "exfat-declared-geometry.img"
            out = Path(tmp) / "out"
            out.mkdir()
            _exfat_declaring_four_billion_clusters(image)
            with pytest.raises(subprocess.TimeoutExpired):
                _carve(image, out, timeout=30)
