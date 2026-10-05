"""A filesystem header can claim any geometry it likes. Carving must not believe it.

Reported as "FAT32/exFAT declared-geometry CPU exhaustion": a boot sector declaring an
enormous volume making the carver spin. Checked against three synthetic images whose
headers lie in three different ways, rather than assumed:

| Image | Declares | Was | Now |
|---|---|---|---|
| FAT32, 1 MiB | data area starting 32 GiB in | 0.2 s | 0.2 s |
| FAT32, 4 MiB | 15 deleted entries x 90 MB | 0.5 s | 0.5 s |
| **exFAT, 4 MiB** | **cluster_count = 4,026,531,840** | **196 s** | **0.3 s** |

The two FAT32 shapes were already bounded (`min(2 + max_scan_clusters, clusters actually
present)`, and `data_offset + size > file_size` rejecting an entry claiming 90 MB inside a
4 MiB image). The exFAT one was not -- see the note on `_exfat_free_space` in
`src/s0/carve/allocation.py`. These are guard tests: a future change that trusts
`total_sectors`, `cluster_count` or `fat_length_sec` fails here instead of turning a 4 MiB
evidence file into an unbounded read. The wall-clock ceiling is deliberately generous --
these run in about 0.3 s, so a regression that loops shows up as a timeout rather than as
a slow test that gets tolerated.
"""

from __future__ import annotations

import os
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
        env={
            **os.environ,
            "PYTHONPATH": str(REPO_ROOT / "src"),
            "HOME": str(out),
            "USERPROFILE": str(out),
            **({} if os.name == "nt" else {"PATH": "/usr/bin:/bin"}),
        },
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


def _exfat_declaring_four_billion_clusters_is_now_bounded(tmp_path):
    """The exFAT case, which used to hang. Kept separate so the reason is legible.

    A 4 MiB image whose header declares four billion clusters spent 196 s inside
    `_exfat_free_space`. All three loops there are now bounded by the clusters the media
    actually has, and clusters past the allocation bitmap are reported as UNKNOWN rather
    than free.
    """
    image = tmp_path / "exfat-declares-4-billion-clusters.img"
    out = tmp_path / "out"
    out.mkdir()
    _exfat_declaring_four_billion_clusters(image)
    return image, out


def test_exfat_declared_geometry_is_bounded_too(tmp_path):
    image, out = _exfat_declaring_four_billion_clusters_is_now_bounded(tmp_path)
    proc = _carve(image, out, timeout=60)
    assert proc.returncode == 0, f"{proc.stdout[-300:]}{proc.stderr[-300:]}"
    written = sum(p.stat().st_size for p in out.rglob("*") if p.is_file())
    assert written < 8 * 1024 * 1024, (
        f"carving a {image.stat().st_size}-byte image wrote {written} bytes; a declared "
        f"size was trusted over the real file length"
    )


def test_exfat_free_space_does_not_claim_a_volume_that_does_not_exist(tmp_path):
    """The DoS and the wrong answer had the same cause, so check the answer too.

    Before the fix the run-length pass ran to the *declared* cluster_count, so a 4 MiB
    image produced hundreds of millions of "free" extents over a ~2 TB phantom volume.
    A carver pointed at that map would place recovered files into regions with no
    allocation evidence at all.
    """
    sys.path.insert(0, str(REPO_ROOT / "src"))
    from s0.carve.allocation import build_free_space

    image, _ = _exfat_declaring_four_billion_clusters_is_now_bounded(tmp_path)
    fsm = build_free_space(str(image), "exfat", 0, 4 * 1024 * 1024)

    assert fsm.free_bytes < image.stat().st_size, (
        f"reported {fsm.free_bytes} free bytes from a {image.stat().st_size}-byte image; "
        f"the declared geometry was believed over the media"
    )
    assert not fsm.ranges or all(end <= image.stat().st_size for _, end in fsm.ranges), (
        f"a free extent reaches past the end of the image: {fsm.ranges[:4]}"
    )
    assert any("UNKNOWN" in n or "not present" in n for n in fsm.notes), (
        f"the gap between the declared geometry and the media was not reported: {fsm.notes}"
    )
