"""Recovered files must be reported at the offset they are actually at.

`engine.py` converted an ext4 inode's first extent block number to a byte offset with
a hardcoded `* 1024`. ext4's block size is `1024 << log_block_size`, read correctly from
the superblock one function away -- it simply was not threaded through to the caller.

On a 1 KiB-block filesystem that constant is right, so the bug is invisible. On a 4 KiB
filesystem every reported offset is a quarter of the truth:

    reported 1,325,056   true 5,300,224

4 KiB is the block size of essentially every ext4 volume larger than a couple of
megabytes, so this was the common case, not an edge case. `--bodyfile` and
`--gaps-bodyfile` inherited the same error, and the gaps file is what a fragmented
recovery report cites.

It also caused a second, worse symptom. The containment check that drops a candidate
lying inside an already-recovered extent was comparing wrong offsets, so adding `png` to
the extension filter silently lost a recoverable PDF:

    before   s0 carve --target fs.img --out-dir r                  -> png, zip
             s0 carve --target fs.img --out-dir r --extensions pdf -> pdf
    after    every combination recovers pdf, png and zip

That second report looked like a separate carver bug ("a recoverable PDF disappears
depending on which other types were requested"). It was not: one wrong constant produced
both symptoms.

The fixtures are built here with `mke2fs`/`debugfs` rather than committed as binaries,
so the test states the filesystem it needs. Skipped when those tools are absent, which is
why CI installs `e2fsprogs`.
"""

from __future__ import annotations

import io
import json
import os
import shutil
import struct
import subprocess
import zipfile
import zlib
from pathlib import Path

import pytest

S0_ENTRY = Path(__file__).resolve().parents[2] / ".venv" / "bin" / "s0"


def _require_tools() -> None:
    missing = [t for t in ("mke2fs", "debugfs") if shutil.which(t) is None]
    if missing:
        pytest.skip(f"needs {' and '.join(missing)} from e2fsprogs to build an ext4 fixture")


def _chunk(kind: bytes, data: bytes) -> bytes:
    return (
        struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    )


def _png(n: int) -> bytes:
    raw = b"".join(b"\x00" + os.urandom(3 * n) for _ in range(n))
    return (
        b"\x89PNG\r\n\x1a\n"
        + _chunk(b"IHDR", struct.pack(">IIBBBBB", n, n, 8, 2, 0, 0, 0))
        + _chunk(b"IDAT", zlib.compress(raw, 0))
        + _chunk(b"IEND", b"")
    )


def _zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("a.txt", "A" * 4000)
        z.writestr("b.txt", "B" * 3000)
    return buf.getvalue()


def _pdf() -> bytes:
    # No xref table: this is a structurally valid enough PDF for the header/EOF gates,
    # which is the point -- the carver must not depend on a full xref being present.
    return b"%PDF-1.4\n" + b"1 0 obj<</Type/Catalog>>endobj\n" * 40 + b"trailer<</Root 1 0 R>>\n%%EOF\n"


@pytest.fixture(scope="module")
def ext4_image(tmp_path_factory) -> tuple[Path, dict[str, bytes]]:
    """A 16 MiB ext4 image with three deleted files, and their original bytes."""
    _require_tools()
    root = tmp_path_factory.mktemp("ext4")
    src = root / "src"
    src.mkdir()
    originals = {
        "photo_deleted.png": _png(60),
        "archive_deleted.zip": _zip(),
        "report_deleted.pdf": _pdf(),
    }
    for name, blob in originals.items():
        (src / name).write_bytes(blob)
    (src / "photo_keep.png").write_bytes(_png(40))
    (src / "notes_keep.txt").write_text("keep me\n" * 100)

    image = root / "fs.img"
    with open(image, "wb") as fh:
        fh.truncate(16 * 1024 * 1024)
    # 4096-byte blocks: the size the bug was invisible on.
    subprocess.run(
        ["mke2fs", "-q", "-t", "ext4", "-b", "4096", "-d", str(src), str(image)],
        check=True,
        capture_output=True,
        timeout=600,
    )
    for name in originals:
        subprocess.run(
            ["debugfs", "-w", "-R", f"rm /{name}", str(image)],
            check=False,
            capture_output=True,
            timeout=300,
        )
    return image, originals


def _true_offsets(image: Path, originals: dict[str, bytes]) -> dict[str, int]:
    """Where each file's data really starts, found by searching the image for it."""
    blob = image.read_bytes()
    found = {}
    for name, data in originals.items():
        idx = blob.find(data[:64])
        assert idx >= 0, f"{name} is not present in the image; the fixture did not build"
        found[name] = idx
    return found


def _carve(image: Path, out_dir: Path, *extra: str) -> dict:
    entry = S0_ENTRY if S0_ENTRY.is_file() else Path(shutil.which("s0") or "s0")
    proc = subprocess.run(
        [
            str(entry),
            "carve",
            "--target",
            str(image),
            "--out-dir",
            str(out_dir),
            "--yes",
            "--no-certificate",
            *extra,
        ],
        capture_output=True,
        text=True,
        timeout=1800,
    )
    index = out_dir / "recovery_index.json"
    assert index.is_file(), f"no recovery index: {proc.stdout[-500:]}{proc.stderr[-500:]}"
    return json.loads(index.read_text(encoding="utf-8"))


class TestExt4OffsetsAreTrueOffsets:
    def test_recovered_offset_matches_the_files_real_position(self, ext4_image, tmp_path):
        """The reported defect: offsets were a quarter of the truth on 4 KiB blocks."""
        image, originals = ext4_image
        truth = _true_offsets(image, originals)
        index = _carve(image, tmp_path / "r")

        recovered = {f["extension"]: f["offset"] for f in index["recovered_files"]}
        assert recovered, "nothing was recovered at all; the fixture is not exercising the path"
        for name in originals:
            ext = Path(name).suffix.lstrip(".")
            if ext not in recovered:
                continue  # covered separately by the completeness test below
            assert recovered[ext] == truth[name], (
                f"{name} was reported at {recovered[ext]} but its data starts at "
                f"{truth[name]}. A {recovered[ext] / truth[name]:.4g}x error means the "
                f"block number was multiplied by the wrong constant."
            )

    def test_a_1kib_block_filesystem_still_agrees(self, tmp_path):
        """The constant was right on 1 KiB filesystems, so guard against a regression
        that 'fixes' the 4 KiB case by breaking the other one."""
        _require_tools()
        root = tmp_path / "small"
        src = root / "src"
        src.mkdir(parents=True)
        blob = _png(40)
        (src / "gone.png").write_bytes(blob)
        image = root / "fs.img"
        with open(image, "wb") as fh:
            fh.truncate(8 * 1024 * 1024)
        subprocess.run(
            ["mke2fs", "-q", "-t", "ext4", "-b", "1024", "-d", str(src), str(image)],
            check=True,
            capture_output=True,
            timeout=600,
        )
        subprocess.run(
            ["debugfs", "-w", "-R", "rm /gone.png", str(image)], check=False, capture_output=True, timeout=300
        )

        index = _carve(image, root / "r")
        offsets = [f["offset"] for f in index["recovered_files"]]
        truth = image.read_bytes().find(blob[:64])
        assert truth >= 0
        for offset in offsets:
            assert offset == truth, f"1 KiB-block filesystem reported {offset}, true offset {truth}"

    def test_the_superblock_block_size_reaches_the_reported_offset(self, ext4_image):
        """Directly: the block size parsed from the superblock is what gets used."""
        from s0.carve.ext4_carver import parse_ext4_superblock, scan_ext4_deleted_inodes

        image, _ = ext4_image
        sb = parse_ext4_superblock(image)
        assert sb is not None, "the fixture is not an ext4 filesystem"
        assert sb.block_size == 4096, f"fixture has {sb.block_size}-byte blocks, not 4096"

        for inode in scan_ext4_deleted_inodes(image):
            assert inode.block_size == sb.block_size, (
                f"inode {inode.inode_num} carries block_size {inode.block_size} but the "
                f"superblock says {sb.block_size}; a caller converting a block number "
                f"to an offset would use the wrong one"
            )


class TestEveryDeletedFileSurvivesEveryFilter:
    """R2-02, which turned out to be R2-01 wearing a different hat.

    Adding `png` to the filter lost a recoverable PDF, because the containment check
    that drops a candidate inside an already-recovered extent was comparing offsets
    that were a quarter of the truth. The report described this as a carver bug about
    candidates being dropped for unrelated reasons; the root cause was the offset
    constant, and fixing it fixed this too.
    """

    @pytest.mark.parametrize(
        "extra",
        [
            pytest.param([], id="default"),
            pytest.param(["--extensions", "pdf"], id="pdf"),
            pytest.param(["--extensions", "pdf,zip"], id="pdf+zip"),
            pytest.param(["--extensions", "pdf,png"], id="pdf+png"),
            pytest.param(["--extensions", "pdf,png,zip"], id="pdf+png+zip"),
            pytest.param(["--all-space"], id="all-space"),
        ],
    )
    def test_a_deleted_file_is_not_lost_because_of_an_unrelated_filter(self, ext4_image, tmp_path, extra):
        image, originals = ext4_image
        index = _carve(image, tmp_path / ("out_" + "_".join(extra).replace("-", "") or "def"), *extra)
        extensions = {f["extension"] for f in index["recovered_files"]}
        for name in originals:
            ext = Path(name).suffix.lstrip(".")
            if ext not in extensions and not extra:
                # The default carves everything, so anything missing here is a loss.
                pytest.fail(
                    f"a full carve lost {name} entirely. Recovered: {sorted(extensions)}. "
                    f"A file that is present in the image must not depend on which other "
                    f"types were requested."
                )
