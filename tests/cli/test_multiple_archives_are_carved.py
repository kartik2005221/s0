"""Several archives in one image must all be recovered.

`_zip_end` located the end-of-central-directory record with `rfind_near` -- the
*last* EOCD before the window limit, because that is the nearest one searching
backwards. With several archives packed into one image, every candidate resolved to
the same record, so every candidate produced the same end offset. The ranges then
overlapped exactly, containment-suppression kept one, and the rest were discarded
as duplicates.

Three ZIPs went in and one came out, with nothing reported as an error: the
suppression counter said "duplicate", which is a true statement about a duplicate
range and a false statement about the evidence. Two archives were simply gone.

The EOCD record carries its own central-directory offset, which is relative to the
start of *its* archive. That makes the record self-identifying: the one belonging
to a candidate at `start` is the one whose `cd_off + cd_size` equals its distance
from `start`. The code already computed that arithmetic as a note; it is now the
selector, which is why the fix is a selection rule rather than a new heuristic.
"""

from __future__ import annotations

import io
import os
import zipfile
from pathlib import Path

import pytest

from s0.carve.boundary import _zip_end


class _BytesSource:
    def __init__(self, data: bytes) -> None:
        self.data = data

    def read(self, offset: int, length: int) -> bytes:
        return self.data[offset : offset + length]

    @property
    def size(self) -> int:
        """A property, matching ByteSource -- the code does min(src.size, ...)."""
        return len(self.data)

    def rfind_near(self, needle: bytes, end: int, limit: int) -> int:
        lo = max(0, end - limit)
        return self.data.rfind(needle, lo, end)

    def read_until(self, needle: bytes, start: int, max_size: int) -> int:
        idx = self.data.find(needle, start, start + max_size)
        return idx


def _zip(member: str, filler: int = 20) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(f"{member}.txt", f"evidence for {member}\n" * filler)
    return buf.getvalue()


def _pad(byte: int, n: int) -> bytes:
    return bytes([byte]) * n


class TestSeveralArchivesGetDistinctEnds:
    def test_each_archive_resolves_to_its_own_end(self):
        archives = [_zip("a"), _zip("b"), _zip("c")]
        blob = (
            _pad(0, 500)
            + archives[0]
            + _pad(0xAA, 3000)
            + archives[1]
            + _pad(0xBB, 3000)
            + archives[2]
            + _pad(0, 500)
        )
        src = _BytesSource(blob)

        starts = []
        cursor = 0
        for archive in archives:
            starts.append(blob.index(archive, cursor))
            cursor = starts[-1] + 1

        ends = [_zip_end(src, s, len(blob)).end for s in starts]

        assert all(e is not None for e in ends), f"at least one archive had no resolvable end: {ends}"

        assert len(set(ends)) == len(ends), (
            f"every archive resolved to the same end offset {set(ends)}, which is "
            f"what made them look like duplicates and lose all but one"
        )

        # Each end must land exactly at the end of its own archive.
        for start, archive, end in zip(starts, archives, ends, strict=True):
            assert end == start + len(archive), (
                "the end offset does not match the archive's real length, so the "
                "recovered file would be truncated or over-long"
            )

    def test_the_resolved_ranges_do_not_overlap(self):
        archives = [_zip("x"), _zip("y")]
        blob = _pad(0, 300) + archives[0] + _pad(0xCC, 2000) + archives[1]
        src = _BytesSource(blob)
        first = blob.index(archives[0])
        second = blob.index(archives[1])

        end_first = _zip_end(src, first, len(blob)).end
        end_second = _zip_end(src, second, len(blob)).end

        assert end_first is not None and end_second is not None
        assert end_first <= second, (
            "the first archive's range extends past the second archive's start, so "
            "suppression would discard the second as contained in the first"
        )
        assert end_second > end_first, (
            "both archives resolved to the same end, so the second is an exact "
            "duplicate of the first and is suppressed"
        )

    def test_a_single_archive_still_resolves(self):
        archive = _zip("solo")
        blob = _pad(0, 100) + archive + _pad(0, 100)
        boundary = _zip_end(_BytesSource(blob), 100, len(blob))
        assert boundary.end == 100 + len(archive)
        assert any("self-consistent" in note for note in boundary.notes), (
            f"the consistent-EOCD path was not taken for a lone archive: {boundary.notes}"
        )

    def test_an_archive_with_a_comment_resolves(self):
        """A ZIP comment shifts the real end, and exercises the comment_len path."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("c.txt", "payload\n" * 10)
            z.comment = b"archive comment" * 100
        archive = buf.getvalue()
        blob = _pad(0, 200) + archive + _pad(0, 200)

        boundary = _zip_end(_BytesSource(blob), 200, len(blob))
        assert boundary.end == 200 + len(archive), (
            "a commented archive's end was miscomputed, which would truncate it"
        )

    def test_an_inconsistent_eocd_is_reported_rather_than_hidden(self):
        """When no candidate is consistent, the boundary must say so.

        Otherwise the caller cannot distinguish a confident length from a guess,
        which is the difference between a measured boundary and an assumed one.
        """
        # Hand-build an EOCD whose cd_off cannot correspond to this start.
        rec = bytearray(22)
        rec[0:4] = b"PK\x05\x06"
        rec[8:10] = (0).to_bytes(2, "little")  # this disk
        rec[10:12] = (0).to_bytes(2, "little")  # cd start disk
        rec[12:16] = (9999).to_bytes(4, "little")  # cd size -- nonsense
        rec[16:20] = (999999).to_bytes(4, "little")  # cd offset -- nonsense
        rec[20:22] = (0).to_bytes(2, "little")  # comment length

        blob = _pad(0, 100) + b"PK\x03\x04" + _pad(0, 50) + bytes(rec) + _pad(0, 100)
        boundary = _zip_end(_BytesSource(blob), 100, len(blob))

        assert boundary.end is not None
        assert any("no EOCD had offsets consistent" in note for note in boundary.notes), (
            "an unresolvable EOCD was presented as a confident measurement; the "
            f"notes must disclose it: {boundary.notes}"
        )

    def test_no_eocd_at_all_is_still_reported_as_undetermined(self):
        blob = _pad(0, 100) + b"PK\x03\x04" + _pad(0x11, 400)
        boundary = _zip_end(_BytesSource(blob), 100, len(blob))
        assert boundary.end is None
        assert any("no end-of-central-directory" in note for note in boundary.notes)


class TestEndToEndCarveRecoversEveryArchive:
    def test_three_archives_in_one_image_all_come_out(self, tmp_path):
        """The user-visible claim: three in, three out."""
        import shutil
        import subprocess
        import sys

        archives = [_zip("one"), _zip("two"), _zip("three")]
        blob = (
            _pad(0, 2000)
            + archives[0]
            + _pad(0xAA, 3000)
            + archives[1]
            + _pad(0xBB, 3000)
            + archives[2]
            + _pad(0, 2000)
        )
        (tmp_path / "multi.img").write_bytes(blob)

        entry = shutil.which("s0") or str(Path(sys.executable).parent / "s0")
        if not Path(entry).is_file():
            pytest.skip("s0 entry point not available")

        proc = subprocess.run(
            [
                entry,
                "carve",
                "--target",
                "multi.img",
                "--out-dir",
                "out",
                "--no-certificate",
                "--no-pdf",
                "--extensions",
                "zip",
                "--min-confidence",
                "0",
            ],
            capture_output=True,
            text=True,
            cwd=str(tmp_path),
            timeout=300,
            env={
                **os.environ,
                "HOME": str(tmp_path),
                "USERPROFILE": str(tmp_path),
                "S0_AUDIT_DB": str(tmp_path / "audit.db"),
                **({} if os.name == "nt" else {"PATH": "/usr/bin:/bin"}),
            },
        )
        assert proc.returncode == 0, proc.stderr

        carved = sorted((tmp_path / "out").glob("*.zip"))
        assert len(carved) == 3, (
            f"3 archives in the image produced {len(carved)} recovered file(s); "
            f"before the fix this was 1, with the rest discarded as duplicates"
        )

        # And each one must actually open and hold its own evidence.
        members = set()
        for path in carved:
            with zipfile.ZipFile(path) as z:
                assert z.testzip() is None, f"{path.name} is a corrupt archive"
                members.update(z.namelist())
        assert members == {"one.txt", "two.txt", "three.txt"}, (
            f"the recovered archives do not hold the expected distinct contents: {members}"
        )
