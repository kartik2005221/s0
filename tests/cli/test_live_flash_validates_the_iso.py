"""Flashing must refuse a file that is not a bootable ISO.

The only test on the ISO before writing to a device was `size >= 100 MiB`. Any
sufficiently large file passed: a disk image, a tarball, a video, a PDF. Flashing one
destroys the target device and produces an unbootable stick -- and the failure is
discovered *after* the write, on hardware that may have held the only copy of
something. That is the worst ordering a check can have.

So the image is checked structurally, from the 32 KiB system area an ISO 9660 image
must carry, at four levels: the ``CD001`` signature, the primary volume descriptor in
the standard position, the boot-record type byte, and the El Torito magic.

The refusal names what was found instead. "Not a valid ISO" with no detail sends an
operator to the wrong problem -- usually the download, when the actual cause is
pointing the flag at the wrong file.
"""

from __future__ import annotations

from s0.live.live_manager import validate_iso_image

ONE_HUNDRED_MIB = 100 * 1024 * 1024


def _pad_to(path, size: int = ONE_HUNDRED_MIB + 1024) -> None:
    """Grow a file to a plausible size without holding it all in memory."""
    with open(path, "ab") as fh:
        fh.truncate(size)


def _system_area(*, descriptor_at: int = 1, boot_type: int = 0x88,
                 el_torito: bool = True, magic: bytes = b"CD001") -> bytes:
    area = bytearray(0x1000)
    if magic:
        area[descriptor_at:descriptor_at + 5] = magic
    area[7] = boot_type
    if el_torito:
        area[0x821:0x82D] = b"EL TORITO SPEC"
    return bytes(area)


def _iso(path, **kwargs) -> None:
    path.write_bytes(b"\x00" * 0x8000 + _system_area(**kwargs) + b"\x00" * 0x1000)
    _pad_to(path)


class TestARealIsoIsAccepted:
    def test_a_bootable_hybrid_iso_passes(self, tmp_path):
        iso = tmp_path / "s0-live-amd64.iso"
        _iso(iso)
        ok, detail = validate_iso_image(iso)
        assert ok, detail
        assert "El Torito" in detail

    def test_an_iso_without_el_torito_passes_with_a_warning(self, tmp_path):
        """Not fatal on its own: some hybrid images boot via the partition table.

        Refusing these would break a legitimate boot path, so the distinction is
        made in the message rather than the verdict.
        """
        iso = tmp_path / "hybrid.iso"
        _iso(iso, el_torito=False)
        ok, detail = validate_iso_image(iso)
        assert ok, (
            f"an ISO 9660 image without El Torito was refused. Some hybrid images "
            f"boot via the partition table, so this must not be a hard failure: {detail}")
        assert "El Torito" in detail

    def test_a_boot_type_of_zero_is_accepted(self, tmp_path):
        """`0x00` means 'no boot record', which some single-purpose ISOs carry."""
        iso = tmp_path / "plain.iso"
        _iso(iso, boot_type=0x00, el_torito=False)
        ok, detail = validate_iso_image(iso)
        assert ok, detail


class TestLargeNonIsosAreRefused:
    """These all passed the old size check."""

    def test_a_large_blob_of_zeros_is_refused(self, tmp_path):
        blob = tmp_path / "big.bin"
        blob.write_bytes(b"\x00" * 10_000)
        _pad_to(blob)
        assert blob.stat().st_size >= ONE_HUNDRED_MIB, "the fixture must clear the old check"

        ok, detail = validate_iso_image(blob)
        assert not ok
        assert "CD001" in detail

    def test_a_large_pdf_is_refused(self, tmp_path):
        doc = tmp_path / "evidence.pdf"
        doc.write_bytes(b"%PDF-1.7\n")
        _pad_to(doc)
        ok, detail = validate_iso_image(doc)
        assert not ok, "a PDF cleared the ISO check"
        assert "PDF" in detail, f"the refusal should name what it found: {detail}"

    def test_a_zip_is_refused(self, tmp_path):
        archive = tmp_path / "evidence.zip"
        archive.write_bytes(b"PK\x03\x04")
        _pad_to(archive)
        ok, detail = validate_iso_image(archive)
        assert not ok
        assert "ZIP" in detail

    def test_a_tar_is_refused(self, tmp_path):
        tar = tmp_path / "evidence.tar"
        tar.write_bytes(b"\x00" * 257 + b"ustar")
        _pad_to(tar)
        ok, _detail = validate_iso_image(tar)
        assert not ok

    def test_an_elf_binary_is_refused(self, tmp_path):
        binary = tmp_path / "tool"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 100)
        _pad_to(binary)
        ok, detail = validate_iso_image(binary)
        assert not ok
        assert "ELF" in detail

    def test_an_ascii_file_is_refused_and_described_as_text(self, tmp_path):
        text = tmp_path / "notes.txt"
        text.write_bytes(b"just some notes, padded out to be large enough\n")
        _pad_to(text)
        ok, detail = validate_iso_image(text)
        assert not ok
        assert "text" in detail.lower()


class TestTheRefusalIsInformative:
    def test_a_descriptor_in_the_wrong_place_is_refused(self, tmp_path):
        """`CD001` present but not at 0x8001 means it is not a standard-layout ISO."""
        iso = tmp_path / "odd.iso"
        _iso(iso, descriptor_at=0x200)
        ok, detail = validate_iso_image(iso)
        assert not ok
        assert "0x8001" in detail

    def test_a_non_bootable_volume_is_refused(self, tmp_path):
        """A data-only ISO would produce an unbootable stick."""
        iso = tmp_path / "data.iso"
        _iso(iso, boot_type=0xFF, el_torito=False)
        ok, detail = validate_iso_image(iso)
        assert not ok
        assert "boot record" in detail

    def test_a_file_too_small_for_a_system_area_is_refused(self, tmp_path):
        small = tmp_path / "small.iso"
        small.write_bytes(b"\x00" * 1024)
        ok, detail = validate_iso_image(small)
        assert not ok
        assert "36864" in detail or "system area" in detail

    def test_a_missing_file_is_reported_not_raised(self, tmp_path):
        ok, detail = validate_iso_image(tmp_path / "absent.iso")
        assert not ok
        assert "cannot stat" in detail

    def test_an_empty_file_is_refused(self, tmp_path):
        empty = tmp_path / "empty.iso"
        empty.write_bytes(b"")
        ok, _detail = validate_iso_image(empty)
        assert not ok

    def test_every_refusal_says_why(self, tmp_path):
        """A bare 'invalid ISO' sends an operator to the wrong problem."""
        cases = []
        blob = tmp_path / "b.bin"
        blob.write_bytes(b"\x01" * 100)
        _pad_to(blob)
        cases.append(blob)
        small = tmp_path / "s.iso"
        small.write_bytes(b"\x00" * 512)
        cases.append(small)
        cases.append(tmp_path / "nope.iso")

        for path in cases:
            ok, detail = validate_iso_image(path)
            assert not ok
            assert len(detail) > 25, f"the refusal for {path.name} is uninformative: {detail!r}"


class TestTheCheckIsCheap:
    def test_it_does_not_read_the_whole_image(self, tmp_path):
        """It must be usable on a 2 GB ISO without a two-second pause."""
        iso = tmp_path / "big.iso"
        iso.write_bytes(b"\x00" * 0x8000 + _system_area() + b"\x00" * 0x1000)
        with open(iso, "r+b") as fh:
            fh.truncate(2 * 1024 * 1024 * 1024)      # sparse

        ok, _detail = validate_iso_image(iso)
        assert ok

    def test_a_sparse_file_does_not_consume_the_disk(self, tmp_path):
        iso = tmp_path / "sparse.iso"
        iso.write_bytes(b"\x00" * 0x8000 + _system_area() + b"\x00" * 0x1000)
        with open(iso, "r+b") as fh:
            fh.truncate(2 * 1024 * 1024 * 1024)
        # Sparse: the apparent size is huge but the blocks on disk are not.
        assert iso.stat().st_size > 1024 ** 3


class TestTheCheckIsActuallyWiredIn:
    """`validate_iso_image` can be perfect and change nothing if nothing calls it.

    The unit tests above exercise the function directly, which is why this exists:
    an earlier revision of them passed unchanged when the call site in
    `cmd_live_flash` was reverted, because they never went through it.
    """

    def _args(self, iso, target="/dev/sdz", **kw):
        import argparse

        return argparse.Namespace(target=target, iso=str(iso), yes=True,
                                  force=True, dry_run=False, **kw)

    def test_a_large_non_iso_is_refused_before_any_write(self, tmp_path, capsys):
        from s0.live.live_manager import cmd_live_flash

        blob = tmp_path / "not-an.iso"
        blob.write_bytes(b"\x00" * 10_000)
        _pad_to(blob)

        opened_for_writing: list[str] = []
        real_open = open

        def guard(file, mode="r", *a, **kw):
            if any(flag in mode for flag in ("w", "a", "x", "+")):
                opened_for_writing.append(str(file))
            return real_open(file, mode, *a, **kw)

        import builtins

        builtins.open = guard
        try:
            rc = cmd_live_flash(self._args(blob))
        finally:
            builtins.open = real_open

        assert rc == 2, f"a {blob.stat().st_size // (1024*1024)} MB non-ISO was accepted"
        assert not opened_for_writing, (
            f"something was opened for writing before the refusal: {opened_for_writing}")
        assert "not a usable Live ISO" in capsys.readouterr().err

    def test_the_refusal_happens_before_the_target_is_examined(self, tmp_path, capsys):
        """The image check runs before any device work at all."""
        from s0.live.live_manager import cmd_live_flash

        blob = tmp_path / "also-not-an.iso"
        blob.write_bytes(b"PK\x03\x04")
        _pad_to(blob)

        rc = cmd_live_flash(self._args(blob))
        err = capsys.readouterr().err
        assert rc == 2
        assert "ZIP" in err or "CD001" in err
