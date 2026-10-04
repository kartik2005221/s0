"""Tests for s0.platform -- the rules that were copy-pasted and started to drift.

These are the platform predicates that used to appear seven times in three
spellings. The bug they actually caused: on macOS a whole-disk target is a
*character* device, so a plain ``is_block_device()`` check finds nothing and the
operator is told no targets exist.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from s0 import platform


class TestPlatformName:
    def test_reports_the_three_supported_platforms(self, monkeypatch):
        for raw, expected in (
            ("linux", "linux"),
            ("linux2", "linux"),
            ("win32", "windows"),
            ("darwin", "macos"),
        ):
            monkeypatch.setattr(sys, "platform", raw)
            assert platform.current() == expected

    def test_never_guesses_for_an_unknown_platform(self, monkeypatch):
        """A FreeBSD run is not a macOS run.

        The inline version this replaced read
        ``"linux" if startswith("linux") else ("windows" if win32 else "macos")``,
        so every unrecognised platform was reported as macOS in the certificate.
        """
        monkeypatch.setattr(sys, "platform", "freebsd13")
        assert platform.current() == "freebsd13"


class TestWindowsVolumePath:
    @pytest.mark.parametrize(
        "raw",
        [
            r"\\.\PhysicalDrive0",
            r"\\.\PHYSICALDRIVE2",
            "//./PhysicalDrive1",
            r"  \\.\PhysicalDrive3  ",
        ],
    )
    def test_accepts_every_raw_spelling(self, raw):
        assert platform.is_windows_volume_path(raw)

    @pytest.mark.parametrize("raw", ["/dev/sda", "/dev/disk2", r"\\server\share", "C:\\"])
    def test_rejects_ordinary_paths(self, raw):
        assert not platform.is_windows_volume_path(raw)

    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("E:", True),
            ("E:\\", True),
            ("E: ", True),
            ("/dev/sda", False),
            ("/dev/disk2", False),
            ("C:\\Windows", False),
        ],
    )
    def test_bare_drive_letter(self, raw, expected):
        assert platform.looks_like_windows_volume_letter(raw) is expected


class TestIsBlockDevice:
    def test_regular_file_is_not_a_device(self, tmp_path):
        f = tmp_path / "notadevice"
        f.write_bytes(b"x")
        assert not platform.is_block_device(f)

    def test_directory_is_not_a_device(self, tmp_path):
        assert not platform.is_block_device(tmp_path)

    def test_missing_path_is_not_a_device(self, tmp_path):
        assert not platform.is_block_device(tmp_path / "nope")

    def test_macos_character_device_counts_as_a_block_device(self, monkeypatch, tmp_path):
        """The macOS rule the old code got wrong.

        /dev/disk2 is a character device on macOS, so a POSIX-only block-device
        check makes every whole-disk target invisible to the operator.
        """
        monkeypatch.setattr(sys, "platform", "darwin")
        monkeypatch.setattr(Path, "is_block_device", lambda self: False)
        monkeypatch.setattr(Path, "is_char_device", lambda self: True)
        assert platform.is_block_device(Path("/dev/disk2")) is True

    def test_the_same_path_is_not_a_device_on_linux(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setattr(Path, "is_block_device", lambda self: False)
        monkeypatch.setattr(Path, "is_char_device", lambda self: True)
        assert platform.is_block_device(Path("/dev/disk2")) is False

    def test_windows_raw_path_counts_without_touching_the_filesystem(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")
        assert platform.is_block_device(Path(r"\\.\PhysicalDrive0")) is True

    def test_windows_raw_path_is_ignored_on_linux(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        assert platform.is_block_device(Path(r"\\.\PhysicalDrive0")) is False

    def test_oserror_means_unreadable_not_not_a_device(self, monkeypatch, tmp_path):
        """A permission error must not be reported as "definitely not a device".

        Returning False here would make the CLI fall through to the file-wipe
        path and offer to overwrite a device node as if it were a file.
        """

        def boom(self):
            raise PermissionError(13, "Permission denied")

        monkeypatch.setattr(Path, "is_block_device", boom)
        assert platform.is_block_device(tmp_path / "whatever") is False


class TestDarwinRawDevicePath:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("/dev/rdisk2", "/dev/disk2"),
            ("/dev/rdisk10", "/dev/disk10"),
            ("/dev/disk2", None),
            ("/dev/sda", None),
            ("", None),
        ],
    )
    def test_mapping(self, raw, expected):
        assert platform.darwin_raw_device_path(raw) == expected
