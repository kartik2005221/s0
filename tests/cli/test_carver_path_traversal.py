"""Unit tests for carver path traversal protection and filename sanitization."""

import pytest

from s0.carve.engine import _sanitize_filename


@pytest.mark.parametrize(
    "adversarial,expected",
    [
        ("../../etc/shadow", "etc_shadow"),
        ("..\\..\\Windows\\System32\\cmd.exe", "Windows_System32_cmd.exe"),
        ("normal_file.png", "normal_file.png"),
        ("nested/folder/file.pdf", "nested_folder_file.pdf"),
        ("../../../evil.sh", "evil.sh"),
        ("....//....//escape.dat", "escape.dat"),
        ("null\x00byte.bin", "null_byte.bin"),
        ("colon:stream.txt", "colon_stream.txt"),
        ("   padded_dots...   ", "padded_dots"),
        ("", "unnamed"),
    ],
)
def test_sanitize_filename_prevents_directory_escape(adversarial, expected):
    clean = _sanitize_filename(adversarial)
    assert "/" not in clean
    assert "\\" not in clean
    assert "\x00" not in clean
    assert not clean.startswith(".")
    assert clean == expected
