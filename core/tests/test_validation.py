"""Tests for shared metadata validation module."""

import pytest
from s0_core.validation import validate_metadata_str, FORBIDDEN_METADATA_CHARS


def test_validate_metadata_str_valid():
    assert validate_metadata_str("operator", "valid_operator-123") == "valid_operator-123"
    assert validate_metadata_str("organization", "  My Org  ") == "My Org"
    assert validate_metadata_str("operator", None) is None


def test_validate_metadata_str_empty_fails():
    with pytest.raises(ValueError, match="cannot be empty"):
        validate_metadata_str("operator", "")
    with pytest.raises(ValueError, match="cannot be empty"):
        validate_metadata_str("operator", "   ")


def test_validate_metadata_str_forbidden_chars():
    for char in "<>&\"\x27\\|":
        with pytest.raises(ValueError, match="contains forbidden characters"):
            validate_metadata_str("operator", f"bad{char}name")


def test_validate_organization_allows_default_org():
    assert validate_metadata_str("organization", "Digital Forensics & Data Sanitization Lab") == "Digital Forensics & Data Sanitization Lab"
    for char in "<>&\"\x27\\|":
        with pytest.raises(ValueError, match="contains forbidden characters"):
            validate_metadata_str("organization", f"bad{char}org")


def test_validate_metadata_str_max_length():
    with pytest.raises(ValueError, match="exceeds maximum length"):
        validate_metadata_str("operator", "a" * 65, max_len=64)
    assert validate_metadata_str("operator", "a" * 64, max_len=64) == "a" * 64

