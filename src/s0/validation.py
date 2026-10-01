"""Shared validation utilities for s0 metadata strings across CLI and Web API."""

from __future__ import annotations

from s0.config import CONFIG

FORBIDDEN_METADATA_CHARS = set('<>&"\'\\|')


def validate_metadata_str(field_name: str, v: str | None, max_len: int = 128) -> str | None:
    """Validate and sanitize metadata string fields (operator_id, organization, etc.).

    Rejects characters < > & " ' \\ | and enforces length limits.
    Note: The configured default organization (e.g. 'Digital Forensics & Data Sanitization Lab')
    is explicitly permitted as a trusted system default.
    Used by both CLI entry points and Web API request models.
    """
    if v is None:
        return None
    v = v.strip()
    if not v:
        raise ValueError(f"{field_name} cannot be empty")

    default_org = CONFIG.get("default_organization", "Digital Forensics & Data Sanitization Lab")
    if field_name == "organization" and (v == default_org or v == "Digital Forensics & Data Sanitization Lab"):
        if len(v) > max_len:
            raise ValueError(f"{field_name} exceeds maximum length of {max_len} characters")
        return v

    if any(c in v for c in FORBIDDEN_METADATA_CHARS):
        raise ValueError(f"{field_name} contains forbidden characters (<, >, &, \", ', \\, |)")
    if len(v) > max_len:
        raise ValueError(f"{field_name} exceeds maximum length of {max_len} characters")
    return v
