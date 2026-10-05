"""Shared validation utilities for s0 metadata strings across CLI and Web API."""

from __future__ import annotations

from s0.config import CONFIG

FORBIDDEN_METADATA_CHARS = set("<>&\"'\\|")


#: Codepoints that visually reorder text. U+202A..U+202E and U+2066..U+2069.
_BIDI_OVERRIDES = frozenset(range(0x202A, 0x202F)) | frozenset(range(0x2066, 0x206A))


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
    if field_name == "organization" and (
        v == default_org or v == "Digital Forensics & Data Sanitization Lab"
    ):
        if len(v) > max_len:
            raise ValueError(f"{field_name} exceeds maximum length of {max_len} characters")
        return v

    if any(c in v for c in FORBIDDEN_METADATA_CHARS):
        raise ValueError(f"{field_name} contains forbidden characters (<, >, &, \", ', \\, |)")
    if len(v) > max_len:
        raise ValueError(f"{field_name} exceeds maximum length of {max_len} characters")

    # Encodability, checked here because this is the last point before the value is
    # written into a certificate. The canonicalizer encodes the payload as UTF-8, and an
    # unencodable value -- which is what a shell produces for an invalid byte, or for a
    # lone surrogate -- raised UnicodeEncodeError from inside certificate generation.
    # That happened *after* the target had been erased, so the operator ended up with a
    # destroyed file, no certificate, and (because the handler only warned) exit 0.
    #
    # C0/C1 controls and the bidi overrides are rejected here too. The forbidden list
    # blocks markup, which stops the dashboard injecting HTML, but an ESC byte still
    # reached `s0 audit list` raw and could repaint the operator's terminal from a value
    # that arrived over the web API. A name that can reorder text on screen is not a
    # name.
    for ch in v:
        code = ord(ch)
        if code < 0x20 or code == 0x7F or 0x80 <= code <= 0x9F:
            raise ValueError(
                f"{field_name} contains a control character (U+{code:04X}); "
                f"control characters are not allowed"
            )
        if code in _BIDI_OVERRIDES:
            raise ValueError(
                f"{field_name} contains a bidirectional override (U+{code:04X}); "
                f"these can make text render in an order other than its logical one"
            )
    try:
        v.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError(
            f"{field_name} is not valid UTF-8 and cannot be encoded into a certificate "
            f"({exc.reason} at position {exc.start})"
        ) from exc
    return v
