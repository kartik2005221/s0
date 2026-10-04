"""s0 Canonical JSON v1 — reference implementation.

Contract: docs/architecture/canonical-json.md. Summary of the rules implemented here:

  * UTF-8 output, no BOM
  * object keys sorted recursively by Unicode code point
  * no insignificant whitespace; separators "," and ":"
  * strings minimally escaped (", \\, control chars); non-ASCII kept literal
  * integers only — a float raises rather than being formatted (schema v1 has
    no float fields; this removes cross-language number-format divergence)
  * arrays keep their order; booleans/null are lowercase literals
"""

from __future__ import annotations

import json
from typing import Any

__all__ = ["CanonicalizationError", "canonicalize", "canonicalize_str"]


class CanonicalizationError(ValueError):
    """Raised when a value cannot be represented in s0 Canonical JSON v1."""


#: Largest integer a JavaScript `Number` represents exactly. Beyond this,
#: JSON.parse rounds and the canonical byte sequence changes.
MAX_EXACT_INTEGER = 2**53 - 1


def _canon(value: Any, out: list[str], _depth: int = 0) -> None:
    if _depth > 64:
        raise CanonicalizationError("data structure exceeds maximum nesting depth (64 levels)")
    # bool must be tested before int: bool is an int subclass in Python.
    if isinstance(value, bool):
        out.append("true" if value else "false")
    elif value is None:
        out.append("null")
    elif isinstance(value, int):
        # Interoperability limit, not a formatting preference.
        #
        # A JavaScript `Number` is an IEEE-754 double: integers above 2**53-1 are
        # silently rounded, and re-serialising produces different bytes. So a
        # certificate carrying 12345678901234567890 is hashed correctly by Python
        # and "TAMPERED_OR_CORRUPT" by the browser portal, on the same signed
        # bytes -- the two implementations of one spec disagreeing.
        #
        # Refusing the value outright makes both verifiers agree, which is the only
        # interoperable answer. It costs nothing real: at 512-byte sectors 2**53
        # bytes is 8 PiB, far beyond any medium that exists.
        if abs(value) > MAX_EXACT_INTEGER:
            raise CanonicalizationError(
                f"integer {value} exceeds the interoperable exact-integer range "
                f"(+/-{MAX_EXACT_INTEGER}, 2**53-1); a JavaScript verifier cannot "
                f"represent it and would disagree about this payload's hash"
            )
        # str(int) is minimal base-10: no leading zeros, optional '-', no exponent.
        out.append(str(value))
    elif isinstance(value, float):
        raise CanonicalizationError(
            "float values are not representable in s0 Canonical JSON v1 "
            "(the certificate schema is integers-only). Refusing to guess a "
            "float format, because implementations diverge on it."
        )
    elif isinstance(value, str):
        # json.dumps(ensure_ascii=False) escapes exactly ", \ and control
        # characters (with \b\f\n\r\t shortcuts, lowercase \u00xx otherwise),
        # which is precisely the rule in CANONICAL_JSON.md.
        out.append(json.dumps(value, ensure_ascii=False))
    elif isinstance(value, list):
        out.append("[")
        for i, item in enumerate(value):
            if i:
                out.append(",")
            _canon(item, out, _depth=_depth + 1)
        out.append("]")
    elif isinstance(value, dict):
        # sorted() on str keys sorts by Unicode code point.
        keys = list(value.keys())
        if any(not isinstance(k, str) for k in keys):
            raise CanonicalizationError("object keys must be strings")
        out.append("{")
        for i, key in enumerate(sorted(keys)):
            if i:
                out.append(",")
            out.append(json.dumps(key, ensure_ascii=False))
            out.append(":")
            _canon(value[key], out, _depth=_depth + 1)
        out.append("}")
    else:
        raise CanonicalizationError(f"type not representable in canonical JSON: {type(value).__name__}")


def canonicalize_str(value: Any) -> str:
    """Serialize *value* to s0 Canonical JSON v1 as a str."""
    out: list[str] = []
    try:
        _canon(value, out)
    except RecursionError:
        raise CanonicalizationError("data structure exceeds maximum recursion depth") from None
    return "".join(out)


def canonicalize(value: Any) -> bytes:
    """Serialize *value* to s0 Canonical JSON v1 as UTF-8 bytes.

    This is the byte string that gets signed and verified.
    """
    return canonicalize_str(value).encode("utf-8")
