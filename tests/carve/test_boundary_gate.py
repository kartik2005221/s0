"""The statistical gate must run only where no structural validator exists.

The `_STRUCTURALLY_VALIDATED` frozenset went stale at eight entries while the
dispatch chain in `validate_structure` grew to twenty-four formats, so the
block-entropy uniform-random gate ran ahead of most validators and vetoed
compressed candidates those validators would have proven. This module pins the
set to the dispatch chain mechanically so the two cannot drift again.
"""

from __future__ import annotations

import re
from pathlib import Path

from s0.carve import boundary

_EVTX_CHUNK_MAGIC = b"ElfChnk\x00"
_EVTX_CHUNK_SIZE = 0x10000
_EVTX_FIRST_CHUNK = 4096
_ISO_BLOCK_SIZE = 2048

BOUNDARY_SOURCE = Path(boundary.__file__).read_text(encoding="utf-8")


def _validated_extensions_from_dispatch() -> set[str]:
    """Extensions routed to a `_validate_*` call inside `validate_structure`."""
    body = BOUNDARY_SOURCE[BOUNDARY_SOURCE.index("def validate_structure") :]
    body = body[: body.index("\ndef _validate_jpeg")]
    exts: set[str] = set()
    for match in re.finditer(
        r'if ext == "([a-z0-9]+)"((?: or ext == "[a-z0-9]+")*):\s*\n\s*return _validate_', body
    ):
        for ext in re.findall(r'ext == "([a-z0-9]+)"', match.group(0)):
            exts.add(ext)
    for match in re.finditer(r"if ext in \(([^)]+)\):\s*\n\s*return _validate_", body):
        exts.update(re.findall(r'"([a-z0-9]+)"', match.group(1)))
    return exts


def test_structurally_validated_set_tracks_the_dispatch_chain():
    dispatch = _validated_extensions_from_dispatch()
    assert dispatch, "the dispatch-chain parser found no validators; the regex broke"
    stale_missing = dispatch - boundary._STRUCTURALLY_VALIDATED
    stale_extra = boundary._STRUCTURALLY_VALIDATED - dispatch
    assert not stale_missing, (
        f"validators exist but the entropy gate still runs first for: {sorted(stale_missing)}"
    )
    assert not stale_extra, (
        f"frozenset lists extensions with no validator in the dispatch chain: {sorted(stale_extra)}"
    )


def test_compressed_formats_skip_the_entropy_gate():
    """A uniformly random compressed payload (encrypted archive shape) must be
    judged by its own validator, not vetoed by the statistical gate."""
    import os

    payload = os.urandom(8192)
    for ext in ("gz", "7z", "zip", "mp4", "sqlite", "elf"):
        ok, reason = boundary.validate_structure(payload, ext)
        assert ok is False, f".{ext} validator should reject random bytes"
        assert "maximum entropy" not in reason, (
            f".{ext} has a structural validator; the statistical gate must not run: {reason}"
        )


# --------------------------------------------------------------------------- #
# jbd2 / FAT chain / new signatures
# --------------------------------------------------------------------------- #


def test_new_signatures_have_boundary_rules_or_footers():
    """A signature the engine cannot size -- no footer, no boundary resolver --
    is refused rather than carved to max_size, so every added family must be
    resolvable or it is dead weight."""
    from s0.carve.signatures import SIGNATURES

    for sig in SIGNATURES:
        if sig.extension in ("evtx", "iso"):
            assert boundary.has_boundary_rule(sig.extension), sig.name
        if sig.extension == "svg":
            assert sig.footer == b"</svg>", sig.name


def test_evtx_boundary_walks_64kib_chunks():

    class Mem:
        def __init__(self, blob):
            self.blob = blob

        def read(self, off, n):
            return self.blob[off : off + n]

        def read_until(self, needle, start, window):
            i = self.blob.find(needle, start, start + window)
            return -1 if i == -1 else i

    chunk = _EVTX_CHUNK_MAGIC + b"\x00" * (_EVTX_CHUNK_SIZE - 8)
    blob = b"ElfFile\x00" + b"\x00" * (_EVTX_FIRST_CHUNK - 8) + chunk + chunk + b"\x00" * _EVTX_CHUNK_SIZE
    b = boundary._evtx_end(Mem(blob), 0, len(blob))
    assert b.resolved
    assert b.end == _EVTX_FIRST_CHUNK + 2 * _EVTX_CHUNK_SIZE
    assert b.method == boundary.CONTAINER_WALK


def test_iso9660_boundary_resolves_from_the_pvd():
    import struct as _s

    class Mem:
        def __init__(self, blob):
            self.blob = blob

        def read(self, off, n):
            return self.blob[off : off + n]

        def read_until(self, needle, start, window):
            i = self.blob.find(needle, start, start + window)
            return -1 if i == -1 else i

    space_blocks = 64  # 64 * 2048 = 128 KiB volume
    pvd = bytearray(_ISO_BLOCK_SIZE)
    pvd[0] = 1
    pvd[1:6] = b"CD001"
    _s.pack_into("<I", pvd, 80, space_blocks)
    _s.pack_into("<H", pvd, 128, 2048)
    blob = bytearray(_ISO_BLOCK_SIZE * 70)
    blob[0x8001 : 0x8001 + _ISO_BLOCK_SIZE] = pvd
    # descriptor sequence: one more descriptor then terminator (type 255)
    blob[0x8001 + _ISO_BLOCK_SIZE + 0] = 255
    blob[0x8001 + _ISO_BLOCK_SIZE + 1 : 0x8001 + _ISO_BLOCK_SIZE + 6] = b"CD001"
    b = boundary._iso9660_end(Mem(bytes(blob)), 0, len(blob))
    assert b.resolved
    assert b.end == 128 * 1024  # declared volume size
    assert b.method == boundary.DECLARED_SIZE
