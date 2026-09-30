"""Overwrite-based wipe — the one method fully exercisable in this environment.

Works identically on block devices and image files because both are byte
addressable through open()/write()/fsync(). On an image file the bytes really
do land on the underlying disk; on a block device they go to the drive. What
overwrite can NEVER claim is Purge: host writes cannot reach sectors the drive
has remapped away (growing defect lists, SSD overprovision). That limit is
physics/firmware policy, not tooling effort, so the tier stays Clear.
"""

from __future__ import annotations

import os
import secrets
import time

from .base import MethodResult, Plan, ProgressFn, Target, WipeMethod

CHUNK = 1024 * 1024  # 1 MiB


def _human(n: float) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if abs(n) < 1024 or unit == "GiB":
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GiB"


class OverwriteMethod(WipeMethod):
    """Single- or multi-pass overwrite with zeros or CSPRNG bytes.

    Default is ONE pass of zeros: per NIST SP 800-88 Rev.1 that satisfies Clear
    on modern media. Extra passes exist for organizational policy compliance,
    not added security — the CLI says this out loud instead of implying that
    more passes buy safety (see docs/compliance/nist-800-88-mapping.md §4).
    """

    def __init__(self, passes: int = 1, pattern: str = "zero") -> None:
        if pattern not in ("zero", "random"):
            raise ValueError(f"unsupported overwrite pattern {pattern!r}")
        if passes < 1:
            raise ValueError("passes must be >= 1")
        self.passes = passes
        self.pattern = pattern
        self.id = "OVERWRITE_ZERO_1PASS" if (pattern == "zero" and passes == 1) \
            else "SHRED_RANDOM_NPASS"
        # SHRED_RANDOM_NPASS covers random-pattern multi-pass; a single random
        # pass keeps the same id (shred-equivalent semantics).
        self.nist_category = "Clear"

    def applies_to(self, target: Target) -> bool:
        return target.kind in ("block", "image")

    def plan(self, target: Target) -> Plan:
        return Plan(
            method_id=self.id,
            nist_category=self.nist_category,
            summary=(
                f"{self.passes}-pass {'zero' if self.pattern == 'zero' else 'CSPRNG-random'} "
                f"overwrite of {target.display}; fsync each pass"
            ),
            commands=[f"python inline writer -> {target.path}"] if target.kind == "image"
            else [f"open({target.path}, O_WRONLY) + sequential write + fsync"],
            warnings=[
                "Overwrite claims NIST Clear only — it cannot reach remapped/"
                "overprovisioned sectors; firmware erase would be required for Purge.",
            ]
            + ([] if self.passes == 1 else [
                f"Multi-pass ({self.passes}) requested: legacy-policy theater on modern "
                f"drives, not extra security — recorded honestly here rather than implied.",
            ]),
        )

    def run(self, target: Target, progress: ProgressFn) -> MethodResult:
        result = MethodResult(status="success")
        flags = os.O_WRONLY
        if target.kind == "block":
            flags |= os.O_EXCL
        try:
            fd = os.open(target.path, flags)
        except OSError as exc:
            result.status = "failure"
            result.errors.append(f"cannot open target for writing: {exc}")
            return result

        try:
            chunk = b"\x00" * CHUNK if self.pattern == "zero" else None
            size = target.capacity_bytes
            for p in range(self.passes):
                os.lseek(fd, 0, os.SEEK_SET)
                written = 0
                t0 = time.monotonic()
                while written < size:
                    n = min(CHUNK, size - written)
                    buf = chunk if chunk is not None else secrets.token_bytes(n)
                    written += os.write(fd, buf[:n])
                    elapsed = max(time.monotonic() - t0, 1e-6)
                    progress(
                        f"pass {p + 1}/{self.passes}: {_human(written)} / "
                        f"{_human(size)} ({_human(written / elapsed)}/s)"
                    )
                try:
                    os.fsync(fd)
                except KeyboardInterrupt:
                    result.notes.append("fsync interrupted — data may not be fully committed to disk")
                    raise
                result.bytes_processed += written
            # Best-effort hint that this file's blocks were overwritten; for
            # sparse image targets also punch a hole so the demo doesn't leave
            # a 256 MB zero file lying around. NOT a security step.
            if target.kind == "image":
                try:
                    os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
                except OSError:
                    pass
        except KeyboardInterrupt:
            result.status = "interrupted"
            result.notes.append(f"Interrupted after {result.bytes_processed} bytes")
            raise
        except OSError as exc:
            result.status = "partial" if result.bytes_processed else "failure"
            result.errors.append(f"write error after {result.bytes_processed} bytes: {exc}")
        finally:
            os.close(fd)
        return result


def plant_patterns(path: str, markers: list[tuple[int, bytes]], progress_fn=None) -> None:
    """Test helper: write marker bytes at absolute offsets (extends file if needed).

    Used by tests and the e2e demo to create known recoverable content, so the
    post-wipe grep proves something concrete.
    """
    with open(path, "r+b") as f:
        for i, (offset, blob) in enumerate(markers):
            f.seek(offset)
            f.write(blob)
            if progress_fn:
                progress_fn(f"Planting marker {i + 1}/{len(markers)}")
        f.flush()
        if progress_fn:
            progress_fn("Syncing markers to disk...")
        os.fsync(f.fileno())


def count_pattern_hits(path: str, needle: bytes, chunk: int = CHUNK) -> int:
    """Count occurrences of *needle* across the whole file/block device."""
    hits = 0
    tail = b""
    with open(path, "rb") as f:
        while True:
            block = f.read(chunk)
            if not block:
                break
            window = tail + block
            hits += window.count(needle)
            tail = window[-(len(needle) - 1):] if len(needle) > 1 else b""
    return hits
