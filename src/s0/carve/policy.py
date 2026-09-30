"""s0 Module 2: carving session policy.

The parameters that decide how much a carving session is allowed to do. These
are deliberately explicit rather than hidden constants: a forensic tool that
writes hundreds of megabytes of low-confidence noise into a case directory is
both useless and, on a real evidence volume, actively harmful.

The default budget is expressed as a fraction of the *input* size, so a 64 MiB
image and a 16 TiB drive are both handled sensibly without operator tuning.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict

_MB = 1024 * 1024
_GB = 1024 * 1024 * 1024


@dataclass
class CarvePolicy:
    """Resource and output limits for one carving session."""

    # Absolute ceiling on everything written to the output directory.
    max_output_bytes: int = 256 * _MB
    # Absolute ceiling per single recovered file.
    max_file_bytes: int = 128 * _MB
    # Ceiling per (extension, category) bucket, so one noisy format cannot
    # consume the whole budget.
    max_files_per_category: int = 64
    max_files_per_extension: int = 32
    # Hard ceiling on recovered files, independent of size.
    max_files_total: int = 512
    # Default --min-confidence.
    min_confidence: int = 60
    # Scan window. Carving no longer depends on this being larger than a
    # recovered file -- boundary resolution reads through a ByteSource -- but it
    # still controls scan throughput.
    scan_chunk_bytes: int = 8 * _MB
    # Bytes of overlap between scan windows, only needs to exceed the longest
    # signature header.
    scan_overlap_bytes: int = 4 * 1024
    # Filesystem-structure recovery is tried first and is never budget-limited:
    # it is the highest-value, lowest-false-positive path available.
    structure_recovery_enabled: bool = True
    # Skip signature carving entirely (structure recovery only).
    structure_only: bool = False
    # Restrict signature carving to unallocated space, using the filesystem's own
    # allocation map. This is the single biggest precision and speed win
    # available: without it, every live file on the volume is re-covered as if it
    # had been deleted, which is what makes a carve report the same set of files
    # over and over. Falls back to a whole-volume search, with a warning, whenever
    # an allocation map cannot be established.
    use_free_space_only: bool = True
    # Extra per-category caps, e.g. {"video": 8}.
    category_caps: Dict[str, int] = field(default_factory=dict)

    @classmethod
    def for_target(cls, target_size: int, **overrides) -> "CarvePolicy":
        """Scale the output budget to the size of the target being carved."""
        policy = cls()
        if target_size > 0:
            # 12.5% of the target, clamped into a sane band. A carver that can
            # emit more than it consumes has stopped being a carver.
            policy.max_output_bytes = max(8 * _MB, min(target_size // 8, 512 * _MB))
            if target_size >= 4 * _GB:
                policy.max_output_bytes = max(256 * _MB, min(target_size // 32, 2 * _GB))
            policy.max_files_total = max(200, min(2048, target_size // (2 * _MB)))
        for key, value in overrides.items():
            if value is not None:
                setattr(policy, key, value)
        return policy

    def cap_for_category(self, category: str) -> int:
        return self.category_caps.get(category, self.max_files_per_category)


@dataclass
class CarveBudget:
    """Live accounting for one carving session."""

    policy: CarvePolicy
    bytes_written: int = 0
    files_written: int = 0
    per_category: Dict[str, int] = field(default_factory=dict)
    per_extension: Dict[str, int] = field(default_factory=dict)
    # Why the session stopped emitting, for the report.
    stop_reason: str = ""

    @property
    def exhausted(self) -> bool:
        return bool(self.stop_reason)

    # Convenience passthroughs so call sites can treat the budget and its policy
    # interchangeably.
    @property
    def max_file_bytes(self) -> int:
        return self.policy.max_file_bytes

    @property
    def max_output_bytes(self) -> int:
        return self.policy.max_output_bytes

    @property
    def min_confidence(self) -> int:
        return self.policy.min_confidence

    def admit(self, category: str, extension: str, size: int) -> tuple[bool, str]:
        """Decide whether a candidate of this size may be written.

        Returns ``(allowed, reason_if_denied)``. Checks run cheapest-first so the
        common rejection (budget) costs almost nothing.
        """
        p = self.policy
        if size > p.max_file_bytes:
            return False, f"single file exceeds the {p.max_file_bytes:,} B per-file cap"
        if self.files_written >= p.max_files_total:
            return False, f"reached the {p.max_files_total}-file session cap"
        if self.bytes_written + size > p.max_output_bytes:
            return False, f"output budget of {p.max_output_bytes:,} B exhausted"
        if self.per_category.get(category, 0) >= p.cap_for_category(category):
            return False, f"reached the {p.cap_for_category(category)}-file cap for '{category}'"
        if self.per_extension.get(extension, 0) >= p.max_files_per_extension:
            return False, f"reached the {p.max_files_per_extension}-file cap for '.{extension}'"
        return True, ""

    def commit(self, category: str, extension: str, size: int) -> None:
        self.bytes_written += size
        self.files_written += 1
        self.per_category[category] = self.per_category.get(category, 0) + 1
        self.per_extension[extension] = self.per_extension.get(extension, 0) + 1
