"""Wipe method protocol shared by all backends.

Every method declares:
  * its identifier (goes verbatim into the certificate's wipe.method)
  * the NIST 800-88 tier it is allowed to claim (enforced again at cert build)
  * applicability checks for a given target
  * a plan() description (what WOULD happen — powers --dry-run)
  * run() which does the work and reports progress

Honesty rule: methods whose real-hardware behavior could not be validated in
the development environment (ATA Secure Erase, NVMe sanitize) carry that note
in their docstrings AND surface it as certificate notes when used.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

ProgressFn = Callable[[str], None]  # human-readable progress line


@dataclass
class Target:
    """A wipe target: either a block device path or an image file path."""

    path: str
    kind: str  # "block" | "image"
    capacity_bytes: int
    sector_size: int = 512
    storage_type: str = "UNKNOWN"  # HDD/SSD/NVMe/eMMC/UFS/IMAGE_FILE
    model: Optional[str] = None
    serial: Optional[str] = None
    removable: bool = False  # block only: /sys/block/<dev>/removable

    @property
    def display(self) -> str:
        return f"{self.path} ({self.kind}, {self.storage_type}, {self.capacity_bytes:,} B)"


@dataclass
class MethodResult:
    status: str  # success | failure | partial
    bytes_processed: int = 0
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class Plan:
    """What a method would do — also what the operator confirms before wiping."""

    method_id: str
    nist_category: str
    summary: str
    commands: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class WipeMethod:
    id: str = ""
    nist_category: str = ""
    pattern: str = "zero"

    def applies_to(self, target: Target) -> bool:  # pragma: no cover - interface
        raise NotImplementedError

    def plan(self, target: Target) -> Plan:  # pragma: no cover - interface
        raise NotImplementedError

    def run(self, target: Target, progress: ProgressFn) -> MethodResult:
        """Execute the wipe. Must raise nothing; report via MethodResult."""
        raise NotImplementedError
