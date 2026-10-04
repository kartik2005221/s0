"""BLKDISCARD wipe — kernel discard ioctl on block devices.

Honest classification: a discard is a Purge only if the drive guarantees
deterministic read-after-discard (DRAT/RZAT per its specification). Most
drives' specs do not promise it, so s0 claims Clear for BLKDISCARD by
default and only records Purge when the operator explicitly supplies the
drive-spec justification (--discard-purge-justification), which lands in the
certificate notes and is validated by the core (see certificate.METHOD_TIERS).

Loop devices backed by sparse files accept BLKDISCARD (it punches holes in the
backing file) — that's how the ioctl path is exercised in this environment.
"""

from __future__ import annotations

import array
import sys

from .base import MethodResult, Plan, ProgressFn, Target, WipeMethod

# BLKDISCARD is a Linux kernel ioctl — it does not exist on Windows or macOS.
# We import fcntl lazily (inside the functions that use it) so that this module
# can be safely imported on Windows without raising ModuleNotFoundError at CLI
# startup. The class itself will simply never match a valid Windows target.
BLKDISCARD = 0x1277  # linux/fs.h — [u64 start_sector, u64 nr_sectors]


class BlkdiscardMethod(WipeMethod):
    id = "BLKDISCARD"
    nist_category = "Clear"  # default; Purge requires documented justification

    def __init__(self, purge_justification: str | None = None) -> None:
        self.purge_justification = purge_justification
        if purge_justification:
            self.nist_category = "Purge"

    def applies_to(self, target: Target) -> bool:
        return target.kind == "block"

    def plan(self, target: Target) -> Plan:
        return Plan(
            method_id=self.id,
            nist_category=self.nist_category,
            summary=(
                f"ioctl(BLKDISCARD) over the full {target.display} address space (trim/unmap every sector)"
            ),
            commands=[f"ioctl(fd, BLKDISCARD=0x1277, [0, {target.capacity_bytes}])"],
            warnings=(
                [
                    "Discard claims Clear by default: without a documented "
                    "deterministic-read-after-discard guarantee (DRAT/RZAT) from the "
                    "drive spec, recovery from unmapped-but-unerased cells is not "
                    "excluded."
                ]
                if not self.purge_justification
                else [f"Purge claimed per operator-supplied justification: {self.purge_justification}"]
            ),
        )

    def run(self, target: Target, progress: ProgressFn) -> MethodResult:
        import os

        result = MethodResult(status="success")
        if sys.platform != "linux":
            result.status = "failure"
            result.errors.append("BLKDISCARD is a Linux kernel ioctl and is not available on this platform")
            return result

        if target.kind != "block":
            result.status = "failure"
            result.errors.append("BLKDISCARD requires a block device, not an image file")
            return result

        if not supports_discard(target.path):
            result.status = "failure"
            result.errors.append(
                f"Device {target.path} does not accept BLKDISCARD (discard/TRIM not supported)"
            )
            return result

        import fcntl

        fd = os.open(target.path, os.O_WRONLY | os.O_EXCL)
        try:
            sector = target.sector_size
            # Range in bytes per Linux BLKDISCARD ioctl contract: [u64 byte_offset, u64 byte_length]
            max_bytes = target.capacity_bytes
            step = 2 * 1024 * 1024 * 1024  # issue in <=2 GiB ranges
            done = 0
            while done < max_bytes:
                n = min(step, max_bytes - done)
                n -= n % sector
                buf = array.array("Q", [done, n])
                fcntl.ioctl(fd, BLKDISCARD, buf, True)
                done += n
                pct = (done * 100) // max_bytes if max_bytes else 100
                progress(
                    f"discarding {target.path}: {done // (1024 * 1024):,} MiB / {max_bytes // (1024 * 1024):,} MiB ({pct}%)"
                )
            result.bytes_processed = max_bytes
        except OSError as exc:
            result.status = "partial" if result.bytes_processed else "failure"
            result.errors.append(f"BLKDISCARD failed: {exc}")
        finally:
            os.close(fd)
        return result


def supports_discard(path: str) -> bool:
    """Cheap probe: does this block device accept a zero-length BLKDISCARD?"""
    if sys.platform != "linux":
        return False

    import fcntl
    import os

    try:
        fd = os.open(path, os.O_WRONLY | os.O_EXCL)
    except OSError:
        return False
    try:
        buf = array.array("Q", [0, 0])
        fcntl.ioctl(fd, BLKDISCARD, buf, True)
        return True
    except OSError:
        return False
    finally:
        os.close(fd)
