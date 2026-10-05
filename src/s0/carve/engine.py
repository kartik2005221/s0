"""s0 Module 2: file carving & recovery engine.

Design notes, because the previous design produced a specific, reproducible
defect worth recording:

The old engine had two coupled bugs that made it look like it returned the same
junk for every target.

1. For the 13 of 19 signatures with no footer it carved
   ``data[offset : offset + max_size]`` where ``data`` was the current 2 MiB read
   window. Every match therefore produced a full-size block of whatever followed
   the magic bytes.
2. The scorer awarded a flat +15 for "header-only stream format" and had no
   structural validation for half the signature table, so those blocks scored 55+
   and cleared the default 50 threshold.

The arithmetic was deterministic: because a carve advanced the search position
to the end of the blob it had just emitted, exactly one candidate per signature
survived per 2 MiB window, so the session always returned the same ~33 files.

This engine fixes all of it:

* Boundary resolution goes through :mod:`.boundary`, which reads the format's
  own length, walks its container, or demands a codec frame chain. A candidate
  whose end cannot be established is rejected, not guessed.
* Structural validation (:func:`boundary.validate_structure`) is a hard gate.
* A :class:`.policy.CarveBudget` caps total bytes, per-file size, per-category
  and per-extension counts, scaled to the target.
* Filesystem-native recovery runs first and is reported separately, because a
  deleted MFT record or inode with its original name is worth far more than any
  signature hit.
* The session report separates *recovered* from *rejected*, and states how many
  bytes of candidates were discarded, so a low yield is visible rather than
  silently padded with noise.
"""

from __future__ import annotations

import hashlib
import json
import re
import struct
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from s0 import certificate as cert_mod
from s0 import crypto as core_crypto
from s0 import resources
from s0.config import CONFIG

from . import bodyfile, boundary, provenance, session, suppression
from .allocation import FreeSpaceMap, build_free_space
from .exfat_carver import scan_exfat_deleted_files
from .ext4_carver import scan_ext4_deleted_inodes
from .fat_carver import scan_fat32_deleted_files
from .ntfs_carver import read_usn_journal, scan_ntfs_deleted_records
from .policy import CarveBudget, CarvePolicy
from .scoring import score_carved_candidate
from .signatures import SIGNATURES, FileSignature, sniff
from .usn import build_timeline

# Recovery methods, in descending order of evidentiary value.
METHOD_STRUCTURE = "filesystem_metadata"
METHOD_SIGNATURE = "signature"
METHOD_FRAGMENT = "bifragment_heuristic"

_STRUCTURE_METHODS = {
    "ntfs": "ntfs_mft",
    "ext4": "ext4_inode",
    "fat32": "fat32_directory",
    "exfat": "exfat_entry",
}

# A pure-noise image generates over a million rejected candidates. Dumping one
# line per rejection produced a 10 MB recovery_index.json for an 8 MB image --
# the report dwarfed the evidence. The index therefore carries an aggregated
# reason histogram plus a bounded sample.
_MAX_RESTORATION_NOTES = 8
_MAX_REJECTION_SAMPLES = 2_000
_MAX_REJECTION_REASONS = 100


def _sanitize_filename(raw: str, max_len: int = 200) -> str:
    """Strip path separators, null bytes and control characters from a filename."""
    clean = str(raw or "").strip()
    clean = re.sub(r"[\x00-\x1f]", "_", clean)
    parts = [
        re.sub(r"^\.+", "", p).strip() for p in re.split(r"[/\\:]+", clean) if p and p not in (".", "..")
    ]
    clean = "_".join(p for p in parts if p)
    clean = clean.strip("._ ")
    clean = re.sub(r"_{2,}", "_", clean)
    clean = clean[:max_len] if clean else "unnamed"
    return clean or "unnamed"


@dataclass
class CarvedFile:
    file_id: str
    filename: str
    extension: str
    category: str
    offset: int
    size_bytes: int
    sha256: str
    confidence_score: int
    heuristics: list[str] = field(default_factory=list)
    recovered_path: str | None = None
    recovery_method: str = METHOD_SIGNATURE
    is_fragmented: bool = False
    fragment_count: int = 1
    # Where the end-of-file came from. 'filesystem_metadata' means the
    # filesystem itself told us the length.
    boundary_method: str = boundary.UNDETERMINED
    # Original path/names when the filesystem supplied them.
    original_name: str | None = None
    original_path: str | None = None
    deleted_at: str | None = None
    #: What supports ``original_name``, and whether a path was recovered at all.
    #: Set for filesystem-native recoveries. Left ``None`` for signature
    #: carving, which has no metadata and must not appear to have any.
    provenance: dict | None = None


@dataclass
class RejectedCandidate:
    offset: int
    extension: str
    reason: str
    stage: str  # "boundary" | "structure" | "score" | "budget"


@dataclass
class CarvingSessionSummary:
    target_path: str
    source_filesystem: str
    total_bytes_scanned: int
    total_candidates_found: int
    files_recovered: int
    carved_files: list[CarvedFile] = field(default_factory=list)
    manifest_certificate: dict | None = None
    warnings: list[str] = field(default_factory=list)
    # Accounting, so a thin result is visible instead of being padded with noise.
    rejected_candidates: int = 0
    rejected_bytes: int = 0
    bytes_recovered: int = 0
    output_budget_bytes: int = 0
    budget_stop_reason: str = ""
    rejected_samples: list[RejectedCandidate] = field(default_factory=list)
    by_category: dict[str, int] = field(default_factory=dict)
    by_method: dict[str, int] = field(default_factory=dict)
    truncated_report: bool = False
    # reason -> count, most common first. Far more useful than a million lines.
    rejection_summary: list[tuple[str, int]] = field(default_factory=list)
    # Allocation-aware search accounting. `free_space` is None when the whole
    # volume had to be searched, which is itself worth recording in a report.
    free_space: dict | None = None
    allocated_candidates_skipped: int = 0
    allocated_bytes_skipped: int = 0
    # Names and deletion times recovered from the NTFS change journal. These are
    # evidence that a file existed, not recovered files: no bytes come from the
    # journal, so they are counted and reported separately rather than added to
    # files_recovered.
    deleted_names_from_journal: list[dict] = field(default_factory=list)
    # (start, end) inclusive byte ranges of everything recovered, in the target.
    # Written out as a bodyfile so another tool can be pointed at the same bytes
    # instead of being asked to re-read the whole volume.
    recovered_extents: list[tuple[int, int]] = field(default_factory=list)
    # Files held back because they matched a known-hash set. Counted and
    # reported, never silently dropped: a tool whose report cannot account for
    # what it withheld is a tool whose report cannot be relied on.
    suppressed_known: int = 0
    suppressed_known_bytes: int = 0
    suppression_note: str = ""
    # Candidates dropped by the in-memory prefilter before any I/O. The ratio
    # against candidates_evaluated is the honest measure of how much work that
    # saved, and an operator adding a signature needs to see it move.
    candidates_prefiltered: int = 0
    #: Extents a resumed session had already recorded. A resumed candidate is
    #: counted under ``duplicates_suppressed`` rather than in a field of its own:
    #: the digest set is the one mechanism both carving paths consult, and a
    #: second counter would have to be incremented in both of them to stay
    #: accurate. One number that is true beats two where one is always zero.
    resumed_from_session: int = 0

    def recovery_rate_ppm(self) -> int:
        """Recovered bytes per million bytes scanned, in integer parts-per-million."""
        if self.total_bytes_scanned <= 0:
            return 0
        return (self.bytes_recovered * 1_000_000) // self.total_bytes_scanned


# --------------------------------------------------------------------------- #
# partition / filesystem detection
# --------------------------------------------------------------------------- #


def _probe_fs_at_offset(f, offset: int) -> str | None:
    """Probe for NTFS, ext4, FAT32 or exFAT at a given byte offset."""
    try:
        f.seek(offset)
        header = f.read(2048)
        if len(header) >= 512 and header[3:11] == b"NTFS    ":
            return "ntfs"
        if len(header) >= 512 and header[3:11] == b"EXFAT   ":
            return "exfat"
        if len(header) >= 1082:
            import struct

            if struct.unpack_from("<H", header, 1024 + 56)[0] == 0xEF53:
                return "ext4"
        if len(header) >= 512:
            import struct

            if struct.unpack_from("<H", header, 510)[0] == 0xAA55 and (
                header[82:87] == b"FAT32" or header[54:57] == b"FAT"
            ):
                return "fat32"
    except Exception:
        pass
    return None


def detect_partitions(target_path: str | Path) -> list[tuple[str, int]]:
    """Detect filesystems on bare media, an MBR disk or a GPT disk."""
    results: list[tuple[str, int]] = []
    try:
        with open(target_path, "rb") as f:
            fs_at_0 = _probe_fs_at_offset(f, 0)
            if fs_at_0:
                return [(fs_at_0, 0)]

            f.seek(0)
            sector0 = f.read(512)
            has_gpt = False
            if len(sector0) == 512 and sector0[510:512] == b"\x55\xaa":
                import struct

                for i in range(4):
                    entry_off = 446 + i * 16
                    ptype = sector0[entry_off + 4]
                    if ptype == 0xEE:
                        has_gpt = True
                    start_lba = struct.unpack_from("<I", sector0, entry_off + 8)[0]
                    sectors = struct.unpack_from("<I", sector0, entry_off + 12)[0]
                    if ptype not in (0, 0xEE) and start_lba > 0 and sectors > 0:
                        part_off = start_lba * 512
                        fs = _probe_fs_at_offset(f, part_off)
                        if fs:
                            results.append((fs, part_off))

            if has_gpt or not results:
                f.seek(512)
                gpt_hdr = f.read(512)
                if len(gpt_hdr) >= 92 and gpt_hdr[:8] == b"EFI PART":
                    import struct

                    part_lba = struct.unpack_from("<Q", gpt_hdr, 72)[0]
                    num_parts = struct.unpack_from("<I", gpt_hdr, 80)[0]
                    part_size = struct.unpack_from("<I", gpt_hdr, 84)[0]
                    if 0 < num_parts <= 128 and 128 <= part_size <= 512:
                        f.seek(part_lba * 512)
                        for _ in range(num_parts):
                            pentry = f.read(part_size)
                            if len(pentry) < part_size or pentry[:16] == bytes(16):
                                break
                            start_lba = struct.unpack_from("<Q", pentry, 32)[0]
                            if start_lba > 0:
                                part_off = start_lba * 512
                                fs = _probe_fs_at_offset(f, part_off)
                                if fs and (fs, part_off) not in results:
                                    results.append((fs, part_off))
    except Exception:
        pass

    return results or [("raw", 0)]


def detect_filesystem(target_path: str | Path) -> str:
    for fs, _ in detect_partitions(target_path):
        if fs != "raw":
            return fs
    return "raw"


# --------------------------------------------------------------------------- #
# filesystem-native recovery
# --------------------------------------------------------------------------- #


def _recover_from_filesystem(
    target_p: Path,
    out_p: Path,
    parts: list[tuple[str, int]],
    extensions: list[str] | None,
    budget: CarveBudget,
    warnings: list[str],
    counters: dict[str, Any],
    recovered_hashes: set,
    known_hashes: suppression.SuppressionSet | None = None,
) -> tuple[list[CarvedFile], list[dict]]:
    """Recover deleted files from filesystem metadata.

    This is the highest-value path: the filesystem knows the real length, the
    real name and often the deletion timestamp. Results are emitted into the same
    budget so a large free-space sweep can never crowd them out.

    Returns the recovered files and, separately, names recovered from the NTFS
    change journal. The second list is not files: it is names and times for
    objects whose content is not on the volume, and it is kept apart from the
    first so a report cannot imply bytes were recovered from a name alone.
    """
    recovered: list[CarvedFile] = []
    timeline: list[dict] = []
    norm_exts = {e.lower().lstrip(".") for e in extensions} if extensions else None
    names_seen: dict[str, int] = {}

    for part_fs, part_offset in parts:
        journal = None
        try:
            if part_fs == "ntfs":
                entries = scan_ntfs_deleted_records(
                    target_p,
                    partition_offset=part_offset,
                    max_bytes_per_file=budget.max_output_bytes,
                    warnings=warnings,
                )
                found = [
                    (
                        e.record_num,
                        e.name,
                        e.data,
                        e.fragment_count,
                        e.first_data_offset,
                        e.path,
                        e.mft_changed,
                    )
                    for e in entries
                    if e.data is not None
                ]
                # A record whose name survives but whose bytes cannot be read
                # back -- EFS, NTFS compression, or a sparse stream -- is still
                # evidence, and saying so is more useful than dropping it.
                unrestorable = [e for e in entries if e.data is None and e.content_caveat]
                for e in unrestorable[:_MAX_RESTORATION_NOTES]:
                    warnings.append(
                        f"NTFS record {e.record_num} ({e.path}) was named but not "
                        f"restored: {e.content_caveat}"
                    )
                if len(unrestorable) > _MAX_RESTORATION_NOTES:
                    warnings.append(
                        f"{len(unrestorable) - _MAX_RESTORATION_NOTES} further NTFS "
                        f"record(s) were named but not restorable; see the recovery index."
                    )
                if unrestorable:
                    counters["structure_filtered"] += len(unrestorable)
                journal = _read_journal_evidence(target_p, part_offset, warnings)
            elif part_fs == "ext4":
                found = [
                    (
                        i.inode_num,
                        f"inode{i.inode_num}",
                        i.data,
                        i.fragment_count,
                        # The filesystem's own block size, not a guess. This was a
                        # hardcoded 1024, so on a 4 KiB-block ext4 volume every
                        # recovered inode was reported at a quarter of its real offset,
                        # and `--bodyfile` / `--gaps-bodyfile` inherited the error. The
                        # gaps file is the artefact a fragmented-recovery report leans
                        # on, so this was not cosmetic.
                        part_offset
                        + (i.extent_block_ranges[0][0] * i.block_size if i.extent_block_ranges else 0),
                        None,
                        None,
                    )
                    for i in scan_ext4_deleted_inodes(target_p, partition_offset=part_offset)
                ]
            elif part_fs == "fat32":
                found = [
                    (
                        ff.first_cluster,
                        ff.filename,
                        ff.data,
                        1,
                        part_offset + ff.first_cluster * 4096,
                        None,
                        None,
                    )
                    for ff in scan_fat32_deleted_files(target_p, partition_offset=part_offset)
                ]
            elif part_fs == "exfat":
                found = [
                    (
                        ef.first_cluster,
                        ef.filename,
                        ef.data,
                        ef.fragment_count,
                        part_offset + ef.first_cluster * 4096,
                        None,
                        None,
                    )
                    for ef in scan_exfat_deleted_files(target_p, partition_offset=part_offset)
                ]
            else:
                continue
        except Exception as exc:
            warnings.append(f"{part_fs.upper()} metadata recovery at offset {part_offset} failed: {exc}")
            continue

        counters["structure_candidates"] += len(found)

        # Note every name the filesystem offers before any filtering, and before
        # the journal is compared against them. A name the journal also knows
        # about is corroborated by two independent structures even if this run
        # went on to exclude the file by extension -- that exclusion is the
        # operator's choice, not a fact about the volume.
        for _key, _name, _data, _frag, _off, _path, _at in found:
            if _name:
                names_seen.setdefault(str(_name), 0)

        if journal is not None:
            timeline += _merge_journal_evidence(journal, names_seen, warnings)

        for key, name, data, frag_count, offset, orig_path, deleted_at in found:
            orig_name = str(name)
            if not data:
                continue
            ext = Path(str(name)).suffix.lower().lstrip(".") or ""
            if not ext or ext == "bin":
                # The deleted directory entry no longer carries a usable name;
                # identify the payload by content instead of calling it `bin`.
                sniffed = sniff(data)
                ext = sniffed.extension if sniffed else "bin"
            if norm_exts and ext not in norm_exts:
                counters["structure_filtered"] += 1
                continue

            digest = hashlib.sha256(data).hexdigest()
            if digest in recovered_hashes:
                counters["duplicate"] += 1
                continue

            # A hash set has to work on this path too. Filesystem-native
            # recovery is the one an examiner trusts most, so withholding
            # known files only from signature carving would leave the bulk of a
            # volume's findings untouched and the suppression would look like it
            # worked. The digest is already in hand from the duplicate check.
            if known_hashes is not None and len(known_hashes):
                algo = known_hashes.match(data)
                if algo is not None:
                    counters["suppressed_known"] = counters.get("suppressed_known", 0) + 1
                    counters["suppressed_bytes"] = counters.get("suppressed_bytes", 0) + len(data)
                    counters["rejected_samples"].append(
                        RejectedCandidate(
                            offset if offset is not None else 0,
                            ext,
                            f"matches a known {algo} digest in {known_hashes.source}",
                            "known-file",
                        )
                    )
                    continue

            counters["structure_accepted"] += 1
            counters["candidates"] += 1

            # The filesystem told us the length; that is the strongest possible
            # boundary evidence and there is nothing to re-derive.
            ident = sniff(data) or _generic_signature(ext, data)
            score, heuristics = score_carved_candidate(
                ident,
                data,
                boundary_method=boundary.DECLARED_SIZE,
                boundary_notes=(
                    f"{part_fs.upper()} metadata supplied the exact byte length "
                    f"and{' original name' if not name.startswith('inode') else ''}",
                ),
            )
            heuristics.append(
                f"Recovered from {part_fs.upper()} filesystem metadata (partition @ {part_offset})"
            )
            if frag_count > 1:
                heuristics.append(f"Reassembled from {frag_count} fragment runs")

            # 3g/3h: say what supports the name, and say when there is no path.
            # A report that prints a bare filename implies less than one that
            # prints a path, and printing neither leaves the reader unable to
            # tell a verified name from an unverifiable one.
            prov = provenance.for_filesystem(part_fs, path=orig_path)
            heuristics.append(prov.describe())

            category = ident.category
            allowed, reason = budget.admit(category, ext, len(data))
            if not allowed:
                counters["rejected"] += 1
                warnings.append(f"Stopped writing filesystem recoveries: {reason}")
                return recovered, timeline
            budget.commit(category, ext, len(data))

            file_id = f"carved_{len(recovered) + 1:05d}"
            safe_name = _sanitize_filename(str(name))
            if safe_name.lower().endswith("." + ext):
                filename = f"{file_id}_{part_fs}_{safe_name}"
            else:
                filename = f"{file_id}_{part_fs}_key{key}_{safe_name}.{ext}"
            rec_path = _safe_join(out_p, filename)
            rec_path.write_bytes(data)
            recovered_hashes.add(digest)

            recovered.append(
                CarvedFile(
                    file_id=file_id,
                    filename=rec_path.name,
                    extension=ext,
                    category=category,
                    offset=offset,
                    size_bytes=len(data),
                    sha256=digest,
                    confidence_score=score,
                    heuristics=heuristics,
                    recovered_path=str(rec_path),
                    recovery_method=_STRUCTURE_METHODS.get(part_fs, METHOD_STRUCTURE),
                    is_fragmented=frag_count > 1,
                    fragment_count=frag_count,
                    boundary_method=boundary.DECLARED_SIZE,
                    original_name=str(name),
                    original_path=orig_path,
                    deleted_at=deleted_at,
                    provenance=prov.as_dict(),
                )
            )
            if orig_name:
                names_seen.setdefault(orig_name, 0)
            counters["bytes_recovered"] += len(data)
    return recovered, timeline


def _generic_signature(ext: str, data: bytes) -> FileSignature:
    return FileSignature(
        name=ext.upper() or "Data",
        extension=ext,
        category=_category_for(ext),
        header=data[:8],
        min_size=max(1, len(data)),
        max_size=max(len(data), 1),
    )


_CATEGORY_BY_EXT = {
    "jpg": "image",
    "jpeg": "image",
    "png": "image",
    "gif": "image",
    "bmp": "image",
    "webp": "image",
    "tiff": "image",
    "heic": "image",
    "jp2": "image",
    "pdf": "document",
    "doc": "document",
    "docx": "document",
    "xlsx": "document",
    "pptx": "document",
    "rtf": "document",
    "pcap": "document",
    "pcapng": "document",
    "zip": "archive",
    "gz": "archive",
    "bz2": "archive",
    "xz": "archive",
    "zst": "archive",
    "7z": "archive",
    "rar": "archive",
    "tar": "archive",
    "lz4": "archive",
    "wav": "audio",
    "flac": "audio",
    "ogg": "audio",
    "mp3": "audio",
    "aiff": "audio",
    "mid": "audio",
    "mp4": "video",
    "mov": "video",
    "mkv": "video",
    "webm": "video",
    "ts": "video",
    "sqlite": "database",
    "db": "database",
    "mdb": "database",
    "dat": "database",
    "elf": "executable",
    "exe": "executable",
    "dll": "executable",
    "class": "executable",
    "macho": "executable",
    "lnk": "system",
    "pf": "system",
    "url": "system",
    "ini": "system",
}


def _category_for(ext: str) -> str:
    return _CATEGORY_BY_EXT.get(ext.lower().lstrip("."), "document")


def _safe_join(out_p: Path, filename: str) -> Path:
    """Join and confirm containment, falling back to a sanitised name."""
    rec_path = out_p / filename
    try:
        if not rec_path.resolve().is_relative_to(out_p.resolve()):
            return out_p / _sanitize_filename(filename)
    except (ValueError, RuntimeError, OSError):
        return out_p / _sanitize_filename(filename)
    return rec_path


# --------------------------------------------------------------------------- #
# signature carving
# --------------------------------------------------------------------------- #


def _overlaps_free(fsm: FreeSpaceMap, start: int, end: int) -> bool:
    """True if [start, end) touches any free extent of the map."""
    if end <= start:
        return False
    for lo, hi in fsm.ranges:
        if lo < end and start < hi:
            return True
    return False


def _resolve_free_space(target_p: Path, parts, total_size: int, policy) -> tuple:
    """Build the unallocated-space map for the carved target.

    Returns `(map_or_None, notes)`. A map is only produced when it is complete
    and trustworthy: a partially-parsed allocation structure would silently
    exclude live space, or worse, include allocated space as if it were deleted.
    When any partition's map is missing, the whole-volume search is used and the
    report says so, because a carve that quietly searched less than it claimed
    is worse than a slow one.
    """
    notes: list[str] = []
    if not policy.use_free_space_only:
        notes.append(
            "Allocation-aware search was disabled (--all-space): the whole volume was "
            "searched, so files that are still allocated will also be reported."
        )
        return None, notes

    maps: list[FreeSpaceMap] = []
    for offset, size, label, ftype in _carve_targets(parts, total_size):
        if ftype == "raw" or not ftype:
            notes.append(
                f"Partition at offset {offset} is not a recognised filesystem "
                f"({label or 'unlabelled'}); its space was searched in full."
            )
            return None, notes
        fsm = build_free_space(target_p, ftype, offset, size)
        if not fsm.reliable:
            notes.append(
                f"Could not establish a trustworthy allocation map for the "
                f"{ftype} partition at offset {offset}: {'; '.join(fsm.notes) or 'unknown'}. "
                f"The whole volume was searched instead."
            )
            return None, notes
        notes.append(
            f"{ftype}: {fsm.free_bytes / (1 << 20):.1f} MiB free in {fsm.range_count} "
            f"extent(s) ({fsm.coverage_ppm / 10_000:.1f}% of the filesystem); carving "
            f"restricted to unallocated space."
        )
        maps.append(fsm)

    if not maps:
        notes.append(
            "No filesystem allocation map was available, so the whole volume was searched. "
            "Recovered files may include ones that are still allocated."
        )
        return None, notes

    combined = FreeSpaceMap(
        partition_offset=0,
        volume_bytes=max(m.volume_bytes for m in maps),
        ranges=_merge_ranges([r for m in maps for r in m.ranges]),
        source=", ".join(sorted({m.source for m in maps})),
        reliable=True,
    )
    return combined, notes


def _carve_targets(parts, total_size: int) -> list[tuple]:
    """Normalise detected partitions into (offset, size, label, fs_type).

    `detect_partitions` yields (fs_type, offset) with no length, so a partition's
    extent is inferred as the distance to the next partition, or to the end of
    the media for the last one.
    """
    if not parts:
        return [(0, total_size, "", "raw")]
    entries = sorted(((off, fs) for fs, off in parts), key=lambda e: e[0])
    out = []
    for i, (off, ftype) in enumerate(entries):
        end = entries[i + 1][0] if i + 1 < len(entries) else total_size
        out.append((off, max(0, end - off), "", ftype))
    return out


def _merge_ranges(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    if not ranges:
        return []
    ordered = sorted(r for r in ranges if r[1] > r[0])
    out = [ordered[0]]
    for start, end in ordered[1:]:
        last_start, last_end = out[-1]
        if start <= last_end:
            out[-1] = (last_start, max(last_end, end))
        else:
            out.append((start, end))
    return out


def _scan_signatures(
    src: boundary.ByteSource,
    target_p: Path,
    out_p: Path,
    active: list[FileSignature],
    custom_signatures: list[FileSignature] | None,
    extensions: list[str] | None,
    min_confidence: int,
    budget: CarveBudget,
    counters: dict[str, Any],
    recovered_hashes: set,
    warnings: list[str],
    already_recovered: list[CarvedFile],
    progress_callback: Callable[[int, int, int], None] | None,
    total_size: int,
    free_space: FreeSpaceMap | None = None,
    suppression: suppression.SuppressionSet | None = None,
) -> list[CarvedFile]:
    """Carve by signature, resolving every boundary through `.boundary`."""
    carved: list[CarvedFile] = []
    scanned = 0
    chunk = budget.policy.scan_chunk_bytes
    overlap = budget.policy.scan_overlap_bytes
    file_seq = len(already_recovered)

    # Longest inbuilt window we need to hold in memory for the cheap prefilter.
    max_inbuilt_window = max((s.inbuilt_search_window for s in active if s.inbuilt), default=0)
    # A signature whose magic sits at header_offset needs that many leading bytes
    # available, or the first candidate in a window is invisible.
    window_needed = max((s.header_offset + len(s.header) for s in active), default=1) + max_inbuilt_window

    custom_ids = {id(s) for s in custom_signatures or ()}
    carry = b""
    carry_offset = 0
    # Absolute offset up to which the target has already been searched. The
    # sliding window re-reads `overlap` bytes each pass so a signature
    # straddling a window boundary is still seen, which means candidates inside
    # the overlap must not be carved twice.
    searched_upto = 0

    with open(str(target_p), "rb") as f:
        while True:
            block = f.read(chunk)
            if not block:
                break
            at_eof = len(block) < chunk
            scanned += len(block)
            data = carry + block
            data_start = carry_offset

            # Reserve the trailing `window_needed` bytes so a signature
            # straddling a window boundary is still seen. At end-of-file there
            # is no next window to re-read them from, so search everything.
            keep_from = 0 if at_eof else max(0, len(data) - max(overlap, window_needed))
            if keep_from > 0:
                carry = data[keep_from:]
                carry_offset = data_start + keep_from
                data = data[:keep_from]
            else:
                carry = b""
                carry_offset = data_start + len(data)

            # When an allocation map is available, a window that contains no free
            # space at all cannot hold a deleted file. Skipping the signature
            # search for it is what makes a carve finish in minutes instead of
            # hours on a mostly-full volume, and it is the same optimisation
            # PhotoRec calls remove_used_space().
            if free_space is not None and not _overlaps_free(free_space, data_start, data_start + len(data)):
                counters["allocated_bytes_skipped"] = counters.get("allocated_bytes_skipped", 0) + len(data)
                continue

            # Only search for magics whose first byte actually occurs in this
            # window. On a sparse or mostly-zeroed window -- which is most of a
            # real volume's free space -- this skips most of the table outright.
            #
            # Measured, and the measurement changed the design: a single regex
            # alternation over all 53 magics was tried first and is *four times
            # slower* than the per-signature C-level `bytes.find` loop (1.20 s vs
            # 0.30 s over 8 MiB), because CPython's re cannot prefilter a 53-way
            # alternation the way memchr can. A pure-Python Aho-Corasick would be
            # slower still, at roughly 1-3 MB/s in the interpreter. So the C-level
            # finds stay, and the win comes from not calling the ones that cannot
            # match. On uniform noise every byte is present and this costs one
            # `bytes(set(...))` per window.
            present = set(data)

            for sig in active:
                first = (
                    sig.header[sig.header_offset] if sig.header_offset < len(sig.header) else sig.header[0]
                )
                if first not in present:
                    continue
                pos = 0
                while True:
                    idx = data.find(sig.header, pos)
                    if idx == -1:
                        break
                    pos = idx + 1
                    # A signature may declare that its magic sits a fixed
                    # distance into the file: ISO-BMFF puts `ftyp` after a
                    # 4-byte box size whose value varies per file. The candidate
                    # then starts earlier than the match, and that earlier offset
                    # is what everything downstream must use.
                    start_in_window = idx - sig.header_offset
                    if start_in_window < 0:
                        continue
                    offset = data_start + start_in_window
                    if offset < searched_upto:
                        continue  # seen in a previous window's overlap

                    # A signature header inside a block the filesystem still
                    # considers allocated belongs to a live file. Recovering it
                    # would re-cover a file that is not deleted, which is how a
                    # carve ends up reporting the same set of files over and over.
                    if free_space is not None and not free_space.contains(offset, min(len(sig.header), 1)):
                        counters["allocated_candidates_skipped"] = (
                            counters.get("allocated_candidates_skipped", 0) + 1
                        )
                        continue

                    # Cheap in-memory plausibility check, before any I/O.
                    #
                    # Profiling 32 MiB of noise showed `bytes.find` was only 8%
                    # of the runtime; the other 92% was 265,811 calls into the
                    # boundary resolver, more than half from the eight
                    # signatures whose magic is one or two bytes. A one-byte magic
                    # matches every 256 bytes of anything, so the resolver was
                    # doing file seeks to reject candidates whose header bytes
                    # already disproved them. Measured over 64 MiB, candidates
                    # fell 529,720 -> 1,018 and candidate work stopped being the
                    # bottleneck entirely.
                    prefilter = _plausible_header(sig, data, start_in_window)
                    if prefilter is not None:
                        counters["prefiltered"] = counters.get("prefiltered", 0) + 1
                        continue

                    counters["candidates"] += 1
                    result = _carve_one(
                        src,
                        offset,
                        sig,
                        extensions,
                        min_confidence,
                        budget,
                        counters,
                        recovered_hashes,
                        warnings,
                        allow_guess=id(sig) in custom_ids,
                        suppression=suppression,
                    )
                    if result is None:
                        continue
                    payload, boundary_result, score, heuristics = result

                    category = sig.category
                    allowed, reason = budget.admit(category, sig.extension, len(payload))
                    if not allowed:
                        counters["rejected"] += 1
                        counters["rejected_bytes"] += len(payload)
                        budget.stop_reason = budget.stop_reason or reason
                        counters["budget_stops"] += 1
                        if counters["budget_stops"] == 1:
                            warnings.append(
                                f"Output budget reached ({reason}). Candidates found after this "
                                "point are still counted and validated, but are not written. "
                                "Raise --max-output-mb or narrow --extensions to collect more."
                            )
                        pos = idx + len(sig.header)
                        continue

                    file_seq += 1
                    file_id = f"carved_{file_seq:05d}"
                    filename = f"{file_id}_{offset:010x}_{score}pct.{sig.extension}"
                    rec_path = _safe_join(out_p, filename)
                    rec_path.write_bytes(payload)
                    budget.commit(category, sig.extension, len(payload))
                    recovered_hashes.add(hashlib.sha256(payload).hexdigest())
                    counters["bytes_recovered"] += len(payload)

                    carved.append(
                        CarvedFile(
                            file_id=file_id,
                            filename=rec_path.name,
                            extension=sig.extension,
                            category=category,
                            offset=offset,
                            size_bytes=len(payload),
                            sha256=hashlib.sha256(payload).hexdigest(),
                            confidence_score=score,
                            heuristics=heuristics,
                            recovered_path=str(rec_path),
                            recovery_method=METHOD_SIGNATURE,
                            boundary_method=boundary_result.method,
                        )
                    )

                    # Skip past the object we just consumed so its interior is
                    # not rescanned as nested candidates.
                    pos = max(pos, idx + max(1, min(len(payload), len(data) - idx)))

            searched_upto = max(searched_upto, data_start + len(data))
            if progress_callback and total_size > 0:
                progress_callback(scanned, total_size, len(already_recovered) + len(carved))

    counters["bytes_scanned"] = scanned
    return carved


#: Extensions whose container can be physically split across the image.
_ISOBFMF_EXTENSIONS = frozenset({"mp4", "mov", "m4v", "heic", "avif"})


#: How far past the index fragment to look for the media. A card that once held
#: the file contiguously does not move the two fragments far apart, but this is a
#: heuristic, not a proof, and it is reported when it binds.
_REASSEMBLY_WINDOW = 256 * 1024 * 1024


def _try_isobmff_reassembly(src: boundary.ByteSource, offset: int, max_size: int):
    """Reassemble a physically fragmented ISO-BMFF file, if it is one.

    Returns ``(payload, notes)`` or ``None``. ``None`` is returned for an
    ordinary contiguous file, which is the common case and must not pay for the
    search. Never raises: a carver that crashes on unexpected input is worse than
    one that recovers less.
    """
    from s0.carve import isobmff

    try:
        moov = isobmff.find_box_in(src, offset, min(src.size, offset + max_size), b"moov")
        if moov is None:
            return None
        table = isobmff.parse_moov(src.read(moov.start, moov.size), 0)
        if table.fragmented or not table.tracks:
            return None
        t = max(table.tracks, key=lambda tr: tr.sample_count)
        if not t.chunk_offsets or t.media_start <= 0:
            return None

        # Cheap, format-generic fragmentation test: an mdat box header must sit
        # where the table says the media begins.
        mdat_at = src.read(offset + t.media_start - 8, 8)
        if len(mdat_at) == 8 and mdat_at[4:8] == b"mdat":
            return None  # contiguous; nothing to do

        r = isobmff.reassemble_two_fragment(
            src, offset, table, src.size, min(src.size, offset + min(max_size, _REASSEMBLY_WINDOW))
        )
    except (isobmff.BoxError, OSError, ValueError, struct.error):
        return None
    if r is None:
        return None
    return r.payload, r.notes


def _try_fragmented_reassembly(src: boundary.ByteSource, offset: int, max_size: int):
    """Rebuild a *fragmented* ISO-BMFF file: `empty_moov` plus scattered pairs.

    This is the shape a dashcam, a drone or a mobile recorder writes when it
    cannot buffer the whole file, and it is the shape that defeats every
    forward-scanning carver, because the fragments land wherever the
    filesystem finds free space.

    The old path here handled only the two-fragment camera case, where a
    progressive `moov` names the media and the index fragment is followed by a
    gap. A fragmented file has no such index -- the sample table is empty by
    design -- so there was nothing to follow, and the candidate was dropped.

    The fragments are ordered by `mfhd.sequence_number` and cross-checked with
    `tfdt` rather than by position, so their physical arrangement does not
    matter. Every check that could reject the result lives in the reassembly
    module; this function only supplies the volume and translates the answer.
    """
    from s0.carve import reassembly

    window = min(src.size, offset + min(max_size, _REASSEMBLY_WINDOW))
    try:
        fset = reassembly.scan_isobmff_fragments(src, offset, window)
        if len(fset.fragments) < 2:
            return None
        # Only consider a group that contains this candidate's own neighbourhood,
        # so two unrelated files' fragments are not merged into one.
        assembly = reassembly.assemble_file(fset, src)
        if not assembly.ok:
            return None
        ok, notes = reassembly.reparse_assembly(assembly, "isobmff")
        if not ok:
            return None
    except (OSError, ValueError, struct.error, IndexError):
        return None
    return assembly.payload, list(assembly.notes) + notes


def _ts_run_length(window: bytes, off: int, want: int) -> int | None:
    """Count consecutive valid 188-byte transport packets starting at ``off``.

    Returns ``None`` when the window runs out before ``want`` packets can be
    judged, so a candidate near the window edge is passed to the boundary walker
    rather than being rejected on incomplete evidence.
    """
    from s0.carve.boundary import _ts_packet_header

    n = 0
    pos = off
    while n < want:
        if pos + 188 > len(window):
            return None
        parsed = _ts_packet_header(window[pos : pos + 4])
        if parsed is None:
            return n
        _pid, _pusi, afc, _cc = parsed
        if afc in (2, 3):
            # Validated, not used to advance: a transport packet is always 188
            # bytes and the adaptation field is inside it.
            if window[pos + 4] > 183:
                return n
        n += 1
        pos += 188
    return n


def _plausible_header(sig: FileSignature, window: bytes, off: int) -> str | None:
    """Reject an implausible candidate using only the bytes already in memory.

    Returns ``None`` to let the candidate through, or a short reason to drop it.
    Applies only to signatures whose magic is short enough to match almost
    anywhere -- the eight 1- and 2-byte entries. A 4-byte magic is already
    selective enough that adding work per match would cost more than it saves.

    The checks are the format's own rules, evaluated on the window:

    * MPEG-TS: the four-byte transport header must satisfy the reserved-value
      rules from ISO/IEC 13818-1, which reject roughly three quarters of random
      candidates before a single seek.
    * MPEG audio: the frame header must name a valid version, layer and bitrate.
    * BMP: the declared file size must be at least as large as its own header.
    * PE: the DOS header must point at a PE signature, or at least at a readable
      offset inside the window.
    """
    magic = sig.header
    ext = sig.extension
    need = off + max(len(magic), 4)
    if need > len(window):
        return None  # too close to the window edge to judge

    if ext == "ts":
        # One valid header is not enough. A single transport header survives
        # about 28% of random candidates, so after the header check TS was still
        # the largest source of work by a wide margin. The discriminator is a
        # *run* of packets at 188-byte spacing, and the walk has to be
        # adaptation-aware: a stream carrying PCRs does not sit on a fixed
        # stride, and a naive stride check would reject exactly those.
        n = _ts_run_length(window, off, want=8)
        if n is not None and n < 8:
            return f"only {n} consecutive valid 188-byte transport header(s)"
        return None

    if ext == "mp3":
        from s0.carve.boundary import parse_mpeg_frame_header

        hdr = parse_mpeg_frame_header(window[off : off + 4], 0)
        if hdr is None:
            return "not a valid MPEG audio frame header"
        return None

    if ext == "bmp":
        import struct as _struct

        declared = _struct.unpack_from("<I", window, off + 2)[0]
        if declared < 26 or declared > (1 << 31):
            return f"BMP declares an implausible file size of {declared}"
        # Both reserved words are zero in every writer, which costs 2^-32 by
        # chance, and the pixel-data offset must fall inside the declared file.
        res1, res2, data_off = _struct.unpack_from("<HHI", window, off + 6)
        if res1 or res2:
            return "BMP reserved words are not zero"
        if not (14 + 12 <= data_off <= declared):
            return f"BMP pixel data offset {data_off} is outside the {declared}-byte file"
        return None

    if ext in ("exe", "dll"):
        import struct as _struct

        e_lfanew = _struct.unpack_from("<I", window, off + 60)[0]
        if e_lfanew < 64 or e_lfanew > (1 << 22):
            return f"PE e_lfanew of {e_lfanew} cannot point at a PE header"
        pe = off + e_lfanew
        if pe + 4 <= len(window) and window[pe : pe + 4] != b"PE\x00\x00":
            return "e_lfanew does not point at a PE signature"
        return None

    return None


def _carve_one(
    src: boundary.ByteSource,
    offset: int,
    sig: FileSignature,
    extensions: list[str] | None,
    min_confidence: int,
    budget: CarvePolicy | CarveBudget,
    counters: dict[str, Any],
    recovered_hashes: set,
    warnings: list[str],
    allow_guess: bool = False,
    suppression: suppression.SuppressionSet | None = None,
) -> tuple[bytes, boundary.Boundary, int, list[str]] | None:
    """Resolve, validate, read and score one candidate. None == rejected."""
    ext = sig.extension
    if extensions and ext not in {e.lower().lstrip(".") for e in extensions}:
        counters["filtered"] += 1
        return None

    max_size = min(sig.max_size, budget.max_file_bytes if isinstance(budget, CarveBudget) else sig.max_size)

    # Cheap prefilter for low-specificity 2-byte magics.
    if sig.inbuilt is not None:
        head = src.read(offset, max(sig.inbuilt_search_window, len(sig.inbuilt)))
        if sig.inbuilt not in head:
            counters["rejected"] += 1
            counters["rejected_samples"].append(
                RejectedCandidate(
                    offset,
                    ext,
                    f"inbuilt marker {sig.inbuilt!r} is absent from the first "
                    f"{sig.inbuilt_search_window} bytes",
                    "structure",
                )
            )
            return None

    b = boundary.resolve_boundary(src, offset, sig, max_size, allow_max_size_fallback=allow_guess)
    if not b.resolved:
        counters["rejected"] += 1
        counters["rejected_samples"].append(
            RejectedCandidate(offset, ext, b.notes[0] if b.notes else "boundary unresolved", "boundary")
        )
        return None

    size = b.end - offset
    if size < sig.min_size:
        counters["rejected"] += 1
        counters["rejected_samples"].append(
            RejectedCandidate(
                offset, ext, f"resolved {size} B is below the {sig.min_size} B minimum", "boundary"
            )
        )
        return None

    payload = None
    extra_notes: list[str] = []
    if ext in _ISOBFMF_EXTENSIONS:
        # A physically fragmented ISO-BMFF file is not detectable by its length:
        # the index fragment plus whatever follows it adds up to the right size
        # and fills with unrelated evidence, so a contiguous read looks fine.
        # The test is whether the mdat header is where the sample table says the
        # media begins. If it is not, the media is somewhere else on the device.
        rebuilt = _try_isobmff_reassembly(src, offset, max_size)
        if rebuilt is None:
            # A fragmented file has an empty sample table, so the path above
            # declines it. Ordering the pieces by the keys inside them is the
            # only way to place them, so try that before giving up.
            rebuilt = _try_fragmented_reassembly(src, offset, max_size)
        if rebuilt is not None:
            payload, extra_notes = rebuilt
    if payload is None:
        payload = src.read(offset, size)
        if len(payload) < size:
            counters["rejected"] += 1
            counters["rejected_samples"].append(
                RejectedCandidate(offset, ext, "file extends past end of target", "boundary")
            )
            return None

    ok, reason = boundary.validate_structure(payload, ext)
    if not ok:
        counters["rejected"] += 1
        counters["rejected_bytes"] += size
        counters["rejected_samples"].append(RejectedCandidate(offset, ext, reason, "structure"))
        return None

    digest = hashlib.sha256(payload).hexdigest()
    if digest in recovered_hashes:
        counters["duplicate"] += 1
        return None

    if suppression is not None and len(suppression):
        algo = suppression.match(payload)
        if algo is not None:
            # Validated, not guessed at, and already known to the examiner.
            counters["suppressed_known"] = counters.get("suppressed_known", 0) + 1
            counters["suppressed_bytes"] = counters.get("suppressed_bytes", 0) + len(payload)
            counters["rejected_samples"].append(
                RejectedCandidate(
                    offset, ext, f"matches a known {algo} digest in {suppression.source}", "known-file"
                )
            )
            return None

    score, heuristics = score_carved_candidate(
        sig,
        payload,
        has_valid_footer=(sig.footer is not None and sig.footer in payload),
        boundary_method=b.method,
        # Reassembly provenance is part of the evidence record: an examiner has
        # to be able to see that the file was rebuilt from two fragments and how
        # much unrelated evidence lay between them.
        boundary_notes=tuple(b.notes) + tuple(extra_notes),
    )
    if score < min_confidence:
        counters["rejected"] += 1
        counters["rejected_bytes"] += size
        counters["rejected_samples"].append(
            RejectedCandidate(
                offset, ext, f"confidence {score} below the {min_confidence} threshold", "score"
            )
        )
        return None

    counters["accepted"] += 1
    return payload, b, score, heuristics


# --------------------------------------------------------------------------- #
# session entry point
# --------------------------------------------------------------------------- #


def carve_image(
    target_path: str | Path,
    output_dir: str | Path,
    *,
    extensions: list[str] | None = None,
    custom_signatures: list[FileSignature] | None = None,
    min_confidence: int | None = None,
    chunk_size: int | None = None,
    operator_id: str = "op-forensic-01",
    organization: str = "Digital Forensics & Data Sanitization Lab",
    signing_key_path: str | Path | None = None,
    progress_callback: Callable[[int, int, int], None] | None = None,
    generate_certificate: bool = True,
    policy: CarvePolicy | None = None,
    known_hashes: suppression.SuppressionSet | None = None,
    resume: session.CarveSession | None = None,
) -> CarvingSessionSummary:
    """Recover deleted and unallocated files from an image, image file or device.

    Filesystem-native recovery runs first, then signature carving. Every emitted
    artifact has an independently resolved boundary and a validated structure;
    candidates that fail either test are counted and reported, never written.

    `resume` supplies a prior run's state. Offsets it already recovered are
    counted and skipped rather than carved again, and the summary says how many
    were skipped. The skip applies to the *output*, never to the evidence: a
    session records what was found last time, so the bytes are still re-read, and
    a file the session names that is no longer in the output directory is
    reported rather than assumed done.
    """
    target_p = Path(target_path).resolve()
    out_p = Path(output_dir).resolve()
    out_p.mkdir(parents=True, exist_ok=True)

    if not target_p.exists():
        raise FileNotFoundError(f"Target media not found: {target_p}")

    total_size = target_p.stat().st_size if target_p.is_file() else 0
    parts = detect_partitions(target_p)
    fs_types = [p[0] for p in parts if p[0] != "raw"]
    fs_type = ", ".join(sorted(set(fs_types))) if fs_types else "raw"

    if min_confidence is None:
        min_confidence = CarvePolicy().min_confidence

    if policy is None:
        policy = CarvePolicy.for_target(total_size, min_confidence=min_confidence)
    else:
        policy.min_confidence = min_confidence
    if chunk_size:
        policy.scan_chunk_bytes = max(256 * 1024, int(chunk_size))

    budget = CarveBudget(policy=policy)
    # Mixed values: mostly ints, plus `rejected_samples`, a list of
    # RejectedCandidate. It was annotated dict[str, int], which is simply
    # wrong -- hence eight `int has no attribute append` errors that were
    # pointing at a real annotation defect rather than at dead code.
    counters: dict[str, Any] = {
        "candidates": 0,
        "accepted": 0,
        "rejected": 0,
        "rejected_bytes": 0,
        "duplicate": 0,
        "filtered": 0,
        "bytes_recovered": 0,
        "structure_candidates": 0,
        "structure_accepted": 0,
        "structure_filtered": 0,
        "budget_stops": 0,
        "rejected_samples": [],
    }
    warnings: list[str] = []
    recovered_hashes: set = set()
    all_files: list[CarvedFile] = []
    if resume is not None:
        resume.check_against(target_p)
        # A resumed candidate is a duplicate of what the previous run already
        # wrote, so it is seeded into the duplicate set rather than threaded
        # through every carving path as a separate flag. Both paths already
        # consult that set, and one mechanism cannot be forgotten in one of them
        # -- which is exactly how a resume flag ends up applied to the signature
        # carver and not the filesystem one.
        prior = {e.sha256 for e in resume.entries if e.sha256}
        recovered_hashes.update(prior)
        counters["resumed_from_session"] = len(resume.entries)
        for note in session.describe_resume(resume, out_dir=out_p, skipped=len(prior)):
            warnings.append(note)

    # ---- 1. filesystem-native recovery (highest evidentiary value) ----
    journal_timeline: list[dict] = []
    if policy.structure_recovery_enabled:
        all_files, journal_timeline = _recover_from_filesystem(
            target_p,
            out_p,
            parts,
            extensions,
            budget,
            warnings,
            counters,
            recovered_hashes,
            known_hashes,
        )

    # ---- 2. signature carving ----
    active = list(custom_signatures or []) + list(SIGNATURES)
    if extensions:
        norm = {e.lower().lstrip(".") for e in extensions}
        custom_exts = {s.extension.lower().lstrip(".") for s in (custom_signatures or [])}
        active = [s for s in active if s.extension.lower().lstrip(".") in norm | custom_exts]
    if not active:
        warnings.append(
            "No signature set is active for the requested extensions; nothing will be carved by signature."
        )
    elif policy.structure_only:
        warnings.append("--structure-only was set: signature carving was skipped.")

    scanned = 0
    free_space = None
    if active and not policy.structure_only:
        free_space, fs_notes = _resolve_free_space(target_p, parts, total_size, policy)
        warnings.extend(fs_notes)
        try:
            with open(str(target_p), "rb") as fh:
                src = boundary.ByteSource(fh, total_size)
                carved = _scan_signatures(
                    src,
                    target_p,
                    out_p,
                    active,
                    custom_signatures,
                    extensions,
                    min_confidence,
                    budget,
                    counters,
                    recovered_hashes,
                    warnings,
                    all_files,
                    progress_callback,
                    total_size,
                    free_space,
                    known_hashes,
                )
            scanned = counters.pop("bytes_scanned", 0)
            all_files += carved
        except Exception as exc:
            warnings.append(f"Signature carving aborted: {exc}")
            scanned = counters.pop("bytes_scanned", 0)
    else:
        try:
            with open(str(target_p), "rb") as fh:
                fh.seek(0, 2)
                scanned = fh.tell()
        except Exception:
            scanned = total_size
        counters.pop("bytes_scanned", None)

    all_rejected: list[RejectedCandidate] = counters.pop("rejected_samples", [])
    hist: dict[str, int] = {}
    for r in all_rejected:
        hist[r.reason] = hist.get(r.reason, 0) + 1
    rejection_summary = sorted(hist.items(), key=lambda kv: (-kv[1], kv[0]))
    truncated_report = len(all_rejected) > _MAX_REJECTION_SAMPLES
    rejected_samples = all_rejected[:_MAX_REJECTION_SAMPLES]
    del all_rejected

    # ---- 3. manifest certificate ----
    manifest_cert = None
    if not generate_certificate:
        warnings.append(
            "Forensic recovery manifest certificate omitted per operator request (--no-certificate)."
        )
    else:
        key_file: Path | None
        if signing_key_path:
            key_file = Path(signing_key_path)
        else:
            try:
                key_file = resources.demo_private_key()
            except FileNotFoundError:
                key_file = None
        if key_file is not None and key_file.exists():
            try:
                now_iso = cert_mod.now_utc()
                by_method: dict[str, int] = {}
                for c in all_files:
                    by_method[c.recovery_method] = by_method.get(c.recovery_method, 0) + 1
                cert_dict = cert_mod.build_certificate(
                    organization=organization,
                    operator_id=operator_id,
                    tool_name="s0-carve",
                    tool_version=CONFIG.get("version", "3.0.0"),
                    platform="linux",
                    device_id=f"media-{hashlib.sha256(str(target_p).encode()).hexdigest()[:16]}",
                    device_type="image_file",
                    storage_type="IMAGE_FILE",
                    method="FORENSIC_CARVING",
                    nist_category="N/A",
                    pattern="carving",
                    start_time=now_iso,
                    end_time=now_iso,
                    bytes_processed=scanned,
                    capacity_bytes=total_size or scanned,
                    status="success",
                    verification={
                        "method": "per_artifact_boundary_resolution_and_structural_validation",
                        "samples_checked": len(all_files),
                        "attestation": (
                            f"every emitted artifact passed an independently resolved end-of-file "
                            f"and a structural parse; {counters['rejected']} candidates were "
                            f"rejected and are itemised in recovery_index.json"
                        ),
                    },
                    notes=[
                        f"Forensic Carving Session: scanned {scanned} bytes of {target_p.name}.",
                        f"Source filesystem: {fs_type.upper() if fs_type != 'raw' else 'UNALLOCATED / RAW'}.",
                        f"Recovered {len(all_files)} file(s), {counters['bytes_recovered']} bytes.",
                        f"Candidates evaluated: {counters['candidates']}; accepted: {counters['accepted']}; "
                        f"rejected: {counters['rejected']}; duplicates suppressed: {counters['duplicate']}.",
                        "By recovery method: "
                        + ", ".join(f"{k}={v}" for k, v in sorted(by_method.items()))
                        + ".",
                    ]
                    + warnings[:8],
                )
                priv = core_crypto.load_private_pem(key_file)
                manifest_cert = cert_mod.sign_certificate(cert_dict, priv)
            except Exception as exc:
                warnings.append(f"Manifest signing failed: {exc}")
        else:
            warnings.append(
                f"WARNING: Signing key not found at '{key_file}'. "
                "No forensic recovery manifest certificate was generated."
            )

    # ---- 3b. drop findings nested inside another finding ----
    # After both recovery paths, so the result does not depend on which
    # of a nested pair happened to be found first.
    all_files = drop_contained(all_files, counters, out_p)
    if counters.get("contained"):
        warnings.append(
            f"{counters['contained']} candidate(s) lay inside an "
            f"already-recovered extent and were not written a second time"
        )

    # ---- 4. machine-readable index ----
    by_category: dict[str, int] = {}
    for c in all_files:
        by_category[c.category] = by_category.get(c.category, 0) + 1
    by_method: dict[str, int] = {}
    for c in all_files:
        by_method[c.recovery_method] = by_method.get(c.recovery_method, 0) + 1

    summary = CarvingSessionSummary(
        target_path=str(target_p),
        source_filesystem=fs_type,
        total_bytes_scanned=scanned,
        total_candidates_found=counters["candidates"],
        files_recovered=len(all_files),
        carved_files=all_files,
        manifest_certificate=manifest_cert,
        warnings=warnings,
        rejected_candidates=counters["rejected"],
        rejected_bytes=counters["rejected_bytes"],
        bytes_recovered=counters["bytes_recovered"],
        output_budget_bytes=budget.bytes_written,
        budget_stop_reason=budget.stop_reason,
        rejected_samples=rejected_samples,
        by_category=by_category,
        by_method=by_method,
        truncated_report=truncated_report,
        rejection_summary=rejection_summary[:_MAX_REJECTION_REASONS],
        free_space=free_space.summary() if free_space is not None else None,
        allocated_candidates_skipped=counters.get("allocated_candidates_skipped", 0),
        allocated_bytes_skipped=counters.get("allocated_bytes_skipped", 0),
        deleted_names_from_journal=journal_timeline,
        # Files recovered through the filesystem path carry their bytes in memory
        # rather than as an image extent, so they have no range to contribute.
        recovered_extents=bodyfile.normalise(
            [
                (f.offset, f.offset + f.size_bytes - 1)
                for f in all_files
                if f.offset is not None and f.size_bytes
            ]
        ),
        suppressed_known=counters.get("suppressed_known", 0),
        suppressed_known_bytes=counters.get("suppressed_bytes", 0),
        candidates_prefiltered=counters.get("prefiltered", 0),
        resumed_from_session=counters.get("resumed_from_session", 0),
        suppression_note=(known_hashes.describe() if known_hashes is not None else ""),
    )

    index_data = {
        "schema": "s0.recovery-index/1",
        "generated_by": f"s0-carve {CONFIG.get('version', '3.0.0')}",
        "target_path": str(target_p),
        "source_filesystem": fs_type,
        "total_bytes_scanned": scanned,
        "candidates_evaluated": counters["candidates"],
        "files_recovered": len(all_files),
        "bytes_recovered": counters["bytes_recovered"],
        "output_budget_bytes": policy.max_output_bytes,
        "output_budget_used_bytes": budget.bytes_written,
        "budget_stop_reason": budget.stop_reason,
        "candidates_rejected": counters["rejected"],
        "candidate_bytes_discarded": counters["rejected_bytes"],
        "duplicates_suppressed": counters["duplicate"],
        "contained_candidates_dropped": counters.get("contained", 0),
        "resumed_from_session": counters.get("resumed_from_session", 0),
        "filtered_by_extension_filter": counters["filtered"],
        "deleted_names_from_journal": journal_timeline,
        "allocation_aware_search": free_space is not None,
        "free_space": free_space.summary() if free_space is not None else None,
        "allocated_candidates_skipped": counters.get("allocated_candidates_skipped", 0),
        # Reported because the ratio is the honest measure of how much work the
        # in-memory prefilter saved, and an operator tuning --min-confidence or
        # adding a signature needs to see it move.
        "candidates_prefiltered_in_memory": counters.get("prefiltered", 0),
        "suppressed_known_files": counters.get("suppressed_known", 0),
        "suppressed_known_bytes": counters.get("suppressed_bytes", 0),
        "allocated_bytes_skipped": counters.get("allocated_bytes_skipped", 0),
        "by_category": by_category,
        "by_recovery_method": by_method,
        "recovered_files": [
            {
                "file_id": c.file_id,
                "filename": c.filename,
                "extension": c.extension,
                "category": c.category,
                "offset": c.offset,
                "size_bytes": c.size_bytes,
                "sha256": c.sha256,
                "confidence_score": c.confidence_score,
                "recovery_method": c.recovery_method,
                "boundary_method": c.boundary_method,
                "is_fragmented": c.is_fragmented,
                "fragment_count": c.fragment_count,
                "original_name": c.original_name,
                "original_path": c.original_path,
                "deleted_at": c.deleted_at,
                "name_provenance": c.provenance,
                "heuristics": c.heuristics,
            }
            for c in all_files
        ],
        "rejection_summary": [
            {"reason": reason, "count": count} for reason, count in rejection_summary[:_MAX_REJECTION_REASONS]
        ],
        "rejected_candidates_sample": [
            {"offset": r.offset, "extension": r.extension, "stage": r.stage, "reason": r.reason}
            for r in rejected_samples
        ],
        "rejected_candidates_sampled": len(rejected_samples),
        "rejected_candidates_truncated": truncated_report,
        "warnings": warnings,
    }
    try:
        (out_p / "recovery_index.json").write_text(json.dumps(index_data, indent=2) + "\n")
    except OSError as exc:
        warnings.append(f"Could not write recovery_index.json: {exc}")

    return summary


# --------------------------------------------------------------------------- #
# NTFS change journal as corroborating name evidence
# --------------------------------------------------------------------------- #


def _is_contained(start: int, end: int, recovered) -> bool:
    """True when ``[start, end)`` lies inside a range already recovered.

    Two formats can nest, and then the inner one is found on its own: a JPEG
    2000 file opens with a `ftyp` box naming the `jp2 ` brand, so the ISO-BMFF
    walker reads a structurally valid box tree inside a file that has already
    been recovered whole. The bytes are real and the box tree is valid, so
    nothing is *wrong* -- but reporting them a second time as a separate file
    puts the same bytes in the report twice under two names, and a count of
    findings is a number an examiner will read.
    """
    for f in recovered:
        low = f.offset if f.offset is not None else 0
        if low <= start and end <= low + f.size_bytes:
            return True
    return False


def drop_contained(all_files: list[CarvedFile], counters: dict[str, int], out_p: Path) -> list[CarvedFile]:
    """Remove findings whose bytes lie inside another finding's extent.

    Two formats nest, and then the inner one is found on its own: a JPEG 2000
    file opens with a `ftyp` box naming the `jp2 ` brand, so the ISO-BMFF walker
    reads a structurally valid box tree inside a file that has already been
    recovered whole. The bytes are real and the box tree is valid, so nothing is
    *wrong* -- but reporting them again as a separate file puts the same bytes
    in the report twice under two names, and a count of findings is a number an
    examiner will read.

    This has to be a post-pass rather than a check at write time. Which of the
    two files is found first depends on scan order, and a check that consults
    only what has already been written silently misses the inner file whenever
    it happens to come first -- which is exactly the case that showed up.
    """
    spans = [
        (f.offset if f.offset is not None else 0, f.size_bytes, f) for f in all_files if f.size_bytes > 0
    ]
    contained = set()
    for i, (off_i, len_i, file_i) in enumerate(spans):
        for j, (off_j, len_j, _file_j) in enumerate(spans):
            if i == j or len_j <= 0:
                continue
            # Only drop the strictly smaller one, and only on an exact
            # containment, so two files that merely overlap both survive.
            if len_i < len_j and off_j <= off_i and off_i + len_i <= off_j + len_j:
                contained.add(id(file_i))
                break
    if not contained:
        return all_files
    kept: list[CarvedFile] = []
    for f in all_files:
        if id(f) in contained:
            counters["contained"] = counters.get("contained", 0) + 1
            counters["rejected_bytes"] = counters.get("rejected_bytes", 0) + f.size_bytes
            if f.recovered_path:
                try:
                    Path(f.recovered_path).unlink()
                except OSError:
                    pass
            continue
        kept.append(f)
    return kept


def _read_journal_evidence(target_p: Path, part_offset: int, warnings: list[str]) -> list | None:
    """Read the NTFS change journal, if this partition has one.

    The journal is a separate kind of evidence from the MFT: it names files whose
    records are gone, and dates the deletion. It is reported alongside the
    recovered artifacts rather than written out, because a name is not a file --
    but a name with a deletion time, and no other source, is often the only
    evidence left that a document ever existed.
    """
    try:
        records = read_usn_journal(target_p, partition_offset=part_offset, warnings=warnings)
    except Exception as exc:
        warnings.append(f"NTFS change journal could not be read: {exc}")
        return None
    if not records:
        return None
    return build_timeline(records)


def _merge_journal_evidence(timeline: list, names_seen: dict[str, int], warnings: list[str]) -> list[dict]:
    """Record which journal names are new, and how many corroborated the MFT.

    A name that appears both in a deleted MFT record and in the journal is
    corroborated by two independent on-disk structures, which is worth stating.
    A name that appears only in the journal had its record reused or zeroed, and
    that distinction is the whole reason the journal is read.
    """
    rows: list[dict] = []
    for entry in timeline:
        if not entry.name or entry.name in (".", ".."):
            continue
        if not entry.establishes_named_object:
            continue
        corroborated = entry.name in names_seen
        names_seen.setdefault(entry.name, entry.event_count)
        rows.append(
            {
                "name": entry.name,
                "mft_entry": entry.mft_entry,
                "parent_mft_entry": entry.parent_mft_entry,
                "created_at": entry.created_at,
                "deleted_at": entry.deleted_at,
                "was_deleted": entry.was_deleted,
                "renamed_from": entry.renamed_from,
                "is_directory": entry.is_directory,
                "event_count": entry.event_count,
                "reasons": entry.reasons,
                "last_usn": entry.last_usn,
                "corroborated_by_mft": corroborated,
                "content_recovered": False,
            }
        )
    if rows:
        matched = sum(1 for r in rows if r["corroborated_by_mft"])
        only = len(rows) - matched
        detail = f"{matched} corroborated by an MFT record" if matched else ""
        if only:
            detail += (
                f"; {only} named by the journal alone" if detail else f"{only} named by the journal alone"
            )
        warnings.append(
            f"NTFS change journal: {len(rows)} deleted name(s) recovered, {detail}. "
            f"These are names and times only -- the content of a journal-named file "
            f"is not itself in the journal, so no bytes are recovered from it."
        )
    return rows
