"""Structure-Based NTFS Filesystem Recovery Engine.

Parses Master File Table ($MFT) directly from raw images/block devices:
  - Boot sector detection (OEM ID 'NTFS    ')
  - MFT record parsing with resident and single-run non-resident $DATA streams
  - $FILE_NAME attribute UTF-16LE extraction
  - Identification and recovery of unallocated / deleted file records
"""

from __future__ import annotations

import os
import struct

from . import mft as mft_mod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional


NTFS_OEM_ID = b"NTFS    "
MFT_RECORD_MAGIC = b"FILE"
ATTR_FILE_NAME = 0x30
ATTR_DATA = 0x80
ATTR_END_MARKER = 0xFFFFFFFF


@dataclass
class NtfsBootSector:
    oem_id: str
    bytes_per_sector: int
    sectors_per_cluster: int
    cluster_size: int
    total_sectors: int
    mft_start_cluster: int
    mft_record_size: int


@dataclass
class NtfsRecoveredFile:
    record_num: int
    filename: str
    size_bytes: int
    is_resident: bool
    is_deleted: bool
    data: Optional[bytes] = None
    fragment_count: int = 1
    runs: List[tuple[int, int]] = field(default_factory=list)


def parse_ntfs_boot_sector(
    image_path: str | Path,
    partition_offset: int = 0,
) -> Optional[NtfsBootSector]:
    """Parse NTFS boot sector at partition_offset."""
    try:
        with open(image_path, "rb") as f:
            f.seek(partition_offset)
            boot_data = f.read(512)
            if len(boot_data) < 512:
                return None

            oem_id = boot_data[3:11]
            if oem_id != NTFS_OEM_ID:
                return None

            bytes_per_sector = struct.unpack_from("<H", boot_data, 0x0B)[0]
            if bytes_per_sector == 0 or (bytes_per_sector & (bytes_per_sector - 1)) != 0:
                bytes_per_sector = 512

            sectors_per_cluster = boot_data[0x0D]
            if sectors_per_cluster == 0:
                sectors_per_cluster = 8

            cluster_size = bytes_per_sector * sectors_per_cluster
            total_sectors = struct.unpack_from("<Q", boot_data, 0x28)[0]
            mft_start_cluster = struct.unpack_from("<q", boot_data, 0x30)[0]

            c_mft = struct.unpack_from("<b", boot_data, 0x40)[0]
            if c_mft < 0:
                mft_record_size = 1 << abs(c_mft)
            else:
                mft_record_size = c_mft * cluster_size

            if mft_record_size <= 0 or mft_record_size > 65536:
                mft_record_size = 1024

            return NtfsBootSector(
                oem_id=oem_id.decode("ascii", errors="ignore").strip(),
                bytes_per_sector=bytes_per_sector,
                sectors_per_cluster=sectors_per_cluster,
                cluster_size=cluster_size,
                total_sectors=total_sectors,
                mft_start_cluster=mft_start_cluster,
                mft_record_size=mft_record_size,
            )
    except Exception:
        return None


def parse_mft_record_bytes(
    rec_bytes: bytes,
    disk_file=None,
    cluster_size: int = 4096,
    partition_offset: int = 0,
) -> Optional[NtfsRecoveredFile]:
    """Parse single MFT record buffer (resident & single-run non-resident DATA)."""
    if len(rec_bytes) < 1024 or rec_bytes[0:4] != MFT_RECORD_MAGIC:
        return None

    flags = struct.unpack_from("<H", rec_bytes, 0x16)[0]
    is_allocated = bool(flags & 0x01)
    is_directory = bool(flags & 0x02)
    if is_directory:
        return None

    record_num = struct.unpack_from("<I", rec_bytes, 0x2C)[0]
    first_attr_offset = struct.unpack_from("<H", rec_bytes, 0x14)[0]

    filename: Optional[str] = None
    file_data: Optional[bytes] = None
    real_size: int = 0
    is_resident: bool = False

    offset = first_attr_offset
    while offset + 8 <= len(rec_bytes):
        attr_type = struct.unpack_from("<I", rec_bytes, offset)[0]
        if attr_type == ATTR_END_MARKER or attr_type == 0:
            break
        attr_len = struct.unpack_from("<I", rec_bytes, offset + 4)[0]
        if attr_len <= 0 or offset + attr_len > len(rec_bytes):
            break

        non_resident = rec_bytes[offset + 8]

        if attr_type == ATTR_FILE_NAME and non_resident == 0:
            val_len = struct.unpack_from("<I", rec_bytes, offset + 16)[0]
            val_offset = struct.unpack_from("<H", rec_bytes, offset + 20)[0]
            fn_payload = rec_bytes[offset + val_offset : offset + val_offset + val_len]
            if len(fn_payload) >= 0x42:
                name_len = fn_payload[0x40]
                name_bytes = fn_payload[0x42 : 0x42 + name_len * 2]
                try:
                    decoded_name = name_bytes.decode("utf-16le")
                    if not filename or len(decoded_name) > len(filename):
                        filename = decoded_name
                except Exception:
                    pass

        elif attr_type == ATTR_DATA:
            name_len = rec_bytes[offset + 9]
            if name_len == 0:  # Default unnamed primary $DATA stream
                if non_resident == 0:
                    val_len = struct.unpack_from("<I", rec_bytes, offset + 16)[0]
                    val_offset = struct.unpack_from("<H", rec_bytes, offset + 20)[0]
                    file_data = bytes(rec_bytes[offset + val_offset : offset + val_offset + val_len])
                    real_size = len(file_data)
                    is_resident = True
                else:
                    # Non-resident multi-fragment runlist reconstruction
                    is_resident = False
                    runlist_offset = struct.unpack_from("<H", rec_bytes, offset + 32)[0]
                    real_size = struct.unpack_from("<Q", rec_bytes, offset + 48)[0]
                    runlist_data = rec_bytes[offset + runlist_offset :]

                    runs: List[tuple[int, int]] = []
                    r_idx = 0
                    current_lcn = 0
                    while r_idx < len(runlist_data):
                        b = runlist_data[r_idx]
                        if b == 0:
                            break
                        len_size = b & 0x0F
                        off_size = (b >> 4) & 0x0F
                        r_idx += 1
                        if r_idx + len_size + off_size > len(runlist_data):
                            break

                        run_len = int.from_bytes(
                            runlist_data[r_idx : r_idx + len_size], byteorder="little", signed=False
                        )
                        r_idx += len_size

                        if off_size > 0:
                            lcn_delta = int.from_bytes(
                                runlist_data[r_idx : r_idx + off_size], byteorder="little", signed=True
                            )
                            r_idx += off_size
                            current_lcn += lcn_delta
                            runs.append((current_lcn, run_len))
                        else:
                            # Sparse run
                            runs.append((-1, run_len))

                    fragment_count = len(runs)
                    if runs and disk_file:
                        saved_pos = disk_file.tell()
                        try:
                            chunks = []
                            remaining_bytes = real_size
                            for lcn, r_len in runs:
                                if remaining_bytes <= 0:
                                    break
                                bytes_in_run = min(remaining_bytes, r_len * cluster_size)
                                if lcn >= 0:
                                    disk_byte_offset = partition_offset + lcn * cluster_size
                                    disk_file.seek(disk_byte_offset)
                                    raw_read = disk_file.read(bytes_in_run)
                                    chunks.append(raw_read)
                                else:
                                    chunks.append(bytes(bytes_in_run))
                                remaining_bytes -= bytes_in_run
                            raw_combined = b"".join(chunks)
                            file_data = raw_combined[:real_size] if real_size > 0 else raw_combined
                        except Exception:
                            pass
                        finally:
                            disk_file.seek(saved_pos)

        offset += attr_len

    if file_data is not None or real_size > 0:
        clean_name = filename or f"ntfs_record_{record_num:05d}.bin"
        return NtfsRecoveredFile(
            record_num=record_num,
            filename=clean_name,
            size_bytes=len(file_data) if file_data is not None else real_size,
            is_resident=is_resident,
            is_deleted=(not is_allocated),
            data=file_data,
            fragment_count=fragment_count if not is_resident else 1,
            runs=runs if not is_resident else [],
        )

    return None


def scan_ntfs_deleted_files(
    image_path: str | Path,
    max_records: int = 2000,
    include_allocated: bool = False,
    partition_offset: int = 0,
) -> List[NtfsRecoveredFile]:
    """Scan NTFS $MFT on disk image and recover deleted file entries."""
    boot = parse_ntfs_boot_sector(image_path, partition_offset=partition_offset)
    if not boot:
        return []

    recovered: List[NtfsRecoveredFile] = []
    try:
        with open(image_path, "rb") as f:
            mft_offset = partition_offset + boot.mft_start_cluster * boot.cluster_size

            for rec_idx in range(max_records):
                # Explicitly seek to record index to ensure stream integrity
                rec_offset = mft_offset + rec_idx * boot.mft_record_size
                f.seek(rec_offset)
                rec_bytes = f.read(boot.mft_record_size)
                if len(rec_bytes) < boot.mft_record_size:
                    break

                if rec_bytes[0:4] == MFT_RECORD_MAGIC:
                    parsed = parse_mft_record_bytes(
                        rec_bytes, disk_file=f, cluster_size=boot.cluster_size, partition_offset=partition_offset
                    )
                    if parsed:
                        if parsed.is_deleted or include_allocated:
                            recovered.append(parsed)
                elif rec_bytes[0:4] == bytes(4):
                    continue
    except Exception:
        pass
    return recovered


# --------------------------------------------------------------------------- #
# deleted-record recovery built on the mft primitives
# --------------------------------------------------------------------------- #


@dataclass
class NtfsDeletedEntry:
    """One deleted file, as it can still be described from its MFT record.

    A deleted record is not blanked. Its $FILE_NAME still holds the original
    name, its run list still points at whatever clusters it held, and its
    $STANDARD_INFORMATION still carries the moment the record was last changed --
    which for a deleted record is the deletion. This is the only place the
    original name survives once the directory entry is gone, which is why
    record-level recovery beats blind carving by the length of a filename.
    """
    record_num: int
    sequence_number: int
    name: str
    path: str
    parent_record: Optional[int]
    size_bytes: int
    data: Optional[bytes]
    fragment_count: int
    is_resident: bool
    mft_changed: Optional[float] = None
    created: Optional[float] = None
    modified: Optional[float] = None
    accessed: Optional[float] = None
    fixup_verified: bool = True
    content_caveat: Optional[str] = None
    recovered_from_satellite: bool = False
    # Byte offset of the file's first cluster, so a report can point at where
    # the content lives rather than at an unrelated MFT record slot.
    first_data_offset: Optional[int] = None

    @property
    def is_restorable(self) -> bool:
        return self.data is not None and self.content_caveat is None


def _mft_extents(fh, boot: NtfsBootSector, partition_offset: int) -> List[tuple]:
    """The cluster runs that make up the $MFT itself.

    $MFT is an ordinary non-resident file and is not guaranteed to be
    contiguous. Walking `mft_start + n * record_size` finds the first handful of
    records and then silently yields nothing, which looks exactly like an empty
    volume. The first record's own run list is the only correct way to find the
    rest.
    """
    start = partition_offset + boot.mft_start_cluster * boot.cluster_size
    fh.seek(start)
    first = fh.read(boot.mft_record_size)
    rec = mft_mod.parse_mft_record(first, sector_size=boot.bytes_per_sector)
    if not rec:
        return []
    for attr in rec.attributes:
        if attr.type == mft_mod.ATTR_DATA and attr.is_primary_stream:
            return list(attr.runs)
    return []


def _iter_mft_records(fh, boot: NtfsBootSector, partition_offset: int,
                     runs: List[tuple]) -> "Iterator[bytes]":
    """Yield MFT record buffers in order, following the $MFT's own extents."""
    rs = boot.mft_record_size
    per_run = boot.cluster_size // rs if rs else 0
    if per_run <= 0:
        return
    for lcn, length in runs:
        if lcn < 0:
            continue
        for i in range(length):
            offset = partition_offset + (lcn + i) * boot.cluster_size
            for j in range(per_run):
                fh.seek(offset + j * rs)
                yield fh.read(rs)


def _iter_mft_records_contiguous(fh, boot: NtfsBootSector, partition_offset: int,
                                 limit_bytes: int) -> "Iterator[bytes]":
    """Walk the MFT assuming it is contiguous from its first cluster.

    Only used when record 0 is unreadable, which happens when the first MFT
    record is among the casualties of a crash. Records are still yielded
    individually and each is verified on its own terms, so the result is
    incomplete but not wrong -- and it is reported as incomplete.
    """
    rs = boot.mft_record_size
    end = partition_offset + limit_bytes
    offset = partition_offset + boot.mft_start_cluster * boot.cluster_size
    while offset + rs <= end:
        fh.seek(offset)
        record = fh.read(rs)
        if not record:
            return
        yield record
        offset += rs


def _reconstruct(rec, fh, boot: NtfsBootSector, partition_offset: int,
                 max_bytes: int) -> "tuple":
    """Read a record's primary stream back off the media.

    Returns (data, fragment_count, caveat, first_data_offset). `caveat` is set
    when the on-disk bytes are not the file's contents -- compressed, encrypted
    or sparse -- in which case nothing is returned rather than something wrong.
    """
    caveat = rec.cannot_restore_reason
    if caveat:
        return None, 0, caveat, None

    primary = None
    for attr in rec.attributes:
        if attr.type == mft_mod.ATTR_DATA and attr.is_primary_stream:
            primary = attr
            break
    if primary is None:
        return None, 0, None, None   # size may survive in $FILE_NAME, content does not

    if not primary.non_resident:
        return bytes(primary.resident_value), 1, None, None

    runs = list(primary.runs)
    if not runs:
        return None, 0, None, None
    size = min(primary.real_size or max_bytes, max_bytes)
    spans = mft_mod.runs_to_byte_spans(runs, boot.cluster_size, size)
    data = mft_mod.read_data(spans, fh, partition_offset, size)
    first = next((lcn * boot.cluster_size for lcn, _ in runs if lcn >= 0), None)
    return (data or None), len([r for r in runs if r[1] > 0]), None, first


def _build_path(rec, names: Dict[int, str], depth: int = 0) -> str:
    """Reconstruct a full path by walking parent references.

    A deleted record's parent directory is usually still alive, so the path
    usually resolves. When the parent is gone too, the walk stops and the
    remaining component is reported with its record number rather than guessed
    at, because a plausible-looking wrong path is worse than an honest gap.
    """
    parts = [rec.name() or f"record_{rec.record_num}"]
    seen = {rec.record_num}
    parent = rec.parent()
    while parent and depth < 32:
        pnum = parent[0]
        if pnum in seen or pnum == 5:
            break
        seen.add(pnum)
        name = names.get(pnum)
        if not name:
            parts.append(f"<record {pnum} not found>")
            break
        parts.append(name)
        depth += 1
        parent_rec = names.get(("ref", pnum))
        if isinstance(parent_rec, tuple):
            parent = parent_rec
    return "\\".join(reversed(parts))


def scan_ntfs_deleted_records(
    image_path: str | Path,
    partition_offset: int = 0,
    max_bytes_per_file: int = 64 * 1024 * 1024,
    max_records: int = 200_000,
    include_allocated: bool = False,
    include_system: bool = False,
    warnings: Optional[List[str]] = None,
) -> List[NtfsDeletedEntry]:
    """Recover deleted files from the $MFT, with their original names.

    Records are visited through the $MFT's own extents rather than by assuming
    it is contiguous, and every record has its update sequence array undone
    before it is parsed. Deleted files are returned newest-first by the time the
    record last changed, which is the moment of deletion and the only ordering
    an examiner actually wants.
    """
    boot = parse_ntfs_boot_sector(image_path, partition_offset=partition_offset)
    if not boot:
        return []
    if warnings is None:
        warnings = []

    out: List[NtfsDeletedEntry] = []
    try:
        with open(image_path, "rb") as fh:
            runs = _mft_extents(fh, boot, partition_offset)
            if runs:
                buffers = _iter_mft_records(fh, boot, partition_offset, runs)
            else:
                # Record 0 is damaged or absent. Fall back to a contiguous walk so
                # the records that are still intact are not lost, and say so.
                warnings.append(
                    "NTFS record 0 could not be read, so the extent of the $MFT is "
                    "unknown. Records were read from the first cluster only; any "
                    "that were relocated when the $MFT was extended are missing "
                    "from this result.")
                size = Path(image_path).stat().st_size
                buffers = _iter_mft_records_contiguous(
                    fh, boot, partition_offset,
                    size - partition_offset - boot.mft_start_cluster * boot.cluster_size)

            records: Dict[int, mft_mod.MftRecord] = {}
            names: Dict[int, str] = {}
            parents: Dict[int, tuple] = {}
            order: List[int] = []

            seen = 0
            for buf in buffers:
                seen += 1
                if seen > max_records:
                    break
                if not buf or len(buf) < 48 or buf[:4] != mft_mod.MFT_RECORD_MAGIC:
                    continue
                rec = mft_mod.parse_mft_record(buf, sector_size=boot.bytes_per_sector)
                if not rec or rec.record_num in records:
                    continue
                records[rec.record_num] = rec
                order.append(rec.record_num)
                if rec.name():
                    names[rec.record_num] = rec.name()
                parent = rec.parent()
                if parent:
                    parents[rec.record_num] = parent

            for rec_num in order:
                rec = records[rec_num]
                if rec.is_directory:
                    continue
                if rec.record_num in mft_mod.SYSTEM_RECORDS and not include_system:
                    continue
                if rec.allocated and not include_allocated:
                    continue
                if not rec.name():
                    continue

                caveat = rec.cannot_restore_reason
                data = None
                fragments = 0
                satellite = False
                first_offset = None
                if not caveat:
                    data, fragments, caveat, first_offset = _reconstruct(
                        rec, fh, boot, partition_offset, max_bytes_per_file)
                    if data is None:
                        # Follow $ATTRIBUTE_LIST: the real $DATA may live in a
                        # satellite record, which is how large files are stored.
                        for sat_num in mft_mod.satellite_records(rec):
                            sat = records.get(sat_num)
                            if not sat:
                                continue
                            mft_mod.merge_satellite(rec, sat)
                            data, fragments, caveat, first_offset = _reconstruct(
                                rec, fh, boot, partition_offset, max_bytes_per_file)
                            satellite = True
                            if data is not None:
                                break

                path = _build_path(rec, names)
                entry = rec.primary_name() or {}
                out.append(NtfsDeletedEntry(
                    record_num=rec.record_num,
                    sequence_number=rec.sequence_number,
                    name=rec.name(),
                    path=path,
                    parent_record=(rec.parent() or (None, None))[0],
                    size_bytes=rec.real_size or len(data or b""),
                    data=data,
                    fragment_count=max(1, fragments),
                    is_resident=any(not a.non_resident for a in rec.attributes
                                    if a.type == mft_mod.ATTR_DATA),
                    mft_changed=rec.mft_changed,
                    created=rec.created,
                    modified=rec.modified,
                    accessed=rec.accessed,
                    fixup_verified=rec.fixup_verified,
                    content_caveat=caveat or rec.cannot_restore_reason,
                    recovered_from_satellite=satellite,
                    first_data_offset=(None if first_offset is None
                                       else partition_offset + first_offset),
                ))
    except Exception:
        return out

    # Newest deletion first, then by record number so the order is deterministic.
    out.sort(key=lambda e: (-(e.mft_changed or 0), e.record_num))
    return out
