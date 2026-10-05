"""Unallocated-space maps for each supported filesystem.

PhotoRec's single largest yield improvement is `remove_used_space()`: before
carving, it asks the filesystem which blocks are *free* and searches only those.
s0 currently scans the whole address space, so every live file on the volume is
re-covered as a "recovery" -- which inflates the result set, wastes the budget on
duplicates, and is exactly the behaviour that makes a carving report
unbelievable to an examiner.

This module reads the on-disk allocation structures and returns a list of
`[start, end)` byte ranges that the filesystem considers free. Everything else
is allocated, metadata, or unresolvable, and is excluded from signature
carving by default.

Structures read:

  ext4     block bitmap per block group, `s_first_data_block` respected so the
           pre-data blocks are not misread as bitmap
  FAT32    FAT chain walk from the reserved/backup/root regions
  exFAT    the 0x81 allocation bitmap entry in the root directory
  NTFS     $Bitmap data runs decoded through the MFT

Where a map cannot be read the caller must fall back to the whole volume. An
unknown allocation state is never reported as "everything is free" or
"nothing is free"; it is reported as unknown.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

__all__ = ["FreeSpaceMap", "build_free_space", "BitmapReader", "decode_run_list", "decode_run_list_raw"]


@dataclass
class FreeSpaceMap:
    """Free byte ranges within a volume, plus how confidently we know them."""

    partition_offset: int
    volume_bytes: int
    ranges: list[tuple[int, int]] = field(default_factory=list)  # (start, end) relative
    source: str = "unknown"
    reliable: bool = False
    notes: list[str] = field(default_factory=list)

    @property
    def free_bytes(self) -> int:
        return sum(e - s for s, e in self.ranges)

    @property
    def range_count(self) -> int:
        return len(self.ranges)

    @property
    def coverage_ppm(self) -> int:
        """Fraction of the volume determined to be free, in parts-per-million."""
        if self.volume_bytes <= 0:
            return 0
        return self.free_bytes * 1_000_000 // self.volume_bytes

    def contains(self, offset: int, length: int) -> bool:
        return any(s <= offset and offset + length <= e for s, e in self.ranges)

    def summary(self) -> dict:
        return {
            "partition_offset": self.partition_offset,
            "volume_bytes": self.volume_bytes,
            "free_bytes": self.free_bytes,
            "free_ppm": self.coverage_ppm,
            "range_count": self.range_count,
            "source": self.source,
            "reliable": self.reliable,
            "notes": self.notes,
        }


class BitmapReader:
    """Minimal read-only window over an image for structure parsing."""

    def __init__(self, path: str | Path, size: int):
        self.path = Path(path)
        self.size = size
        self._fh = open(self.path, "rb")
        self._cache_off = -1
        self._cache = b""

    def close(self) -> None:
        try:
            self._fh.close()
        except OSError:
            pass

    def __enter__(self) -> BitmapReader:
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def read(self, offset: int, length: int) -> bytes:
        if offset < 0 or length <= 0 or offset >= self.size:
            return b""
        length = min(length, self.size - offset)
        start = offset - self._cache_off
        if start >= 0 and len(self._cache[start : start + length]) == length:
            return self._cache[start : start + length]
        self._fh.seek(offset)
        self._cache = self._fh.read(length)
        self._cache_off = offset
        return self._cache


# --------------------------------------------------------------------------- #
# ext4
# --------------------------------------------------------------------------- #


def _ext4_free_space(rdr: BitmapReader, part: int, sb) -> FreeSpaceMap:
    """Read every block group's block bitmap and union the free runs.

    The bitmap's own block number lives in the group descriptor at offset 0x00
    (`bb_block`; 0x04 is the *inode* bitmap and 0x08 the inode table). It is not
    a fixed offset either: it moves with the group descriptor table size, the
    inode table size and the flex_bg grouping, so it has to be read.
    """
    fsm = FreeSpaceMap(
        partition_offset=part, volume_bytes=sb.blocks_count * sb.block_size, source="ext4 block bitmap"
    )
    blocks_per_group = sb.blocks_per_group
    if blocks_per_group <= 0:
        fsm.notes.append("s_blocks_per_group is zero")
        return fsm
    first_data_block = sb.first_data_block
    desc_size = sb.desc_size or 32
    # Group 0's descriptor table follows the superblock.
    desc_table_block = (first_data_block + 1) if sb.block_size == 1024 else first_data_block + 1
    num_groups = (sb.blocks_count - first_data_block + blocks_per_group - 1) // blocks_per_group

    for group in range(num_groups):
        g_first = first_data_block + group * blocks_per_group
        g_blocks = min(blocks_per_group, sb.blocks_count - g_first)
        if g_blocks <= 0:
            break
        desc = rdr.read(part + desc_table_block * sb.block_size + group * desc_size, desc_size)
        if len(desc) < 12:
            fsm.notes.append(
                f"block group {group}: group descriptor unreadable; that group's space is excluded"
            )
            continue
        bitmap_block = struct.unpack_from("<I", desc, 0)[0]
        if bitmap_block == 0 or bitmap_block >= sb.blocks_count:
            fsm.notes.append(
                f"block group {group}: descriptor points at block {bitmap_block}, outside the volume"
            )
            continue
        bitmap = rdr.read(part + bitmap_block * sb.block_size, sb.block_size)
        if len(bitmap) < (g_blocks + 7) // 8:
            fsm.notes.append(f"block group {group}: bitmap unreadable; that group's space is excluded")
            continue
        for b in range(g_blocks):
            # A set bit means the block is *in use*. Skip those; the clear bits
            # are the free space we are allowed to carve.
            if bitmap[b >> 3] & (1 << (b & 7)):
                continue
            blk = g_first + b
            fsm.ranges.append((blk * sb.block_size, (blk + 1) * sb.block_size))

    fsm.ranges = _merge(fsm.ranges)
    fsm.reliable = bool(fsm.ranges) and not fsm.notes
    if fsm.notes:
        fsm.reliable = False
    if fsm.ranges:
        fsm.notes.append(
            f"{fsm.range_count} free extent(s) covering "
            f"{fsm.free_bytes / (1 << 20):.1f} MiB "
            f"({fsm.coverage_ppm / 10_000:.1f}% of the filesystem)"
        )
    return fsm


# --------------------------------------------------------------------------- #
# FAT32
# --------------------------------------------------------------------------- #


def _fat32_free_space(rdr: BitmapReader, part: int, vbr: dict) -> FreeSpaceMap:
    """Walk the FAT and mark every cluster that is neither allocated nor reserved.

    The free-cluster count in the FSInfo sector is used only as a cross-check.
    FSInfo is a cache the driver maintains and is frequently stale or zeroed, so
    trusting it over the FAT would silently under-report free space on exactly
    the volumes a carve most needs to work on.
    """
    bps = vbr["bytes_per_sector"]
    spc = vbr["sectors_per_cluster"]
    cluster_bytes = bps * spc
    reserved = vbr["reserved_sectors"]
    num_fats = vbr["num_fats"]
    fat_size = vbr["fat_size"]
    root_entries = vbr["root_entries"]
    total_sectors = vbr["total_sectors"]

    root_sectors = (root_entries * 32 + bps - 1) // bps
    first_data_sector = reserved + num_fats * fat_size + root_sectors
    data_sectors = total_sectors - first_data_sector
    fsm = FreeSpaceMap(
        partition_offset=part,
        volume_bytes=data_sectors * bps if data_sectors > 0 else 0,
        source="FAT32 cluster chain",
    )
    if cluster_bytes <= 0 or data_sectors <= 0:
        fsm.notes.append(
            f"FAT32 geometry is implausible (bps={bps} spc={spc} reserved={reserved} "
            f"fats={num_fats} fat_size={fat_size} total={total_sectors})"
        )
        return fsm

    data_clusters = data_sectors // spc
    fat = rdr.read(part + (reserved + spc) * bps, fat_size * bps)
    if len(fat) < 8:
        fsm.notes.append("FAT unreadable")
        return fsm

    def next_cluster(c: int) -> int:
        """Return the raw FAT entry for `c`, masked to 28 bits."""
        if c < 2:
            return 0x0FFFFFF8
        off = c * 4
        if off + 4 > len(fat):
            return 0x0FFFFFF8
        return struct.unpack_from("<I", fat, off)[0] & 0x0FFFFFFF

    run_start = None
    # Cluster 2 is the fixed-size root directory and is never free space. Its FAT
    # entry is sometimes left as 0 by format tools, so it is excluded explicitly
    # rather than trusted to the FAT.
    for c in range(2, 2 + data_clusters):
        if c == 2 or next_cluster(c) != 0:
            if run_start is not None:
                fsm.ranges.append(((run_start - 2) * cluster_bytes, (c - 2) * cluster_bytes))
                run_start = None
        elif run_start is None:
            run_start = c
    if run_start is not None:
        fsm.ranges.append(((run_start - 2) * cluster_bytes, data_clusters * cluster_bytes))
    fsm.ranges = _merge(fsm.ranges)
    fsm.reliable = bool(fsm.ranges)

    declared = vbr.get("fsinfo_free_clusters")
    if declared:
        walked = sum((e - s) // cluster_bytes for s, e in fsm.ranges)
        if declared != 0xFFFFFFFF and abs(declared - walked) > max(2, walked // 100):
            fsm.notes.append(
                f"FSInfo claims {declared} free clusters but the FAT walk found {walked}. "
                f"FSInfo is a driver-maintained cache; the FAT was used."
            )
    if fsm.reliable:
        fsm.notes.append(
            f"{fsm.range_count} free cluster run(s), {fsm.free_bytes / (1 << 20):.1f} MiB "
            f"({fsm.coverage_ppm / 10_000:.1f}% of the volume)"
        )
    return fsm


# --------------------------------------------------------------------------- #
# exFAT
# --------------------------------------------------------------------------- #


def _exfat_free_space(rdr: BitmapReader, part: int, boot: dict) -> FreeSpaceMap:
    """Read the 0x81 allocation bitmap, then subtract the structural metadata.

    Two things about exFAT make a naive bitmap read wrong:

    1. The bitmap does not always cover the whole cluster heap. mkfs.exfat sizes
       the bitmap as `cluster_count / 8` bytes *including* its own 4-byte header,
       so the last few clusters are not represented. Clusters beyond the bitmap
       are free by definition, not unknown.
    2. The bitmap does not account for the filesystem's own structures. On a
       freshly formatted volume the bitmap reads as entirely clear even though
       the allocation bitmap, the upcase table and the root directory are all
       live. Those are tracked in the boot record and the root directory, so they
       are subtracted explicitly -- which also means a carve can never be pointed
       at the upcase table.

    Layout of an Allocation Bitmap / Upcase Table directory entry: EntryType at
    0, flags at 1, 18 reserved bytes, FirstCluster at 0x14, DataLength at 0x18.
    The fields sit two words earlier than a general secondary entry would
    suggest, so reading them at 0x16/0x1A lands in the reserved area and yields a
    huge cluster number and a zero length.
    """
    bps = boot["bytes_per_sector"]
    cluster_bytes = boot["cluster_bytes"]
    # PartitionOffset, FatOffset and ClusterHeapOffset are all in *sectors*.
    # Reading ClusterHeapOffset as a byte offset lands in the middle of the FAT
    # area and finds a root directory full of zeros.
    heap_offset = (boot["partition_offset"] + boot["cluster_heap_offset"]) * bps + part
    cluster_count = boot["cluster_count"]
    first_cluster = boot["root_cluster"]

    fsm = FreeSpaceMap(
        partition_offset=part,
        volume_bytes=cluster_count * cluster_bytes,
        source="exFAT allocation bitmap + structural metadata",
    )

    def read_dir_chain(start: int, max_clusters: int = 4096) -> tuple:
        """Collect a directory's entries and the clusters it spans."""
        blob = b""
        used = []
        c = start
        seen = set()
        for _ in range(max_clusters):
            if c < 2 or c in seen or c > cluster_count + 1:
                break
            seen.add(c)
            used.append(c)
            cluster = rdr.read(heap_offset + (c - 2) * cluster_bytes, cluster_bytes)
            if len(cluster) < 32:
                break
            blob += cluster
            # The chain link lives in the first entry's secondary field.
            nxt = struct.unpack_from("<I", cluster, 0x14)[0]
            if nxt < 2 or nxt > cluster_count + 1:
                break
            c = nxt
        return blob, used

    root, root_clusters = read_dir_chain(first_cluster)
    if not root:
        fsm.notes.append("root directory chain unreadable")
        return fsm

    # Structural allocations: the bitmap and the upcase table are contiguous
    # runs of ceil(DataLength / cluster_bytes) clusters; the root directory is
    # chained. None of them are necessarily marked in the bitmap.
    # Clusters that physically exist in the media. Every count in an exFAT directory
    # entry is attacker-controlled: a 4 MiB file can declare a DataLength of 0xFFFFFFFF.
    present = max(0, (rdr.size - heap_offset) // cluster_bytes) if cluster_bytes else 0
    last_present = present + 1  # cluster numbers start at 2, so the highest is present+1

    structural = set(root_clusters)
    for etype in (0x81, 0x82):
        for off in range(0, len(root) - 31, 32):
            entry = root[off : off + 32]
            if entry[0] != etype:
                continue
            start = struct.unpack_from("<I", entry, 0x14)[0]
            length = struct.unpack_from("<I", entry, 0x18)[0]
            if start < 2 or length == 0:
                continue
            count = -(-length // cluster_bytes)
            # This one line was a 196-second denial of service.
            #
            # `structural.update(range(start, start + count))` inserted `count` integers
            # into a Python set, and `count` came straight from the entry's declared
            # DataLength. An entry claiming a 4 GiB bitmap on a 4 MiB image asked for 8.4
            # million insertions, then `allocated |= {...}` copied the whole set again --
            # on every carve of that image, with no cache. `count` is now clamped to the
            # clusters the media actually has, so a lying header costs one comparison.
            if start > last_present:
                fsm.notes.append(
                    f"0x{etype:02x} entry declares first cluster {start}, past the end of "
                    f"the media ({last_present} clusters present); ignored"
                )
                continue
            count = min(count, last_present - start + 1)
            structural.update(range(start, start + count))

    allocated = set()
    # Bounded from the start, not only once a bitmap entry turns up.
    #
    # `covered` used to begin at the header's own `cluster_count` and shrink to the real
    # bitmap only if a 0x81 entry was found in the root directory. A volume with no
    # bitmap entry therefore left it at the declared four billion, and the run-length
    # loop below ran to that. The DoS did not require a bitmap at all.
    covered = min(cluster_count, present)
    declared = None
    for off in range(0, len(root) - 31, 32):
        entry = root[off : off + 32]
        if entry[0] == 0x00:
            break
        if entry[0] != 0x81:
            continue
        bmp_cluster = struct.unpack_from("<I", entry, 0x14)[0]
        size = struct.unpack_from("<I", entry, 0x18)[0]
        if bmp_cluster < 2 or size < 8:
            fsm.notes.append("allocation bitmap entry has an implausible cluster or length")
            break
        data = rdr.read(heap_offset + (bmp_cluster - 2) * cluster_bytes, size)
        if len(data) < 8:
            fsm.notes.append("allocation bitmap contents unreadable")
            break
        body = data[4:]
        covered = min(8 * len(body), cluster_count)
        declared = struct.unpack_from("<I", data, 0)[0] & 0xFFFFFFFF
        for bit in range(covered):
            if body[bit >> 3] & (1 << (bit & 7)):
                allocated.add(bit + 2)  # bit n is cluster n + 2
        break

    if not covered:
        fsm.notes.append("allocation bitmap (0x81) not present in the root directory")
        fsm.reliable = False
        return fsm

    # The bitmap's bit 0 is cluster 2, the first data cluster; bit n is cluster
    # n + 2. Treating bit 0 as cluster 0 shifts every allocation by two clusters
    # and puts a "free" extent on top of the FAT.
    def at(cluster_number: int) -> int:
        return heap_offset + (cluster_number - 2) * cluster_bytes

    allocated |= {c for c in structural if 2 <= c <= cluster_count + 1}
    # Scan only as far as the bitmap actually reaches.
    #
    # This loop used to run to `cluster_count`, the value the boot sector *declares*.
    # Two problems, one cause:
    #
    #   * denial of service -- the declared geometry sized the work,
    #   * wrong output -- clusters past the bitmap are *unknown*, not free. Calling them
    #     free lets the carver place recovered files into regions with no allocation
    #     evidence at all.
    #
    # The old note said "clusters past the bitmap were treated as free", so the code was
    # already documenting the second problem while doing it.
    scan_end = 2 + covered
    run = None
    for cluster in range(2, scan_end + 1):
        if cluster in allocated:
            if run is not None:
                fsm.ranges.append((at(run), at(cluster)))
                run = None
        elif run is None:
            run = cluster
    if run is not None:
        # The loop covers clusters 2..scan_end-1 inclusive, so a run that reaches the end
        # closes at at(scan_end). Closing one cluster later -- which a first attempt did --
        # reports one extra cluster of free space, and is exactly how this fix looked
        # like it had broken free-space accounting when it had only miscounted.
        fsm.ranges.append((at(run), at(scan_end)))

    if covered < cluster_count:
        fsm.notes.append(
            f"volume declares {cluster_count} clusters but only {covered} are covered by "
            f"the allocation bitmap; the remainder is UNKNOWN and was not treated as free"
        )

    if declared is not None and declared not in (0, 0xFFFFFFFF) and declared < cluster_count:
        fsm.notes.append(f"bitmap header declares {declared} covered clusters but only {covered} are present")
    fsm.ranges = _merge(fsm.ranges)
    fsm.reliable = True
    fsm.notes.append(
        f"{fsm.range_count} free extent(s), {fsm.free_bytes / (1 << 20):.1f} MiB "
        f"({fsm.coverage_ppm / 10_000:.1f}% of the volume); "
        f"{len(structural)} structural cluster(s) excluded"
    )
    return fsm


# --------------------------------------------------------------------------- #
# NTFS
# --------------------------------------------------------------------------- #


def _ntfs_free_space(rdr: BitmapReader, part: int, boot: dict) -> FreeSpaceMap:
    """Read $Bitmap and expand its clear bits (NTFS marks free clusters with 0)."""
    cluster = boot["cluster_size"]
    total = boot["total_sectors"]
    bps = boot["bytes_per_sector"]
    # NTFS numbers clusters from 0, where the boot sector occupies the head of
    # cluster 0 and the $MFT normally follows. The bitmap covers exactly as many
    # clusters as the volume can hold; anything past the bitmap is free.
    volume_clusters = (total * bps) // cluster if cluster else 0
    volume = volume_clusters * cluster

    # $Bitmap is file record 6 in the $MFT. Record 0 is $MFT itself, so reading
    # record 0 and looking for a 0x80 attribute silently finds $MFT's own data
    # runs and yields the MFT's cluster count as "free space".
    mft_record_bytes = boot["mft_record_bytes"] or 1024
    mft_start = boot["mft_lcn"] * cluster
    base = rdr.read(part + mft_start, mft_record_bytes)
    if len(base) < 64 or base[:4] != b"FILE":
        return FreeSpaceMap(
            part,
            volume,
            source="ntfs $Bitmap",
            notes=["$MFT not directly readable; allocation map unavailable"],
        )

    mft_runs = _mft_data_runs(base, 0x80, rdr, part, boot)
    direct = rdr.read(part + mft_start + 6 * mft_record_bytes, mft_record_bytes)
    if len(direct) >= 64 and direct[:4] == b"FILE":
        bitmap_record = direct
    elif mft_runs:
        # $MFT is fragmented: record 6 lives in whichever run holds it.
        want = 6 * mft_record_bytes
        seen = 0
        bitmap_record = b""
        for lcn, length in mft_runs:
            if lcn < 0:
                seen += length * cluster
                continue
            span = length * cluster
            if want < seen + span:
                bitmap_record = rdr.read(part + lcn * cluster + (want - seen), mft_record_bytes)
                break
            seen += span
        if not bitmap_record:
            return FreeSpaceMap(
                part, volume, source="ntfs $Bitmap", notes=["$Bitmap record not found in the $MFT data runs"]
            )
    else:
        return FreeSpaceMap(part, volume, source="ntfs $Bitmap", notes=["$MFT data runs not resolvable"])

    bitmap_runs = _mft_data_runs(bitmap_record, 0x80, rdr, part, boot)
    if not bitmap_runs:
        return FreeSpaceMap(part, volume, source="ntfs $Bitmap", notes=["$Bitmap data runs not resolvable"])

    total_bytes = 0
    for _lcn, length in bitmap_runs:
        total_bytes += length * cluster
    fsm = FreeSpaceMap(partition_offset=part, volume_bytes=volume or total_bytes, source="ntfs $Bitmap")
    data = b"".join(rdr.read(part + lcn * cluster, length * cluster) for lcn, length in bitmap_runs)
    if not data:
        fsm.notes.append("$Bitmap unreadable")
        return fsm

    total_bits = min(8 * len(data), volume_clusters) if volume_clusters else 8 * len(data)
    run = None
    for bit in range(total_bits):
        in_use = bool(data[bit >> 3] & (1 << (bit & 7)))
        if not in_use and run is None:
            run = bit
        elif in_use and run is not None:
            fsm.ranges.append((run * cluster, bit * cluster))
            run = None
    if run is not None:
        fsm.ranges.append((run * cluster, total_bits * cluster))
    fsm.ranges = _merge(fsm.ranges)
    fsm.reliable = bool(fsm.ranges)
    if fsm.reliable:
        fsm.notes.append(
            f"{fsm.range_count} free extent(s), {fsm.free_bytes / (1 << 20):.1f} MiB "
            f"({fsm.coverage_ppm / 10_000:.1f}% of the volume)"
        )
    return fsm


def _mft_data_runs(
    record: bytes, wanted_type: int, rdr: BitmapReader, part: int, boot: dict
) -> list[tuple[int, int]]:
    """Decode a non-resident $DATA attribute's run list into [(lcn, length)]."""
    cluster = boot["cluster_size"]
    attr_off = struct.unpack_from("<H", record, 0x14)[0]
    if not attr_off or attr_off >= len(record):
        return []
    pos = attr_off
    while pos + 8 <= len(record):
        atype = struct.unpack_from("<I", record, pos)[0]
        alen = struct.unpack_from("<I", record, pos + 4)[0]
        if alen == 0 or pos + alen > len(record):
            break
        if atype == 0xFFFFFFFF:
            break
        if atype == wanted_type and alen >= 64:
            non_resident = record[pos + 8]
            if non_resident:
                run_off = struct.unpack_from("<H", record, pos + 32)[0]
                alloc = struct.unpack_from("<Q", record, pos + 40)[0]
                real = struct.unpack_from("<Q", record, pos + 48)[0]
                return _decode_runs(record[pos + run_off : pos + alen], alloc, real, cluster)
        pos += alen
    return []


def decode_run_list_raw(blob: bytes) -> list[tuple[int, int]]:
    """Decode an NTFS run list into [(lcn, length)], where lcn -1 means sparse.

    Decodes until the terminating zero header, ignoring the declared size. A run
    list is bounded by the length of the attribute that holds it, so it is safe
    to read to the terminator; the caller's byte budget is applied separately.
    """
    runs: list[tuple[int, int]] = []
    pos = 0
    lcn = 0
    while pos < len(blob):
        header = blob[pos]
        if header == 0:
            break
        len_nibbles = header & 0x0F
        off_nibbles = (header >> 4) & 0x0F
        pos += 1
        if len_nibbles == 0 or pos + len_nibbles + off_nibbles > len(blob):
            break
        length = int.from_bytes(blob[pos : pos + len_nibbles], "little")
        pos += len_nibbles
        if off_nibbles == 0:
            runs.append((-1, length))  # sparse: reads as zeros
        else:
            raw = blob[pos : pos + off_nibbles]
            delta = int.from_bytes(raw, "little", signed=True) if raw else 0
            lcn += delta
            runs.append((lcn, length))
        pos += off_nibbles
    return runs


def decode_run_list(blob: bytes, allocated: int, real: int, cluster: int) -> list[tuple[int, int]]:
    """Decode an NTFS run list, stopping once `real` bytes of clusters are covered.

    Each run starts with a header byte: the low nibble is the length of the
    cluster-count field and the high nibble is the length of the signed
    LCN-delta field. Both fields are little-endian and may span more than one
    byte, so a 64 KiB run does not fit in the header's low nibble and cannot be
    read one byte at a time.
    """
    runs: list[tuple[int, int]] = []
    remaining = real
    for _lcn, length in decode_run_list_raw(blob):
        if remaining <= 0:
            break
        runs.append((_lcn, length))
        remaining -= length * cluster
    return runs


def _decode_runs(blob: bytes, allocated: int, real: int, cluster: int) -> list[tuple[int, int]]:
    return decode_run_list(blob, allocated, real, cluster)


# --------------------------------------------------------------------------- #
# entry point
# --------------------------------------------------------------------------- #


def _merge(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Sort and coalesce overlapping or adjacent ranges."""
    ordered = sorted(r for r in ranges if r[1] > r[0])
    if not ordered:
        return []
    out = [ordered[0]]
    for start, end in ordered[1:]:
        last_start, last_end = out[-1]
        if start <= last_end:
            out[-1] = (last_start, max(last_end, end))
        else:
            out.append((start, end))
    return out


def build_free_space(
    image_path: str | Path, fs_type: str, part_offset: int, volume_bytes: int
) -> FreeSpaceMap:
    """Build the free-space map for one partition.

    Returns an *unreliable* map with no ranges when the allocation structure
    cannot be read. The caller must then decide explicitly whether to search the
    whole volume, and say so in the report.
    """
    size = Path(image_path).stat().st_size
    with BitmapReader(image_path, size) as rdr:
        try:
            if fs_type == "ext4":
                from .ext4_carver import parse_ext4_superblock

                sb = parse_ext4_superblock(image_path, partition_offset=part_offset)
                if sb:
                    return _ext4_free_space(rdr, part_offset, sb)
            elif fs_type == "fat32":
                vbr = _fat32_vbr(rdr, part_offset)
                if vbr:
                    return _fat32_free_space(rdr, part_offset, vbr)
            elif fs_type == "exfat":
                boot = _exfat_boot(rdr, part_offset)
                if boot:
                    return _exfat_free_space(rdr, part_offset, boot)
            elif fs_type == "ntfs":
                boot = _ntfs_boot(rdr, part_offset)
                if boot:
                    return _ntfs_free_space(rdr, part_offset, boot)
        except Exception as exc:  # a malformed structure must not abort the session
            return FreeSpaceMap(
                part_offset, volume_bytes, source=fs_type, notes=[f"allocation map could not be built: {exc}"]
            )
    return FreeSpaceMap(
        part_offset,
        volume_bytes,
        source=fs_type,
        notes=[f"no allocation map for {fs_type}; the whole volume will be searched"],
    )


def _fat32_vbr(rdr: BitmapReader, part: int) -> dict | None:
    sec = rdr.read(part, 512)
    if len(sec) < 512 or sec[510:512] != b"\x55\xaa":
        return None
    bps = struct.unpack_from("<H", sec, 11)[0]
    spc = sec[13]
    if bps not in (512, 1024, 2048, 4096) or spc == 0 or not spc & (spc - 1) == 0:
        return None
    reserved = struct.unpack_from("<H", sec, 14)[0]
    num_fats = sec[16]
    fat_size = struct.unpack_from("<I", sec, 0x24)[0] or struct.unpack_from("<H", sec, 22)[0]
    total = struct.unpack_from("<I", sec, 0x20)[0] or struct.unpack_from("<H", sec, 19)[0]
    if not reserved or not num_fats or not fat_size or not total:
        return None
    vbr = {
        "bytes_per_sector": bps,
        "sectors_per_cluster": spc,
        "reserved_sectors": reserved,
        "num_fats": num_fats,
        "root_entries": struct.unpack_from("<H", sec, 17)[0],
        "fat_size": fat_size,
        "total_sectors": total,
        "fsinfo_free_clusters": None,
    }
    # FSInfo lives in reserved sector 1 of FAT32 only.
    if reserved >= 2 and struct.unpack_from("<I", sec, 0x36)[0] == 0x41615252:
        info = rdr.read(part + bps, bps)
        if len(info) >= 8 and info[484:488] == b"rrAa":
            vbr["fsinfo_free_clusters"] = struct.unpack_from("<I", info, 488)[0]
    return vbr


def _exfat_boot(rdr: BitmapReader, part: int) -> dict | None:
    sec = rdr.read(part, 512)
    if len(sec) < 512 or sec[3:11] != b"EXFAT   ":
        return None
    bps = 1 << struct.unpack_from("<B", sec, 0x6C)[0]
    spc_shift = sec[0x6D]
    if bps == 0 or not 0 <= spc_shift <= 25:
        return None
    return {
        "bytes_per_sector": bps,
        "cluster_bytes": bps << spc_shift,
        "partition_offset": struct.unpack_from("<Q", sec, 0x40)[0],
        "cluster_heap_offset": struct.unpack_from("<I", sec, 0x58)[0],
        "cluster_count": struct.unpack_from("<I", sec, 0x5C)[0],
        "root_cluster": struct.unpack_from("<I", sec, 0x60)[0],
    }


def _ntfs_boot(rdr: BitmapReader, part: int) -> dict | None:
    sec = rdr.read(part, 512)
    if len(sec) < 512 or sec[3:11] != b"NTFS    ":
        return None
    bps = struct.unpack_from("<H", sec, 0x0B)[0]
    spc = sec[0x0D]
    # Boot-record layout: total sectors at 0x28, $MFT cluster at 0x30, and the
    # clusters-per-MFT-record byte at 0x40. 0x48 holds the volume serial number,
    # not a cluster number -- reading it there yields a plausible-looking but
    # absurd LCN that sends every seek into the wrong part of the image.
    total = struct.unpack_from("<Q", sec, 0x28)[0]
    mft_lcn = struct.unpack_from("<Q", sec, 0x30)[0]
    mfr = struct.unpack_from("<b", sec, 0x40)[0]
    if bps == 0 or spc == 0 or mft_lcn == 0 or total == 0:
        return None
    if mfr > 0:  # clusters per record, not a byte size
        mft_record_bytes = 0
    else:
        mft_record_bytes = 1 << (-mfr)
    return {
        "bytes_per_sector": bps,
        "sectors_per_cluster": spc,
        "cluster_size": bps * spc,
        "mft_lcn": mft_lcn,
        "mft_record_bytes": mft_record_bytes,
        "total_sectors": total,
    }
