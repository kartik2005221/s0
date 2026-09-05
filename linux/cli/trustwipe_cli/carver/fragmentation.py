"""TrustWipe Fragmented File Reconstruction Engine.

Provides multi-fragment forensic reassembly capabilities:
1. Multi-run non-resident cluster reassembly for NTFS ($MFT runlists).
2. Multi-extent hierarchical tree reassembly for ext4 inodes.
3. Bifragment / cluster-gap heuristic reassembly for raw signature carving
   (bridging discontiguous cluster fragments for JPEG, PNG, PDF, and ZIP files).
"""

from __future__ import annotations

import io
import math
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple

from .scoring import calculate_shannon_entropy


@dataclass
class FragmentInfo:
    offset: int
    length: int
    sequence: int
    entropy: float = 0.0


@dataclass
class ReconstructedStream:
    total_size: int
    fragments: List[FragmentInfo]
    data: bytes
    is_fragmented: bool = False
    validation_notes: List[str] = field(default_factory=list)


def reassemble_cluster_runs(
    runs: List[Tuple[int, int]],
    disk_file,
    cluster_size: int,
    partition_offset: int = 0,
    target_size: Optional[int] = None,
) -> ReconstructedStream:
    """Reassemble data across a list of (cluster_index, cluster_count) runs."""
    fragments: List[FragmentInfo] = []
    chunks: List[bytes] = []
    remaining = target_size if target_size is not None else float("inf")
    seq = 0

    saved_pos = disk_file.tell() if hasattr(disk_file, "tell") else 0
    try:
        for clus_idx, clus_count in runs:
            if remaining <= 0:
                break

            run_bytes_to_read = clus_count * cluster_size
            if target_size is not None:
                run_bytes_to_read = min(remaining, run_bytes_to_read)

            if clus_idx >= 0:
                byte_offset = partition_offset + clus_idx * cluster_size
                disk_file.seek(byte_offset)
                chunk = disk_file.read(run_bytes_to_read)
            else:
                # Sparse run
                byte_offset = -1
                chunk = bytes(run_bytes_to_read)

            chunks.append(chunk)
            chunk_entropy = calculate_shannon_entropy(chunk) if chunk else 0.0
            fragments.append(
                FragmentInfo(
                    offset=byte_offset,
                    length=len(chunk),
                    sequence=seq,
                    entropy=round(chunk_entropy, 3),
                )
            )
            remaining -= len(chunk)
            seq += 1
    finally:
        if hasattr(disk_file, "seek"):
            disk_file.seek(saved_pos)

    full_data = b"".join(chunks)
    if target_size is not None:
        full_data = full_data[:target_size]

    return ReconstructedStream(
        total_size=len(full_data),
        fragments=fragments,
        data=full_data,
        is_fragmented=(len(fragments) > 1),
        validation_notes=[f"Reassembled {len(fragments)} fragments ({len(full_data)} bytes)"],
    )


def reconstruct_bifragment_stream(
    head_data: bytes,
    disk_file,
    search_start_offset: int,
    footer_pattern: bytes,
    cluster_size: int = 4096,
    max_search_bytes: int = 4 * 1024 * 1024,
    max_file_size: int = 10 * 1024 * 1024,
) -> Optional[ReconstructedStream]:
    """Attempt bifragment heuristic reconstruction when head fragment lacks footer.

    Scans forward unallocated clusters within search window to locate matching footer
    and bridges the two fragments with entropy continuity verification.
    """
    if not footer_pattern or not head_data or not disk_file:
        return None

    # If head already contains footer, it's not bifragmented
    if footer_pattern in head_data:
        return None

    head_entropy = calculate_shannon_entropy(head_data)
    saved_pos = disk_file.tell()
    try:
        disk_file.seek(search_start_offset)
        search_buf = disk_file.read(max_search_bytes)
        if not search_buf or footer_pattern not in search_buf:
            return None

        footer_pos_in_buf = search_buf.find(footer_pattern)
        footer_end_in_buf = footer_pos_in_buf + len(footer_pattern)

        # Align to cluster boundary for the start of second fragment
        # The second fragment spans up to footer_end_in_buf
        tail_data = search_buf[:footer_end_in_buf]
        if not tail_data:
            return None

        tail_entropy = calculate_shannon_entropy(tail_data)
        # Entropy continuity check: fragments of same file have comparable entropy
        entropy_diff = abs(head_entropy - tail_entropy)
        if entropy_diff > 2.5:
            # Drastically different entropy (e.g. compressed image vs text or zeros)
            return None

        combined_data = head_data + tail_data
        if len(combined_data) > max_file_size:
            return None

        fragments = [
            FragmentInfo(offset=0, length=len(head_data), sequence=0, entropy=round(head_entropy, 3)),
            FragmentInfo(
                offset=search_start_offset,
                length=len(tail_data),
                sequence=1,
                entropy=round(tail_entropy, 3),
            ),
        ]

        return ReconstructedStream(
            total_size=len(combined_data),
            fragments=fragments,
            data=combined_data,
            is_fragmented=True,
            validation_notes=[
                f"Bifragment reassembly successful: 2 fragments bridged ({len(combined_data)} bytes)",
                f"Entropy delta: {entropy_diff:.2f} bits/byte",
            ],
        )
    except Exception:
        return None
    finally:
        disk_file.seek(saved_pos)
