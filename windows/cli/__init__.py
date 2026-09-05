"""TrustWipe Windows Native CLI Module."""

from .trustwipe_eraser import (
    GENERIC_READ,
    GENERIC_WRITE,
    WIN32_FIND_STREAM_DATA,
    WinFileEraseResult,
    detect_windows_filesystem,
    enumerate_ntfs_streams_win32,
    erase_batch_windows,
    erase_folder_windows,
    erase_single_file_windows,
    scrub_alternate_data_streams,
    win32_clear_attributes,
    win32_flush_buffers,
)

__all__ = [
    "GENERIC_READ",
    "GENERIC_WRITE",
    "WIN32_FIND_STREAM_DATA",
    "WinFileEraseResult",
    "detect_windows_filesystem",
    "enumerate_ntfs_streams_win32",
    "erase_batch_windows",
    "erase_folder_windows",
    "erase_single_file_windows",
    "scrub_alternate_data_streams",
    "win32_clear_attributes",
    "win32_flush_buffers",
]
