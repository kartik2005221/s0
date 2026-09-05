"""TrustWipe macOS Native CLI Module."""

from .trustwipe_eraser import (
    MacFileEraseResult,
    detect_macos_filesystem,
    erase_batch_macos,
    erase_folder_macos,
    erase_single_file_macos,
    macos_clear_attributes,
    macos_full_fsync,
)

__all__ = [
    "MacFileEraseResult",
    "detect_macos_filesystem",
    "erase_batch_macos",
    "erase_folder_macos",
    "erase_single_file_macos",
    "macos_clear_attributes",
    "macos_full_fsync",
]
