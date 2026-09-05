"""TrustWipe macOS Native CLI Module."""

from .trustwipe_eraser import (
    F_FULLFSYNC,
    MacDriveWipeResult,
    MacFileEraseResult,
    check_macos_wipe_safety,
    detect_macos_filesystem,
    erase_batch_macos,
    erase_folder_macos,
    erase_single_file_macos,
    get_macos_target_size,
    macos_clear_attributes,
    macos_full_fsync,
    unmount_macos_target,
    wipe_drive_or_partition_macos,
)

__all__ = [
    "F_FULLFSYNC",
    "MacDriveWipeResult",
    "MacFileEraseResult",
    "check_macos_wipe_safety",
    "detect_macos_filesystem",
    "erase_batch_macos",
    "erase_folder_macos",
    "erase_single_file_macos",
    "get_macos_target_size",
    "macos_clear_attributes",
    "macos_full_fsync",
    "unmount_macos_target",
    "wipe_drive_or_partition_macos",
]
