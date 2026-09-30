# Windows platform — validated vs. not validated

Development environment: all Windows-specific code paths are structurally tested
on Linux via mocked Win32 ctypes stubs. On genuine Windows deployments, the
real kernel32.dll APIs are invoked. This file documents what has and hasn't been
verified on actual Windows hardware.

## Fully exercised (mock-verified on Linux, code path correct by inspection)

| Capability | Evidence |
|---|---|
| Overwrite wipe of files / folders | `windows/cli/tests/test_win_cli.py` + `tests/cli/test_cross_platform_eraser.py`; real bytes written, unlinked, read-back zero confirmation |
| Secondary partition wiping (`D:`, `E:`) | `test_win_cli.py::test_win_cli_wipe_partition_success`; volume lock & dismount via Win32 `FSCTL_DISMOUNT_VOLUME`, raw sector overwrite, sampled readback |
| USB / Pen drive raw wiping (`\\.\PhysicalDriveX`) | `test_win_cli.py::test_win_cli_wipe_drive_main`; MBR/GPT and raw sector destruction, 32-sample verification |
| Operating system drive safety guardrails | `test_win_cli.py::test_win_cli_wipe_safety_refusal`; hard rejection of active Windows `C:` volume and Disk 0 without force |
| Win32 Alternate Data Stream (ADS) enumeration | `enumerate_ntfs_streams_win32()` dynamically calls `FindFirstStreamW`/`FindNextStreamW` via ctypes; mock-verified in `test_cross_platform_eraser.py::test_win32_ads_mock_enumeration` |
| ADS scrubbing | `scrub_alternate_data_streams()` overwrites + unlinks each ADS; falls back to common stream names (`:Zone.Identifier`, `:SummaryInformation`, etc.) when dynamic enum unavailable |
| FlushFileBuffers hardware flush | `win32_flush_buffers()` calls `kernel32.FlushFileBuffers()` via `msvcrt.get_osfhandle()`; falls back to `os.fsync()` on non-Windows |
| Win32 attribute clearing | `win32_clear_attributes()` strips Read-Only/Hidden/System via `SetFileAttributesW`; chmod fallback |
| Ed25519 signed certificate | `erase_batch_windows()` and `wipe_drive_or_partition_windows()` issue schema-compliant certificates; verified by `s0-verify` |
| ReFS Copy-on-Write detection | `detect_windows_filesystem()` queries `GetVolumeInformationW`; warns operator when target resides on ReFS |

## Coded, NOT executed against the real thing

| Capability | What exists | Why untested | How to validate for real |
|---|---|---|---|
| FlushFileBuffers on real NTFS | Full code path including `msvcrt.get_osfhandle()` | No Windows machine in dev environment; `ctypes.windll` is absent on Linux | Run on genuine Windows 10/11 with NTFS volume |
| Real ADS scrubbing on NTFS | Dynamic `FindFirstStreamW` enumeration + overwrite + unlink | Requires genuine NTFS with ADS-bearing files | Create test files with `notepad test.txt:secret.txt`, then run eraser |
| Physical ReFS CoW semantics | Warning generated, but no verification that old blocks are actually unreachable | Requires Server 2016+ with ReFS-formatted volume | Format a test volume as ReFS, plant markers, erase, then scan raw blocks |
| Windows batch launcher (.bat / .ps1) | `s0-eraser.bat` and `s0-eraser.ps1` shell out to Python | No Windows machine | Run on genuine Windows with Python installed |

## Known behavioral caveats (true on real Windows too)

- **Flash storage (SSD/NVMe):** FTL wear leveling may retain old data in retired
  blocks. Overwrite provides NIST 800-88 "Clear" assurance, not "Purge". For Purge
  on SSDs, use the block wiper with ATA Security Erase or NVMe Sanitize (Linux-only).
- **NTFS compression / sparse files:** Overwrite targets the logical file extent.
  Compressed clusters may be reallocated during overwrite; the NTFS journal preserves
  metadata until flushed.
- **NTFS journal ($LogFile):** File creation/deletion metadata may persist in the
  journal even after successful file erasure. Full-device wipe is the only way to
  guarantee journal destruction.
- **Volume Shadow Copies / System Restore:** Previous file versions may exist in
  VSS snapshots. Operators must `vssadmin delete shadows /for=C:` separately.
- **Recycle Bin:** s0 bypasses the Recycle Bin entirely (direct unlink).
- **Encrypted volumes (BitLocker):** Overwrite operates on the decrypted view.
  Original ciphertext blocks are inaccessible without the BitLocker recovery key,
  providing defense-in-depth.

## Whole-Drive Sanitization: Bootable Live USB

Due to active system file locks, the pagefile, and VSS shadows, wiping the primary `C:` drive of a Windows PC requires booting into an independent environment.

- **Making Bootable USB on Windows:**
  - Build ISO locally using Docker Desktop or WSL2: `.\tools\build_iso.ps1`
  - Download verified release ISO: `irm https://s0-install.pages.dev/download-iso-ps1 | iex`
  - Write to USB using **Rufus** (select **"Write in DD Image mode"**) or **Ventoy**.
- Detailed guide: [Live ISO Guide](../../guides/live-iso.md).
