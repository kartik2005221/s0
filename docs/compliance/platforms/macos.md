# macOS platform — validated vs. not validated

Development environment: all macOS/Darwin-specific code paths are structurally
tested on Linux via mocked fcntl/xattr stubs. On genuine macOS deployments, the
real Darwin kernel APIs are invoked. This file documents what has and hasn't been
verified on actual Apple hardware.

## Fully exercised (mock-verified on Linux, code path correct by inspection)

| Capability | Evidence |
|---|---|
| Overwrite wipe of files / folders | `macos/cli/tests/test_mac_cli.py` + `tests/cli/test_cross_platform_eraser.py`; real bytes written, unlinked, read-back zero confirmation |
| USB / Pen drive raw wiping (`/dev/rdiskX`) | `test_mac_cli.py::test_mac_cli_wipe_drive_main`; unmount via `diskutil`, character device raw overwrite, 32-sample verification |
| Secondary partition wiping (`/dev/rdiskXsY`) | `test_mac_cli.py::test_mac_cli_wipe_partition_success`; volume unmount, raw block wipe, hardware cache flush |
| Operating system drive safety guardrails | `test_mac_cli.py::test_mac_cli_wipe_safety_refusal`; hard rejection of macOS boot disk (`disk0`) and active `/` mounts without force |
| Extended attribute (xattr) clearing | `macos_clear_attributes()` shells out to `xattr -c`; verified via mock in tests |
| F_FULLFSYNC hardware cache flush | `macos_full_fsync()` calls `fcntl.fcntl(fd, 51, 0)` on Darwin; falls back to `os.fsync()` on non-Darwin |
| APFS CoW detection | `detect_macos_filesystem()` parses `mount` output; warns operator when target resides on APFS |
| Ed25519 signed certificate | `erase_batch_macos()` and `wipe_drive_or_partition_macos()` issue schema-compliant certificates; verified by `s0-verify` |
| Directory entry obfuscation | Filename randomized before unlinking to prevent directory-entry-level forensic recovery |
| Timestamp zeroing | File timestamps reset to epoch 0 before unlinking |

## Coded, NOT executed against the real thing

| Capability | What exists | Why untested | How to validate for real |
|---|---|---|---|
| F_FULLFSYNC on real APFS | Full code path via `fcntl.fcntl(fd, 51, 0)` | No macOS machine in dev environment | Run on genuine macOS 12+ with internal APFS volume |
| Real xattr removal on APFS | `xattr -c` invocation | Requires genuine macOS with quarantine-bearing files | Download a file via Safari (creates `com.apple.quarantine`), then erase |
| HFS+ journal interaction | Detection via `mount` output parsing | No HFS+ volumes available | Test on macOS with HFS+ external drive |
| Time Machine snapshot persistence | APFS CoW warning issued, but snapshots not deleted | Requires `tmutil` and root access | Run `tmutil listlocalsnapshots /`, erase files, verify snapshot still contains old data |

## Known behavioral caveats (true on real macOS too)

- **APFS Copy-on-Write:** All writes to APFS allocate new blocks; the original data
  blocks persist until the filesystem reclaims free space. s0 issues an
  explicit CoW warning in the sanitization certificate. For guaranteed destruction,
  use full-volume wipe from the bootable ISO.
- **APFS snapshots:** Time Machine creates automatic local snapshots that preserve
  file states. Erasing a file does NOT erase it from existing snapshots. Operators
  must run `tmutil deletelocalsnapshots <date>` or `tmutil thinlocalsnapshots /`
  to purge snapshot-preserved copies.
- **System Integrity Protection (SIP):** On macOS 10.11+, SIP prevents modification
  of system-protected files even as root. s0 cannot erase files under
  `/System`, `/usr`, or `/Library` without disabling SIP from Recovery Mode.
- **Flash storage (Apple Silicon / T2 chip):** All modern Macs use soldered NVMe
  SSDs with hardware encryption (T2 or Secure Enclave). For NIST "Purge" assurance,
  use macOS Recovery → `Disk Utility → Erase` which performs a cryptographic erase
  (key destruction). s0's overwrite provides NIST "Clear" assurance only.
- **Sealed System Volume:** macOS 11+ uses a cryptographically sealed system volume.
  s0 cannot modify the SSV; this is intentional (no user data resides there).
- **FileVault 2:** Overwrite operates on the decrypted view. Original ciphertext
  blocks are inaccessible without the FileVault recovery key, providing defense-in-depth.
- **Spotlight metadata:** `.Spotlight-V100` may cache file metadata. Full-volume wipe
  is the only way to guarantee Spotlight index destruction.
- **Resource forks:** `macos_clear_attributes()` removes resource forks via `xattr -c`.
  Legacy HFS+ resource forks (pre-APFS) are handled by the same mechanism.
