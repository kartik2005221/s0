# NIST SP 800-88 Rev. 1 & IEEE 2883-2022 Method Mappings

This reference provides exact technical mappings of all `s0` sanitization methods to NIST SP 800-88 Rev. 1 and IEEE 2883-2022 standards.

---

## 1. Compliance Tiers Explained

### Clear
Logical techniques applied to storage media to sanitize data in all user-addressable storage locations for protection against simple non-invasive data recovery techniques.
- **Applies to**: Overwrite passes (zeros/random), single-pass software overwriting, standard file deletion overwrites.
- **Target Threat**: Software-based file recovery utilities, operating system undelete tools, raw disk hex editors.
- **Limitation**: Does not purge data in reallocated sectors, reserved flash blocks, or wear-leveled FTL pages.

### Purge
Physical or logical techniques that render Target Data recovery infeasible using state-of-the-art laboratory techniques.
- **Applies to**: Internal controller-level firmware operations (NVMe Sanitize, NVMe Format with Crypto Erase, ATA Secure Erase Enhanced, BLKDISCARD with certified DRAT/RZAT).
- **Target Threat**: Advanced laboratory reconstruction, magnetic force microscopy (MFM), flash memory chip-off extraction.
- **Advantage**: Clears over-provisioned areas, retired defect tracks, and flash translation tables at the physical silicon level.

### Destroy
Physical destruction of media (incineration, shredding, disintegration, degaussing).
- **s0 Status**: Correctly disclosed as **Not Implemented**. s0 does not incinerate or physically shred hardware.

---

## 2. Complete Method Mapping Matrix

| s0 Method Identifier | Storage Interface | NIST SP 800-88 Tier | IEEE 2883 Tier | Underlying Mechanism | Controller Timeout |
|---|---|---|---|---|---|
| `NVME_SANITIZE_BLOCK_ERASE` | NVMe | **Purge** | Purge | Controller resets electrical voltage across all NAND cells | 10s – 300s |
| `NVME_SANITIZE_CRYPTO_ERASE` | NVMe | **Purge** | Purge | Controller generates new Media Encryption Key (MEK) | < 5s |
| `NVME_FORMAT_CRYPTO_ERASE` | NVMe | **Purge** | Purge | NVMe Format command with crypto-erase attribute | < 10s |
| `NVME_FORMAT_USER_DATA_ERASE`| NVMe | **Purge** | Purge | NVMe Format command with user data erase attribute | 30s – 600s |
| `ATA_SECURE_ERASE_ENHANCED` | SATA / ATA | **Purge** | Purge | Internal firmware write pass including HPA/DCO zones | 30m – 120m |
| `ATA_SECURE_ERASE` | SATA / ATA | **Purge** | Purge | Standard firmware security erase | 30m – 90m |
| `BLKDISCARD` (with justification) | SATA SSD / NVMe | **Purge** | Purge | Kernel `ioctl(BLKDISCARD)` backed by certified DRAT/RZAT | < 10s |
| `BLKDISCARD` (no justification) | SATA SSD / NVMe | **Clear** | Clear | Kernel `ioctl(BLKDISCARD)` without vendor DRAT verification | < 10s |
| `OVERWRITE_ZERO_1PASS` | Any Block / Image | **Clear** | Clear | Sequential `0x00` overwrite of all addressable LBAs | Media-bound |
| `SHRED_RANDOM_NPASS` | Any Block / Image | **Clear** | Clear | N-pass pseudorandom byte overwrite | Media-bound |
| `WINDOWS_CLEAN_ALL` | Windows Win32 | **Clear** | Clear | Win32 physical disk sequential zero fill | Media-bound |
| `WINDOWS_SED_KEY_DESTROY` | Windows SED | **Purge** | Purge | Self-Encrypting Drive (SED) key destruction | < 5s |
| `ANDROID_FACTORY_RESET_FBE` | Android UFS/eMMC | **Purge** | Purge | File-Based Encryption (FBE) master key purge | < 10s |
| `FORENSIC_CARVING` | Raw Disk Image | *N/A* | *N/A* | Read-only deleted artifact recovery | N/A |

---

## 3. The BLKDISCARD Purge Criteria

To legally claim **Purge** tier when using `BLKDISCARD`, two hardware prerequisites must be satisfied:

1. **DRAT (Deterministic Read After Trim)**:
   The drive controller guarantees that every trimmed LBA returns fixed, deterministic data upon subsequent read operations.
2. **RZAT (Return Zeros After Trim)**:
   The drive controller guarantees that every read to a trimmed LBA returns strictly `0x00`.

When both are verified through vendor datasheets or firmware query, pass `--discard-purge-justification "<citation>"` to `s0 wipe`. This justification is canonically signed into the certificate. If omitted, `BLKDISCARD` defaults strictly to **Clear** tier.
