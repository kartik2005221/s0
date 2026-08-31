# TrustWipe — Standards & Regulatory Compliance

**Standards Covered:** NIST SP 800-88 Rev. 1 • IEEE 2883-2022 • DoD 5220.22-M • India DPDPA 2023 • E-Waste Rules 2022  
**Target Authority:** Ministry of Mines / JNARDDC (Jawaharlal Nehru Aluminium Research Development and Design Centre)  
**Version:** 1.0.0

---

## 1. Executive Summary

Data sanitization in circular e-waste supply chains requires strict alignment with internationally recognized cybersecurity standards and national data protection mandates. TrustWipe aligns every wiping algorithm with the taxonomy established in **NIST Special Publication 800-88 Revision 1 (Guidelines for Media Sanitization)** and **IEEE 2883-2022 Standard for Sanitizing Storage**.

Furthermore, TrustWipe enforces technical honesty: **the certificate schema strictly limits the NIST category a method may claim** (e.g., software overwriting cannot claim NIST Purge on flash storage).

---

## 2. NIST SP 800-88 Rev. 1 Sanitization Taxonomy

NIST SP 800-88 Rev. 1 defines three levels of sanitization:

```
┌────────────────────────────────────────────────────────────────────────┐
│                          NIST SP 800-88 LEVELS                         │
├────────────────────────────────────────────────────────────────────────┤
│ 1. CLEAR: Overwrite logical storage using logical interface writes.   │
│    Protects against simple non-invasive keyboard recovery.             │
│    (Suitable for media reused within the same security domain).        │
├────────────────────────────────────────────────────────────────────────┤
│ 2. PURGE: Firmware-level or cryptographic erasure of all addressable   │
│    and non-addressable storage (including overprovisioning & bad blocks)│
│    Protects against laboratory attack tools and forensic reconstruction│
│    (Suitable for media leaving the organization or e-waste recycling). │
├────────────────────────────────────────────────────────────────────────┤
│ 3. DESTROY: Complete physical destruction (shredding, incineration).   │
│    Renders media physically impossible to write or read.               │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. TrustWipe Method Mapping Registry

The table below defines the exact mapping between TrustWipe methods and recognized compliance tiers, as enforced by `core/standards/nist_800_88_mapping.md` and `core/python/trustwipe_core/certificate.py`:

| Method Identifier | Storage Medium | NIST 800-88 Tier | IEEE 2883 Tier | Technical Mechanism |
|---|---|---|---|---|
| `OVERWRITE_ZERO_1PASS` | Magnetic HDD, File Image | **Clear** | Clear | 1-pass host write of 0x00 across all logical block addresses (LBAs) |
| `SHRED_RANDOM_NPASS` | Magnetic HDD | **Clear** | Clear | N-pass pseudo-random overwrite with final zero pass |
| `ATA_SECURE_ERASE` | SATA SSD / HDD | **Purge** | Purge | ATA Security Erase command executed directly by drive firmware |
| `ATA_SECURE_ERASE_ENHANCED` | SATA SSD / HDD | **Purge** | Purge | ATA Enhanced Erase; writes vendor-defined patterns to user & retired blocks |
| `NVME_FORMAT_USER_DATA_ERASE` | NVMe SSD | **Purge** | Purge | NVMe low-level format erasing all user data namespaces |
| `NVME_FORMAT_CRYPTO_ERASE` | NVMe SSD | **Purge** | Cryptographic Erase | NVMe format with cryptographic key change/deletion |
| `NVME_SANITIZE_BLOCK_ERASE` | NVMe SSD | **Purge** | Purge | NVMe Sanitize command; low-level block erase across all NAND dies |
| `NVME_SANITIZE_CRYPTO_ERASE` | NVMe SSD | **Purge** | Cryptographic Erase | NVMe Sanitize command; instantaneous destruction of media encryption key |
| `BLKDISCARD` | SSD / Flash | **Clear / Purge\*** | Purge\* | Kernel `BLKDISCARD` ioctl. \*Claims Purge **only** with verified DRAT/RZAT |
| `ANDROID_FACTORY_RESET_FBE` | Android 7.0+ (FBE) | **Purge** | Cryptographic Erase | Hardware-backed keystore destruction of File-Based Encryption (FBE) keys |
| `ANDROID_USER_SPACE_OVERWRITE` | Legacy Android | **Clear** | Clear | File-level overwrite (unreliable on modern flash; legacy fallback only) |
| `WINDOWS_CLEAN_ALL` | Any Windows disk | **Clear** | Clear | `diskpart clean all` full sequential zero overwrite |
| `WINDOWS_CIPHER_W` | Windows volume | **Clear** | Clear | `cipher /w` free space overwrite |
| `WINDOWS_SED_KEY_DESTROY` | Self-Encrypting Drive | **Purge** | Cryptographic Erase | Hardware SED / BitLocker key destruction |

---

## 4. Critical Technical Insights & Myth Busting

### 4.1 The Multi-Pass Myth on Modern Drives
- **Historical Myth:** DoD 5220.22-M (1995) popularized 3-pass and 7-pass overwrite algorithms based on Peter Gutmann's 1996 paper analyzing 1980s-era MFM/RLL magnetic recording.
- **Modern Reality (NIST SP 800-88 §A.1):** On modern high-density magnetic drives (PRMR/SMR) and all solid-state media, **a single overwrite pass makes prior data magnetically and physically unrecoverable** under any laboratory or atomic force microscopy (AFM) inspection. Multi-pass overwriting on SSDs merely accelerates drive wear without providing additional security.
- **TrustWipe Policy:** Single-pass zero overwrite (`OVERWRITE_ZERO_1PASS`) is the standard default for Clear. Multi-pass options (`SHRED_RANDOM_NPASS`) are provided strictly for legacy client policy compliance.

### 4.2 Why Host Overwrites Cannot Purge Solid-State Media
- Solid-State Drives (SSDs) and NVMe media utilize a **Flash Translation Layer (FTL)** that performs dynamic wear leveling, bad block retirement, and overprovisioning (typically 7%–28% of total NAND capacity).
- Host-level software writes (`dd`, `shred`) can only address visible LBAs. Data residing in overprovisioned or retired sectors remains physically intact on NAND dies.
- **TrustWipe Policy:** Software overwriting on an SSD is strictly restricted to **Clear**. To earn a **Purge** certificate on solid-state media, operators must execute controller-level firmware erasure (`NVME_SANITIZE`, `ATA_SECURE_ERASE`) or hardware cryptographic erasure.

### 4.3 Why Android Factory Reset on FBE is Authentic NIST Purge
- Modern Android devices (Android 7.0+) utilize **File-Based Encryption (FBE)** with keys stored in a Hardware Security Module (Titan M, Qualcomm TrustZone, ARM TEE).
- When a Factory Reset is triggered via `DevicePolicyManager.wipeData()`, the hardware keystore purges the master filesystem encryption keys. Without these keys, all ciphertext on raw flash chips is permanently and mathematically unrecoverable.
- Per NIST SP 800-88 Rev. 1 Section 4.3, cryptographic key destruction on an encrypted device constitutes an authentic **Purge**.

---

## 5. Regulatory Alignment

### 5.1 India E-Waste (Management) Rules 2022 & Ministry of Mines / JNARDDC
- Under Extended Producer Responsibility (EPR) and government IT asset retirement frameworks, decommissioned mining equipment, telemetry servers, and laptops must be sanitized prior to refurbishing or recycling.
- TrustWipe provides the mandatory **tamper-evident audit trail** verifying that data sanitization occurred before recycling, preventing confidential PSU and ministry data leaks.

### 5.2 Digital Personal Data Protection Act (DPDPA 2023)
- Section 8(7) mandates data fiduciaries to erase personal data upon purpose completion or withdrawal of consent.
- TrustWipe signed certificates provide non-repudiable legal proof of irreversible erasure for compliance audits and regulatory filings with the Data Protection Board of India.

### 5.3 European Union GDPR (Articles 17 & 32)
- Satisfies Article 17 ("Right to Erasure / Right to be Forgotten") and Article 32 ("Security of Processing") by guaranteeing irrecoverability and providing cryptographically verifiable deletion records.
