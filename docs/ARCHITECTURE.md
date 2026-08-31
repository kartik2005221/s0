# TrustWipe — System Architecture

**Project:** Secure Data Sanitization & Cryptographic Certification Suite  
**Context:** Smart India Hackathon (SIH 2026) • Ministry of Mines / JNARDDC  
**Status:** Monorepo Architecture Specification (v1.0.0)

---

## 1. Executive Overview

TrustWipe is an open-source, mathematically verifiable, and standards-compliant data sanitization suite engineered to eliminate data residue on retired IT storage media (HDDs, SSDs, NVMe drives, removable flash, and mobile devices) while providing unforgeable, cryptographically signed sanitization certificates.

Developed to address critical e-waste and supply chain integrity challenges for **JNARDDC (Jawaharlal Nehru Aluminium Association / Ministry of Mines)** and national e-waste recyclers, TrustWipe solves the fundamental problem of **unverifiable compliance**: existing commercial tools produce printable or PDF certificates that are trivial to forge or tamper with. TrustWipe anchors every wipe in an **Ed25519 digital signature over a deterministically canonicalized JSON payload**, paired with a **pure client-side, zero-trust verification portal**.

---

## 2. Threat Model & Security Objectives

TrustWipe protects against adversarial actions across the e-waste lifecycle:

```
[Target Storage Device] ──▶ [TrustWipe Wiping Engine] ──▶ [Forensic Readback]
                                     │
                             (Private Key Sign)
                                     ▼
                            [Signed JSON / PDF]
                                     │
                        (Independent Auditor / Portal)
                                     ▼
                       [Ed25519 Math Verification]
```

### Threat Vectors Addressed:
1. **Certificate Forgery & Post-Hoc Alteration:**
   - *Threat:* An attacker modifies disk serial numbers, capacity, operator IDs, or wipe status on a PDF/JSON certificate to falsely claim compliance.
   - *Mitigation:* The entire certificate content (excluding the signature object itself) is canonicalized and signed using Ed25519. Changing a single bit in any field immediately breaks mathematical signature verification.

2. **Incompetent / Partial Wiping Falsely Marked as Complete:**
   - *Threat:* A wiping script encounters I/O errors or early termination but still issues a success certificate.
   - *Mitigation:* The wiper runs an automated forensic sampling verification step (e.g., 64 sampled blocks across the drive and raw pattern scanning for planted markers). If any non-zero block or marker persists, the status is marked `failure` or `partial`.

3. **Vendor Lock-in & "Trust Our Cloud Server" Vulnerabilities:**
   - *Threat:* Proprietary wipe vendors validate certificates via their proprietary cloud database, creating single points of failure, privacy leaks, and reliance on server trust.
   - *Mitigation:* Pure client-side Ed25519 verification. Verifiers pin the public keys of accredited authorities (e.g., JNARDDC); the verification portal contains zero backend and no database.

4. **Hidden Storage Areas (HPA / DCO):**
   - *Threat:* Data remains hidden in ATA Host Protected Areas (HPA) or Device Configuration Overlays (DCO).
   - *Mitigation:* Linux CLI actively queries ATA max sectors vs native max sectors (`hdparm -N`, `hdparm --dco-identify`) and flags hidden capacity prior to sanitization.

5. **Private Key Leaks in Application Bundles:**
   - *Threat:* Shipping signing keys inside the CLI, GUI, or ISO allows rogue operators to mint fraudulent certificates.
   - *Mitigation:* Strict key separation. Private keys are generated out-of-band on air-gapped authority machines and are strictly blocked from code repositories, installer bundles, and live ISOs.

---

## 3. High-Level System Architecture

```
trustwipe/
├── core/                       # Shared Cryptographic & Schema Foundation
│   ├── cert_schema.json        # Machine-readable JSON Schema v1.0.0
│   ├── CANONICAL_JSON.md       # TrustWipe Canonical JSON v1 Specification
│   ├── standards/              # NIST SP 800-88 Rev. 1 Mapping Registry
│   └── python/trustwipe_core/  # Reference Python Crypto & Canonicalization Engine
├── linux/                      # Linux Sanitization Suite
│   ├── cli/                    # Python CLI (methods: NVMe, ATA, BLKDISCARD, Overwrite)
│   ├── gui/                    # Local Web GUI (FastAPI + Modern HTML5 Interface)
│   └── iso/                    # Debian Live-Build Bootable ISO Configuration
├── verification-portal/        # Zero-Trust Static Web Verification Portal
│   ├── index.html              # Responsive Client-Side Auditor UI
│   ├── verify.js               # Standalone JavaScript Verifier
│   └── vendor/crypto-bundle.js # Pure JS TweetNaCl & SHA-256 Engine
└── docs/                       # Comprehensive System Documentation
```

---

## 4. Subsystem Deep-Dives

### 4.1. Core Cryptographic & Serialization Engine (`core/`)

- **TrustWipe Canonical JSON v1 (`CANONICAL_JSON.md`):**
  - Problem: JSON serializers in Python, JavaScript, C#, and Kotlin differ in whitespace, key ordering, string escaping, and floating-point number rendering.
  - Solution: A strict canonicalization standard:
    1. Recursive Unicode code-point key sorting.
    2. Zero insignificant whitespace (separators `,` and `:`).
    3. Minimal escaping (`"`, `\`, control chars U+0000–U+001F).
    4. **Integer-Only Rule:** Schema v1 strictly forbids floating-point numbers anywhere in certificates (sizes in bytes, timestamps in integer seconds). Floats raise immediate errors rather than risking serialization divergence.

- **Ed25519 Digital Signatures (RFC 8032):**
  - High-performance, constant-time Edwards-curve digital signature algorithm.
  - Public keys distributed in standard SubjectPublicKeyInfo (SPKI) PEM/DER format.
  - Key fingerprint calculated as `"sha256:" + hex(sha256(der_spki))`.
  - Signatures encoded in unpadded base64url.

- **Certificate Schema (`cert_schema.json`):**
  - Strongly-typed JSON schema encompassing 100% of audit metadata: schema version, UUID, timestamp, issuer org & operator, tool platform & kernel, device hardware info (ID, model, serial, capacity, sector size), wipe method & NIST category (Clear/Purge/Destroy), execution times, verification samples, and signature block.

### 4.2. Linux Sanitization Engine (`linux/`)

- **Device Discovery & Probing (`devices.py`):**
  - Gathers typed hardware inventory using `lsblk -J`, `/sys/block`, and `udev`.
  - Flags mounted partitions to prevent accidental operating system destruction.
  - Supports both physical block devices (`/dev/sdX`, `/dev/nvmeXnY`) and unprivileged sparse image files for testing and simulation.

- **Sanitization Method Backends (`methods/`):**
  1. `NVME_SANITIZE_CRYPTO_ERASE` / `NVME_SANITIZE_BLOCK_ERASE` / `NVME_FORMAT`: Communicates via `nvme-cli` to execute controller-level purge covering overprovisioned flash.
  2. `ATA_SECURE_ERASE` / `ATA_SECURE_ERASE_ENHANCED`: Issues ATA security erase commands via `hdparm`, handling BIOS frozen states and temporary password workflows.
  3. `BLKDISCARD`: Linux kernel ioctl `BLKDISCARD` for fast SSD trim/discard; records DRAT/RZAT deterministic read behavior.
  4. `OVERWRITE_ZERO_1PASS` / `SHRED_RANDOM_NPASS`: Direct logical block overwrite engine with periodic progress streaming and fsync flushes.

- **Forensic Verification & Planted Marker Engine (`methods/overwrite.py`):**
  - Plants high-entropy test markers (e.g., confidential data simulations) at known offsets prior to wiping.
  - Post-wipe: conducts dual verification:
    * Sampled read-back across 64 uniform offsets.
    * Raw stream scanning across the target to prove 0 marker hits remain.

### 4.3. User Interfaces

- **Command-Line Interface (`linux/cli/trustwipe_cli`):**
  - Commands: `list` (device discovery), `plan` (safe dry-run preview), `wipe` (execution + cert generation), `trustwipe-keygen`, `trustwipe-sign`, `trustwipe-verify`.
- **Local Web GUI (`linux/gui`):**
  - FastAPI backend serving a single-page interface for visual device selection, dry-run inspection, real-time wiping progress bars, and instant PDF/JSON certificate downloads.
- **Bootable Live ISO (`linux/iso`):**
  - Debian-based live kiosk environment configured via `live-build` to boot directly into the TrustWipe GUI without installing software on the target machine.

### 4.4. Verification Portal (`verification-portal/`)

- Pure client-side static web application.
- Embeds a vendored pure JavaScript cryptographic engine (TweetNaCl + SHA-256).
- Zero external build step (no npm/Webpack needed).
- Provides drag-and-drop JSON certificate verification, QR code decoding, and cryptographic breakdown directly in the browser.

---

## 5. Security & Cryptographic Invariants

| Invariant | Implementation Mechanism | Validation / Test |
|---|---|---|
| **Deterministic Canonicalization** | Unicode code point sorting, minimal escaping, float rejection | Golden vectors (`canonical_vectors.json`) tested in Python & JS |
| **Tamper Evidence** | Ed25519 signature over canonical payload (minus signature block) | Exhaustive leaf mutation matrix (`test_tamper.py`) |
| **Tier Integrity** | Strict `METHOD_TIERS` registry in schema & code | Schema validator rejects Clear methods claiming Purge |
| **Forensic Assurance** | 64-point sampled read-back + raw grep pattern scanning | `test_e2e_demo.py` & `demo_e2e.sh` |
| **Zero-Server Dependency** | Pinned public keys in client-side static verifier | `verification-portal/index.html` runs offline via `file://` |
