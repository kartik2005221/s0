# s0 // Digital Forensic & Sanitization Suite

<p align="center" style="font-size: 1.25rem; font-weight: 600; color: #00adb5; margin-top: 10px;">
  Zero-Trust • Mathematical Non-Repudiation • NIST SP 800-88 Rev. 1 Compliant
</p>

Welcome to the official technical documentation for **s0 (Sector Zero)** — an open-source, forensic-grade digital sanitization, file recovery, and cryptographic audit platform engineered for defense, enterprise, and forensic laboratory workflows.

---

## The Four Core Modules

<div class="grid cards" markdown>

-   :material-harddisk: __Module 1: Drive Eraser__

    ---

    NIST SP 800-88 *Clear* & *Purge* sanitization for physical media. Automates `NVMe Sanitize`, `NVMe Format (Crypto Erase)`, `ATA Secure Erase`, `BLKDISCARD` ioctls, and multi-pass pattern overwriting. Includes bare-metal Debian Live ISO recipes.

    [:octicons-arrow-right-24: Read Drive Eraser Manual](USER_MANUAL.md#module-1-drive-eraser)

-   :material-file-lock: __Module 2: File & Folder Eraser__

    ---

    Native cross-platform selective data destruction. Overwrites cluster runs in-place, zeroes filesystem timestamps, purges Alternate Data Streams (Windows ADS), flushes hardware caches via `F_FULLFSYNC` (macOS), and scrambles directory entries before unlinking.

    [:octicons-arrow-right-24: Read File Eraser Docs](USER_MANUAL.md#module-2-secure-file--folder-eraser)

-   :material-magnify-scan: __Module 3: Multi-FS File Carver__

    ---

    Forensic deleted file recovery engine. Features direct filesystem structure traversal for **ext4** (inode extents), **NTFS** ($MFT non-resident multi-fragment runlists), **FAT32** (BPB directory entries), and **exFAT** (Cluster Heap allocation sets) alongside header/footer magic carving with Shannon entropy filtering.

    [:octicons-arrow-right-24: Explore Carver Specs](USER_MANUAL.md#module-3-file-carver)

-   :material-shield-check: __Module 4: Cryptographic Ledger & Audit__

    ---

    Single-authority, append-only SHA-256 block hash chained audit ledger. Generates Ed25519 digital signatures (RFC 8032) over deterministic **s0 Canonical JSON v1** payloads and renders tamper-evident PDF sanitization certificates with embedded QR codes.

    [:octicons-arrow-right-24: Verify Certificates](VERIFICATION_AND_DEPLOYMENT.md)

</div>

---

## Key System Properties

### 1. Mathematical Non-Repudiation
Every sanitization operation outputs a digitally signed certificate. The signature is computed using **Ed25519** over canonical JSON. Any modification to a single character (e.g. altering the timestamp, device ID, or sectors wiped) invalidates the signature mathematically.

### 2. Air-Gapped & Offline Verification
Certificates can be audited without connecting to the internet or any central database. The suite provides three independent offline verification mechanisms:
- **Client-Side Web Portal:** Single-page application using pure WebCrypto. Drag & drop JSON to audit signatures offline.
- **CLI Verifier:** `python3 -m s0_core.cli verify --cert certificate.json --key pubkey.pem`
- **Tamper-Evident PDF & QR:** Offline optical verification using standard smartphone cameras.

### 3. Absolute Engineering Honesty
We do not believe in vaporware or exaggerated claims. Hardware boundaries, Copy-on-Write (Btrfs, ZFS, APFS) filesystem limits, Flash Translation Layer (FTL) wear leveling, and unverified components are openly disclosed in the [Technical Limitations & Boundaries](LIMITATIONS.md) specification.

---

## Quick Navigation

- **Getting Started:** [User Manual & CLI Reference](USER_MANUAL.md)
- **Bare-Metal Live ISO:** [Build & Deployment Guide](LIVE_ISO_BUILD_GUIDE.md)
- **Architecture Overview:** [System Architecture](ARCHITECTURE.md)
- **Compliance Mapping:** [NIST SP 800-88 & Legal Standards](COMPLIANCE.md)
- **Developer Handover:** [Handover & Quickstart Guide](HANDOVER.md)
- **Verification Portal:** [Offline Verification Guide](VERIFICATION_AND_DEPLOYMENT.md#3-how-offline-verification-is-performed)
