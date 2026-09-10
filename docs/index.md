# s0 · Sector Zero

<div align="center" markdown>

[![License](https://img.shields.io/github/license/kartik2005221/s0?style=for-the-badge&color=00ADB5&labelColor=222831)](https://github.com/kartik2005221/s0/blob/master/LICENSE)
[![NIST SP 800-88](https://img.shields.io/badge/NIST%20SP%20800--88-Rev.1%20Compliant-00ADB5?style=for-the-badge&labelColor=222831)](COMPLIANCE.md)
[![Ed25519](https://img.shields.io/badge/Signatures-Ed25519%20RFC%208032-00ADB5?style=for-the-badge&labelColor=222831)](certificate-format.md)
[![Tests](https://img.shields.io/badge/Tests-190%2B%20Passing-4CAF50?style=for-the-badge&labelColor=222831)](TEST_PLAN.md)
[![Portal](https://img.shields.io/badge/Verification%20Portal-Live-brightgreen?style=for-the-badge&labelColor=222831)](https://s0-vp.vercel.app/)

</div>

---

**s0 (Sector Zero)** is an open-source, forensic-grade command-line suite and web dashboard for **secure digital sanitization** and **deleted-file recovery**. Every wipe operation produces a cryptographically signed, hash-chained audit certificate — verifiable offline, forever, by anyone — making s0 the only sanitization tool that delivers mathematical proof of data destruction rather than an unverified log entry.

Built for security engineers, digital forensic examiners, compliance auditors, and field technicians who must guarantee and mathematically prove that confidential evidence or retired media is beyond forensic reconstruction.

---

## Core Modules

<div class="grid cards" markdown>

-   :material-harddisk:{ .lg .middle } **Drive Eraser**

    ---

    NIST SP 800-88 Rev.1 *Clear* and *Purge* sanitization for NVMe SSDs, SATA HDDs/SSDs, USB flash drives, and raw disk images. Automates `NVME_SANITIZE`, `ATA_SECURE_ERASE`, `BLKDISCARD` ioctls, and multi-pass pattern overwriting with 64-block post-wipe readback verification.

    **Standards:** NIST SP 800-88 Rev.1 · IEEE 2883-2022 · ISO/IEC 27037 · DPDPA 2023

    [:octicons-arrow-right-24: Drive Eraser Manual](USER_MANUAL.md#3-module-1-secure-drive-eraser)

-   :material-file-lock:{ .lg .middle } **File & Folder Eraser**

    ---

    Cross-platform native cluster sanitization. Overwrites file extents in-place, truncates files to 0 bytes, resets inode timestamps to Unix epoch zero (`1970-01-01`), purges Windows Alternate Data Streams (`:Zone.Identifier`), flushes Darwin hardware caches (`F_FULLFSYNC`), and scrambles directory entry filenames before unlinking.

    **Platforms:** Linux · macOS · Windows

    [:octicons-arrow-right-24: File Eraser Docs](USER_MANUAL.md#4-module-2-secure-file-folder-eraser)

-   :material-magnify-scan:{ .lg .middle } **File Carver**

    ---

    Forensic deleted file recovery engine. Reconstructs lost evidence directly from filesystem structures (**ext4** inode extent trees, **NTFS** `$MFT` multi-fragment runlists, **FAT32** directory entries, and **exFAT** cluster heaps) alongside raw sliding-window signature carving with 4-factor Shannon entropy scoring.

    **Filesystems:** ext4 · NTFS · FAT32 · exFAT · raw signature carving

    [:octicons-arrow-right-24: File Carver Guide](forensic-carving-guide.md)

-   :material-content-copy:{ .lg .middle } **Drive Imager & Cloner**

    ---

    Forensic bit-stream disk acquisition engine compliant with NIST SP 800-86 and ISO/IEC 27037. Creates forensically sound raw images (`.raw`, `.img`, `.dd`) or 1:1 hardware disk clones with real-time simultaneous SHA-256/MD5 hashing, write-blocking safety refusals, and fault-tolerant zero-filling for failing storage media.

    **Capabilities:** Raw Bit-Stream Image · 1:1 Disk Clone · Fault-Tolerant Bad Sector Recovery · Live Dual Hashing

    [:octicons-arrow-right-24: Drive Imager Manual](USER_MANUAL.md#6-module-4-forensic-drive-imager-bit-stream-copy)

-   :material-shield-check:{ .lg .middle } **Blockchain Audit Ledger**

    ---

    Every operation is permanently recorded in a SHA-256 block hash-chained SQLite ledger (`~/.s0/s0_audit.db`). Altering any past block invalidates all subsequent hashes, providing local, mathematically provable tamper evidence without external internet dependencies.

    **Verification:** Ed25519 · SHA-256 chain · 100% client-side portal

    [:octicons-arrow-right-24: Audit Ledger Specs](USER_MANUAL.md#7-module-5-blockchain-cryptographic-audit-ledger)

</div>

---

## Why s0?

Most sanitization tools tell you a drive was wiped. s0 **proves it mathematically.**

| Capability | s0 Suite | Conventional Tools (e.g. Blancco / DBAN) |
|---|:---:|:---:|
| **NIST SP 800-88 Rev.1 Purge & Clear** | ✅ Automatic selection | Varies |
| **Ed25519 Asymmetric Digital Signatures** | ✅ Built-in RFC 8032 | ❌ Closed proprietary signatures |
| **Deterministic s0 Canonical JSON v1** | ✅ Strict integer discipline | ❌ Unstandardized XML/CSV |
| **SHA-256 Hash-Chained Blockchain Ledger**| ✅ Tamper-evident | ❌ Plain text / mutable logs |
| **Offline Air-Gapped Verification** | ✅ 100% client-side WebCrypto | ❌ Requires central cloud server |
| **Offensive Forensics in Same Binary** | ✅ ext4, NTFS, FAT32 carvers | ❌ Separate, costly software needed |
| **Zero External Network Exfiltration** | ✅ Strict SCIF/air-gap compliant | ❌ Telemetry beacons |
| **Permissive Open Source License** | ✅ MIT License | ❌ Expensive per-wipe paywalls |

### Three Architectural Pillars

#### :material-math-integral: Mathematical Non-Repudiation
Every sanitization certificate carries an **Ed25519 digital signature** (RFC 8032) computed over **s0 Canonical JSON v1**. The canonicalization engine eliminates JSON whitespace, key ordering, and floating-point divergences. The certificate content and its signature are mathematically inseparable: if the operation data is modified by even one bit, the signature check fails.

#### :material-wifi-off: Air-Gapped Verification
The [Verification Portal](https://s0-vp.vercel.app/) runs **100% in browser memory**. It downloads zero external CDN scripts and makes zero server requests. The portal can be saved to a thumb drive and executed via `file:///` on an isolated air-gapped machine in a secure facility or courtroom.

#### :material-scale-balance: Absolute Engineering Honesty
We disclose every technical boundary. Hardware limitations, Flash Translation Layer (FTL) wear-leveling nuances on solid-state media, and Copy-on-Write (Btrfs, ZFS, APFS) filesystem behaviors are logged explicitly as signed warnings in certificates.

---

## Quick Start

!!! tip "Three commands to your first verified wipe"
    The installer runs on Linux, macOS, and Windows. No root is required for installation or disk image testing.

=== ":fontawesome-brands-linux: Linux / macOS"

    ```bash
    # 1. Install s0
    curl -sSL https://raw.githubusercontent.com/kartik2005221/s0/master/scripts/install.sh | bash

    # 2. Inventory attached block devices
    s0 list

    # 3. Dry-run plan (inspect recommended NIST tier; writes nothing)
    s0 plan --target /dev/sdb

    # 4. Wipe target drive and issue signed certificate
    sudo s0 wipe --target /dev/sdb --operator "analyst-01" --organization "Forensics Lab"
    ```

=== ":fontawesome-brands-windows: Windows (PowerShell)"

    ```powershell
    # 1. Install s0
    irm https://raw.githubusercontent.com/kartik2005221/s0/master/scripts/install.ps1 | iex

    # 2. Inventory drives
    s0 list

    # 3. Dry-run plan
    s0 plan --target \\.\PhysicalDrive1

    # 4. Wipe drive
    s0 wipe --target \\.\PhysicalDrive1 --operator "analyst-01" --organization "Forensics Lab"
    ```

!!! warning "Destructive Operation"
    `s0 wipe` permanently and irreversibly destroys data on the target storage. Always confirm the target device path with `s0 list` and `s0 plan` before proceeding.

---

## Standards & Compliance

s0's sanitization algorithms and evidence collection protocols are mapped directly to international standards:

| Standard | Coverage Tier | Legal & Evidentiary Role |
|---|---|---|
| **NIST SP 800-88 Rev. 1** | **Clear & Purge** | Automated controller firmware purge and multi-pass logical clearing |
| **IEEE 2883-2022** | **Clear & Purge** | Sanitization method definitions and verification readback standards |
| **ISO/IEC 27037:2012** | **Evidence Handling** | Cryptographic SHA-256 evidence hashing and immutable audit logging |
| **DPDPA 2023** | **Data Destruction** | Verifiable sanitization records of hardware containing personal digital data |

---

## Documentation Directory

<div class="grid cards" markdown>

-   :material-book-open-variant: **Getting Started**

    Installation, prerequisites, platform support, and your first wipe walkthrough.

    [:octicons-arrow-right-24: Getting Started](getting-started.md)

-   :material-harddisk: **Drive Eraser Manual**

    Device inventory, dry-run planning, wiping workflows, and 64-block verification.

    [:octicons-arrow-right-24: User Manual](USER_MANUAL.md#3-module-1-secure-drive-eraser)

-   :material-file-lock: **File & Folder Eraser**

    In-place cluster overwriting, metadata zeroing, and directory entry scrambling.

    [:octicons-arrow-right-24: File Eraser Manual](USER_MANUAL.md#4-module-2-secure-file-folder-eraser)

-   :material-magnify-scan: **Forensic File Carver**

    Structure-based ext4/NTFS/FAT/exFAT recovery and 4-factor confidence scoring.

    [:octicons-arrow-right-24: Carving Guide](forensic-carving-guide.md)

-   :material-content-copy: **Forensic Drive Imager**

    Bit-stream acquisition, 1:1 disk cloning, fault-tolerant zero filling, and dual hashing.

    [:octicons-arrow-right-24: Imager Docs](USER_MANUAL.md#6-module-4-forensic-drive-imager-bit-stream-copy)

-   :material-shield-check: **Blockchain Audit Ledger**

    Append-only SQLite architecture, SHA-256 hash chaining, and integrity audits.

    [:octicons-arrow-right-24: Audit Ledger Docs](USER_MANUAL.md#7-module-5-blockchain-cryptographic-audit-ledger)

-   :material-certificate: **Verification & Air-Gapped Trust**

    Running the portal offline, strict public key pinning, and optical QR verification.

    [:octicons-arrow-right-24: Verification Guide](VERIFICATION_AND_DEPLOYMENT.md)

-   :material-api: **CLI Reference**

    Exhaustive reference for every subcommand, flag, argument, exit code, and JSON output.

    [:octicons-arrow-right-24: CLI Reference](cli-reference.md)

-   :material-scale-balance: **Compliance Guide**

    NIST SP 800-88, IEEE 2883, ISO 27037, and DPDPA compliance specifications.

    [:octicons-arrow-right-24: Compliance Guide](COMPLIANCE.md)

-   :material-disc: **Bare-Metal Live ISO**

    Debian Live USB creation, Fedora Podman builds, Windows Rufus DD mode, and offline kiosk wiping.

    [:octicons-arrow-right-24: Live ISO Guide](LIVE_ISO_BUILD_GUIDE.md)

-   :material-help-circle: **Frequently Asked Questions**

    NIST standards, device safety refusals, air-gap verification, and forensic carver mechanics.

    [:octicons-arrow-right-24: View FAQ](faq.md)

</div>

---

<div align="center" markdown>

[:fontawesome-brands-github: View Repository on GitHub](https://github.com/kartik2005221/s0){ .md-button .md-button--primary }
[:material-certificate: Launch Verification Portal](https://s0-vp.vercel.app/){ .md-button }

</div>
