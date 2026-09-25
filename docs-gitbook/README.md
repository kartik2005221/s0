---
description: "Forensic-grade digital sanitization, deleted-file recovery, and cryptographic audit ledger suite. NIST SP 800-88 compliant with Ed25519 signed certificates."
layout:
  width: wide
  tableOfContents:
    visible: false
  outline:
    visible: false
---

# s0 · Sector Zero

<div align="center">

[![License](https://img.shields.io/github/license/kartik2005221/s0?style=for-the-badge&color=00ADB5&labelColor=222831)](https://github.com/kartik2005221/s0/blob/master/LICENSE)
[![NIST SP 800-88](https://img.shields.io/badge/NIST%20SP%20800--88-Rev.1%20Compliant-00ADB5?style=for-the-badge&labelColor=222831)](compliance/nist-compliance.md)
[![Ed25519](https://img.shields.io/badge/Signatures-Ed25519%20RFC%208032-00ADB5?style=for-the-badge&labelColor=222831)](architecture/certificate-spec.md)
[![Tests](https://img.shields.io/badge/Tests-190%2B%20Passing-4CAF50?style=for-the-badge&labelColor=222831)](project/test-plan.md)
[![Portal](https://img.shields.io/badge/Verification%20Portal-Live-brightgreen?style=for-the-badge&labelColor=222831)](https://s0-verify.pages.dev/)

</div>

---

**s0 (Sector Zero)** is an open-source, forensic-grade command-line suite and web console for **secure digital sanitization** and **deleted-file recovery**. Every wipe operation produces a cryptographically signed, hash-chained audit certificate — verifiable offline, forever, by anyone — delivering mathematical proof of data destruction rather than an unverified log entry.

Built for security engineers, digital forensic examiners, compliance auditors, and field technicians who must guarantee and mathematically prove that confidential evidence or retired media is beyond forensic reconstruction.

{% hint style="danger" %}
**Legal & Responsible Use Requirement:**
s0 is a certified digital forensic sanitization and recovery tool. You must **only** operate on storage devices and files that you legally own or for which you have explicit, documented written authorization to process. Unauthorized data destruction or forensic acquisition may violate computer crime legislation (including CFAA 18 U.S.C. § 1030, UK Computer Misuse Act 1990, and India IT Act 2000). See the [Legal & Ethics FAQ](getting-started/faq.md#0-legal-ethical-use).
{% endhint %}

---

## Core Capabilities

<table data-view="cards">
  <thead>
    <tr>
      <th></th>
      <th></th>
      <th data-hidden data-card-target data-type="content-ref"></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Drive Eraser</strong></td>
      <td>NIST SP 800-88 Rev.1 Clear and Purge sanitization for NVMe SSDs, SATA HDDs/SSDs, USB drives, and disk images. Automates NVME_SANITIZE, ATA_SECURE_ERASE, BLKDISCARD ioctls, and multi-pass pattern overwriting with 64-block post-wipe readback verification.</td>
      <td><a href="guides/user-manual.md#3-module-1-secure-drive-eraser">Drive Eraser Manual</a></td>
    </tr>
    <tr>
      <td><strong>File &amp; Folder Eraser</strong></td>
      <td>Cross-platform native cluster sanitization. Overwrites file extents in-place, truncates files to 0 bytes, resets inode timestamps to Unix epoch zero (1970-01-01), purges Windows Alternate Data Streams, flushes Darwin hardware caches (F_FULLFSYNC), and scrambles directory entry filenames before unlinking.</td>
      <td><a href="guides/user-manual.md#4-secure-file-folder-erasure-s0-wipe-targets">File Eraser Manual</a></td>
    </tr>
    <tr>
      <td><strong>File Carver</strong></td>
      <td>Forensic deleted file recovery engine. Reconstructs lost evidence directly from filesystem structures (ext4 inode extent trees, NTFS $MFT multi-fragment runlists, FAT32 directory entries, and exFAT cluster heaps) alongside raw sliding-window signature carving with 4-factor Shannon entropy scoring.</td>
      <td><a href="guides/forensic-carving.md">File Carver Guide</a></td>
    </tr>
    <tr>
      <td><strong>Drive Imager &amp; Cloner</strong></td>
      <td>Forensic bit-stream disk acquisition engine compliant with NIST SP 800-86 and ISO/IEC 27037. Creates forensically sound raw images (.raw, .img, .dd) or 1:1 hardware disk clones with real-time simultaneous SHA-256/MD5 hashing, write-blocking safety refusals, and fault-tolerant zero-filling for failing storage media.</td>
      <td><a href="guides/user-manual.md#6-module-3-forensic-drive-imager-bit-stream-copy">Drive Imager Manual</a></td>
    </tr>
    <tr>
      <td><strong>Blockchain Audit Ledger</strong></td>
      <td>Every operation is permanently recorded in a SHA-256 block hash-chained SQLite ledger (~/.s0/s0_audit.db). Altering any past block invalidates all subsequent hashes, providing local, mathematically provable tamper evidence without external internet dependencies.</td>
      <td><a href="guides/user-manual.md#7-module-4-blockchain-cryptographic-audit-ledger">Audit Ledger Specs</a></td>
    </tr>
  </tbody>
</table>

---

## Why s0?

Most sanitization tools tell you a drive was wiped. s0 **proves it mathematically.**

| Capability | s0 Suite | Conventional Tools (e.g. Blancco / DBAN) |
|---|:---:|:---:|
| **NIST SP 800-88 Rev.1 Purge & Clear** | Yes (Automatic selection) | Varies |
| **Ed25519 Asymmetric Digital Signatures** | Yes (Built-in RFC 8032) | No (Closed proprietary signatures) |
| **Deterministic s0 Canonical JSON v1** | Yes (Strict integer discipline) | No (Unstandardized XML/CSV) |
| **SHA-256 Hash-Chained Blockchain Ledger**| Yes (Tamper-evident) | No (Plain text / mutable logs) |
| **Offline Air-Gapped Verification** | Yes (100% client-side WebCrypto) | No (Requires central cloud server) |
| **Offensive Forensics in Same Binary** | Yes (ext4, NTFS, FAT32 carvers) | No (Separate, costly software needed) |
| **Zero External Network Exfiltration** | Yes (Strict SCIF/air-gap compliant) | No (Telemetry beacons) |
| **Permissive Open Source License** | Yes (MIT License) | No (Expensive per-wipe paywalls) |

### Three Architectural Pillars

#### Mathematical Non-Repudiation
Every sanitization certificate carries an **Ed25519 digital signature** (RFC 8032) computed over **s0 Canonical JSON v1**. The canonicalization engine eliminates JSON whitespace, key ordering, and floating-point divergences. The certificate content and its signature are mathematically inseparable: if the operation data is modified by even one bit, the signature check fails.

#### Air-Gapped Verification
The [Verification Portal](https://s0-verify.pages.dev/) runs **100% in browser memory**. It downloads zero external CDN scripts and makes zero server requests. The portal can be saved to a thumb drive and executed via `file:///` on an isolated air-gapped machine in a secure facility or courtroom.

#### Absolute Engineering Honesty
We disclose every technical boundary. Hardware limitations, Flash Translation Layer (FTL) wear-leveling nuances on solid-state media, and Copy-on-Write (Btrfs, ZFS, APFS) filesystem behaviors are logged explicitly as signed warnings in certificates.

---

## Quick Start

{% hint style="success" %}
**Three commands to your first verified wipe:**
The installer runs on Linux, macOS, and Windows. No root is required for installation or disk image testing.
{% endhint %}

{% tabs %}
{% tab title="Linux / macOS" %}
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
{% endtab %}

{% tab title="Windows (PowerShell)" %}
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
{% endtab %}
{% endtabs %}

{% hint style="warning" %}
**Destructive Operation:**
`s0 wipe` permanently and irreversibly destroys data on the target storage. Always confirm the target device path with `s0 list` and `s0 plan` before proceeding.
{% endhint %}

---

## Standards & Compliance

s0 algorithm implementations and evidence collection protocols are mapped directly to international standards:

| Standard | Coverage Tier | Legal & Evidentiary Role |
|---|---|---|
| **NIST SP 800-88 Rev. 1** | **Clear & Purge** | Automated controller firmware purge and multi-pass logical clearing |
| **IEEE 2883-2022** | **Clear & Purge** | Sanitization method definitions and verification readback standards |
| **ISO/IEC 27037:2012** | **Evidence Handling** | Cryptographic SHA-256 evidence hashing and immutable audit logging |
| **DPDPA 2023** | **Data Destruction** | Verifiable sanitization records of hardware containing personal digital data |

---

## Documentation Directory

<table data-view="cards">
  <thead>
    <tr>
      <th></th>
      <th></th>
      <th data-hidden data-card-target data-type="content-ref"></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Getting Started</strong></td>
      <td>Installation, prerequisites, platform support, and your first wipe walkthrough.</td>
      <td><a href="getting-started/quickstart.md">Getting Started</a></td>
    </tr>
    <tr>
      <td><strong>Drive Eraser Manual</strong></td>
      <td>Device inventory, dry-run planning, wiping workflows, and 64-block verification.</td>
      <td><a href="guides/user-manual.md#3-module-1-secure-drive-eraser">User Manual</a></td>
    </tr>
    <tr>
      <td><strong>File &amp; Folder Eraser</strong></td>
      <td>In-place cluster overwriting, metadata zeroing, and directory entry scrambling.</td>
      <td><a href="guides/user-manual.md#4-secure-file-folder-erasure-s0-wipe-targets">File Eraser Manual</a></td>
    </tr>
    <tr>
      <td><strong>Forensic File Carver</strong></td>
      <td>Structure-based ext4/NTFS/FAT/exFAT recovery and 4-factor confidence scoring.</td>
      <td><a href="guides/forensic-carving.md">Carving Guide</a></td>
    </tr>
    <tr>
      <td><strong>Forensic Drive Imager</strong></td>
      <td>Bit-stream acquisition, 1:1 disk cloning, fault-tolerant zero filling, and dual hashing.</td>
      <td><a href="guides/user-manual.md#6-module-3-forensic-drive-imager-bit-stream-copy">Imager Docs</a></td>
    </tr>
    <tr>
      <td><strong>Blockchain Audit Ledger</strong></td>
      <td>Append-only SQLite architecture, SHA-256 hash chaining, and integrity audits.</td>
      <td><a href="guides/user-manual.md#7-module-4-blockchain-cryptographic-audit-ledger">Audit Ledger Docs</a></td>
    </tr>
    <tr>
      <td><strong>Verification &amp; Air-Gapped Trust</strong></td>
      <td>Running the portal offline, strict public key pinning, and optical QR verification.</td>
      <td><a href="architecture/verification.md">Verification Guide</a></td>
    </tr>
    <tr>
      <td><strong>CLI Reference</strong></td>
      <td>Exhaustive reference for every subcommand, flag, argument, exit code, and JSON output.</td>
      <td><a href="guides/cli-reference.md">CLI Reference</a></td>
    </tr>
    <tr>
      <td><strong>Compliance Guide</strong></td>
      <td>NIST SP 800-88, IEEE 2883, ISO 27037, and DPDPA compliance specifications.</td>
      <td><a href="compliance/nist-compliance.md">Compliance Guide</a></td>
    </tr>
    <tr>
      <td><strong>Bare-Metal Live ISO</strong></td>
      <td>Debian Live USB creation, Fedora Podman builds, Windows Rufus DD mode, and offline kiosk wiping.</td>
      <td><a href="guides/live-iso.md">Live ISO Guide</a></td>
    </tr>
    <tr>
      <td><strong>Frequently Asked Questions</strong></td>
      <td>NIST standards, device safety refusals, air-gap verification, and forensic carver mechanics.</td>
      <td><a href="getting-started/faq.md">View FAQ</a></td>
    </tr>
  </tbody>
</table>
