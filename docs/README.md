---
description: "Forensic-grade digital sanitization, deleted-file recovery, and cryptographic audit ledger suite. Aligned with NIST SP 800-88 Rev. 2, with Ed25519-signed certificates."
layout:
  width: wide
  tableOfContents:
    visible: true
  outline:
    visible: false
---

# s0 · Sector Zero

**s0 (Sector Zero)** is an open-source, forensic-grade command-line suite and web console for **secure digital sanitization** and **deleted-file recovery**. Every wipe operation produces a cryptographically signed, hash-chained audit certificate — verifiable offline, forever, by anyone — delivering mathematical proof of data destruction rather than an unverified log entry.

Built for security engineers, digital forensic examiners, compliance auditors, and field technicians who must guarantee and mathematically prove that confidential evidence or retired media is beyond forensic reconstruction.

{% hint style="danger" %}
**Legal & Responsible Use Requirement:**
s0 is a digital forensic sanitization and recovery tool. You must **only** operate on storage devices and files that you legally own or for which you have explicit, documented written authorization to process. Unauthorized data destruction or forensic acquisition may violate computer crime legislation (including CFAA 18 U.S.C. § 1030, UK Computer Misuse Act 1990, and India IT Act 2000). See the [Legal & Ethics FAQ](getting-started/faq.md#0-legal-ethical-use).
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
      <td>NIST SP 800-88 Rev. 2 Clear and Purge sanitization for NVMe SSDs, SATA HDDs/SSDs, USB drives, and disk images. Automates NVME_SANITIZE, ATA_SECURE_ERASE, BLKDISCARD ioctls, and multi-pass pattern overwriting with 64-block post-wipe readback verification.</td>
      <td><a href="guides/user-manual.md#3-module-1-secure-drive-eraser">Drive Eraser Manual</a></td>
    </tr>
    <tr>
      <td><strong>File &amp; Folder Eraser</strong></td>
      <td>Cross-platform native cluster sanitization via <code>--target</code> (single path) or <code>--targets</code> (batch). Overwrites file extents in-place, truncates files to 0 bytes, resets inode timestamps to Unix epoch zero (1970-01-01), purges Windows Alternate Data Streams, flushes hardware caches, and scrambles directory entries before unlinking.</td>
      <td><a href="guides/user-manual.md#4-secure-file-folder-erasure-s0-wipe-targets">File Eraser Manual</a></td>
    </tr>
    <tr>
      <td><strong>File Carver</strong></td>
      <td>Forensic deleted file recovery engine supporting 19 binary signature definitions. Reconstructs lost evidence directly from filesystem structures (ext4 inode extent trees, NTFS $MFT runlists, FAT32 directory entries, and exFAT cluster heaps) alongside raw signature carving with 4-factor Shannon entropy scoring.</td>
      <td><a href="guides/forensic-carving.md">File Carver Guide</a></td>
    </tr>
    <tr>
      <td><strong>Drive Imager &amp; Cloner</strong></td>
      <td>Forensic bit-stream disk acquisition engine aligned with NIST SP 800-86 and ISO/IEC 27037. Creates forensically sound raw images (.raw, .img, .dd) or 1:1 hardware disk clones with real-time simultaneous SHA-256/MD5 hashing, write-blocking safety refusals, and fault-tolerant zero-filling for failing storage media.</td>
      <td><a href="guides/user-manual.md#6-module-3-forensic-drive-imager-bit-stream-copy">Drive Imager Manual</a></td>
    </tr>
  </tbody>
</table>

---

## Why s0?

Most sanitization tools tell you a drive was wiped. s0 **proves it mathematically.**

| Capability | s0 Suite | Conventional Tools (e.g. Blancco / DBAN) |
|---|:---:|:---:|
| **NIST SP 800-88 Rev. 2 Purge & Clear** | Yes (Automatic selection) | Varies |
| **Ed25519 Asymmetric Digital Signatures** | Yes (Built-in RFC 8032) | No (Closed proprietary signatures) |
| **Deterministic s0 Canonical JSON v1** | Yes (Strict integer discipline) | No (Unstandardized XML/CSV) |
| **SHA-256 Hash-Chained Audit Ledger** | Yes (Tamper-evident SQLite) | No (Plain text / mutable logs) |
| **Offline Air-Gapped Verification** | Yes (100% client-side WebCrypto) | No (Requires central cloud server) |
| **Offensive Forensics in Same Binary** | Yes (ext4, NTFS, FAT32 carvers) | No (Separate, costly software needed) |
| **No Telemetry** | Yes (nothing is phoned home; see the network note below) | No (Telemetry beacons) |
| **Works Fully Offline** | Yes, for every command except `s0 live download` | Varies |
| **Permissive Open Source License** | Yes (MIT License) | No (Expensive per-wipe paywalls) |

#### What "No Telemetry" Does and Does Not Mean

s0 contains no telemetry, no analytics, no crash reporting and no beacon. Running a
sanitization does not contact anyone, and an offline workstation never touches the
network.

It is not, however, air-gap-clean in every code path, and claiming otherwise would be
the kind of overclaim this project elsewhere refuses to make. These are the only
outbound connections, and all of them are explicit operator actions:

| What | Contacts | When |
|---|---|---|
| `s0 live download` | `api.github.com`, then `github.com` for the release asset | Only when you run it, to fetch the Live ISO. The download is SHA-256 verified against the release checksum, and a missing or mismatched checksum fails closed. |
| `site/install/install.sh` and the PowerShell/cmd installers | `github.com` (clone or fetch), PyPI (`pip install`), Debian mirrors and `deb.debian.org` (the Live ISO build, inside the buildroot only) | Only during installation or `s0 upgrade`. |
| `s0 upgrade` | `github.com`, PyPI | Only when you run it. |

`s0 list`, `s0 plan`, `s0 wipe`, `s0 image`, `s0 clone`, `s0 carve`, `s0 verify`,
`s0 audit`, `s0 keygen` and `s0 web` make **no** outbound connections. `s0 web` binds
to loopback only. The verification portal is a static site: a certificate is checked
in the browser or with `s0 verify`, and no certificate, key, target path or operator
identity is ever sent anywhere.

### Core Architectural Mechanisms

#### Mathematical Non-Repudiation
Every sanitization certificate carries an **Ed25519 digital signature** (RFC 8032) computed over **s0 Canonical JSON v1**. The canonicalization engine eliminates JSON whitespace, key ordering, and floating-point divergences. The certificate content and its signature are mathematically inseparable: if the operation data is modified by even one bit, the signature check fails.

#### Air-Gapped Verification
The [Verification Portal](https://sector0.pages.dev/verify/) runs **100% in browser memory**. It downloads zero external CDN scripts and makes zero server requests. The portal can be saved to a thumb drive and executed via `file:///` on an isolated air-gapped machine in a secure facility or courtroom.

---

## Quick Start

{% hint style="success" %}
**Three commands to your first verified wipe:**
The installer runs on Linux, macOS, and Windows. No root is required for installation or disk image testing.
{% endhint %}

{% tabs %}
{% tab title="Linux/MacOS" %}
```bash
curl -fsSL https://sector0.pages.dev/sh | bash

s0 list

s0 plan --target /dev/sdb

sudo s0 wipe --target /dev/sdb --operator "analyst-01" --organization "Forensics Lab"
```
{% endtab %}

{% tab title="Windows (PowerShell)" %}
```powershell
irm https://sector0.pages.dev/ps1 | iex

s0 list

s0 plan --target \\.\PhysicalDrive1

s0 wipe --target \\.\PhysicalDrive1 --operator "analyst-01" --organization "Forensics Lab"
```
{% endtab %}

{% tab title="Windows (CMD)" %}
```cmd
curl -fsSL https://sector0.pages.dev/cmd -o s0-install.cmd && s0-install.cmd && del s0-install.cmd

s0 list

s0 plan --target \\.\PhysicalDrive1

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

s0 sanitization methods and evidence handling protocols are mapped to international standards including **NIST SP 800-88 Rev. 2**, **IEEE 2883-2022**, and **ISO/IEC 27037**. For full technical mappings and court-admissibility checklists, see the [Compliance Guide](compliance/nist-compliance.md).
