<div align="center">

# S0 — Sector Zero

**Unified Forensic Data Sanitization, Bit-Stream Acquisition & Evidence Carving Suite**

[![Release](https://img.shields.io/badge/Release-v2.4.4-blue.svg)](https://github.com/kartik2005221/s0/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Website](https://img.shields.io/badge/Website-s0--site.pages.dev-blueviolet.svg)](https://s0-site.pages.dev/)
[![NIST SP 800-88](https://img.shields.io/badge/NIST_SP_800--88-Rev.1_Compliant-green.svg)](https://s0-docs.gitbook.io/COMPLIANCE/)
[![Ed25519](https://img.shields.io/badge/Signatures-Ed25519_RFC_8032-blueviolet.svg)](https://s0-docs.gitbook.io/CANONICAL_JSON/)
[![Documentation](https://img.shields.io/badge/Docs-s0--docs.gitbook.io-orange.svg)](https://s0-docs.gitbook.io/)

*One unified toolchain. Five forensic capabilities. Cryptographic chain-of-custody.*

---

### Official Portals & Live Deployment

| Service | Live URL | Purpose |
|---|---|---|
| **Official Website** | [s0-site.pages.dev](https://s0-site.pages.dev/) | Main product showcase, feature overview & ecosystem hub |
| **Documentation Portal** | [s0-docs.gitbook.io](https://s0-docs.gitbook.io/) | Complete engineering manuals, compliance matrices & guides |
| **Verification Portal** | [s0-verify.pages.dev](https://s0-verify.pages.dev/) | 100% client-side, air-gapped Ed25519 certificate verifier |
| **Installation Portal** | [s0-install.pages.dev](https://s0-install.pages.dev/) | One-line installation scripts, checksums & release packages |
| **GitHub Releases** | [github.com/kartik2005221/s0/releases](https://github.com/kartik2005221/s0/releases) | Pre-built hybrid Bootable Live ISOs, tarballs & checksums |

</div>

---

## What is S0?

**S0** is an open-source digital forensic and media sanitization suite engineered for investigators, compliance auditors, and system administrators. It integrates three core modules and a zero-trust verification portal into a single multi-platform suite:

| Capability | Module | What S0 Does |
|---|:---:|---|
| **Defensive Sanitization** | Module 1 | Irreversibly purges drives, files, and partitions per NIST SP 800-88 Rev. 1 & IEEE 2883-2022, emitting Ed25519-signed PDF/JSON compliance certificates. |
| **Offensive Carving** | Module 2 | Reconstructs deleted evidence from raw images, formatted disks, and USB drives across ext4, NTFS, FAT32, and exFAT with 4-factor Shannon entropy scoring. |
| **Bit-Stream Imaging** | Module 3 | Fault-tolerant raw evidence acquisition (`s0 image`) and drive duplication (`s0 clone`) with simultaneous live SHA-256/MD5 hashing and ddrescue-style bad sector zero-filling. |
| **Zero-Trust Verification** | Portal | Instant client-side verification of emitted certificates via WebCrypto or CLI without uploading sensitive case data. |

Every operation is recorded in a supporting hash-chained audit ledger (`~/.s0/s0_audit.db`), providing a tamper-evident chain of custody verifiable offline in milliseconds.

---

## Legal & Responsible Use Notice

> **IMPORTANT:** s0 is a digital forensic sanitization and recovery tool.

Only operate on storage media, physical drives, or files that you **legally own** or have **documented, written authorization** to examine. Unauthorized data destruction or forensic acquisition violates computer crime laws worldwide:
- **United States:** Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030
- **United Kingdom:** Computer Misuse Act 1990
- **European Union:** Directive 2013/40/EU
- **India:** Information Technology Act 2000, §§ 43, 66
- **International:** Budapest Convention on Cybercrime

Consult the [Documentation Legal FAQ](https://s0-docs.gitbook.io/faq/) for responsible use policies.

---

## Quick Installation

Full installation instructions and verification guides are hosted at [s0-install.pages.dev](https://s0-install.pages.dev/).

### Linux/MacOS
```bash
curl -fsSL https://s0-install.pages.dev/sh | bash
```

### Windows (PowerShell)
```powershell
irm https://s0-install.pages.dev/ps1 | iex
```

### Windows (Command Prompt)
```cmd
curl -fsSL https://s0-install.pages.dev/cmd -o s0-install.cmd && s0-install.cmd && del s0-install.cmd
```

After installation, `s0` is immediately registered on your system `PATH`:
```bash
s0 --version
```

<details>
<summary><b>Lifecycle Management (Upgrade & Uninstall)</b></summary>

```bash
s0 upgrade

s0 uninstall
```
</details>

---

## Quick Start CLI Examples

### 1. Storage Device Inventory & Pre-Flight Planning
```bash
s0 list

s0 plan --target /dev/sdb
```

### 2. NIST SP 800-88 Drive Sanitization
```bash
sudo s0 wipe --target /dev/sdb --yes --operator "analyst-01" --organization "Forensic Lab"
```

### 3. File & Directory Secure Deletion
```bash
s0 wipe --targets /path/to/file.pdf /path/to/sensitive_folder/ --passes 1
```

### 4. Forensic File Carving & Recovery
```bash
s0 carve --target evidence.raw --out-dir ./recovered --extensions jpg,png,pdf,zip --min-confidence 50
```

### 5. Bit-Stream Disk Imaging & Hardware Cloning
```bash
s0 image --source /dev/sdb --destination /evidence/drive_image.raw

sudo s0 clone --source /dev/sdb --destination /dev/sdc --yes
```

### 6. Audit Trail & Offline Cryptographic Verification
```bash
s0 audit list --limit 25

s0 audit verify

s0 verify certificate_12345678.json --key src/s0/data/keys/demo_issuer_public.pem
```

### 7. Bootable Live Media & USB Station (`s0 live`)
```bash
s0 live download

s0 live devices

sudo s0 live flash --target /dev/sdb -y
```

---

## Interfaces: CLI, Web Console & Bare-Metal ISO

### 1. Local Forensic Web Dashboard (`sudo s0 web`)
Launch the air-gapped 4-tab browser console directly on loopback (`127.0.0.1:8669`):
```bash
sudo s0 web
```
> **Note on Root Privileges:** Direct block device sanitization and raw disk acquisition require root (`sudo`) privileges to access raw storage controllers. Without sudo, unprivileged file/folder wiping remains available, while direct drive wiping is disabled for safety.

The Web Dashboard runs the identical cryptographic and carving engines as the CLI and shares the local SQLite audit ledger.

### 2. Bare-Metal Bootable Live ISO (Debian 12)
When internal or system drives cannot be unmounted within a running host OS:
1. Download verified hybrid ISO directly from CLI or GitHub Releases:
   ```bash
   s0 live download
   ```
2. Flash to USB pendrive:
   ```bash
   sudo s0 live flash --target /dev/sdb
   ```
3. Boot target system into the air-gapped Chromium kiosk wipe station. Consult the [Live ISO Build & Deployment Guide](https://s0-docs.gitbook.io/LIVE_ISO_BUILD_GUIDE/) for details.

### 3. Verification Portal ([s0-verify.pages.dev](https://s0-verify.pages.dev/))
Every certificate issued embeds a QR code linking to the client-side portal. Built with pure WebCrypto:
- Zero data ever leaves your browser.
- Operates 100% offline — drag and drop `certificate.json` into `verification-portal/index.html`.
- Accredited authority public keys are pinned; untrusted keys trigger immediate visual warnings.

---

## Agentic AI Skill (`skills/s0-forensics/`)

`s0` includes a dedicated, high-assurance agentic skill conforming to the **Skill Creator** standard:
- **Specification:** [`skills/s0-forensics/SKILL.md`](skills/s0-forensics/SKILL.md) (also mirrored in `.agents/skills/s0-forensics/SKILL.md`)
- **Safety Directives:** Enforces mandatory pre-flight dry-runs (`s0 plan`), drive serial/model confirmation, operational patience (no premature aborts during controller sanitization), and post-execution certificate verification.
- **Reference Manuals:** Comprehensive technical guides covering NIST/IEEE method mappings, hardware safety rules, magic-byte signatures, and cryptographic audit specifications.
- **Documentation Guide:** See [Agentic AI & High-Risk Safety Guide](https://s0-docs.gitbook.io/agentic-ai/) on the docs portal.

---

## Standards Compliance Matrix

| Standard | Category | S0 Engineering Implementation |
|---|---|---|
| **NIST SP 800-88 Rev. 1** | Media Sanitization | Purge (NVMe Sanitize, ATA Secure Erase), Clear (1-pass zero overwrite, file cluster sanitization). |
| **IEEE 2883-2022** | Storage Sanitization | Standardized classification of physical and logical block sanitization. |
| **ISO/IEC 27037** | Digital Evidence Handling | Simultaneous SHA-256 & MD5 evidence hashing, non-repudiation via Ed25519 signing, append-only ledger. |
| **RFC 8785** | Canonical JSON (JCS) | Deterministic cryptographic certificate serialization and block hashing. |
| **RFC 8032** | Digital Signatures | High-performance Ed25519 public-key signature system. |

Full compliance details: [docs/compliance/nist-compliance.md](https://s0-docs.gitbook.io/COMPLIANCE/)

---

## Documentation Index

| Guide | Online URL | Local File |
|---|---|---|
| **User & Operator Manual** | [s0-docs.gitbook.io/USER_MANUAL](https://s0-docs.gitbook.io/USER_MANUAL/) | [`docs/guides/user-manual.md`](docs/guides/user-manual.md) |
| **Architecture Specification** | [s0-docs.gitbook.io/ARCHITECTURE](https://s0-docs.gitbook.io/ARCHITECTURE/) | [`docs/architecture/system-architecture.md`](docs/architecture/system-architecture.md) |
| **CLI Complete Reference** | [s0-docs.gitbook.io/cli-reference](https://s0-docs.gitbook.io/cli-reference/) | [`docs/guides/cli-reference.md`](docs/guides/cli-reference.md) |
| **Forensic Carving Guide** | [s0-docs.gitbook.io/forensic-carving-guide](https://s0-docs.gitbook.io/forensic-carving-guide/) | [`docs/guides/forensic-carving.md`](docs/guides/forensic-carving.md) |
| **Live ISO Build Guide** | [s0-docs.gitbook.io/LIVE_ISO_BUILD_GUIDE](https://s0-docs.gitbook.io/LIVE_ISO_BUILD_GUIDE/) | [`docs/guides/live-iso.md`](docs/guides/live-iso.md) |
| **Agentic AI Guide** | [s0-docs.gitbook.io/agentic-ai](https://s0-docs.gitbook.io/agentic-ai/) | [`docs/project/agentic-ai.md`](docs/project/agentic-ai.md) |
| **Standards Compliance** | [s0-docs.gitbook.io/COMPLIANCE](https://s0-docs.gitbook.io/COMPLIANCE/) | [`docs/compliance/nist-compliance.md`](docs/compliance/nist-compliance.md) |
| **Engineering Handover** | [s0-docs.gitbook.io/HANDOVER](https://s0-docs.gitbook.io/HANDOVER/) | [`docs/project/evaluator-guide.md`](docs/project/evaluator-guide.md) |

---

## Automated Test Verification

Execute the complete automated test suite locally:

```bash
.venv/bin/pytest core/tests linux/cli/tests web/tests windows/cli/tests macos/cli/tests verification-portal/tests -v

bash scripts/build_all.sh
```

---

## License

Distributed under the **MIT License**. See [LICENSE](LICENSE) for full legal text.
