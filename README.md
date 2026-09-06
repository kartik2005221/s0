# S0 (Sector Zero) 🛡️

> **Integrated Secure Data Erasure and Advanced File Recovery Platform**  
> *Smart India Hackathon (SIH 2026) • Problem Statement ID: 26149*  
> *National Technical Research Organisation (NTRO) • Theme: Blockchain & Cybersecurity*

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![NIST SP 800-88](https://img.shields.io/badge/Compliance-NIST%20SP%20800--88%20Rev.1-success.svg)](docs/COMPLIANCE.md)
[![Ed25519 Verified](https://img.shields.io/badge/Signatures-Ed25519%20RFC%208032-blueviolet.svg)](core/CANONICAL_JSON.md)
[![Tests: 180+ Passed](https://img.shields.io/badge/Tests-180%2B%20Passed-brightgreen.svg)](docs/TEST_PLAN.md)
[![Blockchain Ledger](https://img.shields.io/badge/Audit-SHA256%20Blockchain%20Ledger-orange.svg)](docs/ARCHITECTURE.md)
[![Verification Portal](https://img.shields.io/badge/Web%20Portal-Live%20on%20Vercel-success.svg)](https://trustwipe-vp.vercel.app/)

---

## 📌 Executive Overview

**S0 (Sector Zero)** is an integrated digital forensics and data sanitization suite developed for the **National Technical Research Organisation (NTRO)** under **SIH26149**.

It unifies two critical operational capabilities into a single high-assurance platform:
1. **Defensive Sanitization:** Irreversible drive, file, and partition sanitization adhering to **NIST SP 800-88 Rev. 1** and **IEEE 2883-2022**, verified by 64-block forensic readback and certified via **Ed25519 digital signatures**. Native cross-platform execution on **Linux, Windows, and macOS** with in-place overwriting and metadata cleansing.
2. **Offensive Digital Forensics:** Advanced signature-based, structure-based (**ext4, NTFS, FAT32, exFAT**), and Shannon entropy-scored file carving with **multi-fragment and bifragment reconstruction** to recover deleted evidence from formatted disks, USB pendrives, and raw images.
3. **Blockchain Cryptographic Audit Trail:** An append-only local SQLite ledger with continuous **SHA-256 block hash chaining** guaranteeing an unbroken, tamper-evident chain of custody for all forensic operations.
4. **Zero-Trust Verification Portal:** A 100% client-side, air-gapped web verifier powered by audited TweetNaCl WebCrypto, supporting automated URL parameter loading (`?cert=`), custom public key verification, and tamper detection.

---

## ⚡ One-Line Install

### Linux & macOS
```bash
curl -sSL https://raw.githubusercontent.com/kartik2005221/sih26149/master/scripts/install.sh | bash
```

### Windows (PowerShell)
```powershell
irm https://raw.githubusercontent.com/kartik2005221/sih26149/master/scripts/install.ps1 | iex
```

### Windows (Command Prompt)
```cmd
curl -sSL https://raw.githubusercontent.com/kartik2005221/sih26149/master/scripts/install.cmd | cmd
```

---

## 🌟 Core Modules

```
┌────────────────────────────────────────────────────────────────────────┐
│                          S0 CORE MODULES                               │
├──────────────────────────────────┬─────────────────────────────────────┤
│ 1. Secure Drive Eraser           │ Firmware Purge (NVMe/ATA), Discard, │
│    (Module 1)                    │ 1-pass Clear + 64-block verification│
├──────────────────────────────────┼─────────────────────────────────────┤
│ 2. Secure File & Folder Eraser   │ Cross-Platform (Linux/Win/macOS),   │
│    (Module 2)                    │ in-place overwrite, ADS/xattr scrub │
├──────────────────────────────────┼─────────────────────────────────────┤
│ 3. Advanced File Carving         │ Multi-FS (ext4, NTFS, FAT32, exFAT),│
│    (Module 3)                    │ multi-run & bifragment reassembly   │
├──────────────────────────────────┼─────────────────────────────────────┤
│ 4. Blockchain Audit Ledger       │ Append-only SQLite ledger with      │
│    (Module 4)                    │ SHA-256 block hash chaining         │
└──────────────────────────────────┴─────────────────────────────────────┘
```

---

## 💻 CLI Quick Reference (`s0`)

### 1. Drive Sanitization
```bash
# List physical storage targets
s0 list

# Dry-run plan (nothing written)
s0 plan --target /dev/sdb

# Sanitize drive with real-time progress and opportunistic temperature monitoring
s0 wipe --target /dev/sdb --yes --operator "op-01" --organization "NTRO Lab"
```

### 2. Secure File & Folder Erasure
```bash
# In-place overwrite with metadata cleansing and timestamp resetting
s0 erase --targets /classified/doc.pdf /classified/folder/ --passes 1
```

### 3. Advanced File Carving & Recovery
```bash
# Carve files across ext4/NTFS/FAT32/exFAT partitions
s0 carve --target /evidence/disk.raw --out-dir ./recovered --extensions jpg,png,pdf,zip --min-confidence 50
```

### 4. Blockchain Audit Ledger
```bash
# List recent audit ledger blocks
s0 audit list --limit 25

# Verify cryptographic hash-chain continuity from genesis to tip
s0 audit verify
```

### 5. Offline Certificate Verification & Key Ceremony
```bash
# Verify any signed certificate offline
s0 verify certificate_12345678.json --key core/keys/demo_issuer_public.pem

# Generate an Ed25519 authority keypair
s0 keygen --out-dir ./my_keys --name ntro_authority
```

---

## 📊 Unified Progress & Temperature Monitoring

All long-running wipe and carve operations stream a unified, rate-throttled ANSI progress bar:

```text
[s0 wipe]  | [████████████████░░░░] | 78.2% | 22.6 GiB / 28.9 GiB | 18.4 MB/s | Elapsed: 20m 30s | ETA: 05m 42s | Temp: 44°C
[s0 carve] | [████████░░░░░░░░░░░░] | 35.4% | 10.2 GiB / 28.9 GiB | 142 MB/s  | Elapsed: 01m 15s | ETA: 02m 10s | Found: 36,790
```

- **Opportunistic Thermal Probing:** Discovers thermal sensors automatically via Linux sysfs hwmon, NVMe SMART telemetry, or SATA SMART attribute 194/190.
- **Graceful Fallback:** If a target (e.g. standard USB flash drive or virtual disk image) lacks thermal sensors, the temperature indicator is silently omitted without errors.

---

## 🌐 Zero-Trust Verification Portal

Certificates generated by S0 can be verified independently using the client-side portal:
- **Live Deployment:** [https://trustwipe-vp.vercel.app/](https://trustwipe-vp.vercel.app/)
- **Zero-Backend Architecture:** Pure JavaScript running in the user's browser via audited TweetNaCl WebCrypto; no sensitive data or certificates are ever uploaded to any server.
- **URL Parameter Verification:** Scan the QR code on any certificate PDF to automatically open and verify the certificate via `?cert=`.
- **Two-Tier Public Key Verification:** Supports official pinned authorities as well as custom operator public keys with clear visual badges.

---

## 🧪 Master Test Suite (180+ Tests)

Execute the full cross-platform test matrix including unit tests, end-to-end forensic demonstrations, and Node.js browser crypto cross-verification:

```bash
bash scripts/build_all.sh
```

---

## 📖 Documentation Index

| Document | Focus Area |
|---|---|
| [System Architecture](docs/ARCHITECTURE.md) | Subsystem architecture, threat model, cryptographic flow, ext4 structure |
| [User & Operator Manual](docs/USER_MANUAL.md) | Comprehensive CLI manual for all modules, web dashboard guide, batch operations |
| [Standards & Compliance](docs/COMPLIANCE.md) | NIST SP 800-88 Rev. 1, IEEE 2883-2022, ISO/IEC 27037 forensic standards |
| [Test Plan & QA](docs/TEST_PLAN.md) | Testing pyramid, tamper matrix protocol, entropy tests, 180+ test suites |
| [Technical Limitations](docs/LIMITATIONS.md) | Honest disclosure of SSD FTL, journaling filesystem remnants, ext4 parsing |
| [Evaluator Handover](docs/HANDOVER.md) | Quickstart, automated build script, module execution, key ceremony |
| [SIH Pitch Deck](docs/PITCH_OUTLINE.md) | Problem crisis, technical differentiators, live demo script, roadmap |
| [Verification Portal](docs/VERIFICATION_AND_DEPLOYMENT.md) | Zero-trust offline web deployment, public key pinning, custom key audit |

---

## 📄 License & Attribution

Developed for **Smart India Hackathon (SIH 2026)** • **National Technical Research Organisation (NTRO)**.  
Licensed under the [MIT License](LICENSE).
