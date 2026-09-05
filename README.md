# TrustWipe 🛡️

> **Integrated Secure Data Erasure and Advanced File Recovery Platform**  
> *Smart India Hackathon (SIH 2026) • Problem Statement ID: 26149*  
> *National Technical Research Organisation (NTRO) • Theme: Blockchain & Cybersecurity*

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![NIST SP 800-88](https://img.shields.io/badge/Compliance-NIST%20SP%20800--88%20Rev.1-success.svg)](docs/COMPLIANCE.md)
[![Ed25519 Verified](https://img.shields.io/badge/Signatures-Ed25519%20RFC%208032-blueviolet.svg)](core/CANONICAL_JSON.md)
[![Tests: 150 Passed](https://img.shields.io/badge/Tests-150%20Passed-brightgreen.svg)](docs/TEST_PLAN.md)
[![Blockchain Ledger](https://img.shields.io/badge/Audit-SHA256%20Blockchain%20Ledger-orange.svg)](docs/ARCHITECTURE.md)

---

## 📌 Executive Overview

**TrustWipe** is a unified digital forensic and data sanitization platform developed for the **National Technical Research Organisation (NTRO)** under **SIH26149**.

It integrates two critical security capabilities into a single environment:
1. **Defensive Sanitization:** Irreversible drive, file, and folder data destruction adhering to **NIST SP 800-88 Rev. 1** and **IEEE 2883-2022**, verified by 64-block forensic readback and certified via **Ed25519 digital signatures**. Native cross-platform support across **Linux, Windows, and macOS**.
2. **Offensive Digital Forensics:** Advanced signature-based, structure-based (**ext4, NTFS, FAT32, exFAT**), and Shannon entropy-scored file carving with **multi-fragment and bifragment reconstruction** to extract and reassemble deleted evidence from formatted disks, USB flash drives, and SD cards.
3. **Blockchain Cryptographic Audit Trail:** An append-only local SQLite ledger with continuous **SHA-256 block hash chaining** guaranteeing unbroken chain of custody for all forensic operations.

---

## 🌟 Four Core Modules

```
┌────────────────────────────────────────────────────────────────────────┐
│                        TRUSTWIPE CORE MODULES                          │
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

## ⚡ Quickstart

### 1. Run Master Build & Verification (120 Tests)
```bash
bash scripts/build_all.sh
```

### 2. Drive Sanitization & Forensic Grep Demo
```bash
TRUSTWIPE_DEMO_SIZE_MIB=32 bash linux/cli/demo_e2e.sh
```

### 3. Secure File & Folder Erasure
```bash
.venv/bin/trustwipe-wipe erase-files --targets /path/to/classified_file.txt --passes 1
```

### 4. Advanced File Carving
```bash
.venv/bin/trustwipe-wipe carve --target /evidence/disk_image.raw --out-dir ./recovered_evidence
```

### 5. Blockchain Audit Chain Verification
```bash
.venv/bin/trustwipe-wipe audit verify
```

### 6. Launch Unified Web Dashboard
```bash
bash linux/gui/run.sh
# Open http://127.0.0.1:8000
```

---

## 📖 Documentation Index

| Document | Focus Area |
|---|---|
| [System Architecture](docs/ARCHITECTURE.md) | Subsystem architecture, threat model, cryptographic flow, ext4 structure |
| [User & Operator Manual](docs/USER_MANUAL.md) | CLI manual for all 4 modules, web dashboard guide, batch operations |
| [Standards & Compliance](docs/COMPLIANCE.md) | NIST SP 800-88 Rev. 1, IEEE 2883-2022, ISO/IEC 27037 forensic standards |
| [Test Plan & QA](docs/TEST_PLAN.md) | Testing pyramid, tamper matrix protocol, entropy tests, 120 test suites |
| [Technical Limitations](docs/LIMITATIONS.md) | Honest disclosure of SSD FTL, journaling filesystem remnants, ext4 parsing |
| [Evaluator Handover](docs/HANDOVER.md) | Quickstart, automated build script, module execution, key ceremony |
| [SIH Pitch Deck](docs/PITCH_OUTLINE.md) | Problem crisis, technical differentiators, live demo script, roadmap |

---

## 📄 License & Attribution

Developed for **Smart India Hackathon (SIH 2026)** • **National Technical Research Organisation (NTRO)**.  
Licensed under the [MIT License](LICENSE).
