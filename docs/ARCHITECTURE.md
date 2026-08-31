# TrustWipe — System Architecture & Forensic Engineering

**Problem Statement ID:** 26149  
**Problem Statement Title:** Design and Development of an Integrated Secure Data Erasure and Advanced File Recovery Tool for Digital Forensics and Data Sanitization  
**Organization / Department:** National Technical Research Organisation (NTRO)  
**Theme:** Blockchain & Cybersecurity  
**Version:** 2.0.0 (SIH26149 Production Architecture)

---

## 1. Executive Mission & System Overview

TrustWipe is an integrated, dual-capability software suite engineered specifically for intelligence, defense, and digital forensics operations at the **National Technical Research Organisation (NTRO)**. 

TrustWipe bridges the gap between two traditionally disjoint domains:
1. **Defensive Anti-Forensics & Data Sanitization:** Irreversible destruction of sensitive intelligence data, files, and physical drives in compliance with **NIST SP 800-88 Rev. 1** and **IEEE 2883-2022**, anchored by **Ed25519 digital signatures**.
2. **Offensive Digital Forensics & Evidence Recovery:** Advanced signature-based, structure-based (ext4), and entropy-scored carving to extract and reconstruct deleted or fragmented files from formatted or corrupted storage media.
3. **Blockchain-Themed Cryptographic Audit Trail:** An append-only local SQLite ledger where every wipe, file erasure, and forensic carving operation forms a cryptographic block chained by **SHA-256 block hashing**, ensuring complete non-repudiation and forensic chain of custody.

---

## 2. Threat Model & Forensic Objectives

```
   ┌────────────────────────────────────────────────────────────────────────┐
   │                       TRUSTWIPE ARCHITECTURE                           │
   ├───────────────────────────────────┬────────────────────────────────────┤
   │     SANITIZATION SUBSYSTEM        │        FORENSIC SUBSYSTEM          │
   ├───────────────────────────────────┼────────────────────────────────────┤
   │ • Module 1: Drive Eraser          │ • Module 3: Advanced File Carver   │
   │   (NVMe, ATA, Discard, Overwrite) │   (Signature, Ext4, Entropy Score) │
   │ • Module 2: File/Folder Eraser    │ • Evidence Reconstruction Engine   │
   │   (Extents, Metadata Cleansing)   │   (Bounded Fragment Reassembly)    │
   ├───────────────────────────────────┴────────────────────────────────────┤
   │                  CRYPTOGRAPHIC CORE & INTEGRITY LAYER                  │
   ├────────────────────────────────────────────────────────────────────────┤
   │ • Ed25519 Digital Signatures (RFC 8032) & TrustWipe Canonical JSON v1  │
   │ • Module 4: Blockchain Hash-Chained Audit Ledger (SQLite + SHA-256)    │
   └────────────────────────────────────────────────────────────────────────┘
```

### Forensic Threats & Integrity Guarantees:
1. **Evidence Tampering & Chain-of-Custody Break:**
   - *Threat:* Defense attorneys or adversaries claim digital evidence was planted or modified post-extraction.
   - *Mitigation:* Every carved file generates a cryptographic SHA-256 hash. The session manifest is Ed25519-signed and recorded into the hash-chained blockchain audit ledger.
2. **Incomplete Sanitization & Data Residue:**
   - *Threat:* File deletion leaves directory entry names, timestamps, or allocated cluster remnants reachable by forensic tools.
   - *Mitigation:* Module 2 executes physical cluster overwriting, resets inode timestamps to epoch 0, and scrambles directory entry filenames before unlinking.
3. **Audit Record Alteration:**
   - *Threat:* An insider alters database records to hide unauthorized data destruction or evidence tampering.
   - *Mitigation:* Modifying any row in the SQLite ledger breaks the SHA-256 block hash continuity (`prev_hash != block_hash`), detected instantly by `trustwipe-wipe audit verify`.

---

## 3. Subsystem Architecture

### 3.1 Module 1: Secure Drive Eraser (`trustwipe_cli/methods/`)
- Sanitizes physical HDDs, SSDs, NVMe drives, USB media, and raw image files.
- Communicates via controller-level commands (`NVME_SANITIZE`, `ATA_SECURE_ERASE`, `BLKDISCARD`) and host-level multi-pass overwrite engines.
- Conducts automated 64-block sampled readback verification and raw grep scanning for planted forensic markers.

### 3.2 Module 2: Secure File & Folder Eraser (`trustwipe_cli/file_eraser.py`)
- Selective sanitization of targeted files and directories.
- In-place cluster overwriting with fsync flushes.
- Metadata cleansing (timestamp zeroing, file truncation, directory entry renaming before unlinking).
- Issues consolidated batch certificates signed with Ed25519.

### 3.3 Module 3: Advanced File Carving & Recovery (`trustwipe_cli/carver/`)
- **Signature Engine (`signatures.py`):** High-fidelity header/footer scanning for JPEG, PNG, PDF, ZIP/DOCX/XLSX, GIF, GZIP.
- **ext4 Structure Engine (`ext4_carver.py`):** Direct ext4 superblock, block group descriptor, and inode extent tree parser for recovering deleted files with intact structure.
- **NTFS Structure Engine (`ntfs_carver.py`):** Direct Master File Table ($MFT) parser extracting resident attributes and single-run non-resident data streams for deleted NTFS records.
- **Confidence Scoring (`scoring.py`):** Multi-factor scoring (header match 30%, footer match 30%, size plausibility 20%, Shannon entropy analysis 20%).

### 3.4 Module 4: Blockchain Audit Management Ledger (`trustwipe_cli/audit/`)
- Append-only local SQLite ledger (`trustwipe_audit.db`).
- Every sanitization and forensic carving event forms a block:
  $$	ext{block\_hash} = 	ext{SHA256}(	ext{index} \parallel 	ext{timestamp} \parallel 	ext{op\_type} \parallel 	ext{target\_id} \parallel 	ext{operator\_id} \parallel 	ext{cert\_uuid} \parallel 	ext{payload\_hash} \parallel 	ext{signature} \parallel 	ext{prev\_hash})$$
- Verification engine iterates from Genesis to tip, proving unbroken mathematical continuity.

### 3.5 Unified Web Dashboard (`linux/gui/`)
- Multi-tab forensic operator console (FastAPI backend + responsive frontend):
  1. Drive Eraser Tab
  2. File & Folder Eraser Tab
  3. Forensic File Carver Tab
  4. Blockchain Audit Ledger Tab
