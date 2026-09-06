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
   - *Mitigation:* Modifying any row in the SQLite ledger breaks the SHA-256 block hash continuity (`prev_hash != block_hash`), detected instantly by `s0 audit verify`.

---

## 3. Subsystem Architecture

### 3.1 Module 1: Secure Drive Eraser (`trustwipe_cli/methods/`)
- Sanitizes physical HDDs, SSDs, NVMe drives, USB media, and raw image files.
- Communicates via controller-level commands (`NVME_SANITIZE`, `ATA_SECURE_ERASE`, `BLKDISCARD`) and host-level multi-pass overwrite engines.
- Conducts automated 64-block sampled readback verification and raw grep scanning for planted forensic markers.

### 3.2 Module 2: Secure File & Folder Eraser (`trustwipe_cli/file_eraser.py`, `windows/`, `macos/`)
- Cross-platform selective sanitization across Linux, Windows, and macOS.
- In-place cluster overwriting with hardware cache flushes (`fsync()`, `F_FULLFSYNC`, `FlushFileBuffers`).
- File attribute and stream cleansing (Windows Alternate Data Streams `:Zone.Identifier`, macOS `xattr` quarantine stripping).
- CoW filesystem detection (Linux Btrfs/ZFS, macOS APFS, Windows ReFS).
- Metadata cleansing (timestamp zeroing, file truncation, directory entry renaming before unlinking).
- Issues consolidated batch certificates signed with Ed25519.

### 3.3 Module 3: Advanced File Carving & Recovery (`trustwipe_cli/carver/`)
- **Signature Engine (`signatures.py`):** High-fidelity header/footer scanning for JPEG, PNG, PDF, ZIP/DOCX/XLSX, GIF, GZIP, BMP, ELF, SQLite3, MP3.
- **ext4 Structure Engine (`ext4_carver.py`):** Direct ext4 superblock, block group descriptor, and multi-extent tree parser for recovering deleted files with intact structure.
- **NTFS Structure Engine (`ntfs_carver.py`):** Direct Master File Table ($MFT) parser extracting resident attributes and multi-fragment non-resident runlists for deleted NTFS records.
- **FAT32 & exFAT Structure Engines (`fat_carver.py`, `exfat_carver.py`):** Direct parsing of BPB and exFAT VBR, cluster heap geometry, and directory entry sets for USB flash drives and SD cards.
- **Fragmented Reconstruction Engine (`fragmentation.py`):** Non-resident cluster run reassembly, ext4 extent tree traversal, and bifragment heuristic stream reassembly across cluster gaps.
- **Confidence Scoring (`scoring.py`):** Multi-factor scoring (header match 30%, footer match 30%, size plausibility 20%, Shannon entropy analysis 20%).

### 3.4 Module 4: Blockchain Audit Management Ledger (`trustwipe_cli/audit/`)
- **Unified Architecture (GUI & CLI):** Both the `s0` CLI and the Web GUI share the exact same append-only SQLite ledger file located at `~/.trustwipe/trustwipe_audit.db` (governed by `trustwipe_cli.audit.ledger.AuditLedger`). Every wipe, file erasure, or forensic carving operation—regardless of whether initiated from the terminal or the browser dashboard—appends to this shared ledger, forming a single unbroken timeline.
- **Cryptographic Hash-Chained Blocks:** Every sanitization and forensic carving event forms an immutable block:
  $$\text{block\_hash} = \text{SHA256}(\text{index} \parallel \text{timestamp} \parallel \text{op\_type} \parallel \text{target\_id} \parallel \text{operator\_id} \parallel \text{cert\_uuid} \parallel \text{payload\_hash} \parallel \text{signature} \parallel \text{prev\_hash})$$
- **Forensic Chain of Custody & Verification:** The verification engine iterates from the Genesis block to the tip, proving unbroken mathematical continuity. Any manual tampering with past SQLite rows instantly invalidates downstream block hashes (`prev_hash != block_hash`), detected immediately via `s0 audit verify` or the GUI Blockchain Audit Ledger tab.
- **Cross-Platform Compatibility:** Linux, Windows (`s0-windows-eraser`), and macOS (`s0-macos-eraser`) generate JSON audit records and certificates conforming to the same cryptographic specification, which can be verified identically or imported into the unified ledger.

### 3.5 Unified Web Dashboard (`gui/`)
- Multi-tab forensic operator console (FastAPI backend + responsive frontend):
  1. Drive Eraser Tab
  2. File & Folder Eraser Tab
  3. Forensic File Carver Tab
  4. Blockchain Audit Ledger Tab
