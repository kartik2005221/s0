# s0 (Forensic & Sanitization Suite) — Master Engineering Plan

**Title:** Integrated Secure Data Erasure and Advanced File Recovery Tool for Digital Forensics and Data Sanitization  
**Status:** Unified Engineering Plan (v2.0.0)

---

## 1. Executive Mission & Context

s0 addresses a dual operational necessity faced by security, intelligence, defense, and forensic recovery operations:
1. **Defensive Anti-Forensics & Sanitization:** Securely and irreversibly destroying sensitive data, classified files, or entire retired storage media so that no adversary or forensic laboratory can recover residual traces.
2. **Offensive Digital Forensics & Evidence Recovery:** Extracting, carving, and reconstructing deleted or damaged files from formatted, corrupted, or tampered storage media to recover digital evidence with strict chain of custody.
3. **Cryptographic Integrity & Chain of Custody (Blockchain Theme):** Providing an immutable, hash-chained local audit trail and Ed25519-signed certificates for all erasure and recovery operations.

Existing commercial tools force investigators to switch between separate, expensive, proprietary utilities (e.g. Blancco for wiping vs. FTK/Autopsy for recovery). s0 provides a single, unified, open-source platform combining high-assurance sanitization, advanced file carving, and a blockchain-style tamper-evident audit ledger.

---

## 2. System Architecture & Module Breakdown

```
s0/
├── core/                               # Shared Cryptographic & Serialization Engine
│   ├── cert_schema.json                # Schema v2.0.0 (Drive Wipe, File Wipe, Carving Manifest)
│   ├── CANONICAL_JSON.md               # Deterministic Canonical JSON v1 Specification
│   ├── standards/nist_800_88_mapping.md # NIST SP 800-88 & IEEE 2883-2022 registry
│   └── python/s0_core/          # Ed25519 signing, verifying, canonicalization, PDF/QR
├── linux/
│   ├── cli/s0_cli/
│   │   ├── devices.py                  # Physical block and image device inventory
│   │   ├── methods/                    # Module 1: NVMe, ATA, BLKDISCARD, Overwrite
│   │   ├── wipe.py                     # Module 1: Drive erasure orchestrator
│   │   ├── file_eraser.py              # Module 2: Secure File & Folder Eraser (extents, metadata)
│   │   ├── carver/                     # Module 3: Advanced File Carving & Recovery
│   │   │   ├── signatures.py           # Magic byte signatures & footer patterns (JPEG, PDF, PNG, ZIP, etc.)
│   │   │   ├── engine.py               # Raw stream & signature-based carving engine
│   │   │   ├── ext4_carver.py          # Structure-based ext4 inode & extent parser
│   │   │   └── scoring.py              # Forensic confidence scoring (heuristics + entropy)
│   │   ├── audit/                      # Audit Management & Hash-Chained Blockchain Ledger
│   │   │   ├── db.py                   # SQLite append-only ledger with SHA-256 hash chaining
│   │   │   └── verify.py               # Ledger continuity & integrity auditor
│   │   └── main.py                     # Unified CLI: drive-wipe, file-wipe, carve, audit
│   ├── gui/                            # Unified Web Dashboard (FastAPI + 4 Forensic Views)
│   └── iso/                            # Debian Live Bootable Kiosk for field deployments
├── verification-portal/                # Zero-Trust Client-Side Web Verifier
├── docs/                               # Comprehensive Technical Documentation
└── scripts/                            # Packaging, Loop Target, and Build Orchestrators
```

---

## 3. Core Modules Specification

### Module 1: Secure Drive Eraser
- **Target Media:** NVMe, SATA HDDs/SSDs, USB flash, SD cards, and raw forensic disk images (`.raw`, `.img`, `.dd`).
- **Sanitization Algorithms:**
  * Firmware Purge: NVMe Sanitize (Block/Crypto), NVMe Format, ATA Security Erase / Enhanced.
  * Kernel Discard: `BLKDISCARD` with DRAT/RZAT deterministic read validation.
  * Logical Overwrite: Single-pass zero (NIST Clear), multi-pass pseudo-random (DoD/NIST policy).
- **Verification:** 64-block uniform sampled readback + raw grep pattern scanning for planted forensic markers.
- **Reporting:** Signed Ed25519 Canonical JSON certificate + human PDF + QR code.

### Module 2: Secure File & Folder Eraser
- **Target Scope:** Individual sensitive files, nested directory trees, and batch file lists.
- **Sanitization Mechanism:**
  * Extent Resolution & In-Place Overwriting: Maps physical file extents (via `filefrag` / extent diagnostics) and performs multi-pass in-place cluster overwriting with fsync flushes.
  * Multi-Pass In-Place Cluster Overwriting: Overwrites allocated sectors with random/zero patterns before unlinking.
  * Metadata Cleansing: Truncates file size to 0, resets inode timestamps (atime, mtime to epoch 0), renames file to random string before unlinking to scrub directory entry remnants.
  * OS Cache, CoW, & Journaling Disclosure: Logs explicit caveats regarding journaling filesystems (ext4/NTFS journals), Copy-on-Write filesystems (Btrfs/ZFS), and flash wear leveling.
- **Verification:** Post-erase sampled block readback confirming 0x00 pattern and file non-existence.
- **Certification:** Consolidated batch erasure certificate signed via Ed25519.

### Module 3: Advanced File Carving & Recovery
- **Forensic Scope:** Extracting deleted, lost, or concealed evidence from formatted or corrupted storage media without relying on intact filesystem tables.
- **Carving Engines:**
  1. **Signature-Based Carving:** Header and footer pattern matching for high-value forensic formats:
     * Images: JPEG (`FF D8 FF` -> `FF D9`), PNG (`89 50 4E 47` -> `49 45 4E 44`), GIF, BMP.
     * Documents: PDF (`%PDF-` -> `%%EOF`), Office Open XML / ZIP (`50 4B 03 04`).
     * Executables & Archives: ELF, TAR, GZIP.
  2. **Structure-Based ext4 and NTFS Recovery:**
     * **ext4:** Direct parsing of ext4 superblocks, block group descriptors, inode tables, and extent trees.
     * **NTFS:** Master File Table ($MFT) parsing with resident attributes and single-run non-resident data streams.
  3. **Bounded Fragmented Reconstruction:** Reassembles fragmented data blocks within a bounded search window using format structural validation (e.g. JPEG SOS scan segment validation).
  4. **Forensic Confidence Scoring:** Computes objective confidence scores (0–100%) based on:
     * Valid magic header (30%)
     * Valid footer / terminator (30%)
     * Plausible file length & internal structure (20%)
     * Shannon entropy analysis (e.g. high entropy for compressed images, medium for text/PDF) (20%).
- **Certification:** Generated forensic recovery manifest signed with Ed25519.

### Audit Management System (Blockchain Hash-Chained Ledger)
- **Storage:** Local SQLite database (`s0_audit.db`).
- **Blockchain Mechanism:**
  * Genesis block initialized at installation.
  * Each audit event (Drive Wipe, File Wipe, File Carve, Recovery) forms a new block containing:
    `index`, `timestamp`, `operation_type`, `target_id`, `operator_id`, `cert_uuid`, `payload_hash`, `signature`, `prev_hash`, and `block_hash`.
  * `block_hash = SHA256(index + timestamp + op_type + target_id + cert_uuid + payload_hash + signature + prev_hash)`.
- **Auditing Tool:** Built-in `s0-cli audit verify` command verifying unbroken cryptographic chain from genesis to tip.

---

## 4. Phase Plan & Deliverables

| Phase | Module / Scope | Key Deliverables | Exit Verification Test |
|---|---|---|---|
| **Phase 1** | Foundation & Bug Fixes | Fix `linux/cli` probe bugs, auto-venv in `build_all.sh` | 100% pytest green across `core` and `linux/cli`. |
| **Phase 2** | Drive Eraser (Module 1) | Fixed ATA/NVMe/Overwrite drive wiper, e2e forensic demo | `demo_e2e.sh` passes with 0 marker hits and Ed25519 verification. |
| **Phase 3** | File & Folder Eraser (Module 2) | `file_eraser.py`, extents overwrite, metadata cleansing, batch API | `test_file_eraser.py`: files overwritten, metadata wiped, batch signed cert verified. |
| **Phase 4** | Advanced File Carver (Module 3) | `signatures.py`, `engine.py`, `ext4_carver.py`, `ntfs_carver.py`, `scoring.py` | `test_carver.py`, `test_ntfs_carver.py`: extracts planted JPEGs, PDFs, PNGs from ext4 & NTFS media with confidence scores > 85%. |
| **Phase 5** | Blockchain Audit Ledger | `audit/db.py`, `audit/verify.py`, hash chain verification | `test_audit.py`: logs operations, verifies chain, detects simulated row tamper. |
| **Phase 6** | Unified Web Dashboard | Extended GUI with Drive Erase, File Wipe, Carving, and Audit tabs | GUI tests pass; all 4 modules accessible in single web console. |
| **Phase 7** | Documentation & Packaging | Updated technical documentation and master build script | `scripts/build_all.sh` runs all suites cleanly and outputs green report. |
