# Evaluator & Technical Demonstration Guide

> **Target Audience:** Technical Evaluators, Digital Forensic Examiners, Hackathon Judges, and Core Maintainers.  
> **Software Release:** v2.4.3  
> **Format:** Automated Verification Suite + 5-Minute Technical Pitch + 3-Minute Live Demonstration

---

## 1. Quickstart: One-Command Automated Setup & Test

The s0 suite provides an automated bootstrap script that validates system prerequisites, provisions a virtual environment, installs platform dependencies, and runs the test suite:

```bash
bash scripts/build_all.sh
```

---

## 2. Module-by-Module Verification

### Comprehensive Test Suite (190+ Tests)
Execute the complete cross-platform test suite spanning core cryptographic invariants, CLI interfaces, web controllers, Win32/macOS drivers, and verification portal:

```bash
.venv/bin/pytest core/tests linux/cli/tests web/tests windows/cli/tests macos/cli/tests verification-portal/tests -v
```

### Module 1: End-to-End Drive Wipe Forensic Demo
Executes a full lifecycle test on a temporary 32 MiB synthetic loopback image (partitioning, random byte seeding, NIST overwrite, 64-block post-wipe readback verification, Ed25519 cert generation, and ledger insertion):

```bash
S0_DEMO_SIZE_MIB=32 bash linux/cli/demo_e2e.sh
```

### Targeted File & Folder Erasure
Surgically sanitizes specific file paths with extent overwriting, metadata timestamp zeroing, and directory entry scrambling:

```bash
.venv/bin/s0 wipe --targets /path/to/sensitive_file.txt --passes 1
```

### Module 2: Advanced Forensic File Carving
Scans raw disk images or unallocated drive space using filesystem-aware structure parsers and raw sliding-window signature carving:

```bash
.venv/bin/s0 carve --target /path/to/image.raw --out-dir ./recovered
```

### Module 3: Bit-Stream Forensic Disk Acquisition
Acquires raw bit-stream evidence images or performs 1:1 drive cloning with real-time simultaneous SHA-256 and MD5 streaming digests:

```bash
sudo .venv/bin/s0 image /dev/sdb ./evidence.dd
```

### Module 4: Blockchain Cryptographic Audit Ledger
Audits the append-only SQLite ledger (`~/.s0/s0_audit.db`) and verifies mathematical hash continuity across every block:

```bash
.venv/bin/s0 audit verify
```

### Local Web Dashboard Console
Launches the local, zero-external-dependency web interface on `127.0.0.1:8669`:

```bash
sudo .venv/bin/s0 web
```

### Bare-Metal Live ISO
For offline, host-level drive decommissioning under NIST SP 800-88 §2.4, see [Bare-Metal Live ISO Guide](../guides/live-iso.md) for build pipelines, containerized tools, and QEMU test environments.

---

## 3. Defense & Forensics Technical Presentation

**Title:** Integrated Secure Data Erasure and Advanced File Recovery Tool for Digital Forensics and Data Sanitization  
**Format:** 5-Minute Technical Pitch + 3-Minute Live Interactive Demonstration

### The Core Problem in Digital Forensics
Digital forensics and data security operations face two fundamental, conflicting operational requirements:
1. **The Sanitization Challenge (Defensive):** Intelligence agencies and enterprises need to irreversibly sanitize decommissioned storage media and classified files so that unauthorized parties cannot recover sensitive data.
2. **The Recovery Challenge (Offensive):** Cyber forensic investigators need to extract, carve, and reconstruct deleted or concealed digital evidence from seized, formatted, or corrupted storage devices.
3. **The Fragmentation Problem:** Currently, practitioners must juggle multiple disjoint, proprietary tools (e.g. Blancco for drive wiping, BCWipe for file deletion, Autopsy/FTK for carving). This introduces operational friction, licensing paywalls, and fragmented, unverified audit trails.

### The s0 Unified Architecture

```
+------------------------------------------------------------------------+
|                              S0 CORE MODULES                           |
+----------------------------------+-------------------------------------+
| 1. Media & File Sanitizer        | Firmware Purge (NVMe/ATA), Discard, |
|    (Unified Drive/File Wipe)     | 1-pass Clear + Forensic Verification|
+----------------------------------+-------------------------------------+
| 2. Advanced File Carving         | Signature (JPEG/PNG/PDF/ZIP), Ext4  |
|    (Recovery Engine)             | & NTFS MFT parser & entropy scoring |
+----------------------------------+-------------------------------------+
| 3. Bit-Stream Disk Imaging       | Bad sector zero-filling & dual      |
|    (Acquisition & Cloning)       | live SHA-256/MD5 stream hashing     |
+----------------------------------+-------------------------------------+
| 4. Blockchain Audit Ledger       | Append-only SQLite ledger with      |
|    (Cryptographic Ledger)        | SHA-256 block hash chaining         |
+----------------------------------+-------------------------------------+
```

---

## 4. Live 3-Minute Demonstration Script

### Minute 1: Drive & File Sanitization (`s0 wipe`)
- **Presenter:** *"Judges, let us demonstrate irreversible sanitization on sensitive files and storage media."*
- **Action:** Run `s0 wipe --targets classified_intel.pdf` and `demo_e2e.sh`.
- **Result:** File clusters overwritten, metadata zeroed, 64-block forensic scan verifies complete sanitization, and an Ed25519 signed certificate is generated.

### Minute 2: Module 2 (Advanced File Carving & Recovery)
- **Presenter:** *"Now let us demonstrate our offensive forensic capability: carving deleted evidence from a formatted raw disk image."*
- **Action:** Run `s0 carve --target /evidence/suspect_drive.raw --out-dir ./recovered`.
- **Result:** Carver scans disk, identifies magic headers/footers, calculates Shannon entropy confidence scores (>85%), extracts recovered files, and outputs a signed forensic recovery manifest.

### Minute 3: Module 4 (Blockchain Audit Ledger)
- **Presenter:** *"How do we guarantee unbroken chain-of-custody for compliance audits?"*
- **Action:** Open web dashboard or run `s0 audit verify`.
- **Result:** Displays the SHA-256 hash-chained block ledger. Simulate a tampering attempt in SQLite and show the auditor detecting the exact broken block index immediately.
