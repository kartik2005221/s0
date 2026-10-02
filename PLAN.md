# s0 (Sector Zero) — Master Engineering Architecture & Blueprint

**Title:** Integrated Secure Data Erasure, Bit-Stream Imaging, File Recovery, and Cryptographic Ledger Suite for Digital Forensics and Media Sanitization  
**Status:** Production Release (v2.4.4) — All Core Modules, Platform Extensions, and CI Pipelines Fully Delivered & Hardened  
**Repository:** [github.com/kartik2005221/s0](https://github.com/kartik2005221/s0)  
**Documentation:** [s0-docs.gitbook.io](https://s0-docs.gitbook.io)  
**Install Portal:** [s0-install.pages.dev](https://s0-install.pages.dev)  
**Verification Portal:** [s0-verify.pages.dev](https://s0-verify.pages.dev)  

---

## 1. Mission & Operational Context

s0 unifies five core operational requirements in digital forensics, intelligence, incident response, and media decommissioning:

1. **Defensive Anti-Forensics & Data Sanitization (Module 1):** Securely and irreversibly sanitizing storage media, physical drives, partitions, or individual sensitive files per **NIST SP 800-88 Rev. 1** and **IEEE 2883-2022**, anchored by RFC 8032 **Ed25519 digital signatures** and RFC 8785 Canonical JSON v1.
2. **Offensive Digital Forensics & Evidence Recovery (Module 2):** Extracting, carving, and reconstructing deleted or concealed files from formatted, corrupted, or raw storage media (ext4, NTFS, FAT32, exFAT) with strict chain of custody and 4-factor Shannon entropy scoring.
3. **Forensic Bit-Stream Acquisition & Physical Cloning (Module 3):** Sector-by-sector fault-tolerant raw image acquisition (`s0 image`) and target cloning (`s0 clone`) with simultaneous dual SHA-256 and MD5 hashing, ddrescue-style bad-sector zero filling, and signed acquisition manifest emission.
4. **Cryptographic Chain of Custody & Audit Trail:** Providing an immutable, append-only **RFC 8785 Canonical JSON block hash-chained SQLite ledger** (`~/.s0/s0_audit.db`) for all wipe, erase, carve, and acquisition operations, verifiable offline without network connectivity.
5. **Universal Multi-Platform Operation:** Native CLI parity and platform-optimized execution across Linux (`s0`), Windows (`windows/cli`), and macOS (`macos/cli`), accompanied by a local loopback FastAPI Web Dashboard (`src/s0/web/`), an air-gapped Verification Portal (`site/verify/`), and automated Bare-Metal Live ISO builds.

---

## 2. Completed Phases & Engineering Deliverables

All planned development phases are **100% complete, hardened, and validated**:

| Phase | Module / Scope | Status | Key Deliverables | Verification Test |
|---|---|:---:|---|---|
| **Phase 0** | Project Initialization | **DONE** | Repository skeleton, MIT license, engineering standards, single source-of-truth config (`s0_config.json`) | Clean Git repository |
| **Phase 1** | Cryptographic Foundation | **DONE** | Ed25519 signing/verifying (`s0.crypto`), s0 Canonical JSON v1 (`s0.canonical`), `src/s0/data/cert_schema.json`, ReportLab PDF generator with QR (`s0.pdfgen`) | `tests/core/test_canonical.py`<br>`tests/core/test_tamper.py` |
| **Phase 2** | Media & File Sanitizer (Module 1) | **DONE** | NVMe Sanitize (`nvme.py`), ATA Secure Erase (`ata.py`), `BLKDISCARD` ioctl (`blkdiscard.py`), multi-pass zero/random overwriter (`overwrite.py`), 64-block post-wipe readback sampler | `tools/demo/e2e.sh`<br>`tests/cli/test_overwrite.py` |
| **Phase 3** | File & Folder Erasure | **DONE** | Cross-platform cluster overwriting (`file_eraser.py`, unified into `s0 wipe`), `O_NOFOLLOW` atomic opening, POSIX `fsync()`, Windows Win32 `FlushFileBuffers` & multi-chunk ADS scrubbing, macOS `F_FULLFSYNC` & symlink-safe `xattr -s` stripping | `tests/cli/test_file_eraser.py`<br>`windows/cli/tests/`<br>`macos/cli/tests/` |
| **Phase 4** | Advanced File Carver (Module 2) | **DONE** | Multi-format sliding-window carver (`engine.py`), ext4 inode extent tree parser (`ext4_carver.py`), NTFS $MFT non-resident runlist carver (`ntfs_carver.py`), FAT32/exFAT carvers, 4-factor Shannon entropy scoring | `tests/cli/test_carver.py`<br>`tests/cli/test_ntfs_carver.py`<br>`tools/demo/e2e_ntfs.sh` |
| **Phase 5** | Forensic Drive Imager (Module 3) | **DONE** | Fault-tolerant bit-stream acquisition & drive-to-drive cloning (`imager.py`), bad sector zero-fill recovery, dual SHA-256/MD5 hashing, signed acquisition manifest | `tests/cli/test_imager.py` |
| **Phase 6** | Hash-Chained Audit Ledger | **DONE** | Local SQLite3 append-only ledger (`audit/db.py`), RFC 8785 Canonical JSON block hash chaining, genesis-to-tip integrity auditor (`audit/verify.py`) | `tests/cli/test_audit.py` |
| **Phase 7** | Unified Web Dashboard & Verifier | **DONE** | FastAPI 4-tab visual console (`src/s0/web/`) with session auth token (`X-S0-Auth-Token`, mode 0640), zero-backend static Verification Portal (`site/verify/`) with WebCrypto and pinned key registry | `tests/src/s0/web/test_gui.py`<br>`tests/portal/` |
| **Phase 8** | Cross-Platform Parity & Automation | **DONE** | Full CLI subcommand parity on Windows & macOS (`s0` wrapper suites), automated GitHub Actions Live ISO builder (`build-iso.yml`), automated GitHub release assets, GitBook documentation suite (`docs/`), Agentic AI Skill (`skills/s0-forensics/`) | `pytest`<br>`bash tools/build-docs.sh` (100% green) |
| **Phase 9** | Live Media & USB Station (`s0 live`) | **DONE** | Native `s0 live` command suite (`download`, `devices`, `flash`, `build`), automated safe USB discovery, versioned release ISO naming, and progress bar burning | `tests/cli/test_live_manager.py` |

---

## 3. Architecture Specification

```
s0/
├── core/                               # Cryptographic engine & Canonical JSON v1
│   ├── cert_schema.json                # JSON Schema v1.0.0
│   ├── CANONICAL_JSON.md               # Deterministic canonicalization contract
│   └── python/s0/                 # Reference Python library (crypto, canonical, pdf, config)
├── src/s0/                   # Master cross-platform CLI suite
│   ├── methods/                        # Module 1: NVMe, ATA, BLKDISCARD, Overwrite
│   ├── file_eraser.py                  # Module 1: File & folder cluster sanitizer (s0 wipe)
│   ├── carver/                         # Module 2: ext4, NTFS, FAT32, exFAT, Entropy
│   ├── imager.py                       # Module 3: Bit-stream acquisition & disk cloning engine
│   ├── audit/                          # Supporting: Append-only SQLite hash-chained ledger
│   └── live_manager.py                 # Live ISO acquisition, safe USB inspection & flashing
├── windows/                            # Windows native subsystem & launchers (s0.bat, s0.ps1)
│   └── cli/s0_eraser.py                # Windows eraser with subcommand dispatch & Win32 API
├── macos/                              # macOS native subsystem & launchers (s0.sh)
│   └── cli/s0_eraser.py                # macOS eraser with subcommand dispatch & Darwin ioctls
├── src/s0/web/                                # FastAPI 4-tab forensic console (127.0.0.1:8669)
│   ├── app.py                          # REST API & WebSocket progress daemon
│   └── static/                         # Self-contained zero-CDN frontend (HTML, CSS, JS, fonts)
├── iso/                          # Bare-metal Debian 12 Live bootable ISO recipe
│   ├── config/                         # live-build chroot hooks, packages & systemd units
│   └── auto/build.sh                   # ISO compilation script
├── site/verify/                # 100% client-side WebCrypto verifier (s0-verify.pages.dev)
├── site/install/                     # Resilient web installer portal (s0-install.pages.dev)
├── docs/                       # Production documentation suite (s0-docs.gitbook.io)
├── skills/s0-forensics/                # Agentic AI Skill specification & reference manuals
└── tools/                            # Master build, test, install & release orchestrators
```

---

## 4. Operational Role of this Document

This document serves as the high-level engineering blueprint and architectural design record for the `s0` repository. It is maintained to provide engineers, evaluating organizations, and forensic compliance auditors with an authoritative, top-down summary of the project scope, completed phases, module capabilities, and verification references.

---

## 5. Future Roadmap

1. **Bare-Metal Live ISO Hardware Validation:** Smoke-test the Debian 12 Live ISO on physical x86_64 Dell, HP, and Lenovo enterprise server chassis.
2. **Native C# Windows Client:** Direct Win32 / PInvoke assembly packaging for Windows enterprise GPO deployments.
3. **Android Recovery & Sanitization (Termux/Native):** Android package implementing Canonical JSON v1 and File-Based Encryption (FBE) key destruction attestation.
4. **Btrfs / ZFS CoW Direct Extent Overwrite Driver:** Advanced kernel-level ioctl bypass for Copy-on-Write storage volumes.
