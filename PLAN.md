# s0 (Sector Zero) — Master Engineering Architecture & Roadmap

**Title:** Integrated Secure Data Erasure and Advanced File Recovery Suite for Digital Forensics and Data Sanitization  
**Status:** Production Release (v2.0.0) — All Phases Fully Delivered  
**Repository:** [github.com/kartik2005221/s0](https://github.com/kartik2005221/s0)

---

## 1. Mission & Operational Context

s0 unifies three core operational requirements in digital forensics, intelligence, and incident response:
1. **Defensive Anti-Forensics & Data Sanitization:** Securely and irreversibly sanitizing storage media, physical drives, or individual sensitive files per **NIST SP 800-88 Rev. 1** and **IEEE 2883-2022**, anchored by RFC 8032 **Ed25519 digital signatures**.
2. **Offensive Digital Forensics & Evidence Recovery:** Extracting, carving, and reconstructing deleted or concealed files from formatted, corrupted, or raw storage media (ext4, NTFS, FAT32, exFAT) with strict chain of custody.
3. **Cryptographic Chain of Custody & Audit Trail:** Providing an immutable, append-only **SHA-256 block hash-chained SQLite ledger** (`~/.s0/s0_audit.db`) for all wipe and recovery operations, verifiable offline without network connectivity.

---

## 2. Completed Phases & Engineering Deliverables

All planned development phases are **100% complete and validated**:

| Phase | Module / Scope | Status | Key Deliverables | Verification Test |
|---|---|:---:|---|---|
| **Phase 0** | Project Initialization | **DONE** | Repository skeleton, MIT license, engineering standards | Clean Git repository |
| **Phase 1** | Cryptographic Foundation | **DONE** | Ed25519 signing/verifying (`s0_core.crypto`), s0 Canonical JSON v1 (`s0_core.canonical`), `core/cert_schema.json`, ReportLab PDF generator with QR (`s0_core.pdfgen`) | `core/tests/test_canonical.py`<br>`core/tests/test_tamper.py` |
| **Phase 2** | Secure Drive Eraser (Module 1) | **DONE** | NVMe Sanitize (`nvme.py`), ATA Secure Erase (`ata.py`), `BLKDISCARD` ioctl (`blkdiscard.py`), multi-pass zero/random overwriter (`overwrite.py`), 64-block post-wipe readback sampler | `linux/cli/demo_e2e.sh`<br>`linux/cli/tests/test_overwrite.py` |
| **Phase 3** | Secure File Eraser (Module 2) | **DONE** | Cross-platform cluster overwriting (`file_eraser.py`), POSIX `fsync()`, Windows Win32 `FlushFileBuffers` & ADS scrubbing, macOS `F_FULLFSYNC` & `xattr` stripping, inode timestamp zeroing, directory scrambling | `linux/cli/tests/test_file_eraser.py`<br>`windows/cli/tests/`<br>`macos/cli/tests/` |
| **Phase 4** | Advanced File Carver (Module 3) | **DONE** | Multi-format sliding-window carver (`engine.py`), ext4 inode extent tree parser (`ext4_carver.py`), NTFS $MFT non-resident runlist carver (`ntfs_carver.py`), FAT32/exFAT carvers, 4-factor Shannon entropy scoring | `linux/cli/tests/test_carver.py`<br>`linux/cli/tests/test_ntfs_carver.py`<br>`linux/cli/demo_e2e_ntfs.sh` |
| **Phase 5** | Blockchain Audit Ledger (Module 4) | **DONE** | Local SQLite3 append-only ledger (`audit/ledger.py`), SHA-256 block hash chaining, genesis-to-tip integrity auditor (`audit/verify.py`) | `linux/cli/tests/test_audit.py` |
| **Phase 6** | Unified Web Dashboard & Verifier | **DONE** | FastAPI 4-tab visual console (`gui/`), zero-backend static Verification Portal (`verification-portal/`) with TweetNaCl WebCrypto and pinned key registry (`keys.json`) | `gui/tests/test_gui.py`<br>`verification-portal/tests/` |
| **Phase 7** | Packaging, Live ISO & Documentation | **DONE** | Debian 12 Live ISO recipe (`linux/iso/`), cross-platform installers (`scripts/`), master test orchestrator (`build_all.sh`), Material for MkDocs documentation site | `bash scripts/build_all.sh`<br>`bash scripts/build-docs.sh` (100% green) |

---

## 3. Architecture Specification

```
s0/
├── core/                               # Cryptographic engine & Canonical JSON v1
│   ├── cert_schema.json                # JSON Schema v1.0.0
│   ├── CANONICAL_JSON.md               # Deterministic canonicalization contract
│   └── python/s0_core/                 # Reference Python library (crypto, canonical, pdf)
├── linux/cli/s0_cli/                   # Unified CLI suite
│   ├── methods/                        # Module 1: NVMe, ATA, BLKDISCARD, Overwrite
│   ├── file_eraser.py                  # Module 2: File & folder cluster sanitizer
│   ├── carver/                         # Module 3: ext4, NTFS, FAT32, exFAT, Entropy
│   └── audit/                          # Module 4: Append-only SQLite blockchain ledger
├── windows/                            # Windows native Module 2 (Win32 API, ADS)
├── macos/                              # macOS native Module 2 (Darwin F_FULLFSYNC, xattr)
├── gui/                                # FastAPI 4-tab forensic console (127.0.0.1:8000)
├── linux/iso/                          # Bare-metal Debian 12 Live bootable ISO recipe
├── verification-portal/                # 100% client-side WebCrypto verifier (s0-vp.vercel.app)
├── docs/                               # Production documentation suite (s0-docs-ten.vercel.app)
└── scripts/                            # Master build, test, install & uninstall scripts
```

---

## 4. Future Roadmap (v2.1+)

1. **Bare-Metal Live ISO Hardware Validation:** Smoke-test the Debian 12 Live ISO on physical x86_64 Dell, HP, and Lenovo hardware.
2. **Native C# Windows Client:** Direct Win32 / PInvoke assembly packaging for Windows enterprise deployments.
3. **Android Recovery & Sanitization (Termux/Native):** Android package implementing Canonical JSON v1 and File-Based Encryption (FBE) key destruction attestation.
4. **Btrfs / ZFS CoW Direct Extent Overwrite Driver:** Advanced kernel-level ioctl bypass for Copy-on-Write storage volumes.
