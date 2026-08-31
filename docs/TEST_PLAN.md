# TrustWipe — Comprehensive Test Plan & Verification Strategy (NTRO / SIH26149)

**Problem Statement ID:** 26149  
**Organization:** National Technical Research Organisation (NTRO)  
**Theme:** Blockchain & Cybersecurity  
**Test Suite Status:** 120 Automated Tests Passing (100% Green)

---

## 1. Test Pyramid & Quality Assurance Strategy

```
                   ▲
                  / \     Blockchain Hash-Chain Integrity & Tamper Tests
                 /───\    Forensic File Carving & Recovery Parity Tests
                /─────\   Secure File & Folder Erasure Extents Tests
               /───────\  Drive Sanitization & 64-Block Forensic Readback
              /─────────\ Core Cryptography, Canonical JSON & Tamper Matrix
```

---

## 2. Test Suites Breakdown

| Test File | Module Tested | Test Objectives & Invariants |
|---|---|---|
| `test_canonical.py` | Core Foundation | Validates Canonical JSON v1 against golden vectors (`canonical_vectors.json`). |
| `test_crypto.py` | Core Crypto | Ed25519 key generation, signing, and verification roundtrips. |
| `test_tamper.py` | Core Security | **Tamper Matrix:** Mutates every leaf node in a certificate and asserts rejection. |
| `test_pdf.py` | Core Output | Validates ReportLab PDF certificate and QR code rendering. |
| `test_e2e_demo.py` | Module 1: Drive Eraser | End-to-end drive wipe on sparse disk image with planted markers -> 0 hits. |
| `test_overwrite.py` | Module 1: Overwrite | Multi-pass and single-pass zero overwrite chunk streaming and fsync flushes. |
| `test_firmware_probes.py` | Module 1: Probes | ATA Security Erase, NVMe Sanitize, and HPA/DCO detection output parsers. |
| `test_selection_safety.py` | Module 1: Safety | Target safety checks, mount refusals, and method selection rules. |
| `test_file_eraser.py` | Module 2: File Eraser | Single file zero/random passes, recursive directory scrubbing, batch certificates. |
| `test_carver.py` | Module 3: File Carver | Shannon entropy calculation, confidence scoring, multi-format carving from raw disk image. |
| `test_audit.py` | Module 4: Audit Ledger | Genesis block creation, event recording, blockchain hash-chain verification, tamper detection. |
| `test_gui.py` | User Dashboard | FastAPI headless test suite for all 4 module API endpoints. |
| `test_portal.py` | Verification Portal | Cross-language test suite ensuring JavaScript verifier parity with Python reference. |

---

## 3. Running All Tests

Execute all 120 automated tests:
```bash
.venv/bin/pytest core/tests linux/cli/tests linux/gui/tests verification-portal/tests -v
```
