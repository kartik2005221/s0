# TrustWipe — Comprehensive Test Plan & Verification Strategy

**Project:** TrustWipe Secure Sanitization Suite  
**Scope:** Core Crypto, Linux CLI, Web GUI, Verification Portal, and Forensic Verification  
**Status:** Automated & Validated (v1.0.0)

---

## 1. Quality Assurance Philosophy & Testing Pyramid

TrustWipe operates under a **zero-trust, high-assurance security model**. Because sanitization certificates are legal and regulatory compliance artifacts, testing must prove not only that valid workflows succeed, but that **every conceivable tampering or forgery attempt fails deterministically**.

```
                   ▲
                  / \     Cross-Language Verification (Python vs JS Portal)
                 /───\    End-to-End Forensic Demo (Planted Markers + Grep)
                /─────\   Tamper-Evidence Matrix (Exhaustive Leaf Mutation)
               /───────\  CLI & GUI Integration Tests (FastAPI TestClient)
              /─────────\ Unit Tests (Crypto, Canonical JSON, Schema, PDF)
```

---

## 2. Test Suites Breakdown

### 2.1 Core Cryptography & Canonicalization (`core/tests/`)

| Test File | Test Scope | Verification Invariant |
|---|---|---|
| `test_canonical.py` | Validates `trustwipe_core.canonical` against `canonical_vectors.json` | 100% byte-for-byte matching on recursive sorting, minimal escaping, float rejection, and Unicode code points. |
| `test_crypto.py` | Ed25519 keygen, signing, verification, and SPKI DER fingerprinting | Valid signatures verify; invalid signatures, wrong keys, and malformed base64url reject with `False`. |
| `test_certificate.py` | Schema v1 validation, defaults, field constraints, and tier limits | Disallowed NIST tiers, invalid UUIDs, float values, and missing fields raise `CertificateError`. |
| `test_tamper.py` | **Tamper Matrix:** Iterates through every signed leaf node in a certificate, mutates it by 1 byte / value, and asserts verification rejection | Any alteration to any signed field invalidates the Ed25519 signature. Reordered JSON keys continue to verify. |
| `test_pdf.py` | ReportLab PDF certificate generation, styling, and QR code embedding | Valid PDF bytes generated with embedded QR payload and accurate metadata. |

---

### 2.2 Linux CLI & Sanitization Engines (`linux/cli/tests/`)

| Test File | Test Scope | Verification Invariant |
|---|---|---|
| `test_e2e_demo.py` | Full end-to-end sanitization cycle on a sparse image file | Target file initialized with non-zero bytes -> wiped with `OVERWRITE_ZERO_1PASS` -> sampled 64-block readback matches 0x00 -> signed cert generated -> independent verification passes -> tampered copy rejected. |
| `test_overwrite.py` | Overwrite engine, progress callback, chunk streaming, and fsync | Multi-pass write correctness, throughput calculations, and cancellation safety. |
| `test_firmware_probes.py` | Mocked parsing of `hdparm -I`, `hdparm -N`, `nvme list`, and `lsblk` | Accurate parsing of ATA Security Erase support, frozen drive state detection, HPA/DCO max sectors, and NVMe sanitize capabilities. |
| `test_selection_safety.py` | Target selection safety, mount checks, and method selection rules | Refuses to wipe mounted active root partitions without unmount/override. |

---

### 2.3 Local Web GUI (`linux/gui/tests/`)

| Test File | Test Scope | Verification Invariant |
|---|---|---|
| `test_gui.py` | FastAPI backend endpoints (`/api/devices`, `/api/plan`, `/api/wipe`, `/api/certificate`) | Correct JSON responses, SSE progress streaming, and certificate retrieval via `TestClient`. |

---

### 2.4 Verification Portal & Cross-Language Parity (`verification-portal/tests/`)

| Test File | Test Scope | Verification Invariant |
|---|---|---|
| `test_portal.py` | Static assets, pinned keys parity, and cross-verification tests | `keys.json` matches `core/keys/demo_issuer_public.pem`. Python and JS engines agree on valid and tampered certificates. |
| `test_runner.html` | In-browser automated suite executing `verify.js` and `crypto-bundle.js` | Runs directly in web browser; validates all canonical golden vectors, schema rules, and Ed25519 signature checks in pure JavaScript. |

---

## 3. The Forensic Verification Protocol

To provide tangible, indisputable proof of data destruction during demonstrations and audits, TrustWipe implements a two-stage forensic test:

```
Step 1: Plant High-Entropy Markers
  Target Disk (Offset 0MB)   ──▶ [PAN/Aadhaar Marker #1]
  Target Disk (Offset 16MB)  ──▶ [PAN/Aadhaar Marker #2]
  Target Disk (Offset 32MB)  ──▶ [PAN/Aadhaar Marker #3]
  Pre-Wipe Raw Scan Check    ──▶ 16 Markers Found ✅

Step 2: Execute TrustWipe Sanitization Engine
  Target Disk Overwritten with 0x00 + fsync()

Step 3: Dual Forensic Verification
  A. Sampled Read-Back: Read 64 uniform 4096-byte blocks -> 100% 0x00 ✅
  B. Raw Grep Stream Scan: Read entire disk image for marker string -> 0 Hits ✅
```

---

## 4. Test Execution Guide

### Run All Python Test Suites (105+ Tests):
```bash
.venv/bin/pytest core/tests linux/cli/tests linux/gui/tests verification-portal/tests
```

### Run End-to-End Live Forensic Demo:
```bash
TRUSTWIPE_DEMO_SIZE_MIB=32 bash linux/cli/demo_e2e.sh
```

### Run In-Browser JavaScript Test Suite:
Open `verification-portal/tests/test_runner.html` in any web browser or via local HTTP server (`python3 -m http.server 8080`).
