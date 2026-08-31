# TrustWipe 🛡️

> **Secure Data Sanitization & Cryptographic Certification Suite**  
> *Smart India Hackathon (SIH 2026) • Ministry of Mines / JNARDDC*

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![NIST SP 800-88](https://img.shields.io/badge/Compliance-NIST%20SP%20800--88%20Rev.1-success.svg)](docs/COMPLIANCE.md)
[![Ed25519 Verified](https://img.shields.io/badge/Signatures-Ed25519%20RFC%208032-blueviolet.svg)](core/CANONICAL_JSON.md)
[![Tests: 105 Passed](https://img.shields.io/badge/Tests-105%20Passed-brightgreen.svg)](docs/TEST_PLAN.md)

---

## 📌 Executive Summary

**TrustWipe** is an open-source, mathematically verifiable, and standards-compliant data wiping suite engineered to eliminate data residue on retired IT assets (HDDs, SSDs, NVMe, and mobile devices) while issuing **unforgeable, cryptographically signed sanitization certificates**.

Built for **JNARDDC (Jawaharlal Nehru Aluminium Research Development and Design Centre / Ministry of Mines)** and certified e-waste recyclers, TrustWipe solves the critical flaw in legacy sanitization tools: **unverifiable compliance and PDF certificate forgery**.

---

## 🌟 Core Innovations

1. **Deterministic Cryptographic Certification:**
   - Every certificate payload is serialized into **TrustWipe Canonical JSON v1** (strict code-point key ordering, minimal escaping, and integer-only rule) and signed using **Ed25519 (RFC 8032)**.
   - Any single-byte modification to certificate data (serial numbers, capacity, wipe status) mathematically breaks verification.

2. **NIST SP 800-88 Rev. 1 & IEEE 2883-2022 Enforcement:**
   - Real firmware-level **Purge** (`NVME_SANITIZE`, `ATA_SECURE_ERASE`) that reaches overprovisioned/retired flash blocks.
   - 1-pass zero overwrite for **Clear** (eliminating slow, drive-wearing legacy multi-pass myths).
   - Cryptographic key destruction on modern **Android File-Based Encryption (FBE)** and Self-Encrypting Drives (**Purge**).

3. **Zero-Trust Verification Portal:**
   - Pure client-side static web application (`verification-portal/index.html`) using a vendored pure JS Ed25519 and SHA-256 cryptographic bundle.
   - Zero backend server, zero database, zero telemetry: *"Trust the math, not our server."*

4. **Forensic Readback Assurance:**
   - Dual-stage automated audit: 64-block uniform sampled readback plus full disk byte-level scanning for planted confidential markers (**0 hits guaranteed**).

5. **Universal Deployment Modalities:**
   - **Linux CLI:** Production block device and unprivileged sparse image wiping.
   - **Local Web GUI:** Modern FastAPI single-page kiosk interface with live progress streaming.
   - **Bootable Live ISO:** Air-gapped Debian live kiosk for bare-metal decommissioning.

---

## ⚡ Quickstart

### 1. Run Automated Test Suites (105+ Tests)
```bash
source .venv/bin/activate
.venv/bin/pytest core/tests linux/cli/tests linux/gui/tests verification-portal/tests
```

### 2. Run the Live End-to-End Forensic Demonstration
```bash
TRUSTWIPE_DEMO_SIZE_MIB=32 bash linux/cli/demo_e2e.sh
```
*Executes disk creation -> marker planting -> wipe -> forensic grep -> signed certificate -> tamper rejection.*

### 3. Launch the Local Web GUI
```bash
bash linux/gui/run.sh
# Open http://127.0.0.1:8000
```

### 4. Launch the Verification Portal
```bash
bash scripts/run_portal.sh 8080
# Open http://127.0.0.1:8080
```

---

## 📂 Repository Structure

```
trustwipe/
├── core/                           # Cryptographic Foundation & Standards
│   ├── CANONICAL_JSON.md           # Canonical JSON v1 specification
│   ├── cert_schema.json            # Certificate JSON schema v1.0.0
│   ├── standards/                  # NIST 800-88 mapping registry
│   ├── keys/                       # Public issuer keys & policy docs
│   ├── python/trustwipe_core/      # Reference Python crypto & canonical library
│   └── tests/                      # Pytest suite & golden vectors
├── linux/                          # Linux Sanitization Suite
│   ├── cli/                        # CLI wiping engine (methods, devices, wipe)
│   ├── gui/                        # FastAPI local web UI
│   └── iso/                        # Bootable live ISO build configuration
├── verification-portal/            # Pure Client-Side Verification Portal
│   ├── index.html                  # Responsive auditor web interface
│   ├── verify.js                   # JavaScript verifier engine
│   ├── vendor/crypto-bundle.js     # TweetNaCl & SHA-256 engine (zero dependencies)
│   ├── keys.json                   # Pinned issuer public keys
│   └── tests/                      # In-browser test runner & cross-tests
├── docs/                           # Complete Technical Documentation
│   ├── ARCHITECTURE.md             # System architecture & threat model
│   ├── USER_MANUAL.md              # Operator and auditor manual
│   ├── COMPLIANCE.md               # Standards & regulatory compliance
│   ├── TEST_PLAN.md                # QA strategy & test matrix
│   ├── LIMITATIONS.md              # Hardware & platform constraints
│   ├── HANDOVER.md                 # Developer & evaluator handover
│   └── PITCH_OUTLINE.md            # SIH 2026 presentation pitch deck
├── scripts/                        # Orchestration Scripts
│   ├── build_all.sh                # Master build & test orchestrator
│   ├── make_loop_target.sh         # Helper to create loop block devices
│   └── run_portal.sh               # Local portal launcher
└── PLAN.md                         # Master Engineering Plan & Contract
```

---

## 📖 Documentation Index

| Document | Description |
|---|---|
| [System Architecture](docs/ARCHITECTURE.md) | Component architecture, threat model, cryptographic protocols, data flow |
| [User & Operator Manual](docs/USER_MANUAL.md) | Comprehensive CLI, GUI, ISO, and Portal step-by-step walkthrough |
| [Standards Compliance](docs/COMPLIANCE.md) | NIST SP 800-88 Rev. 1, IEEE 2883, DPDPA 2023, E-Waste Rules 2022 |
| [Test Plan & QA](docs/TEST_PLAN.md) | Unit testing, tamper matrix, forensic readback, cross-language tests |
| [Technical Limitations](docs/LIMITATIONS.md) | Honest disclosure of SSD wear leveling, ATA freeze lock, Android FBE |
| [Evaluator Handover](docs/HANDOVER.md) | Quickstart, test execution, key ceremony, ISO build instructions |
| [SIH Pitch Deck](docs/PITCH_OUTLINE.md) | Problem crisis, technical differentiators, live demo script, roadmap |

---

## 🛠️ Master Build & Packaging

Execute the master orchestrator to validate all components and test suites in one command:

```bash
bash scripts/build_all.sh
```

---

## 📄 License & Attribution

Developed for **Smart India Hackathon (SIH 2026)** in collaboration with **JNARDDC / Ministry of Mines**.  
Licensed under the [MIT License](LICENSE).
