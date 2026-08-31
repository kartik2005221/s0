# TrustWipe — Evaluator & Developer Handover Guide (NTRO / SIH26149)

**Target Audience:** Hackathon Evaluators, NTRO Technical Committee, Digital Forensic Engineers, and Maintainers.  
**Version:** 2.0.0 (SIH26149 Release)

---

## 1. Quickstart (One-Command Automated Setup & Test)

```bash
# Run master build and test orchestrator
bash scripts/build_all.sh
```

---

## 2. Testing Individual Modules

### Run All 120 Automated Pytest Tests:
```bash
.venv/bin/pytest core/tests linux/cli/tests linux/gui/tests verification-portal/tests -v
```

### Run Module 1: End-to-End Drive Wipe Forensic Demo:
```bash
TRUSTWIPE_DEMO_SIZE_MIB=32 bash linux/cli/demo_e2e.sh
```

### Run Module 2: File & Folder Erasure:
```bash
.venv/bin/trustwipe-wipe erase-files --targets /path/to/file.txt --passes 1
```

### Run Module 3: Advanced File Carving:
```bash
.venv/bin/trustwipe-wipe carve --target /path/to/image.raw --out-dir ./recovered
```

### Run Module 4: Blockchain Audit Ledger Verification:
```bash
.venv/bin/trustwipe-wipe audit verify
```

### Launch Unified Web Console:
```bash
bash linux/gui/run.sh
# Open http://127.0.0.1:8000
```
