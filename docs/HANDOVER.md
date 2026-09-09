# s0 — Technical Evaluator & Developer Handover Guide

**Target Audience:** Technical Evaluators, Digital Forensic Engineers, and Maintainers.  
**Version:** 2.0.0

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
.venv/bin/pytest core/tests linux/cli/tests gui/tests windows/cli/tests macos/cli/tests verification-portal/tests -v
```

### Run Module 1: End-to-End Drive Wipe Forensic Demo:
```bash
S0_DEMO_SIZE_MIB=32 bash linux/cli/demo_e2e.sh
```

### Run Module 2: File & Folder Erasure:
```bash
.venv/bin/s0 erase --targets /path/to/file.txt --passes 1
```

### Run Module 3: Advanced File Carving:
```bash
.venv/bin/s0 carve --target /path/to/image.raw --out-dir ./recovered
```

### Run Module 4: Blockchain Audit Ledger Verification:
```bash
.venv/bin/s0 audit verify
```

### Launch Unified Web Console:
```bash
bash gui/run.sh
# Open http://127.0.0.1:8000
```

### Build & Deploy Bare-Metal Live ISO:
For offline drive decommissioning per NIST SP 800-88, refer to the complete zero-to-one guide:
```bash
# Full build and deployment documentation
cat docs/LIVE_ISO_BUILD_GUIDE.md
```
See [docs/LIVE_ISO_BUILD_GUIDE.md](LIVE_ISO_BUILD_GUIDE.md) for build toolchains, QEMU test commands, and USB flashing instructions.
