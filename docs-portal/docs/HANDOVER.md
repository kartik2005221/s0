# s0 — Technical Evaluator & Developer Handover Guide

**Target Audience:** Technical Evaluators, Digital Forensic Engineers, and Maintainers.  
**Version:** 2.2.1

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
# Execute comprehensive cross-platform test suite
.venv/bin/pytest core/tests linux/cli/tests web/tests windows/cli/tests macos/cli/tests verification-portal/tests -v
```

### Run Module 1: End-to-End Drive Wipe Forensic Demo:
```bash
# Run end-to-end sanitization test on 32MB synthetic image
S0_DEMO_SIZE_MIB=32 bash linux/cli/demo_e2e.sh
```

### Run File & Folder Erasure (auto-detected):
```bash
# Securely erase file with single-pass zero overwrite
.venv/bin/s0 wipe --targets /path/to/file.txt --passes 1
```

### Run Module 2: Advanced File Carving:
```bash
# Carve deleted evidence from raw disk image
.venv/bin/s0 carve --target /path/to/image.raw --out-dir ./recovered
```

### Run Module 3: Bit-Stream Forensic Imaging:
```bash
# Acquire forensic bit-stream image with dual SHA-256/MD5 hashing
sudo .venv/bin/s0 image /dev/sdb ./evidence.dd
```

### Run Module 4: Blockchain Audit Ledger Verification:
```bash
# Verify integrity of SHA-256 hash-chained audit blocks
.venv/bin/s0 audit verify
```

### Launch Unified Web Console:
```bash
sudo .venv/bin/s0 web
# Opens http://127.0.0.1:8669
```

### Build & Deploy Bare-Metal Live ISO:
For offline drive decommissioning per NIST SP 800-88, refer to the complete zero-to-one guide:
```bash
# Full build and deployment documentation
cat docs-portal/docs/LIVE_ISO_BUILD_GUIDE.md
```
See [LIVE_ISO_BUILD_GUIDE.md](LIVE_ISO_BUILD_GUIDE.md) for build toolchains, QEMU test commands, and USB flashing instructions.
