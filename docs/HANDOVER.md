# TrustWipe — Evaluator & Developer Handover Guide

**Target Audience:** Hackathon Evaluators, JNARDDC Technical Committee, DevOps Engineers, and Future Maintainers.  
**Version:** 1.0.0 (SIH 2026 Production Handover)

---

## 1. Quickstart & Environment Verification

TrustWipe is ready to run immediately in this workspace.

### Step 1: Verify Python Virtual Environment
```bash
# Python 3.10+ virtualenv is pre-configured
source .venv/bin/activate
```

### Step 2: Run Full Automated Test Suite (105+ Tests)
```bash
.venv/bin/pytest core/tests linux/cli/tests linux/gui/tests verification-portal/tests
```
*Expected Result:* **105 passed, 0 failed**.

---

## 2. Running the End-to-End Live Forensic Demo

The demo script (`linux/cli/demo_e2e.sh`) exercises the entire core lifecycle without requiring root privileges:

```bash
TRUSTWIPE_DEMO_SIZE_MIB=32 bash linux/cli/demo_e2e.sh
```

### Demo Steps Executed:
1. Creates a real 32 MiB binary disk image file (`target_disk.img`).
2. Plants 16 high-entropy "CONFIDENTIAL PAN/Aadhaar" test markers at known offsets.
3. Probes the device inventory via `trustwipe-wipe list`.
4. Performs a dry-run plan inspection via `trustwipe-wipe plan`.
5. Executes the real 1-pass zero wipe with real-time throughput monitoring.
6. Forensically audits the wiped image:
   - 64 sampled block reads -> All match 0x00.
   - Raw grep across all 33,554,432 bytes for markers -> **0 hits**.
7. Generates signed JSON, human PDF, and QR certificates.
8. Verifies the authentic certificate with Ed25519; mutates 1 byte in a forged copy and confirms **immediate rejection**.

---

## 3. Running the Local Web GUI

To launch the local web interface:

```bash
bash linux/gui/run.sh
```
Or:
```bash
.venv/bin/python3 -m trustwipe_gui.app --host 127.0.0.1 --port 8000
```
Open `http://127.0.0.1:8000` in your web browser.

---

## 4. Running the Verification Portal

The verification portal is 100% static and client-side (no Node.js build step needed):

```bash
# Serve locally via Python HTTP server:
python3 -m http.server 8080 --directory verification-portal
```
Open `http://127.0.0.1:8080` in your browser.

**Demonstration Actions in Portal:**
- Click **"Load Authentic Certificate"** -> Green shield, verified authentic.
- Click **"Load Tampered Certificate"** -> Red alert, tampered capacity detected.
- Drag & Drop any certificate JSON generated in Step 2.

---

## 5. Loop Device Testing with Root / Sudo

If sudo privileges are granted on a bare-metal machine:

```bash
# 1. Create a 1 GB sparse loop block device:
sudo bash scripts/make_loop_target.sh /tmp/trustwipe_loop.img 1024

# 2. Wipe the loop device via BLKDISCARD or Overwrite:
sudo trustwipe-wipe wipe --target /dev/loop0 --yes
```

---

## 6. Building the Bootable Live ISO

The live ISO configuration in `linux/iso` builds a standalone Debian Live kiosk that boots directly into the TrustWipe GUI.

### Prerequisites (Requires Sudo on Debian/Ubuntu):
```bash
sudo apt update && sudo apt install -y live-build xorriso qemu-system-x86-64
```

### Build the ISO:
```bash
cd linux/iso
sudo auto/build.sh
```
Outputs `trustwipe-live-amd64.iso`.

### Test in QEMU:
```bash
bash linux/iso/qemu-test.sh
```

---

## 7. Production Key Ceremony & Security Policy

1. **Key Generation (Out-of-Band):**
   ```bash
   trustwipe-keygen --out-dir /secure/airgap_keys --name jnarddc_master_2026
   ```
2. **Private Key Handling:**
   - The private key (`jnarddc_master_2026_private.pem`) must NEVER be committed to Git or bundled into live ISOs or desktop applications.
   - It is stored securely on an air-gapped signing station or managed via an HSM/KMS.
3. **Public Key Distribution:**
   - The public key (`jnarddc_master_2026_public.pem`) is published openly and pinned in `verification-portal/keys.json`.
4. **Key Rotation:**
   - Certificates record `public_key_fingerprint`. When rotating keys, add the new public key to `keys.json` while retaining the old key for historical verification.

---

## 8. Repository Structure & Key File Index

```
trustwipe/
├── core/
│   ├── CANONICAL_JSON.md         # Canonicalization specification
│   ├── cert_schema.json          # Certificate JSON schema v1.0.0
│   ├── keys/                     # Public issuer keys & policy docs
│   ├── python/trustwipe_core/    # Core cryptographic engine
│   └── tests/                    # Core tests (canonical, crypto, tamper matrix)
├── linux/
│   ├── cli/                      # Linux CLI wiping engine & e2e demo
│   ├── gui/                      # FastAPI local web UI
│   └── iso/                      # Bootable live ISO build scripts
├── verification-portal/          # Pure client-side static verification portal
├── docs/                         # Complete technical & compliance documentation
└── scripts/                      # Build, loop device, and portal runner scripts
```
