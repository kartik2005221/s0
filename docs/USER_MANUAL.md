# TrustWipe — User & Operator Manual

**Target Audience:** E-waste Recyclers, IT Asset Disposition (ITAD) Technicians, JNARDDC Auditors, and Security Evaluators.  
**Version:** 1.0.0 (SIH 2026 Release)

---

## Table of Contents

1. [Quickstart & System Requirements](#1-quickstart--system-requirements)
2. [Command-Line Interface (CLI) Guide](#2-command-line-interface-cli-guide)
   - [2.1 Device Inventory (`list`)](#21-device-inventory-list)
   - [2.2 Dry-Run Planning (`plan`)](#22-dry-run-planning-plan)
   - [2.3 Executing a Wipe (`wipe`)](#23-executing-a-wipe-wipe)
   - [2.4 Key Generation & Verification Utilities](#24-key-generation--verification-utilities)
3. [Local Web GUI Guide](#3-local-web-gui-guide)
4. [Bootable Live ISO Guide](#4-bootable-live-iso-guide)
5. [Verification Portal Guide](#5-verification-portal-guide)
6. [Troubleshooting & FAQs](#6-troubleshooting--faqs)

---

## 1. Quickstart & System Requirements

TrustWipe operates across two primary environments:
- **Root-free Test & Development:** Wipe sparse disk images (`.img`), verify cryptographic signatures, and generate PDFs without root privileges.
- **Production Block Device Sanitization:** Requires root / `sudo` privileges to issue ATA Security Erase, NVMe Sanitize, `BLKDISCARD`, or raw physical drive overwrite.

### Requirements:
- Linux (Ubuntu 22.04+, Debian 12+, Fedora, Arch)
- Python 3.10+ (with `cryptography`, `reportlab`, `qrcode`, `pillow`, `fastapi`, `uvicorn`)
- Standard storage utilities: `lsblk`, `hdparm` (for SATA), `nvme-cli` (for NVMe), `blkdiscard`

---

## 2. Command-Line Interface (CLI) Guide

All wiping commands are accessible via `trustwipe-wipe` (or `python -m trustwipe_cli.main`).

### 2.1 Device Inventory (`list`)

List all attached physical block devices and supported storage targets:

```bash
trustwipe-wipe list
```

**Example Output:**
```text
PATH           TYPE    STORAGE        CAPACITY  MODEL                    SERIAL           MOUNTED?
/dev/sda       block   SSD            512.0 GiB Samsung SSD 870 EVO      S5YCNF0N123456   NO
/dev/nvme0n1   block   NVMe           1.0 TiB   WD_BLACK SN850X          22430C801234     NO
/dev/vda       block   HDD            25.0 GiB  QEMU HARDDISK            QM00001          YES (OS)

Image-file targets work too (no root needed): use --target /path/to/file.img
```

> **Safety Warning:** Devices marked `MOUNTED? YES` contain active filesystems. TrustWipe requires explicit unmounting or override flags before touching mounted media.

---

### 2.2 Dry-Run Planning (`plan`)

Before executing any destructive operation, preview the exact wiping plan:

```bash
trustwipe-wipe plan --target /dev/sda
```

Or for a file target:
```bash
trustwipe-wipe plan --target /tmp/test_disk.img
```

**Output Details Provided:**
- Probed device metadata (storage type, capacity, sector size)
- Automatically recommended method and NIST 800-88 category (Clear vs Purge)
- Exact low-level commands that will be executed
- Firmware limitations and compliance warnings
- Alternative available methods

---

### 2.3 Executing a Wipe (`wipe`)

To perform the wipe, run the `wipe` subcommand with operator identification:

```bash
trustwipe-wipe wipe     --target /dev/sda     --operator "op-rahul-01"     --organization "JNARDDC Accredited Recycling Center #4"     --out-dir ./certificates     --yes
```

#### Available Flags:
| Flag | Description | Default |
|---|---|---|
| `--target <path>` | Target block device or image file path | **Required** |
| `--method <id>` | Override method (`OVERWRITE_ZERO_1PASS`, `SHRED_RANDOM_NPASS`, `ATA_SECURE_ERASE`, `NVME_SANITIZE_BLOCK_ERASE`, `BLKDISCARD`) | Auto-selected |
| `--passes <int>` | Number of passes (for overwrite methods) | `1` |
| `--operator <id>` | Operator identifier recorded on certificate | `$USER` |
| `--organization <org>` | Certified entity issuing the wipe certificate | `"TrustWipe Unaccredited"` |
| `--signing-key <path>` | Private Ed25519 PEM key for certificate signing | Demo key |
| `--plant-markers` | Plant forensic test markers before wipe to verify 0 hits after | `false` |
| `--out-dir <dir>` | Directory to save generated JSON, PDF, and QR certificates | `./` |
| `--yes` | Confirm execution without interactive prompt | `false` |

#### Generated Output Artifacts:
Upon completion, TrustWipe creates:
1. `certificate_<UUID>.json`: Signed Canonical JSON certificate.
2. `certificate_<UUID>.pdf`: Human-readable PDF certificate with embedded QR code.
3. `certificate_<UUID>.qr.png`: Standalone QR code containing the full verification payload.

---

### 2.4 Key Generation & Verification Utilities

#### 1. Keypair Generation (`trustwipe-keygen`)
Generate an Ed25519 issuer keypair out-of-band:
```bash
trustwipe-keygen --out-dir ./authority_keys --name jnarddc_issuer
```
Creates:
- `authority_keys/jnarddc_issuer_private.pem` (Owner-only 0600 permissions — KEEP OFFLINE)
- `authority_keys/jnarddc_issuer_public.pem` (Distributed to verifiers and pinned in portal)

#### 2. Manual Verification (`trustwipe-verify`)
Verify any signed certificate against a trusted public key directly in terminal:
```bash
trustwipe-verify --cert ./certificates/certificate_12345678.json --key authority_keys/jnarddc_issuer_public.pem
```

---

## 3. Local Web GUI Guide

For touchscreens, live kiosks, and visual operators, TrustWipe includes a local web GUI.

### Launching the GUI:
```bash
bash linux/gui/run.sh
```
Or directly via Python:
```bash
python3 -m trustwipe_gui.app --host 127.0.0.1 --port 8000
```
Open your browser at `http://127.0.0.1:8000`.

### GUI Workflow:
1. **Device Selection:** Auto-refreshes attached disks, displaying capacity, model, serial, and mount status.
2. **Method Preview:** Displays recommended NIST tier (Clear / Purge) with detailed technical explanations.
3. **Real-Time Progress:** Live stream of throughput (MiB/s), pass count, and estimated time remaining.
4. **Instant Certificate Download:** View the cryptographic status and download PDF/JSON certificates with one click.

---

## 4. Bootable Live ISO Guide

The TrustWipe Live ISO provides an air-gapped, vendor-neutral bootable USB environment.

### Use Cases:
- Sanitizing laptops, desktops, and enterprise servers where host OS cannot be running.
- Air-gapped recycling facilities requiring clean-room guarantees.

### Flashing the ISO:
```bash
sudo dd if=trustwipe-live-amd64.iso of=/dev/sdX bs=4M status=progress oflag=sync
```
*(Replace `/dev/sdX` with your target USB drive).*

### Kiosk Boot Flow:
1. Insert USB into the target computer and boot via UEFI/BIOS.
2. The ISO boots directly into a lightweight systemd kiosk session.
3. The TrustWipe GUI launches automatically in full-screen mode on display `:0`.
4. Target internal disks are unmounted and ready for sanitization.
5. Generated certificates can be saved to an external USB or printed via network printer.

---

## 5. Verification Portal Guide

The verification portal (`verification-portal/index.html`) is an independent, zero-trust audit tool.

### How to Use:
1. Open `verification-portal/index.html` in any web browser (works offline, even via `file://`).
2. **Drag & Drop** the certificate `.json` file or paste the JSON text into the input box.
3. The portal executes:
   - Schema validation against `cert_schema.json`.
   - Re-canonicalization of the payload according to `CANONICAL_JSON.md`.
   - Ed25519 signature verification against pinned issuer public keys.
4. **Audit Interpretation:**
   - 🛡️ **GREEN ("AUTHENTIC & VERIFIED"):** Mathematical signature matches pinned issuer key. Payload is completely unmodified.
   - ⚠️ **RED ("TAMPER DETECTED"):** Any byte in the certificate has been modified (serial number, capacity, timestamp, status).
   - ❓ **AMBER ("UNTRUSTED ISSUER"):** Valid signature, but issued by an unrecognized/unpinned public key.

---

## 6. Troubleshooting & FAQs

### Q1: Why does `hdparm` report "drive security is FROZEN"?
**Answer:** Modern BIOS/UEFI firmware locks the ATA security state at boot to prevent malicious firmware overwrites.  
**Resolution:** Put the computer into a warm suspend (sleep) and resume it. This resets the drive lock without re-triggering the BIOS freeze lock.

### Q2: Does TrustWipe require an internet connection?
**Answer:** No. TrustWipe CLI, GUI, ISO, and Verification Portal are 100% offline and self-contained. No telemetry or server calls are ever made.

### Q3: Why is 1-pass overwrite classified as NIST Clear instead of Purge?
**Answer:** Host-level writes over SATA/NVMe cannot touch overprovisioned, retired, or wear-leveled flash blocks. Only firmware-level commands (ATA Secure Erase, NVMe Sanitize) or physical destruction can achieve NIST Purge.
