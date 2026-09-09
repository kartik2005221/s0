<div align="center">

# S0 — Sector Zero

**Digital Forensics & Cryptographic Data Sanitization Suite**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![NIST SP 800-88](https://img.shields.io/badge/NIST_SP_800--88-Rev.1-green.svg)](docs/COMPLIANCE.md)
[![Ed25519](https://img.shields.io/badge/Signatures-Ed25519_RFC_8032-blueviolet.svg)](core/CANONICAL_JSON.md)
[![Tests](https://img.shields.io/badge/Tests-180%2B_Passed-brightgreen.svg)](docs/TEST_PLAN.md)
[![Verification Portal](https://img.shields.io/badge/Web_Portal-Live-success.svg)](https://s0-vp.vercel.app/)

*One tool. Two capabilities. Unbreakable audit trail.*

</div>

---

## What is S0?

**S0** is an open-source command-line suite that unifies two capabilities that typically require separate enterprise tools:

| Capability | What S0 Does |
|---|---|
| 🛡️ **Defensive Sanitization** | Irreversibly destroys drives, files, and partitions per NIST SP 800-88 Rev. 1 & IEEE 2883-2022, then issues an Ed25519-signed certificate |
| 🔍 **Offensive Forensics** | Carves and reconstructs deleted evidence from formatted disks, USB drives, and raw images across ext4, NTFS, FAT32, and exFAT |
| 🔗 **Blockchain Audit Ledger** | Every operation writes an immutable SHA-256 block-chained entry into a local SQLite ledger — tamper-evident by math |
| 🌐 **Zero-Trust Verification** | Certificates are verifiable in any browser, fully offline, with zero data ever sent to a server |

---

## Install

> **Requirements:** Python 3.10+, Git

### Linux & macOS
```bash
curl -sSL https://raw.githubusercontent.com/kartik2005221/s0/master/scripts/install.sh | bash
```

### Windows — PowerShell
```powershell
irm https://raw.githubusercontent.com/kartik2005221/s0/master/scripts/install.ps1 | iex
```

### Windows — Command Prompt
```cmd
curl -sSL https://raw.githubusercontent.com/kartik2005221/s0/master/scripts/install.cmd | cmd
```

After install, `s0` is immediately available in your terminal. Verify with:
```bash
s0 --version
```

---

## Upgrade

To upgrade an existing S0 installation to the latest version:

### Linux & macOS
```bash
curl -sSL https://raw.githubusercontent.com/kartik2005221/s0/master/scripts/upgrade.sh | bash
```

### Windows — PowerShell
```powershell
irm https://raw.githubusercontent.com/kartik2005221/s0/master/scripts/upgrade.ps1 | iex
```

### Windows — Command Prompt
```cmd
curl -sSL https://raw.githubusercontent.com/kartik2005221/s0/master/scripts/upgrade.cmd | cmd
```

Or directly from your terminal:
```bash
s0 upgrade
```

---

## Uninstall

### Linux & macOS
```bash
curl -sSL https://raw.githubusercontent.com/kartik2005221/s0/master/scripts/uninstall.sh | bash
```

### Windows — PowerShell
```powershell
irm https://raw.githubusercontent.com/kartik2005221/s0/master/scripts/uninstall.ps1 | iex
```

### Windows — Command Prompt
```cmd
curl -sSL https://raw.githubusercontent.com/kartik2005221/s0/master/scripts/uninstall.cmd | cmd
```

---

## Quick Start

### List storage devices
```bash
s0 list
```

### Plan a wipe (dry run — nothing written)
```bash
s0 plan --target /dev/sdb
```

### Sanitize a drive
```bash
s0 wipe --target /dev/sdb --yes --operator "analyst-01" --organization "Forensic Lab"
```

### Securely erase files or folders
```bash
s0 erase --targets /path/to/file.pdf /path/to/folder/ --passes 1
```

### Carve deleted files from a disk image
```bash
s0 carve --target /evidence/disk.raw --out-dir ./recovered --extensions jpg,png,pdf,zip --min-confidence 50
```

### Create a forensic bit-stream image of a drive (for safe recovery)
```bash
s0 image --source /dev/sdb --destination /evidence/disk.raw
```

### Clone a drive (bit-for-bit hardware disk copy)
```bash
s0 clone --source /dev/sdb --destination /dev/sdc
```

### Inspect the audit ledger
```bash
s0 audit list --limit 25
s0 audit verify
```

### Verify a certificate offline
```bash
s0 verify certificate_12345678.json --key core/keys/demo_issuer_public.pem
```

---

## Modules

### Module 1 — Secure Drive Eraser

Sanitizes NVMe drives, SATA HDDs/SSDs, USB flash, SD cards, and raw `.raw`/`.img`/`.dd` forensic images.

| Method | NIST 800-88 Tier | Speed |
|---|---|---|
| `NVME_SANITIZE` (Block/Crypto) | **Purge** | < 30s per TB |
| `ATA_SECURE_ERASE` | **Purge** | Firmware-bound |
| `BLKDISCARD` (SSD TRIM) | **Purge / Clear** | Instantaneous |
| Zero Overwrite (1-pass) | **Clear** | ~1.2 GB/s |
| Random Overwrite (1-pass) | **Clear** | ~450 MB/s |

After every wipe: 64-block sampled readback verification + Ed25519-signed PDF certificate with embedded QR code.

---

### Module 2 — Secure File & Folder Eraser

Cross-platform in-place cluster overwriting for Linux, Windows, and macOS.

- **Linux:** POSIX extent overwriting (`filefrag`), `fsync()`, Btrfs/ZFS CoW warnings, inode timestamp zeroing
- **Windows:** Win32 `FlushFileBuffers`, Alternate Data Stream (`:Zone.Identifier`) scrubbing, ReFS CoW detection
- **macOS:** `fcntl(F_FULLFSYNC)`, `xattr` extended attribute cleansing, APFS CoW warnings

Each batch erasure produces a consolidated Ed25519-signed certificate.

---

### Module 3 — Advanced File Carver & Recovery

Recovers deleted evidence from formatted storage without relying on intact filesystem tables.

**Four carving engines:**

1. **Signature Engine** — Header/footer byte-pattern scanning for JPEG, PNG, PDF, ZIP/Office, GIF, BMP, ELF, MP3, SQLite3, GZIP
2. **ext4 Structure Engine** — Direct superblock, block group descriptor, inode table & extent tree parsing
3. **NTFS Structure Engine** — Raw `$MFT` parsing: resident attributes, multi-fragment non-resident runlists, deleted record discovery
4. **FAT32 / exFAT Engines** — BPB/VBR parsing, deleted directory entry scanning, cluster heap recovery (USB drives & SD cards)

**Confidence scoring (0–100%):**
- Header match: 30% · Footer match: 30% · Size plausibility: 20% · Shannon entropy: 20%

**Structure-based carving performance:** 1 TB volume indexed in under 15 seconds.

---

### Module 4 — Forensic Drive Imager & Bit-Stream Copy

Complies with **NIST SP 800-86** and **ISO/IEC 27037** for digital evidence acquisition and hardware drive preservation.

- **Safe Bit-Stream Duplication:** Creates forensically sound raw images (`.raw`, `.img`, `.dd`) or direct 1:1 disk clones before running recovery operations.
- **Simultaneous Dual Cryptographic Hashing:** Computes live SHA-256 and MD5 hashes on-the-fly during acquisition.
- **Fault-Tolerant Bad Sector Recovery:** Automatically detects degraded or failing NAND/magnetic sectors, drops down to sector-by-sector reads, zero-fills unreadable blocks to preserve offset alignment, and generates a bad sector error map (similar to GNU ddrescue).
- **Write-Blocking Safety Verification:** Refuses to overwrite the source media or system/root drives.
- **Signed Acquisition Manifest & Ledger:** Generates an Ed25519-signed acquisition certificate and records the forensic event in the blockchain audit ledger.

---

### Module 5 — Blockchain Audit Ledger

Every operation — wipe, file erasure, carving, drive imaging — is appended to a local SQLite ledger as a cryptographic block:

$$\text{block\_hash} = \text{SHA256}(\text{index} \| \text{timestamp} \| \text{op\_type} \| \text{target\_id} \| \text{cert\_uuid} \| \text{payload\_hash} \| \text{signature} \| \text{prev\_hash})$$

- **Append-only:** No row can be deleted or modified
- **Tamper-evident:** Altering any past block invalidates every subsequent hash
- **Instant verification:** `s0 audit verify` traverses genesis→tip in milliseconds
- **Shared by CLI and Web GUI:** One unified ledger regardless of how an operation was initiated

---

## Live Progress Bar

All long-running operations stream a unified real-time ANSI progress bar:

```
[s0 wipe]  ████████████████░░░░  78.2%  22.6 GiB / 28.9 GiB  18.4 MB/s  ETA 05m 42s  44°C
[s0 carve] ████████░░░░░░░░░░░░  35.4%  10.2 GiB / 28.9 GiB  142 MB/s   ETA 02m 10s  Found: 36,790
```

Temperature is read automatically from Linux `sysfs hwmon`, NVMe SMART telemetry, or SATA SMART attribute 194/190. If no thermal sensor exists (USB sticks, virtual images), it is silently omitted — no error.

---

## Verification Portal

Every certificate S0 issues can be independently verified at **[s0-vp.vercel.app](https://s0-vp.vercel.app/)**.

- **100% client-side** — pure JavaScript via TweetNaCl WebCrypto. No certificate data ever leaves your browser.
- **Air-gap compatible** — open `verification-portal/index.html` locally with no internet required.
- **QR scan** — each PDF certificate embeds a QR code that auto-loads the certificate in the portal.
- **Key pinning** — accredited authority keys are pinned in `keys.json`; unknown-but-valid keys display an amber warning instead of a false pass.

### Three offline verification modes

```bash
# A. Command-line
s0 verify certificate_12345678.json --key core/keys/issuer_public_key.pem

# B. Browser (no server needed)
# Open file:///path/to/verification-portal/index.html → drag & drop certificate.json

# C. QR code on PDF certificate → mobile browser → zero upload
```

---

## Architecture

```
s0/
├── core/python/s0_core/      # Ed25519 signing, s0 Canonical JSON v1, PDF/QR generation
├── linux/cli/s0_cli/
│   ├── methods/              # Module 1: NVMe, ATA, BLKDISCARD, Overwrite engines
│   ├── wipe.py               # Module 1: Drive erasure orchestrator
│   ├── file_eraser.py        # Module 2: Secure file & folder eraser
│   ├── carver/               # Module 3: Signature, ext4, NTFS, FAT32, exFAT, entropy engines
│   ├── imager.py             # Module 4: Forensic drive bit-stream imaging & cloning
│   └── audit/                # Module 5: SHA-256 blockchain audit ledger (SQLite)
├── skills/s0-forensics/      # Native Agentic AI Skill (Skill Creator standard)
│   ├── SKILL.md              # Instructions, patience directives, and safety invariants
│   ├── references/           # NIST 800-88 mapping, safety rules, carving specs, crypto
│   ├── scripts/              # Standalone verification helper (verify_cert.py)
│   └── evals/                # Benchmark evaluation prompts and criteria
├── windows/                  # Windows-native Module 2 (Win32 API, ADS scrubbing)
├── macos/                    # macOS-native Module 2 (F_FULLFSYNC, xattr, APFS)
├── gui/                      # FastAPI unified web dashboard (4 forensic tabs)
├── linux/iso/                # Debian Live bootable ISO (see docs/LIVE_ISO_BUILD_GUIDE.md)
├── verification-portal/      # Zero-backend static web certificate verifier
└── scripts/                  # Install, uninstall, build & test orchestrators
```

---

## Web Dashboard

Launch the local 4-tab forensic console:

```bash
bash gui/run.sh
# Open: http://127.0.0.1:8000
```

| Tab | Function |
|---|---|
| Drive Eraser | Device selector, NIST category picker, real-time progress |
| File Eraser | Batch path input, pattern selection, instant sanitization |
| Forensic Carver | Image target, file type filters, interactive carved artifact table |
| Blockchain Ledger | Live block timeline, block detail inspector, one-click hash-chain verification |

---

## Run Tests

```bash
# Full test suite (sets up venv automatically)
bash scripts/build_all.sh

# Pytest only
.venv/bin/pytest core/tests linux/cli/tests -v

# End-to-end drive wipe forensic demo
S0_DEMO_SIZE_MIB=32 bash linux/cli/demo_e2e.sh

# End-to-end NTFS carving demo
bash linux/cli/demo_e2e_ntfs.sh
```

---

## Compliance

| Standard | Coverage |
|---|---|
| **NIST SP 800-88 Rev. 1** | Purge (NVMe/ATA firmware), Clear (overwrite, file erase) |
| **IEEE 2883-2022** | Sanitization method classification |
| **ISO/IEC 27037** | Evidence SHA-256 hashing at extraction, operator audit logging, Ed25519 non-repudiation |
| **DPDPA 2023** | Certified destruction of personal data on retired media |

See [docs/COMPLIANCE.md](docs/COMPLIANCE.md) for the full compliance matrix.

## Agentic AI Skill (`skills/s0-forensics/`)

`s0` includes a dedicated, high-assurance agentic skill adhering to the **Skill Creator** standard:
- **Location**: [`skills/s0-forensics/SKILL.md`](skills/s0-forensics/SKILL.md)
- **Directives**: Enforces critical patience rules, dry-run simulations (`s0 plan`), target confirmation, and zero-trust verification.
- **Bundled Resources**:
  - `references/`: Deep dives on NIST/IEEE mappings, hardware safety rules, magic byte signatures, and Canonical JSON v1.
  - `scripts/verify_cert.py`: Standalone certificate verification utility.
  - `evals/evals.json`: Benchmark evaluation suite for automated agent validation.

For complete agent safety protocols and integration examples, see [docs/agentic-ai.md](docs/agentic-ai.md).

---

## Documentation

| Document | Contents |
|---|---|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Subsystem design, threat model, cryptographic flow |
| [USER_MANUAL.md](docs/USER_MANUAL.md) | Complete CLI reference, web dashboard guide |
| [COMPLIANCE.md](docs/COMPLIANCE.md) | NIST / IEEE / ISO / DPDPA standards matrix |
| [agentic-ai.md](docs/agentic-ai.md) | Agentic AI guardrails, skill architecture, and prompt protocols |
| [PERFORMANCE.md](docs/PERFORMANCE.md) | Throughput benchmarks, scaling projections |
| [LIMITATIONS.md](docs/LIMITATIONS.md) | Honest scope: SSD FTL, CoW filesystems, journal remnants |
| [VERIFICATION_AND_DEPLOYMENT.md](docs/VERIFICATION_AND_DEPLOYMENT.md) | Air-gapped verification, key pinning, portal deployment |
| [HANDOVER.md](docs/HANDOVER.md) | Evaluator quickstart, per-module test commands |

---

## License

MIT — see [LICENSE](LICENSE).

