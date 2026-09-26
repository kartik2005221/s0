# s0 — User & Forensic Operator Manual

{% hint style="info" %}
**Document Scope: Comprehensive Operator & Field Reference Manual**
This document serves as the authoritative operational manual for digital forensic examiners, incident responders, field technicians, and compliance auditors. It details end-to-end procedures for certified media sanitization, bit-stream drive imaging, deleted evidence carving, blockchain ledger continuity audits, and regulatory sign-offs.

If you only need to perform a quick 5-minute setup and test run on an image file, refer to the **[Getting Started Guide](../getting-started/quickstart.md)**. For in-depth sanitization physics and firmware mechanics, see the **[Secure Data Erasure Guide](secure-erasure.md)**.
{% endhint %}

---

## 1. Introduction & Operational Philosophy

The **s0 (Sector Zero)** suite unifies offensive and defensive storage operations into a single open-source platform:
1. **Defensive Anti-Forensics & Sanitization:** Irreversibly destroying digital data across storage drives, individual files, and directory hierarchies in compliance with **NIST SP 800-88 Rev. 1** and **IEEE 2883-2022**.
2. **Offensive Digital Forensics & Evidence Recovery:** Reconstructing deleted, concealed, or lost files from formatted media and raw disk images across ext4, NTFS, FAT32, and exFAT without mounting the filesystem.
3. **Forensic Acquisition & Cloning:** Creating bit-stream disk images with live dual hashing (SHA-256 and MD5) and bad-sector fault tolerance per **ISO/IEC 27037**.
4. **Cryptographic Non-Repudiation:** Binding every action to an **Ed25519 digital signature** and appending the event to an immutable **SHA-256 hash-chained local blockchain ledger**.

---

## 2. Installation & Upgrade Workflows

### 2.1 Installation Across Operating Systems

{% tabs %}
{% tab title="Linux & macOS" %}
```bash
# Download and execute the universal Linux/macOS installer
curl -sSL https://raw.githubusercontent.com/kartik2005221/s0/master/scripts/install.sh | bash
    
# Confirm installation and print version
s0 --version
```
{% endtab %}
{% tab title="Windows (PowerShell)" %}
```powershell
# Execute the Windows PowerShell automated bootstrap installer
irm https://raw.githubusercontent.com/kartik2005221/s0/master/scripts/install.ps1 | iex
    
# Confirm installation and print version
s0 --version
```
{% endtab %}
{% tab title="From Source (All Platforms)" %}
```bash
# Clone repository and execute master bootstrap orchestrator
git clone https://github.com/kartik2005221/s0.git
cd s0
bash scripts/build_all.sh
```
{% endtab %}
{% endtabs %}

### 2.2 Upgrading s0 to the Latest Version

To keep s0 synchronized with the latest NIST compliance profiles, carving signatures, and patches:

{% tabs %}
{% tab title="Command Line (Universal)" %}
```bash
# Check remote repository and upgrade the active installation in-place
s0 upgrade
# Use --force to reinstall all virtual environment dependencies
s0 upgrade --force
```
{% endtab %}
{% tab title="Linux & macOS" %}
```bash
# Re-run the automated upgrade pipeline from GitHub master
curl -sSL https://raw.githubusercontent.com/kartik2005221/s0/master/scripts/upgrade.sh | bash
```
{% endtab %}
{% tab title="Windows (PowerShell)" %}
```powershell
# Execute remote PowerShell upgrade script
irm https://raw.githubusercontent.com/kartik2005221/s0/master/scripts/upgrade.ps1 | iex
```
{% endtab %}
{% tab title="Windows (Command Prompt)" %}
```cmd
:: Execute CMD batch upgrade pipeline
curl -sSL https://raw.githubusercontent.com/kartik2005221/s0/master/scripts/upgrade.cmd | cmd
```
{% endtab %}
{% endtabs %}

---

## 3. Module 1: Secure Drive Eraser

The Drive Eraser sanitizes whole physical disks (NVMe, SATA HDD/SSD, USB flash drives, SD cards) and forensic disk images (`.raw`, `.img`, `.dd`).

### 3.1 Device Inventory (`s0 list`)
Display all attached block devices, hardware serial numbers, and mount states:

```bash
# List all visible block devices in human-readable table format
s0 list
```

Example Output:
```
PATH           TYPE    STORAGE        CAPACITY  MODEL                    SERIAL           MOUNTED?  OS_DRIVE?
/dev/sda       block   SSD           465.8 GiB  Samsung SSD 870 EVO      S5YANG0N123456K  YES       -
/dev/sdb       block   NVMe          931.5 GiB  Samsung SSD 980 PRO 1TB  S464NX0M789012A  YES       YES [OS]
/dev/sdc       block   USB            28.9 GiB  SanDisk Ultra Fit        4C5300012309181  -         -

Image-file targets work too (no root needed): use --target /path/to/file.img
```

For JSON output suitable for automated scripts:
```bash
# Query storage devices in machine-readable JSON format
s0 list --output-format json
```

### 3.2 Dry-Run Planning (`s0 plan`)
Before executing an irreversible wipe, run `s0 plan` to inspect which sanitization method will be selected, its NIST tier, and any safety warnings:

```bash
# Simulate sanitization strategy without writing a single byte
s0 plan --target /dev/sdb
```

Example Output:
```
target          : /dev/sdb (Samsung SSD 980 PRO 1TB, 931.5 GiB)
method          : NVME_SANITIZE_BLOCK_ERASE
nist category   : Purge
summary         : NVMe Sanitize Block Erase via controller firmware
commands        :
  - nvme sanitize /dev/sdb -a 0x02
warnings        :
  ! Target is an NVMe solid-state device. Controller-level purge will be executed.
alternatives    :
  - [available] NVME_FORMAT_CRYPTO_ERASE (Purge)
  - [available] OVERWRITE_ZERO_1PASS (Clear)
```

{% hint style="success" %}
**Method Recommendation**
For **NVMe SSDs**, allow s0 to execute controller-level firmware purges (default). This achieves NIST **Purge**, completes in under 30 seconds for 1 TB, and prevents NAND write cycle degradation. For **HDDs**, standard `OVERWRITE_ZERO_1PASS` satisfies NIST **Clear** and runs 3× faster than pseudo-random overwriting.
{% endhint %}

### 3.3 Executing Sanitization (`s0 wipe`)
Perform certified sanitization:

```bash
# Execute physical drive wipe with operator attribution
sudo s0 wipe \
    --target /dev/sdb \
    --operator "analyst-42" \
    --organization "Digital Forensic Unit" \
    --out-dir ./certificates
```

To skip the interactive `WIPE` confirmation prompt in automated pipelines:
```bash
# Non-interactive wipe with explicit override flag
sudo s0 wipe --target /dev/sdb --yes --operator "auto-runner"
```

#### Real-Time Telemetry:
During operation, s0 renders an ANSI progress bar displaying real-time I/O throughput, elapsed time, ETA, and thermal sensor telemetry (queried every 2 seconds):

```
# Terminal status line output
[s0 wipe] ████████████████░░░░  78.2%  22.6 GiB / 28.9 GiB  482 MB/s  ETA 00m 14s  Temp: 44°C
```

#### Post-Wipe Sampling:
Immediately following the write operation, s0 conducts an automated **64-block sampled readback verification** across the physical address space, asserting that every sampled block matches the expected pattern (e.g. `0x00`).

---

## 4. Secure File & Folder Erasure (`s0 wipe --targets`)

Selective, in-place cluster sanitization for sensitive files and directories is seamlessly integrated into `s0 wipe`. Passing file or directory paths to `--targets` (or as target paths) automatically routes the operation to surgical file erasure without wiping the surrounding filesystem or requiring root access.

### 4.1 Basic File Erasure
```bash
# Securely erase specific target files and directory trees (auto-detected)
s0 wipe --targets /evidence/confidential_memo.pdf /evidence/financial_records/
```

### 4.2 Multi-Pass Random Overwrite
```bash
# Multi-pass random sanitization for defense contract compliance
s0 wipe \
    --targets /evidence/suspect_payload.bin \
    --passes 3 \
    --pattern random \
    --operator "investigator-01" \
    --out-dir ./reports
```

{% hint style="success" %}
**Pattern Recommendation**
Unless external regulations (such as legacy DoD 5220.22-M mandates) require multiple random passes, choose `--pattern zero --passes 1`. A single pass completely zeros physical file extents and runs significantly faster.
{% endhint %}

---

## 5. Module 2: Advanced File Carving & Evidence Recovery

Module 2 recovers deleted files from disk images (`.raw`, `.dd`, `.img`) or unmounted partitions without relying on intact filesystem tables.

### 5.1 Basic Carving Operation
```bash
# Carve deleted documents and images from raw disk image
s0 carve \
    --target /evidence/seized_drive.raw \
    --out-dir ./recovered_evidence \
    --extensions jpg,png,pdf,zip \
    --min-confidence 60
```

{% hint style="success" %}
**Confidence Score Recommendation**
- **Threshold 50% (Default):** Optimal for general triage and initial incident surveys.
- **Threshold 75%+:** Recommended when generating court-ready exhibits to eliminate partial fragments.
- **Threshold 25–40%:** Recommended for heavily damaged or partially overwritten storage media to maximize recovery chances.
{% endhint %}

### 5.2 Supported File Formats
- **Images:** JPEG (`FF D8 FF`), PNG (`89 50 4E 47`), GIF (`GIF8`), BMP (`BM`)
- **Documents:** PDF (`%PDF-`), Office OpenXML / ZIP (`PK 03 04` covering `.docx`, `.xlsx`, `.pptx`)
- **Archives & Databases:** GZIP (`1F 8B 08`), SQLite3 (`SQLite format 3\0`)
- **Executables & Audio:** ELF (`7F ELF`), MP3 (`ID3`)

### 5.3 Filesystem Structure Acceleration
When carving from raw media, s0 automatically detects filesystem signatures:
- **NTFS:** Parses the Master File Table (`$MFT`) directly, extracting resident attributes and reassembling non-resident cluster runlists. Indexes 1 TB in under 15 seconds.
- **ext4:** Traverses block group descriptors and inode extent trees directly.
- **FAT32 / exFAT:** Scans deleted directory entries (`0xE5` / `0x05`) and reassembles cluster allocation sets.

### 5.4 Carving Output Structure
```
# Layout of recovered evidence directory
recovered_evidence/
├── CRV_0001.pdf
├── CRV_0002.jpg
├── CRV_0003.zip
├── recovery_index.json                # Complete machine-readable index
└── carving_manifest_1092a4bc.json     # Ed25519-signed manifest of all extracted artifacts
```

---

## 6. Module 3: Forensic Drive Imager & Bit-Stream Copy

In digital forensics and incident response (**NIST SP 800-86**, **ISO/IEC 27037**), recovery operations or file carving must never be performed directly on original evidence media. 

The `s0 image` and `s0 clone` commands create an exact, bit-for-bit physical replica of storage drives with simultaneous cryptographic verification and fault-tolerant recovery.

### 6.1 Creating a Forensic Bit-Stream Disk Image
To acquire a complete raw image (`.raw` / `.img` / `.dd`) of a physical drive or flash media:

```bash
# Acquire bit-stream raw image with live dual hashing and bad-sector recovery
s0 image \
    --source /dev/sdb \
    --destination /evidence/suspect_drive.raw \
    --block-size 1048576 \
    --operator "analyst-01" \
    --organization "Forensic Lab"
```

{% hint style="success" %}
**Block Size Recommendation**
The default block size `--block-size 1048576` (1 MiB) delivers maximum sequential streaming throughput on modern PCIe and SATA controllers. Use smaller blocks (e.g. 64 KiB) only when imaging legacy USB 1.1/2.0 thumb drives.
{% endhint %}

### 6.2 Cloning a Drive (1:1 Disk Duplication)
To duplicate a source drive directly to a clean target drive:

```bash
# Clone source disk directly to target physical drive
s0 clone \
    --source /dev/sdb \
    --destination /dev/sdc \
    --yes
```

### 6.3 Fault-Tolerant Bad-Sector Handling
Degraded or failing drives with unreadable magnetic sectors or worn NAND blocks normally crash standard tools with `EIO (Input/output error)`. 

`s0 image` features built-in error recovery:
- Drops down to 512-byte sector-level reads across failing blocks
- Zero-fills unreadable sectors (`\x00` padding) to maintain exact cluster/sector offset alignment
- Logs bad block offsets in a forensic error map within the acquisition manifest
- Completes acquisition without aborting

---

## 7. Module 4: Blockchain Cryptographic Audit Ledger

Every wipe, file erasure, carving session, and drive acquisition is appended as an immutable block to `~/.s0/s0_audit.db`.

### 7.1 Inspecting Audit Blocks (`s0 audit list`)
```bash
# Display the 20 most recent blocks in the audit ledger
s0 audit list --limit 20
```

Output:
```
==> S0 Blockchain Cryptographic Audit Ledger (24 blocks)
IDX   TIMESTAMP            OPERATION      OPERATOR       TARGET_ID            BLOCK_HASH      
24    2026-09-09T14:22:15Z DRIVE_ERASE    analyst-42     S464NX0M789012A      4b227777d4dd1fc6...
23    2026-09-09T12:05:30Z FILE_ERASE     investigator   confidential_memo    88c019a2e41bf901...
22    2026-09-09T10:14:02Z FILE_CARVE     analyst-42     seized_drive.raw     f100e49ab88190c3...
```

### 7.2 Verifying Blockchain Continuity (`s0 audit verify`)
Audit the cryptographic continuity from Genesis to Tip:

```bash
# Verify mathematical SHA-256 hash continuity of the audit chain
s0 audit verify
```

Expected Output:
```
==> Auditing Blockchain Cryptographic Hash Chain...
Chain Status : [OK] VALID & CONTINUOUS
Blocks Tested: 24
Details      : Hash-chain continuity mathematically verified across 24 blocks from genesis to tip.
```

---

## 8. Offline Certificate Verification

### 8.1 Command-Line Verification (`s0 verify`)
```bash
# Verify an issued certificate against trusted public authority key
s0 verify certificates/certificate_a8f3b201.json --key core/keys/demo_issuer_public.pem
```

Output:
```
[OK] CERTIFICATE AUTHENTIC & VERIFIED
UUID         : a8f3b201-9c42-4f1e-8e77-5d2a938c110e
Status       : success
NIST Tier    : Purge
Device       : S464NX0M123456K
Issuer       : Digital Forensic Unit
Fingerprint  : sha256:d8a264a93c94f09d846b9ec14389df0398bb2c954627d37a5b39922e339d251a
```

### 8.2 Air-Gapped Web Verification
1. Double-click `verification-portal/index.html` on any offline computer.
2. Drag and drop `certificate_a8f3b201.json`.
3. The portal executes pure WebCrypto validation in browser memory and displays the verified green banner.

---

## 9. Authority Key Generation (`s0 keygen`)

To establish an accredited signing authority:

```bash
# Generate a new Ed25519 signing keypair for an accredited lab
s0 keygen --out-dir /secure/keys --name lab_authority
```

Outputs:
- `lab_authority_private.pem`: Keep secret and offline.
- `lab_authority_public.pem`: Distribute to auditors or register in `keys.json`.
- Prints the SHA-256 SubjectPublicKeyInfo fingerprint.

---

## 10. Automated Agentic Operations (`skills/s0-forensics/`)

In automated laboratory triage pipelines or headless decommissioning stations driven by autonomous agents (such as Antigravity, Claude Code, or custom forensic agents), operators should equip the agent with the official **s0 Forensics Skill**:

- **Location**: [`skills/s0-forensics/SKILL.md`](https://github.com/kartik2005221/s0/tree/master/skills/s0-forensics/SKILL.md)
- **Role**: Guides autonomous agents through high-risk media sanitization, bit-stream acquisition, and deleted file carving while strictly enforcing patience, pre-wipe dry runs (`s0 plan`), and post-operation cryptographic verification.
- **Reference Manuals**: Includes bundled specifications for NIST mappings, device safety rules, and carving signatures.
- **Evaluation Suite**: Validated against real-world test scenarios in `skills/s0-forensics/evals/evals.json`.

For detailed agent safety guardrails and prompt protocols, see the [Agentic AI Guide](../project/agentic-ai.md).

