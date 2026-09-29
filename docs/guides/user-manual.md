# s0 — User & Forensic Operator Manual

{% hint style="info" %}
**Document Scope: Comprehensive Operator & Field Reference Manual**
This document serves as the authoritative operational manual for digital forensic examiners, incident responders, field technicians, and compliance auditors. It details end-to-end procedures for forensic-grade media sanitization, bit-stream drive imaging, deleted evidence carving, audit ledger continuity checks, and regulatory sign-offs.

If you only need to perform a quick 5-minute setup and test run on an image file, refer to the **[Getting Started Guide](../getting-started/quickstart.md)**. For in-depth sanitization physics and firmware mechanics, see the **[Secure Data Erasure Guide](secure-erasure.md)**.
{% endhint %}

---

## 1. Introduction & Operational Philosophy

The **s0 (Sector Zero)** suite unifies offensive and defensive storage operations into a single open-source platform:
1. **Defensive Anti-Forensics & Sanitization:** Irreversibly destroying digital data across storage drives, individual files, and directory hierarchies in compliance with **NIST SP 800-88 Rev. 1** and **IEEE 2883-2022**.
2. **Offensive Digital Forensics & Evidence Recovery:** Reconstructing deleted, concealed, or lost files from formatted media and raw disk images across ext4, NTFS, FAT32, and exFAT without mounting the filesystem.
3. **Forensic Acquisition & Cloning:** Creating bit-stream disk images with live dual hashing (SHA-256 and MD5) and bad-sector fault tolerance per **ISO/IEC 27037**.
4. **Cryptographic Non-Repudiation:** Binding every action to an **Ed25519 digital signature** and appending the event to an immutable **SHA-256 hash-chained local audit ledger**.

---

## 2. Installation & Upgrade Workflows

### 2.1 Installation Across Operating Systems

{% tabs %}
{% tab title="Linux/MacOS" %}
```bash
curl -fsSL https://s0-install.pages.dev/sh | bash
s0 --version
```
{% endtab %}
{% tab title="Windows (PowerShell)" %}
```powershell
irm https://s0-install.pages.dev/ps1 | iex
s0 --version
```
{% endtab %}
{% tab title="Windows (CMD)" %}
```cmd
curl -fsSL https://s0-install.pages.dev/cmd -o s0-install.cmd && s0-install.cmd && del s0-install.cmd
s0 --version
```
{% endtab %}
{% tab title="From Source (All Platforms)" %}
```bash
git clone https://github.com/kartik2005221/s0.git
cd s0
bash scripts/build_all.sh
```
{% endtab %}
{% endtabs %}

### 2.2 Upgrading s0 to the Latest Version

To keep s0 synchronized with the latest sanitization profiles, carving signatures, and patches:

{% tabs %}
{% tab title="Command Line (Universal)" %}
```bash
s0 upgrade
s0 upgrade --force
```
{% endtab %}
{% tab title="Linux/MacOS" %}
```bash
curl -fsSL https://s0-install.pages.dev/upgrade-sh | bash
```
{% endtab %}
{% tab title="Windows (PowerShell)" %}
```powershell
irm https://s0-install.pages.dev/upgrade-ps1 | iex
```
{% endtab %}
{% tab title="Windows (CMD)" %}
```cmd
curl -fsSL https://s0-install.pages.dev/upgrade-cmd -o s0-upgrade.cmd && s0-upgrade.cmd && del s0-upgrade.cmd
```
{% endtab %}
{% endtabs %}

---

## 3. Module 1: Secure Drive Eraser

The Drive Eraser sanitizes whole physical disks (NVMe, SATA HDD/SSD, USB flash drives, SD cards) and forensic disk images (`.raw`, `.img`, `.dd`).

### 3.1 Device Inventory (`s0 list`)
Display all attached block devices, hardware serial numbers, and mount states:

```bash
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
s0 list --output-format json
```

### 3.2 Dry-Run Planning (`s0 plan`)
Before executing an irreversible wipe, run `s0 plan` to inspect which sanitization method will be selected, its NIST tier, and any safety warnings:

```bash
s0 plan --target /dev/sdb
```

Example Output:
```
[s0 plan]  Target        : /dev/sdb (block, NVMe, 931.5 GiB)
[s0 plan]  Method        : NVME_SANITIZE_BLOCK_ERASE
[s0 plan]  NIST Category : Purge
[s0 plan]  Summary       : NVMe Sanitize Block Erase via controller firmware
[s0 plan]  Commands      :
[s0 plan]    - nvme sanitize /dev/sdb -a 0x02
[s0 plan]  Warnings      :
[s0 plan]    ! Target is an NVMe solid-state device. Controller-level purge will be executed.
[s0 plan]  Alternatives  :
[s0 plan]    - [available] NVME_FORMAT_CRYPTO_ERASE (Purge)
[s0 plan]    - [available] OVERWRITE_ZERO_1PASS (Clear)

[s0 plan]  DRY RUN — nothing was written. Run `s0 wipe` when satisfied.
```

{% hint style="success" %}
**Method Recommendation**
For **NVMe SSDs**, allow s0 to execute controller-level firmware purges (default). This achieves NIST **Purge**, completes in under 30 seconds for 1 TB, and prevents NAND write cycle degradation. For **HDDs**, standard `OVERWRITE_ZERO_1PASS` satisfies NIST **Clear** and runs 3× faster than pseudo-random overwriting.
{% endhint %}

### 3.3 Executing Sanitization (`s0 wipe`)
Perform sanitization:

```bash
sudo s0 wipe \
    --target /dev/sdb \
    --operator "analyst-42" \
    --organization "Digital Forensic Unit" \
    --out-dir ./certificates
```

To skip the interactive `WIPE` confirmation prompt in automated pipelines:
```bash
sudo s0 wipe --target /dev/sdb --yes --operator "auto-runner"
```

#### Post-Wipe Sampling:
Immediately following the write operation, s0 conducts an automated **64-block sampled readback verification** across the physical address space, asserting that every sampled block matches the expected pattern (e.g. `0x00`).

---

## 4. Secure File & Folder Erasure

Selective, in-place cluster sanitization for sensitive files and directories is integrated into `s0 wipe`. No root access is required for file-level sanitization:

- **Single Target:** `s0 wipe --target /path/to/file.pdf` auto-detects that the target is a file or directory rather than a block device and invokes file sanitization.
- **Batch Targets:** `s0 wipe --targets file1.pdf dir1/ file2.docx` processes multiple files and folders in a single pass and emits a consolidated compliance certificate.

### 4.1 Basic File Erasure
```bash
s0 wipe --targets /evidence/confidential_memo.pdf /evidence/financial_records/
```

### 4.2 Multi-Pass Random Overwrite
```bash
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

Module 2 recovers deleted files from disk images (`.raw`, `.dd`, `.img`) or storage media without relying on intact filesystem tables.

{% hint style="warning" %}
**Advisory on Live Operating System Partitions**
Carving against an active running OS drive is strongly discouraged. Continuous operating system background writes, pagefile/swap updates, and automatic SSD TRIM overwrite freed clusters in real time, drastically reducing evidence recovery yield. For reliable forensic recovery, capture an offline bit-stream disk image (`s0 image`) or boot the bare-metal [s0 Live ISO](live-iso.md).
{% endhint %}

### 5.1 Basic Carving Operation
```bash
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
s0 includes 19 built-in binary signature definitions across 16 primary formats:
- **Images:** JPEG (`FF D8 FF`), PNG (`89 50 4E 47`), GIF (`GIF8`), BMP (`BM`)
- **Documents & Archives:** PDF (`%PDF-`), ZIP / Office OpenXML (`PK 03 04` covering `.docx`, `.xlsx`, `.pptx`), 7-Zip (`7z`), GZIP (`1F 8B 08`), SQLite3 (`SQLite format 3\0`)
- **Audio:** MP3 (`ID3` and MPEG sync frames), WAV (`RIFF`), FLAC (`fLaC`), OGG (`OggS`)
- **Binaries & Captures:** ELF (`7F ELF`), PCAP (`D4 C3 B2 A1`), PCAPng (`0A 0D 0D 0A`)
- **Custom Signatures:** Pass `--custom-signatures <path.json>` to define domain-specific file headers and footers.

### 5.3 Filesystem Structure Acceleration
When carving from raw media, s0 automatically detects filesystem signatures:
- **NTFS:** Parses the Master File Table (`$MFT`) directly, extracting resident attributes and reassembling non-resident cluster runlists. Indexes 1 TB in under 15 seconds.
- **ext4:** Traverses block group descriptors and inode extent trees directly.
- **FAT32 / exFAT:** Scans deleted directory entries (`0xE5` / `0x05`) and reassembles cluster allocation sets.

### 5.4 Carving Output Structure
```
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

## 7. Module 4: Hash-Chained Cryptographic Audit Ledger

Every wipe, file erasure, carving session, and drive acquisition is appended as an immutable block to `~/.s0/s0_audit.db`.

### 7.1 Inspecting Audit Blocks (`s0 audit list`)
```bash
s0 audit list --limit 20
```

Output:
```
==> S0 Hash-Chained Cryptographic Audit Ledger (24 blocks)
IDX   TIMESTAMP            OPERATION      OPERATOR       TARGET_ID            BLOCK_HASH      
24    2026-09-09T14:22:15Z DRIVE_ERASE    analyst-42     S464NX0M789012A      4b227777d4dd1fc6...
23    2026-09-09T12:05:30Z FILE_ERASE     investigator   confidential_memo    88c019a2e41bf901...
22    2026-09-09T10:14:02Z FILE_CARVE     analyst-42     seized_drive.raw     f100e49ab88190c3...
```

### 7.2 Verifying Audit Ledger Continuity (`s0 audit verify`)
Audit the cryptographic continuity from Genesis to Tip:

```bash
s0 audit verify
```

Expected Output:
```
==> Auditing Hash-Chained Cryptographic Ledger...
Chain Status : [OK] VALID & CONTINUOUS
Blocks Tested: 24
Details      : Hash-chain continuity mathematically verified across 24 blocks from genesis to tip.
```

---

## 8. Offline Certificate Verification

### 8.1 Command-Line Verification (`s0 verify`)
```bash
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

