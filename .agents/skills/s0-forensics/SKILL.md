---
name: s0-forensics
description: Execute forensic-grade media sanitization, bit-stream disk imaging, deleted file carving, and blockchain audit ledger operations using s0 (Sector Zero). Use whenever tasks involve securely wiping drives or files, recovering deleted artifacts from disk images, imaging evidence drives, or verifying Ed25519 sanitization certificates.
---

# s0 Forensics & Data Sanitization Skill

This skill guides an AI agent through safely, accurately, and patiently executing operations using **s0 (Sector Zero)**.

## CRITICAL SAFETY & PATIENCE DIRECTIVE: HIGH-RISK OPERATIONS

> [!CAUTION] **Irreversible Destruction & Hardware Locking Risk**  
> Operations executed by `s0` involve **permanent, non-recoverable destruction of digital storage media** or long-running forensic acquisitions.  
> 1. **Patience is mandatory.** Never terminate, abort, or kill a running `s0 wipe` or `s0 image` command. Interrupting a controller-level firmware erase (`NVME_SANITIZE` or `ATA_SECURE_ERASE`) can lock the drive into a permanent frozen state or render the hardware unusable.  
> 2. **Never wipe without dry-running.** ALWAYS run `s0 plan --target <path>` first.  
> 3. **Identify the device explicitly.** Always inspect `s0 list` and report the drive **Model**, **Serial Number**, and **Capacity** to the user before proceeding with any destructive command.  
> 4. **Warn the user explicitly at every step** of the irreversible nature of sanitization.

---

## 1. Subcommands & Capabilities

| Command | Capability | Safety Level |
|---|---|---|
| `s0 list` | Enumerate attached block devices, storage types, serials, and mount states | **Safe (Read-Only)** |
| `s0 plan` | Dry-run simulation of sanitization method, NIST category, and warnings | **Safe (Read-Only)** |
| `s0 image` / `s0 clone` | Forensic bit-stream drive imaging & cloning with dual live hashing (SHA-256/MD5) | **Safe (Non-Destructive for imaging; high-risk if cloning to block device)** |
| `s0 carve` | Reconstruct deleted files from raw disk images (`.raw`, `.img`, `.dd`) or partitions | **Safe (Read-Only from source)** |
| `s0 audit list` / `verify` | Inspect audit ledger and verify unbroken SHA-256 blockchain continuity | **Safe (Read-Only)** |
| `s0 verify` | Mathematically verify Ed25519-signed certificate JSON offline | **Safe (Read-Only)** |
| `s0 keygen` | Generate Ed25519 keypair for an authority or operator | **Safe (Creates Files)** |
| `s0 upgrade` | Pull latest release from GitHub and upgrade suite dependencies | **System Maintenance** |
| `s0 erase` | Securely overwrite files/folders in-place with metadata scrubbing | **DESTRUCTIVE (Irreversible)** |
| `s0 wipe` | Physical whole-drive sanitization per NIST SP 800-88 Rev. 1 | **HIGH-RISK DESTRUCTIVE (Irreversible)** |

---

## 2. Standard Operational Workflows

### Workflow A: Drive Sanitization (NIST SP 800-88)

1. **Discover Devices:**
   ```bash
   # Enumerate all storage targets
   s0 list
   ```
2. **Execute Dry-Run Simulation:**
   ```bash
   # Review selected method and safety warnings (writes nothing)
   s0 plan --target /dev/sdb
   ```
3. **Confirm with User:** State target device model, serial number, capacity, and selected NIST tier (`Purge` or `Clear`). Wait for user alignment.
4. **Execute Sanitization (Patiently):**
   ```bash
   # Execute wipe and output signed certificate
   sudo s0 wipe --target /dev/sdb --operator "analyst-01" --organization "Forensics Lab"
   ```
   *Do not send interrupt signals while the command is executing.*
5. **Verify Certificate:**
   ```bash
   # Confirm signature authenticity
   s0 verify certificate_<UUID>.json --key core/keys/demo_issuer_public.pem
   ```

---

### Workflow B: Forensic Bit-Stream Drive Imaging (`s0 image`)

1. **Acquire Evidence Disk:**
   ```bash
   # Create forensic image with live dual hashing and bad sector zero-filling
   s0 image --source /dev/sdb --destination /evidence/suspect_drive.raw --block-size 1048576
   ```
2. **Review Output Artifacts:** Inspect generated acquisition manifest and verification certificate in the target directory.

---

### Workflow C: Forensic Evidence Carving (`s0 carve`)

1. **Carve from Forensic Image:**
   ```bash
   # Carve deleted documents and images with confidence filter >= 60%
   s0 carve --target /evidence/suspect_drive.raw --out-dir ./recovered --extensions jpg,png,pdf,zip --min-confidence 60
   ```
2. **Review Output:** Inspect `recovery_index.json` and `carving_manifest_<UUID>.json`.

---

### Workflow D: Targeted File Erasure (`s0 erase`)

1. **Scrub Files In-Place:**
   ```bash
   # Overwrite clusters, zero timestamps, scramble filenames, and purge ADS
   s0 erase --targets /path/to/confidential_file.pdf /path/to/staging_folder/ --passes 1
   ```

---

## 3. Decision Recommendations for Agents

- **Drive Type = NVMe SSD:** Recommend firmware purge (`NVME_SANITIZE_BLOCK_ERASE` or `NVME_FORMAT_CRYPTO_ERASE`). It runs in under 30 seconds and preserves flash cell endurance.
- **Drive Type = SATA HDD:** Recommend single-pass zero overwrite (`OVERWRITE_ZERO_1PASS`). It satisfies NIST SP 800-88 Rev. 1 Clear and runs 3x faster than pseudo-random overwriting.
- **Filesystem = Copy-on-Write (Btrfs, ZFS, APFS, ReFS):** Warn the user that in-place file erasure cannot guarantee overwrite of historical physical extents. Recommend volume-level or whole-device wiping for 100% assurance.
- **Carving Confidence:** Default to `--min-confidence 50`. Recommend `--min-confidence 75` for court-ready forensic reports with zero false-positive fragments.
