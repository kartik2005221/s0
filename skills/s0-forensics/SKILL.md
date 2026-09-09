---
name: s0-forensics
description: Execute forensic-grade media sanitization, bit-stream disk imaging, deleted file carving, and blockchain audit ledger operations using s0 (Sector Zero). Use whenever tasks involve securely wiping drives or files, decommissioning laptops or servers, recovering deleted artifacts from disk images, imaging evidence drives, auditing forensic operations, or verifying Ed25519 sanitization certificates. Make sure to trigger this skill whenever the user mentions wiping, sanitizing, forensic imaging, file carving, NIST SP 800-88, or s0 commands, even if they only ask to 'delete a drive safely' or 'recover deleted files'.
---

# s0 Forensics & Data Sanitization Skill

This skill guides an AI agent through safely, accurately, and patiently executing operations using **s0 (Sector Zero)** — the NIST SP 800-88 Rev. 1 compliant forensic sanitization, imaging, carving, and cryptographic verification suite.

---

## CRITICAL SAFETY & PATIENCE DIRECTIVE: HIGH-RISK OPERATIONS

> [!CAUTION] **Irreversible Destruction & Hardware Locking Risk**  
> Operations executed by `s0` involve **permanent, non-recoverable destruction of digital storage media** or long-running forensic acquisitions. Adhere strictly to the four non-negotiable invariants:  
> 1. **Patience is mandatory.** Never terminate, abort, or send `SIGKILL` / `SIGINT` to a running `s0 wipe` or `s0 image` process. Interrupting a controller-level firmware erase (`NVME_SANITIZE` or `ATA_SECURE_ERASE`) can lock the drive into a permanently bricked or frozen state. Always wait for completion.  
> 2. **Never wipe without a dry-run.** ALWAYS run `s0 plan --target <path>` first. Inspect the chosen method and warnings before taking any destructive action.  
> 3. **Identify the device explicitly.** Run `s0 list` and report the drive **Model**, **Serial Number**, and **Capacity** to the user. Demand explicit user confirmation of the target before executing destructive commands.  
> 4. **Verify certificates immediately.** After any destructive wipe, file erase, or image acquisition, execute `s0 verify` on the emitted certificate to confirm cryptographic non-repudiation.

---

## 1. Subcommands & Capabilities

| Command | Capability | Safety Level | Primary Use Case |
|---|---|---|---|
| `s0 list` | Enumerate block devices, buses, serials, and mount states | **Safe (Read-Only)** | Initial device discovery and serial verification |
| `s0 plan` | Dry-run simulation of sanitization method and NIST tier | **Safe (Read-Only)** | Pre-flight inspection; writes zero bytes |
| `s0 image` / `s0 clone` | Bit-stream disk acquisition & cloning with dual SHA-256/MD5 | **Safe (Non-Destructive for image; High-Risk if cloning)** | Forensic preservation and physical duplication |
| `s0 carve` | Reconstruct deleted files from raw disk images or partitions | **Safe (Read-Only from source)** | Post-incident recovery of deleted evidence |
| `s0 audit list` / `verify` | Inspect audit ledger and verify SHA-256 blockchain chain | **Safe (Read-Only)** | Validating tamper-evidence of past laboratory actions |
| `s0 verify` | Offline verification of Ed25519-signed certificate JSON | **Safe (Read-Only)** | Zero-trust verification of compliance reports |
| `s0 keygen` | Generate Ed25519 keypair for an authority or operator | **Safe (Creates Files)** | Establishing laboratory cryptographic authority |
| `s0 upgrade` | Pull latest release from GitHub and rebuild packages | **Maintenance** | Upgrading local toolchain and dependencies |
| `s0 erase` | In-place file/directory overwrite with metadata cleansing | **DESTRUCTIVE (Irreversible)** | Scrubbing individual sensitive files or folders |
| `s0 wipe` | Physical whole-drive sanitization per NIST SP 800-88 | **HIGH-RISK DESTRUCTIVE** | Decommissioning, repurposing, or sanitized disposal |

---

## 2. Core Decision Recommendations

When configuring parameters for `s0`, follow these engineering rules:

### A. Overwrite Pattern (`--pattern zero` vs `random`)
- **Recommendation**: Always use `zero` (default).
- **Rationale**: NIST SP 800-88 Rev. 1 Section 2.4 confirms that a single pass of fixed zeros provides full Clear sanitization across modern PRML magnetic hard drives and solid-state storage. Writing zeros achieves maximum sequential bus throughput (1,280–1,350 MB/s), whereas `random` requires CSPRNG generation that limits speed to ~450 MB/s without adding forensic security. Use `random` only if contractually mandated by legacy client agreements.

### B. Overwrite Pass Count (`--passes 1`)
- **Recommendation**: Always use `1` pass (default).
- **Rationale**: Multi-pass wiping (e.g., DoD 5220.22-M 3-pass or 7-pass) was designed in the 1980s for stepper-motor drives prone to track drift. Modern drives do not retain residual magnetic signals after a single overwrite pass. Multi-pass wiping causes needless flash cell write-wear on SSDs and wastes hours on multi-terabyte drives.

### C. Firmware Commands vs Overwrite (`--no-firmware`)
- **Recommendation**: Allow s0 to auto-select firmware commands (do not pass `--no-firmware` unless troubleshooting).
- **Rationale**: Firmware commands (NVMe Sanitize, ATA Secure Erase) operate at the internal controller level, purging flash cells, over-provisioned blocks, and reallocated bad blocks that host LBA overwriting cannot reach. This achieves NIST **Purge** tier in seconds to minutes. Use `--no-firmware` only if connected through an unstable USB-to-SATA bridge that drops connections during SCSI/ATA pass-through.

### D. Carver Confidence Threshold (`--min-confidence 50`)
- **Recommendation**: Use `50` for standard triage, `25`–`35` for heavily corrupted media, and `75`–`90` for court-admissible automated pipelines.
- **Rationale**: A score of 50 requires matching magic headers, plausible length fields, and expected entropy distributions, while allowing recovery of truncated files that lack closing footers.

### E. Acquisition Buffer Size (`--block-size 1048576`)
- **Recommendation**: Use `1048576` (1MB, default) for general acquisition; use `4194304` (4MB) when capturing PCIe Gen4/Gen5 NVMe targets.
- **Rationale**: Optimizes kernel buffer efficiency and hardware queue depth without thrashing memory.

### F. Fault-Tolerant Sector Recovery (`--no-recovery`)
- **Recommendation**: Omit `--no-recovery` when imaging suspect media.
- **Rationale**: Faulty drives frequently have bad sectors. `s0 image` replaces unreadable sectors with zeros (ddrescue-style) and logs the bad sector offsets into the manifest, capturing all surviving sectors. Only use `--no-recovery` when evaluating pristine master drives.

---

## 3. Standard Operational Workflows

### Workflow 1: Pre-Sanitization Survey & Planning
Always execute this two-stage discovery before any destructive command:

```bash
# Step 1: Enumerate all block targets
s0 list

# Step 2: Simulate wiping plan (non-destructive dry-run)
s0 plan --target /dev/sdb
```

**Agent Validation Protocol:**
1. Review the output table of `s0 list`. Check `MOUNTED?`. If `yes`, refuse to proceed until unmounted.
2. Review the plan summary: note the selected method (e.g. `NVME_SANITIZE_CRYPTO_ERASE` or `OVERWRITE_ZERO_1PASS`) and the NIST category (`Purge` or `Clear`).
3. Communicate the Target Path, Model, Serial Number, Capacity, and NIST Category to the user and request confirmation.

---

### Workflow 2: Patient Drive Sanitization (`s0 wipe`)
Once confirmed, execute the wipe operation:

```bash
# Execute sanitization with operator identity and custom output directory
sudo s0 wipe \
    --target /dev/sdb \
    --operator "analyst-01" \
    --organization "Digital Forensics & Sanitization Lab" \
    --out-dir /evidence/certs/
```

**Agent Patience Protocol:**
- During firmware sanitization (NVMe Sanitize or ATA Secure Erase), the controller may take between 10 seconds and 90 minutes. **Do not terminate or poll aggressively.**
- If running in headless automation, add `--yes` and `--json` to capture the event stream.
- On completion, verify that `s0` sampled 64 post-wipe verification blocks with 0 non-zero hits.

---

### Workflow 3: Bit-Stream Forensic Disk Duplication (`s0 image` / `s0 clone`)
For evidence preservation under ISO/IEC 27037:

```bash
# Bit-stream image acquisition with dual hashing
sudo s0 image \
    --source /dev/sdb \
    --destination /evidence/cases/case_042/disk.raw \
    --operator "examiner.carter" \
    --organization "State Police Cyber Lab" \
    --out-dir /evidence/cases/case_042/
```

**Agent Protocol:**
- Confirm the source device is write-blocked.
- Review the generated `acquisition_manifest_<UUID8>.json` for `source_sha256`, `source_md5`, `bad_sectors_count`, and `speed_mbps`.

---

### Workflow 4: Forensic Artifact Carving (`s0 carve`)
To recover deleted evidence from raw forensic images or unmounted volumes:

```bash
# Carve specific formats with confidence filtering
s0 carve \
    --target /evidence/cases/case_042/disk.raw \
    --out-dir /evidence/cases/case_042/recovered/ \
    --extensions jpg,pdf,sqlite,zip \
    --min-confidence 50 \
    --operator "examiner.carter"
```

**Agent Protocol:**
- Check whether filesystem-aware carving (ext4 inode table, NTFS $MFT, FAT32 directory, exFAT cluster heap) or signature-based carving was selected.
- Review `recovery_index.json` to verify recovered artifact IDs, SHA-256 hashes, and confidence ratings.

---

### Workflow 5: Surgical File & Folder Erasure (`s0 erase`)
To sanitize specific sensitive documents, secret keys, or test directories:

```bash
# In-place file scrubbing with metadata zeroing
s0 erase \
    --targets /tmp/staging/keys.pem /tmp/confidential/ \
    --passes 1 \
    --operator "analyst-01" \
    --out-dir /evidence/certs/
```

**Agent Protocol:**
- Check target filesystem. If on a Copy-on-Write filesystem (Btrfs, ZFS, APFS, ReFS), warn the user that host overwriting allocates new blocks while prior blocks linger in snapshots. Advise whole-disk wiping (`s0 wipe`) for high-assurance destruction on CoW volumes.

---

### Workflow 6: Cryptographic Verification & Audit
After generating any certificate or ledger entry, verify mathematical continuity:

```bash
# Verify certificate offline against authority public key
s0 verify /evidence/certs/certificate_a1b2c3d4.json --key /path/to/authority_public.pem

# Verify unbroken continuity of the SQLite blockchain ledger
s0 audit verify
```

---

## 4. Error Handling & Edge Cases

| Failure Scenario | Root Cause | Mandatory Agent Remediation |
|---|---|---|
| `SafetyError: Target is mounted` | A partition is in active use | Refuse to wipe. Instruct user to run `umount /dev/sdX*` or use a bootable Live USB. Never use `--force` on system mounts. |
| `ATA Security State: Frozen` | BIOS/UEFI locked security register on boot | Instruct user to sleep/suspend system for 5 seconds or power-cycle drive via SATA power hot-plug to clear frozen lock. |
| `NVMe Sanitize Not Supported` | Drive firmware lacks Sanitize opcode | s0 automatically cascades to NVMe Format with Crypto Erase (Purge) or BLKDISCARD. |
| `Audit Verify: BROKEN / TAMPER DETECTED` | SQLite database modified out-of-band | Immediately alert operator. Cease issuing certificates from this station until investigated. |
| `Verification Hits > 0` | Post-wipe readback detected non-zero data | Sanitization failed! Drive may have reallocated bad blocks or ignored discard. Fall back to software overwrite. |

---

## 5. Detailed Reference Documentation

When deep technical domain context is needed, consult the bundled reference files:
- [NIST SP 800-88 & IEEE 2883-2022 Method Mappings](references/nist-800-88-mapping.md)
- [Device Safety, Mount Guards & OS Path Architecture](references/device-safety-rules.md)
- [Carving Signatures, File Formats & Entropy Heuristics](references/carving-signatures.md)
- [Canonical JSON v1, Ed25519 Signatures & Audit Ledger](references/audit-and-crypto.md)
