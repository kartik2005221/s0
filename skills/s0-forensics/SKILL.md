---
name: s0-forensics
description: Execute forensic-grade media sanitization, bit-stream disk imaging, deleted file carving, and hash-chained audit ledger operations using s0 (Sector Zero). Use whenever tasks involve securely wiping drives or files, decommissioning laptops or servers, recovering deleted artifacts from disk images, imaging evidence drives, auditing forensic operations, or verifying Ed25519 sanitization certificates. Make sure to trigger this skill whenever the user mentions wiping, sanitizing, forensic imaging, file carving, NIST SP 800-88, or s0 commands, even if they only ask to 'delete a drive safely' or 'recover deleted files'.
---

# s0 Forensics & Data Sanitization Skill

This skill guides an AI agent through safely, accurately, and patiently executing operations using **s0 (Sector Zero)** — the NIST SP 800-88 **Rev. 2** compliant forensic sanitization, imaging, carving, and cryptographic verification suite.

!!! warning "Never relay a sanitization tier as fact unless the certificate states it"
    s0 refuses to claim a tier its evidence does not support, and it will not
    accept one on request. If you find yourself about to tell a user that a
    drive "is sanitized" because the tool exited zero, stop and read the
    certificate's `result.verification.attestation` instead. An exit code is not a
    claim; the attestation is.

---

## CRITICAL SAFETY & PATIENCE DIRECTIVE: HIGH-RISK OPERATIONS

!!! danger "Irreversible Destruction & Hardware Locking Risk"
    Operations executed by `s0` involve **permanent, non-recoverable destruction of digital storage media** or long-running forensic acquisitions. Adhere strictly to the four non-negotiable invariants:

    1. **Patience is mandatory.** Never terminate, abort, or send `SIGKILL` / `SIGINT` to a running `s0 wipe` or `s0 image` process. Interrupting a controller-level firmware erase (`NVME_SANITIZE` or `ATA_SECURE_ERASE`) can lock the drive into a permanently bricked or frozen state. Always wait for completion.
    2. **Never wipe without a dry-run.** ALWAYS run `s0 plan --target <path>` first. Inspect the chosen method and warnings before taking any destructive action.
    3. **Identify the device explicitly.** Run `s0 list` and report the drive **Model**, **Serial Number**, and **Capacity** to the user. Demand explicit user confirmation of the target before executing destructive commands.
    4. **Verify certificates immediately.** After any destructive wipe, file erase, or image acquisition, execute `s0 verify` on the emitted certificate to confirm cryptographic non-repudiation.

---

## 1. Subcommands & Capabilities

| Command | Capability | Safety Level | Primary Use Case |
|---|---|---|---|
| `s0 list` | Enumerate block devices, buses, serials, and mount states | **Safe (Read-Only)** | Initial device discovery and serial verification |
| `s0 plan` | Dry-run simulation of sanitization method and NIST tier | **Safe (Read-Only)** | Pre-flight inspection; writes zero bytes |
| `s0 image` / `s0 clone` | Bit-stream disk acquisition & cloning with dual SHA-256/MD5 | **Safe (Non-Destructive for image; High-Risk if cloning)** | Forensic preservation and physical duplication |
| `s0 carve` | Reconstruct deleted files from raw disk images or partitions | **Safe (Read-Only from source)** | Post-incident recovery of deleted evidence |
| `s0 audit list` / `verify` | Inspect audit ledger and verify SHA-256 hash chain | **Safe (Read-Only)** | Validating tamper-evidence of past laboratory actions |
| `s0 verify` | Offline verification of Ed25519-signed certificate JSON | **Safe (Read-Only)** | Zero-trust verification of compliance reports |
| `s0 keygen` | Generate Ed25519 keypair for an authority or operator | **Safe (Creates Files)** | Establishing laboratory cryptographic authority |
| `s0 upgrade` | Pull latest release from GitHub and rebuild packages | **Maintenance** | Upgrading local toolchain and dependencies |
| `sudo s0 web` | Launch unified forensic web dashboard (FastAPI loopback) | **Safe (Local UI)** | Interactive multi-tab browser dashboard (requires sudo for direct disk sanitization) |
| `s0 wipe` | Physical whole-drive sanitization & surgical file/folder erasure | **HIGH-RISK DESTRUCTIVE** | Decommissioning, repurposing, or sanitized file/folder disposal (auto-detects target type) |

---

## 2. Core Decision Recommendations

When configuring parameters for `s0`, follow these engineering rules:

### A. Overwrite Pattern (`--pattern zero` vs `random`)
- **Recommendation**: Use `zero` (the default) for speed, but **do not describe the
  result as "fully sanitized"**.
- **Rationale**: A single zero pass is the fastest option — sequential bus
  throughput rather than CSPRNG generation — and it is what SP 800-88 Rev. 2
  Clear is normally understood to mean. It is **not** a statement about the
  medium's spare area, wear-levelled remapping or on-device caches, none of
  which a host-level overwrite reaches. Say "a single zero pass was performed and
  readback sampled", and let the certificate's tier field carry the claim. Use
  `random` when a contract mandates it.

### B. Overwrite Pass Count (`--passes 1`)
- **Recommendation**: Use `1` pass (the default) unless a contract says otherwise.
- **Rationale**: Multi-pass wiping (DoD 5220.22-M 3-pass or 7-pass) was designed
  for 1980s stepper drives prone to track drift. One pass is the norm now, and
  extra passes cost real flash write-endurance on SSDs and hours on a
  multi-terabyte drive. State this as the rationale, never as a claim that extra
  passes would add nothing.

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
- On completion, read `result.verification` from the certificate. Do **not** treat
  the sample count as the evidence. s0 records:
  - `samples_checked` — how many were read.
  - `population_blocks` — the population the sample was drawn from.
  - `confidence_percent` — 95.
  - `residual_fraction_upper_bound_ppm` — **the number that matters**: the
    one-sided upper bound on the fraction of the medium still holding the
    pattern, in parts per million.
  - `attestation` — the above as a sentence, for your report.

  The default 64 samples bound the residue at about **4.5%**, which is weak
  evidence for a compliance claim. If the bound matters, raise
  `--verify-samples`: 299 samples bound it at 1%, and 0.01% takes about 29,956.
  A clean sample is not a clean drive, and the certificate says so.

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

**What s0 can now recover that a forward-scanning carver cannot:**

- **Fragmented files, out of order.** Fragments are ordered by the key *inside*
  each one — ISO-BMFF `mfhd.sequence_number` and `tfdt` decode time, Matroska
  `Cluster.Timestamp` — not by where they sit on the volume. 46% of real fragmented
  recordings are laid out out of order, which is why no shipping tool recovers
  them. You do not need to do anything special to benefit; it happens on every
  carve.
- **Matroska and WebM**, including recordings with an unknown-size Segment,
  which is what most in-car cameras write.
- **Twelve container formats** that previously had a signature but no way to
  establish a length, and so were carved to `max_size` — a file with unrelated
  evidence glued to the end. AIFF, TIFF, JPEG 2000, MIDI, RTF, Java `.class`,
  RAR5, registry hives, and exact decompression-derived lengths for bzip2, xz,
  lzma, zstd and lz4.

**Useful options worth knowing:**

| Flag | Purpose |
|---|---|
| `--hash-set <file\|dir>` | Suppress files the examiner already has. Reads bare digests, `sha*sum` output and NSRL rows, or hashes a directory in place. Applies to both the signature and the filesystem-native path. |
| `--bodyfile <path>` | Write the recovered byte ranges for another tool. |
| `--gaps-bodyfile <path>` | Write the ranges that were **searched and found nothing**. For fragmented work this is usually the more useful of the two — the holes are the finding. |
| `--session <file>` | Resume an interrupted carve. Refused if the image has changed since the session was written. |
| `--write-session <file>` | Record this run's recovered extents so it can be resumed. |

**Agent Protocol:**
- Check whether filesystem-aware carving (ext4 inode table, NTFS $MFT, FAT32
  directory, exFAT cluster heap) or signature-based carving was selected.
- Review `recovery_index.json` for recovered artifact IDs, SHA-256 hashes,
  confidence ratings, `contained_candidates_dropped`, and the `warnings` list.
- **Name provenance is a separate question from data recovery.** A file recovered
  from filesystem metadata carries `name_provenance` saying what supports the
  name. On exFAT, FAT32 and ext4 a deleted record holds the name and the first
  cluster but **no parent**, so the path is not recoverable from the volume and
  s0 says so in a sentence rather than printing a bare filename as though it
  were a path. Read `path_is_recovered` before writing a path into your report.
- ext4 **journal (jbd2) filenames are not recovered yet.** The journal reader
  works and is verified against a real superblock, but the fixture that would
  prove end-to-end name recovery needs a mounted filesystem. Deleted ext4 files
  are reported as `inode<N>` with their data recovered — which is honest, and
  not a name.

---

### Workflow 5: Surgical File & Folder Erasure (`s0 wipe --targets`)
To sanitize specific sensitive documents, secret keys, or test directories:

```bash
# In-place file scrubbing with metadata zeroing (auto-detected by s0 wipe)
s0 wipe \
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

# Verify unbroken continuity of the SQLite hash-chained ledger
s0 audit verify
```

---

### Workflow 7: Bare-Metal Live ISO Deployment (`s0 live`)
When internal or system drives cannot be unmounted within a running host operating system:

```bash
# 1. Download official Live ISO with automatic SHA-256 verification
s0 live download

# 2. Inspect connected removable USB flash drives safely (filters out internal drives)
s0 live devices

# 3. Flash to target USB pendrive with real-time progress and confirmation
sudo s0 live flash --target /dev/sdb -y
```
Boot the target system directly into the air-gapped live environment to access internal drives.

---

## 4. Refusals Are Correct Behaviour — Do Not Work Around Them

This is the section most likely to save you from a bad report.

s0 refuses to do several things it *could* do by guessing. Each refusal names
its reason in `recovery_index.json`, the CLI output, and the boundary notes.
When you see one, the correct action is to report it, not to find a way around it.

| Refusal | Why | What to do |
|---|---|---|
| Compressed TIFF (LZW, Deflate, PackBits) | A compressed strip's length is not its byte count, so the strip geometry gives a confident *wrong* answer | Report it as not sized. Uncompressed TIFF is exact. |
| Multi-page TIFF whose IFD chain leaves the file | The chain cannot be followed, so no bound can be proven | Report it. |
| Registry hive with no terminating empty block | A truncated hive and a complete one are otherwise indistinguishable | Report it as truncated. |
| Windows INI, Berkeley DB | Text with no length and no terminator; no magic to size by | Report it. |
| A fragment whose header was overwritten | No in-band key survives, so any position is a guess | Report the bytes as unassigned. |
| No original path on exFAT/FAT32/ext4 | A deleted record holds no parent pointer | Report the filename and say the path is unavailable. |
| A sanitize tier the device did not support | Invariant 2: never claim a tier the evidence does not support | Report the downgrade with its reason. |
| A candidate inside an already-recovered extent | The same bytes would be reported twice under two names | Expected; see `contained_candidates_dropped`. |

A tool that guesses here produces a file that looks complete and is not. That is
worse than no output, because it is believed. If a refusal blocks work that
genuinely needs doing, say so to the user — do not bypass it.

---

## 5. Reading a Certificate Attestation

The certificate is the evidence; the exit code is not. For any wipe:

```bash
python3 -c "import json,sys; v=json.load(open(sys.argv[1]))['result']['verification']; \
print('sampled:', v.get('samples_checked'), 'of', v.get('population_blocks')); \
print('confidence:', str(v.get('confidence_percent'))+'%'); \
print('residue bound:', (v.get('residual_fraction_upper_bound_ppm') or 0)/10000, '%'); \
print(v.get('attestation'))" /evidence/certs/certificate_*.json
```

Three cases, and they are not interchangeable:

- **Sampled readback** (device wipe). Carries a statistical bound. The default
  64 samples bound the residue at ~4.5% at 95% confidence — weak. Raise
  `--verify-samples` when the bound is load-bearing.
- **Exhaustive over supplied paths** (file/folder erase). Not a sample, so no
  residual bound applies. It attests absence *for the paths you supplied* — s0
  cannot verify that your list was complete.
- **NVMe sanitize** (`s0.wipe.attest`). The strongest available: the
  controller's own Global Data Erased bit, plus the action it reports having run.
  Note that the bit means nothing has been written *since the last successful
  sanitize*; it does not mean this operation was that sanitize. Always read it
  together with the status code, which is `result.status` in the sanitize log.

---

## 6. Error Handling & Edge Cases

| Failure Scenario | Root Cause | Mandatory Agent Remediation |
|---|---|---|
| `SafetyError: Target is mounted` | A partition is in active use | Refuse to wipe. Instruct user to run `umount /dev/sdX*` or use a bootable Live USB. Never use `--force` on system mounts. |
| `ATA Security State: Frozen` | BIOS/UEFI locked security register on boot | Instruct user to sleep/suspend system for 5 seconds or power-cycle drive via SATA power hot-plug to clear frozen lock. |
| `NVMe Sanitize Not Supported` | Drive firmware lacks Sanitize opcode | s0 automatically cascades to NVMe Format with Crypto Erase (Purge) or BLKDISCARD. |
| `Audit Verify: BROKEN / TAMPER DETECTED` | SQLite database modified out-of-band | Immediately alert operator. Cease issuing certificates from this station until investigated. |
| `Verification Hits > 0` | Post-wipe readback detected non-zero data | Sanitization failed! Drive may have reallocated bad blocks or ignored discard. Fall back to software overwrite. |

---

## 7. Detailed Reference Documentation

When deep technical domain context is needed, consult the bundled reference files:
- [NIST SP 800-88 & IEEE 2883-2022 Method Mappings](references/nist-800-88-mapping.md)
- [Device Safety, Mount Guards & OS Path Architecture](references/device-safety-rules.md)
- [Carving Signatures, File Formats & Entropy Heuristics](references/carving-signatures.md)
- [Canonical JSON v1, Ed25519 Signatures & Audit Ledger](references/audit-and-crypto.md)
