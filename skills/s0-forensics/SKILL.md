---
name: s0-forensics
description: Execute forensic-grade media sanitization, bit-stream disk imaging, deleted file carving, and hash-chained audit ledger operations using s0 (Sector Zero). Use whenever tasks involve securely wiping drives or files, decommissioning laptops or servers, recovering deleted artifacts from disk images, imaging evidence drives, auditing forensic operations, or verifying Ed25519 sanitization certificates. Make sure to trigger this skill whenever the user mentions wiping, sanitizing, forensic imaging, file carving, NIST SP 800-88, or s0 commands, even if they only ask to 'delete a drive safely' or 'recover deleted files'.
---

# s0 Forensics & Data Sanitization Skill

This skill guides an AI agent through safely, accurately, and patiently executing operations using **s0 (Sector Zero)** — the NIST SP 800-88 **Rev. 2** compliant forensic sanitization, imaging, carving, and cryptographic verification suite.

**Contents**

1. [Subcommands & Capabilities](#1-subcommands--capabilities) — every command and its safety level
2. [Core Decision Recommendations](#2-core-decision-recommendations) — when to use which parameter, and why
3. [Standard Operational Workflows](#3-standard-operational-workflows) — seven worked procedures, survey through Live ISO
4. [Refusals Are Correct Behaviour](#4-refusals-are-correct-behaviour--do-not-work-around-them) — **read before routing around anything**
5. [Reading a Certificate Attestation](#5-reading-a-certificate-attestation) — what the exit code does not tell you
6. [Error Handling & Edge Cases](#6-error-handling--edge-cases) — the strings s0 actually prints, and the exit codes
7. [Reference Documentation & Where This Skill Lives](#7-detailed-reference-documentation--where-this-skill-lives) — bundled references and install locations

> **WARNING — never relay a sanitization tier as fact unless the certificate
> states it.**
>
> s0 refuses to claim a tier its evidence does not support, and it will not accept
> one on request. If you find yourself about to tell a user that a drive "is
> sanitized" because the tool exited zero, stop and read the certificate's
> `result.verification.attestation` instead. An exit code is not a claim; the
> attestation is.

---

## CRITICAL SAFETY & PATIENCE DIRECTIVE: HIGH-RISK OPERATIONS

> **DANGER — irreversible destruction and hardware locking risk.**
>
> Operations executed by `s0` involve **permanent, non-recoverable destruction of
> digital storage media** or long-running forensic acquisitions. Adhere strictly
> to the four non-negotiable invariants:
>
> 1. **Patience is mandatory.** Never terminate, abort, or send `SIGKILL` /
>    `SIGINT` to a running `s0 wipe` or `s0 image` process. Interrupting a
>    controller-level firmware erase (`NVME_SANITIZE` or `ATA_SECURE_ERASE`) can
>    lock the drive into a permanently bricked or frozen state. Always wait for
>    completion.
> 2. **Never wipe without a dry-run.** ALWAYS run `s0 plan --target <path>` first.
>    Inspect the chosen method and warnings before taking any destructive action.
> 3. **Identify the device explicitly.** Run `s0 list` and report the drive
>    **Model**, **Serial Number**, and **Capacity** to the user. Demand explicit
>    user confirmation of the target before executing destructive commands.
> 4. **Verify certificates immediately.** After any destructive wipe, file erase,
>    or image acquisition, execute `s0 verify` on the emitted certificate to
>    confirm cryptographic non-repudiation.

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
| `s0 web` | Launch the forensic web dashboard (FastAPI, loopback only) | **Safe to start; the API it serves is destructive** | Interactive dashboard. Runs as the invoking user — do **not** run it under `sudo`: the dashboard serves `/api/erase-files` and writes its session token to `~/.s0`, so root here is root over the evidence on the machine. |
| `s0 uninstall` | Remove an s0 installation | **HIGH-RISK DESTRUCTIVE** | Only with `--purge-all`. See §1.1 — never pass this flag on an agent's own initiative. |
| `s0 wipe` | Physical whole-drive sanitization & surgical file/folder erasure | **HIGH-RISK DESTRUCTIVE** | Decommissioning, repurposing, or sanitized file/folder disposal (auto-detects target type) |

---

### 1.1 Flags an agent must know exist, and must not reach for

Naming these is the point: an agent that does not know a flag exists will invent a
workflow to avoid it.

| Flag | On | Rule |
|---|---|---|
| `--no-certificate` | `wipe`, `carve`, `image`, `clone` | Suppresses the signed certificate. Legitimate only when the operator explicitly asks for an uncertified run. **Never add it to make a command "succeed".** |
| `--purge-all` | `uninstall` | Deletes `~/.s0` in full, including the audit ledger. **Never pass this.** It destroys the chain of custody for every past operation. Refuse and escalate. |
| `--keep-audit` | `uninstall` | The default. Implies `--purge-all` must not be combined with it. |
| `--discard-purge-justification` | `wipe` | Downgrades a Purge request to Clear with a recorded justification. **Never pass this.** The NIST tier is the operator's decision, not yours. |
| `--force` | `wipe`, `image`, `clone` | Overrides a safety interlock: a mounted target, an existing destination, a system path. **Never pass this in response to a refusal.** A refusal is information. |
| `--dry-run` | every subcommand | Changes nothing. Use it freely to preview. Note that a *refused* plan exits non-zero (77) — that is the refusal being reported, not a crash. |

---

## 1.2 Driving the dashboard over HTTP

`s0 web` serves the same operations as a loopback JSON API. An agent may use it, but
the dashboard is the most destructive surface s0 has: it can erase files on the host
without a prompt once authenticated.

**Authentication.** One token per run, written to `~/.s0/web_auth_token` (mode 0600).

```bash
s0 web --no-browser &            # or open the printed URL in a browser
TOKEN=$(cat ~/.s0/web_auth_token)
```

The token is accepted two ways, and only two:

* `X-S0-Auth-Token: $TOKEN` — **use this for anything scripted.**
* `?token=...` — bootstrap only, accepted on `/` alone. It exists because the kiosk
  cannot set a header. It is then moved into an HttpOnly cookie and the URL
  redirected, because a token in a URL leaks into history, `Referer` and proxy logs.

Passing `?token=` to an `/api/*` route returns 401. Do not work around this.

**Routes.** Read-only: `GET /healthz`, `GET /api/list`, `/api/devices`, `/api/config`,
`/api/capabilities`, `/api/browse`, `/api/audit/blocks`, `/api/audit/verify`,
`GET /api/download/{job}/{artifact}`.

State-changing, all `POST`, all returning a job id to poll:
`/api/plan` (read-only despite the verb), `/api/wipe`, `/api/erase-files`,
`/api/image`, `/api/clone`, `/api/carve`.

**Rules when driving it:**

* `/api/wipe` requires the **exact destination path** in `confirm_text`. It is not a
  boolean and not an acknowledgement.
* `/api/erase-files` runs **in-process**, not through the CLI. It applies the same
  shared path guard, so `/etc` and s0's own state directory are refused — but the
  guard is the only thing standing between a request and the filesystem. Confirm the
  target list with the operator before sending it.
* State-changing requests are rejected (403) when they carry a foreign `Origin` or
  `Sec-Fetch-Site`, so a cross-site request cannot drive them.
* `/api/download` refuses any filename that resolves outside the job's output
  directory. Do not attempt traversal; it is refused, and trying is the wrong signal
  to send.

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
- **Recommendation**: Use `50` (the CLI default) for standard triage and
  `75`–`90` for court-admissible automated pipelines. **Lowering it does not
  recover anything the structural gates rejected** — see the warning below.
- **Rationale**: A score of 50 requires a magic header, an independently
  resolved end of file, and a plausible size; above that, entropy and boundary
  method separate a good recovery from a merely possible one.

> **WARNING — `--min-confidence` is a rank, not an override.**
>
> Two gates run *before* any candidate is scored, and neither is a score
> component:
>
> 1. **Boundary resolution.** A candidate whose end cannot be derived is dropped
>    before it is ever read.
> 2. **Structural validation** (`s0.carve.boundary.validate_structure`). A
>    candidate that does not parse as its claimed format is dropped.
>
> `--min-confidence 0` changes neither. A truncated or corrupted file is refused
> with a reason in `recovery_index.json`, not admitted at zero confidence. So
> there is **no confidence value that recovers a structurally damaged file**:
> lower the number only to admit *well-formed but lower-scoring* files — a small
> text document, a truncated-but-valid container, a repetitive image.
>
> **What actually helps on corrupted media:**
>
> - Read `recovery_index.json` → `rejection_summary` and
>   `rejected_candidates_sample`. They name the gate and the reason, so you can
>   tell a damaged file from a signature that was never there.
> - Narrow `--extensions` to the formats present, so the budget is not spent on
>   2-byte magics like MP3 frame sync that match inside random data.
> - Re-acquire the source from the original medium. A carve cannot restore bytes
>   the image does not contain.
> - Report the refusal. Do not tune a threshold until something appears.

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
1. Review the inventory table `s0 list` prints. The column is headed `MOUNTED`
   and a mounted target shows `YES` (an unmounted one shows `-`). In
   `--format csv` the same column is `mounted` with lowercase `yes`/`no`, and in
   `--format json` it is the boolean `mounted`. If a target is mounted, refuse to
   proceed until it is unmounted.
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
- Read the manifest the run prints as `Manifest file`. Its name is
  `acquisition_manifest_<unix_start_seconds>_<source_basename>.json` — **not**
  `acquisition_manifest_<UUID8>.json`; there is no UUID in it. The fields are
  nested, so read them at the right depth:
  - `cryptographic_hashes.sha256` and `cryptographic_hashes.md5`
  - `integrity_recovery.bad_sectors_encountered`, `bad_bytes_zero_filled`,
    `bad_sector_ranges`
  - `average_speed_mbps`, `duration_seconds`, `source.capacity_bytes`,
    `destination.bytes_written`
  - `operator.operator_id`, `operator.organization`
- A `bad_sectors_encountered` above zero is not a failed acquisition: those
  sectors were zero-filled and logged in `bad_sector_ranges`. Report the count
  and the ranges; the image is incomplete in exactly those extents and nowhere
  else.

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

**What s0 does that a forward-scanning carver does not** — verified against the
live signature table in `src/s0/carve/signatures.py`, which is 62 signatures
across 51 extensions. 38 of those extensions have a **structural boundary
rule**: the end of the file comes from the format's own structure, not from a
ceiling. The other 13 are named in
[Carving Signatures](references/carving-signatures.md) and are sized from a
declared field or footer where the format has one.

- **Exact lengths for containers that previously had none.** A structural
  boundary rule exists for each of: AIFF (`FORM` declared size), TIFF (IFD chain
  plus strip extents), JPEG 2000 (box walk to EOC), MIDI (`MTrk` chunk walk), RTF
  (group nesting must close), Java `.class` (constant pool and member tables),
  RAR5 (block chain to end-of-archive), registry hives (the `hbin` chain),
  Matroska/WebM (below), and the compressed-stream formats in the next bullet.
  AIFF, uncompressed TIFF, JPEG 2000, MIDI, RTF, `.class`, bzip2, xz, zstd and
  tar were each recovered byte-exactly from a purpose-built fixture on this
  branch; RAR5, registry hives and LZ4 are covered by the test suite in
  `tests/cli/test_containers.py` rather than by a fixture built here.
  **A rule existing is not a guarantee of recovery** — compressed TIFF is
  refused outright (see section 4), and the boundary notes on every recovered
  file say which rule actually bound it.
- **Compressed-stream ends, by two different mechanisms — do not conflate
  them.** `bzip2` and `xz` get an exact, *decompressor-reported* end (the
  decoder says how much it consumed). `zstd` and `lz4` get an exact end from a
  *frame and block header walk*, with no decoder involved. There is **no `.lzma`
  signature**, so a legacy alone-format `.lzma` file is not carved at all; the
  `xz` signature covers the XZ container only.
- **Matroska and WebM**, including recordings with an unknown-size Segment,
  which is what most in-car cameras write, and unknown-size Clusters, where the
  cluster ends where the next element ID appears.
- **Fragmented ISO-BMFF, out of order.** For `mp4`, `mov` and `m4v`,
  fragments are ordered by the key *inside* each one —
  `mfhd.sequence_number`, cross-checked against `tfdt` base media decode time —
  not by where they sit on the volume. Assemblies are checked three ways
  (key contiguity, decode-time projection, reparse through the format's own
  parser) and a hole is reported as a hole rather than bridged. This happens on
  every carve; there is no flag for it.
  **Scope, precisely:** Matroska cluster ordering by `Cluster.Timestamp` exists
  in `s0.carve.reassembly` and is exercised by the test suite, but it is **not
  wired into the `s0 carve` path**, which only reassembles ISO-BMFF. Do not tell a
  user that `s0 carve` reassembles a fragmented Matroska file; report the
  clusters it derives individually.
- **The formats that are *not* structural are named, not implied.** 13
  extensions — `avif`, `db`, `doc`, `docx`, `heic`, `ini`, `lnk`, `mdb`, `mp3`,
  `pf`, `pptx`, `url`, `xlsx` — have no boundary rule and are carved from a
  declared field, a footer, or the signature's `max_size`. Read
  `boundary_method` on each recovered file and say which kind it is.

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
| BigTIFF (8-byte IFD offsets) | The offset width is doubled and the reader does not decode it | Report it as not sized. |
| Multi-page TIFF whose IFD chain leaves the file | The chain cannot be followed, so no bound can be proven | Report it. |
| Registry hive with no terminating empty block | A truncated hive and a complete one are otherwise indistinguishable | Report it as truncated. |
| Windows INI, Berkeley DB | Text with no length and no terminator; no magic to size by | Report it. |
| Windows prefetch that is not version 3 | Only v3 declares the original file's size; the prefetcher routinely truncates the container | Report it as not sized. |
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
# Device wipes emit certificate_<uuid8>.json; file/folder erases emit
# file_wipe_certificate_<uuid8>.json. The leading * is required: a glob of
# `certificate_*.json` alone matches nothing for a file erase, and the shell
# then passes the literal pattern to python.
python3 - /evidence/certs/*certificate_*.json <<'PY'
import json, sys

for path in sys.argv[1:]:
    with open(path, encoding="utf-8") as fh:
        cert = json.load(fh)
    result = cert.get("result") or {}
    v = result.get("verification") or {}
    print(f"== {path}")
    print(f"  result.status    : {result.get('status')}")
    print(f"  method           : {cert.get('wipe', {}).get('method')}"
          f" (NIST {cert.get('wipe', {}).get('nist_category')})")
    checked = v.get("samples_checked")
    population = v.get("population_blocks")
    print(f"  readbacks checked: {checked}"
          + (f" of {population}" if population is not None else ""))
    print(f"  sample strategy  : {v.get('sample_strategy') or '(not recorded)'}")
    if "residual_fraction_upper_bound_ppm" in v:
        ppm = v["residual_fraction_upper_bound_ppm"]
        print(f"  residual bound   : {ppm / 10000:.4f}% of the medium at"
              f" {v.get('confidence_percent')}% confidence")
    else:
        print("  residual bound   : NONE RECORDED -- this was not a statistical"
              " sample, so there is no bound. Read the attestation below.")
    print(f"  attestation      : {v.get('attestation') or '(not recorded)'}")
PY
```

Two things that snippet deliberately does not do, because doing them is how a
reader ends up reporting a number the certificate never produced:

- **It never prints `0` for an absent bound.** `residual_fraction_upper_bound_ppm`
  is optional in the schema and is genuinely *absent* on a file/folder erase,
  where the operation was exhaustive rather than sampled. A missing bound means
  "no bound applies", which is not the same claim as "the residue is zero", and
  an exhaustive re-stat of a file list is not a measurement of a medium.
- **It never calls a file list a "sample".** `samples_checked` on a file erase
  counts the paths that were re-stat()ed; `sample_strategy` says
  `exhaustive_over_supplied_paths` so you can tell.

Three cases, and they are not interchangeable:

- **Sampled readback** (device wipe, `method: sampled_readback`). Carries a
  statistical bound in `residual_fraction_upper_bound_ppm`. The default 64
  samples bound the residue at ~4.5% at 95% confidence — weak. Raise
  `--verify-samples` when the bound is load-bearing.
- **Exhaustive over supplied paths** (file/folder erase, `method:
  post_erase_absence_and_overwrite_readback`). Not a sample, so no
  residual bound applies. It attests absence *for the paths you supplied* — s0
  cannot verify that your list was complete.
- **NVMe sanitize** (`s0.wipe.attest`). The strongest available: the
  controller's own Global Data Erased bit, plus the action it reports having run.
  Note that the bit means nothing has been written *since the last successful
  sanitize*; it does not mean this operation was that sanitize. Always read it
  together with the status code, which is `result.status` in the sanitize log.

---

## 6. Error Handling & Edge Cases

Every string in the "as printed" column below was checked against
`src/s0/cli/main.py`, `src/s0/cli/devices.py`, `src/s0/safety.py` and
`src/s0/audit/verify.py`. Quote them back to the user as they appear; do not
paraphrase them into a different failure.

| As printed | Exit | Root cause | Mandatory agent remediation |
|---|---|---|---|
| `REFUSED: <path> has mounted filesystems (<hits>). Unmount them first, or pass --force if you truly mean it.` | 2 | A partition on the target is in active use | Refuse to wipe. Ask the user to unmount (`umount /dev/sdX*`) or boot the s0 Live ISO. **Never** supply `--force` on a system mount. `s0 plan` prints the same refusal and exits 0 — it is a dry run, so the refusal is in the `Warnings` block. |
| `REFUSED: <path> hosts the running ROOT filesystem. The tool refuses this without --force; if you mean it, boot the s0 ISO instead.` | 2 | The target hosts `/` | Refuse. The only correct path is the Live ISO. Do not pass `--force`. |
| `error: Refusing to target system path: <path>` | 77, for both `--target` and `--targets` | The shared path guard protects `/etc`, `/usr`, the filesystem root, `$HOME` itself and s0's own state directory | Refuse. Report which guard fired; do not retry with `--force`. |

> Quote these strings back as they appear. Both `--target` and `--targets` exit **77**
> on a protected path, the message is prefixed `error:` (not `REFUSED:`), and a
> `==> Target items (N): [...]` banner is printed first — so an agent expecting a
> different exit code or prefix will misread a successful refusal as something else.
> The code 77 means "s0 declined", not specifically "insufficient privilege": the
> same code covers `image`/`clone` onto an existing destination without `--force`.
| `Cannot verify whether <path> hosts the running ROOT filesystem (findmnt unavailable and /proc/mounts could not be verified). Refusing to proceed without --force.` | 2 | `findmnt` and `/proc/mounts` both unreadable, so the root-filesystem check cannot be made | Refuse. Report that the guard could not evaluate, not that the target is safe. |
| `<path> reports no firmware-mediated Purge method (no ATA Sanitize, no NVMe Sanitize, no SCSI SANITIZE, no FDE key destruction). … s0 will not issue a Purge claim it cannot substantiate …` | 75 | `--require-tier Purge` on a device that cannot reach Purge (`s0 wipe` and `s0 plan` both refuse) | Report the downgrade. Only proceed with `--allow-downgrade`, which records the decision on the certificate — and then report the **achieved** tier, not the requested one. |
| `drive security state is FROZEN — BIOS froze it to block hot-attach attacks; warm-sleep/resume (suspend the machine, resume) then retry` | 1 | BIOS/UEFI issued an ATA Security Freeze Lock during POST | Ask the user to suspend and resume the machine, or power-cycle the drive on the SATA power header. Do not keep retrying in a loop. In `s0 plan` this appears as the alternative `ATA Security Erase unavailable: drive security state is FROZEN`. |
| `controller lacks sanitize capability` / `nvme-cli not installed` / `crypto erase capability unconfirmed` (listed under `Alternatives` in `s0 plan`) | 0 | NVMe firmware does not advertise Sanitize, or `nvme-cli` is absent, or the probe was inconclusive | s0 falls back to NVMe Format, then to a single-pass overwrite. Report the **fallback that was chosen** and its tier. Do not describe the result as a Purge sanitize. |
| `CHAIN INTEGRITY FAILURE` (`s0 audit verify`) | 1 | Hash-chain continuity or a block signature failed | Alert the operator immediately and stop issuing certificates from this station. Preserve the ledger; do not delete or rebuild it. |
| `UNVERIFIABLE - SIGNING KEY NOT IN THE TRUST SET` (`s0 audit verify`) | 1 | The ledger hashes verify, but the signing key is not among the keys `--key` / `~/.s0/keys` supplied | **This is the first state most users hit, and it is a refusal, not a pass.** The chain is continuous; continuity is not authenticity, because anyone can recompute a SHA-256 block hash. Re-run with `--key <issuer_public.pem>` (repeatable; a directory of `*.pem` also works) and report the result. Never write "audit chain verified" on this state alone. |
| `VALID & CONTINUOUS - SIGNED WITH UNACCREDITED DEMO KEY` (`s0 audit verify`) | 0 | The chain is intact but was signed with the bundled `demo_issuer_private.pem` | Report it as cryptographically continuous **and** unusable for legal chain of custody. |
| `VERIFICATION FAILED` (`s0 verify`) | 1 | Signature does not match the payload, or the issuer fingerprint is not pinned | Treat the certificate as suspect. `Reason` distinguishes `signature does NOT match payload — the certificate content has been modified after signing` from `unknown issuer key fingerprint … — certificate was not issued by any pinned authority`. The second is an unknown *authority*, not tampering; say which one it is. |
| `AUTHENTIC - but signed with an unaccredited demonstration key` (`s0 verify`) | 0 | Valid signature, demonstration key | Report it as authentic but not accredited. |
| `no trusted public key available; pass --key <issuer_public.pem>` | 78 | No key at all, so nothing could be checked | Report that verification did not happen. Do not report it as a pass or a fail. |
| `Verification  <n> read-back sample(s) - MISMATCH` followed by `sanitization did not complete cleanly: the certificate records the failure and must not be presented as a completed wipe.` | 1 | Post-wipe readback did not match the pattern | The wipe failed. Report the failure and the certificate's `result.status`. Do not re-run `s0 plan` and describe the retry as success until its own readback matches. |
| `Planted markers  <n> hit(s) after sanitization` | 0 or 1 — the line is printed unconditionally, so read `result.status` and the `Verification` line above it for the verdict | A known pre-wipe needle is still readable. This is recorded on demo/test targets, where the pre-wipe content was known | Report it regardless of the exit code. It is the strongest single indication that data survived, and a wipe can still exit 0 with it present. |
| `WIPE INTERRUPTED (Ctrl+C). The target may be partially overwritten and must not be released. Re-run s0 wipe to completion, or escalate to a physical destruction method.` | 130 | The operator interrupted the run | Report the target as **partially** sanitized. Never describe it as sanitized, and never release the media. |

---

## 7. Detailed Reference Documentation & Where This Skill Lives

### 7.1 Bundled references

When deep technical domain context is needed, consult the bundled reference
files. All four paths are relative to this `SKILL.md`:

| Reference | Use it for |
|---|---|
| [NIST SP 800-88 & IEEE 2883-2022 Method Mappings](references/nist-800-88-mapping.md) | Which method earns which tier, and the DRAT/RZAT rules for a Purge claim |
| [Device Safety, Mount Guards & OS Path Architecture](references/device-safety-rules.md) | OS device paths, the four safety interlocks, ATA frozen state, HPA/DCO |
| [Carving Signatures, File Formats & Entropy Heuristics](references/carving-signatures.md) | The live per-extension table: magic bytes, and whether an extension is **structural** (length derived from the format) or **sized from a declared field / footer** |
| [Canonical JSON v1, Ed25519 Signatures & Audit Ledger](references/audit-and-crypto.md) | The serialization contract and the block-hash formula |

`references/carving-signatures.md` is **generated** from
`src/s0/carve/signatures.py` by `tools/gen_carving_reference.py`. Do not hand-edit
it. If a format you need is missing from it, the signature registry is missing it
too; check `python tools/gen_carving_reference.py --check` before believing
anything either of them says about the format count.

Also in this directory:

- `scripts/verify_cert.py` — standalone certificate verifier. Runs with or
  without s0 importable, and walks up from its own location looking for the
  repository; if it is copied somewhere shallower it tells you to pass `--key`
  rather than raising `IndexError`.
- `evals/evals.json` — benchmark prompts and the behaviour each one is meant to
  elicit.

### 7.2 Where the skill is installed

This skill ships **inside the distribution**, so a `pip install s0` user has it
as well as a git clone:

```bash
python3 -c "import importlib.util, pathlib; \
  s = importlib.util.find_spec('skills'); \
  print(pathlib.Path(s.submodule_search_locations[0]).resolve())"
```

- **pip / wheel:** `<site-packages>/skills/s0-forensics/` — a real directory
  inside the installed package, not a link back to a checkout.
- **git clone and the curl one-liner** (which clones to `~/.s0` and editable-installs
  from it): `~/.s0/skills/s0-forensics/`.

Point an agent at that `SKILL.md`. If neither location exists, the install is
broken, not merely incomplete — say so rather than improvising guidance.
