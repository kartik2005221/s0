# Technical Limitations & Boundaries

{% hint style="info" %}
**Engineering Philosophy**
**Honest tools build trusted outcomes.** A forensic instrument that overpromises is not merely useless — it is actively dangerous. If a court or an investigator relies on a guarantee that the underlying hardware silently violates, the entire chain of custody collapses. s0 is built to be precise about what it can and cannot accomplish. Every limitation documented here is a constraint of the physical world, the filesystem layer, or the current development state — not a gap to be papered over with marketing language.
{% endhint %}

---

## Module Status at a Glance

| Module | Status | Notes |
|---|---|---|
| **Module 1 — Media & File Sanitizer (`s0 wipe`)** | Fully validated | Whole drives, images, and Linux, Windows, macOS file/folder wiping |
| **Module 2 — File Carver** | Fully validated | Multi-format header/footer + multi-filesystem structure carving |
| **Module 3 — Forensic Imager** | Fully validated | Bit-stream disk acquisition, device cloning, and bad sector recovery |
| **Audit Ledger** | Fully validated | Single-authority hash chain (not distributed consensus — see §9) |

{% hint style="info" %}
**Reading the Status Column**
"Fully real & validated" means the code path has been exercised against real or simulated block devices and the outputs have been verified. "Scaffolded, unverified on bare metal" means the code is complete and syntactically correct but has not been run in its intended hardware environment.
{% endhint %}

---

## 1. Flash Translation Layer (FTL) — The Fundamental SSD Constraint

### What It Is

When you issue a write to logical sector 0 of an SSD, you are communicating with the drive's **Flash Translation Layer** — a firmware-level indirection table that maps logical block addresses (LBAs) to physical NAND flash pages. The FTL is free to satisfy your write by allocating a **fresh physical block**, marking your data as committed to the new block, and leaving the old physical block in a "stale" state until the drive's internal garbage collector reclaims it.

From the operating system's perspective, the write succeeded. From a forensic perspective, the original data still exists at a physical location the host operating system has no visibility into.

### Why It Exists

NAND flash cells degrade with each program/erase cycle. The FTL exists to distribute write load across all physical cells (wear leveling), absorb bursty writes (write buffering), and extend the operational life of the device. These are correct engineering tradeoffs — but they make host-level overwrite semantically unreliable for secure erasure.

### Impact on s0

`OVERWRITE_ZERO_1PASS`, `OVERWRITE_RANDOM_1PASS`, and all multi-pass DOD/Gutmann patterns executed at the **host level** operate against logical addresses only. The SSD firmware decides where the actual bits land physically.

{% hint style="danger" %}
**Host-Level Overwrite Cannot Guarantee SSD Erasure**
Writing zeros or random data to every logical sector of an SSD does **not** guarantee that all physical NAND pages have been zeroed. Overprovisioned zones, wear-leveled blocks, and recently-written stale pages are entirely outside host-level visibility.
{% endhint %}

### What to Do Instead

s0 explicitly detects NVMe and SATA SSD targets and prefers firmware-level commands:

- **`NVME_SANITIZE` (NVMe Sanitize Block Erase / Crypto Erase)** — issued via `ioctl(fd, NVME_IOCTL_ADMIN_CMD, ...)`, instructs the controller to erase all physical blocks including overprovisioned areas.
- **`ATA_SECURE_ERASE` (ATA Security Erase Unit)** — issued via `hdparm --security-erase`, resets all user data including HPA/DCO-hidden zones.

These commands operate at the **controller firmware level**, resetting the FTL map and all physical blocks. They are the only host-accessible mechanisms that provide high-assurance erasure for SSDs.

---

## 2. Copy-on-Write Filesystems

### Affected Filesystems

| Filesystem | Platforms | CoW Behavior |
|---|---|---|
| **Btrfs** | Linux | Always CoW on file writes |
| **ZFS** | Linux (OpenZFS) | Always CoW |
| **APFS** | macOS | Always CoW |
| **ReFS** | Windows Server | Always CoW |

### What Happens During File Overwrite

When `s0 wipe` is invoked on files located on a CoW filesystem and writes overwrite passes, the filesystem does **not** modify the original data blocks in place. Instead it:

1. Allocates new blocks for the new (overwritten) content.
2. Updates the B-tree or extent tree to point the file's inode to the new blocks.
3. Marks the old blocks as free — but does not immediately zero them.
4. Schedules the old blocks for reclamation during the next garbage collection pass.

The original file content remains physically intact until the garbage collector runs — which may not happen for seconds, minutes, or never if the volume is unmounted first.

### How s0 Handles This

s0 detects CoW filesystems at runtime:

- **Btrfs / ZFS**: Parsed from `/proc/mounts` (Linux).
- **APFS**: Detected via platform check (`sys.platform == 'darwin'`).
- **ReFS**: Detected via `GetVolumeInformationW` (Windows).

When a CoW filesystem is detected, s0 **emits an explicit signed warning** in the operation certificate's `notes` field. The certificate is cryptographically signed, so this warning cannot be silently removed downstream.

{% hint style="warning" %}
**File-Level Overwrite Is Ineffective on CoW Filesystems**
On Btrfs, ZFS, APFS, and ReFS, overwriting a file's content does not overwrite the original data blocks. The certificate will carry a `cow_filesystem_warning` note. **Treat this as informational, not as a guarantee of erasure.**
{% endhint %}

### What to Do Instead

For maximum assurance on CoW volumes:

- Use `NVME_SANITIZE` or `ATA_SECURE_ERASE` to wipe the entire physical device.
- For software RAID / ZFS pools: issue a `zpool destroy` followed by a block-level device wipe.
- Accept that file-level erasure on CoW is a best-effort operation and document this in your chain of custody.

---

## 3. Journaling Filesystems

### Affected Filesystems

| Filesystem | Journal Type | Scope |
|---|---|---|
| **ext4** (with `has_journal`) | Circular journal (`journal_data_writeback` default) | Metadata journal by default |
| **NTFS** | `$LogFile` + `$UsnJrnl` | Metadata + change journal |
| **HFS+** | Journal | Metadata |

### The Journal Retention Window

Journaling filesystems maintain a circular log of metadata changes. When s0 deletes a file and overwrites its directory entry, the journal may still contain records that prove the file existed: its name, size, allocation timestamp, and inode number.

The journal overwrites itself as new operations fill the circular buffer — but there is a **window** between the s0 operation and the journal recycling that window. On a lightly-used forensic workstation in airplane mode, this window could persist indefinitely.

{% hint style="warning" %}
**Journal May Retain File Existence Records**
After secure deletion with s0 on ext4 or NTFS, the filesystem journal may temporarily (or permanently, on a static volume) retain metadata entries that prove the file existed. s0 discloses this in the `operation_notes` field of the audit certificate.
{% endhint %}

### What to Do Instead

- For ext4: mount with `data=journal` to journal data in addition to metadata, then wipe the journal (`tune2fs -O ^has_journal` + surface wipe) — or wipe the entire volume.
- For NTFS: a full volume wipe is the only reliable option for clearing `$LogFile` and `$UsnJrnl`.
- Accept journal residue as a known, documented limitation when file-level erasure is the only option.
### jbd2: file names are not recovered from the journal

s0 parses the ext4 journal (jbd2) and reads it back cleanly: all 4,096 blocks of a
real 1 GiB test image decode with zero checksum failures. What it will not do is
invent a file name.

A jbd2 journal stores the *old* block contents. When a file's directory entry is
unlinked, the journal may retain that entry, which contains the name. Recovering it
requires the journal to actually contain that block, and that block to have not yet
been recycled.

Testing this needs care, because the obvious method does not work. An ext4 image
built and modified with `debugfs` is **not journalled** — `debugfs` writes directly
to the image and bypasses the kernel's journal. In that fixture the name survives only
in a stale directory entry *outside* the journal, so s0 correctly reports `inode<N>`
rather than a name. That is the honest outcome and the parser behaving correctly, not
a silent failure.

To exercise the path where a name is recoverable you need a **kernel-written
journal**: mount a real ext4 filesystem, unlink a file, and unmount. That requires
loop-device privileges. Until such a fixture exists, the journal *contents* are
verified and journal-based name recovery is not.

### Readback verification is sampling, not exhaustion

For a file or image wipe, s0 verifies by reading back a sample of blocks (64 by
default, `--verify-samples`). A clean sample means the sampled blocks were zeroed. It
does not mean every block on the medium was read.

The certificate reports the bound this supports rather than an absolute: see
`sample_strategy`, `population_blocks`, `confidence_percent` and
`residual_fraction_upper_bound_ppm` in `verification`. With the defaults, a clean
sample bounds residual data at about 45,730 ppm (4.573%) at 95% confidence.

For a claim of complete erasure, use a hardware Purge command rather than overwrite,
and confirm the firmware status. s0 cannot verify what the controller did after the
fact, and says so.


---

## 4. NTFS Carving Limitations

Module 2's NTFS structure-based carver operates on raw images and block devices. The following constraints apply:

### No Transaction Log Replay

s0 does **not** replay `$LogFile` journal entries. This means:

- File metadata states visible only in uncommitted or rolled-back journal transactions are not recovered.
- Fragmented MFT entries that were in-flight during a crash may not be reassembled.

This is a deliberate choice: journal replay requires understanding the exact transaction state at crash time, which is unverifiable without the original NTFS driver state machine.

### USN Journal (`$UsnJrnl`) Not Parsed

The NTFS Update Sequence Number Journal records every file operation but is not currently parsed by the carver. File names and operation timestamps embedded in `$UsnJrnl` are not surfaced in s0 recovery output.

### Alternate Data Streams (ADS)

Only the **primary unnamed `$DATA` stream** is extracted per MFT entry. Secondary named streams (e.g., `file.txt:Zone.Identifier`) are bypassed. If your investigation targets ADS content specifically, use a dedicated NTFS ADS enumeration tool.

{% hint style="info" %}
**ADS Enumeration on Live Systems**
s0's Windows file erasure implementation **does** enumerate ADS on live files during secure deletion (to ensure named streams are overwritten). The carver limitation applies only to post-mortem image analysis.
{% endhint %}

---

## 5. FAT32 / exFAT Carving Limitations

### No FAT Chain Following

The FAT (File Allocation Table) chain defines how clusters are linked for fragmented files. s0's FAT32/exFAT carver does **not** follow FAT chain entries. Recovery is limited to:

- **Contiguous cluster runs**: Files whose data occupies sequentially allocated clusters.
- **Header/footer signature matching**: Files identifiable by magic bytes at their start (and optionally their end).

### Fragmented Files May Be Incomplete

If a file's clusters are scattered non-contiguously and the FAT chain has been zeroed or overwritten, s0 cannot reassemble the complete file. The carver will return what it can find at the first contiguous run, which may be a partial (and therefore corrupt) file.

{% hint style="warning" %}
**Fragmentation Means Partial Recovery**
On heavily fragmented FAT32/exFAT volumes, recovered files may be truncated or corrupt. Confidence scores in the recovery index reflect structural validity of what was found, not completeness of the original file.
{% endhint %}

---

## 6. Live ISO — Bare Metal Status

The Live ISO build infrastructure (`iso/`) is fully specified against `live-build` syntax, including:

- Preseed configuration for unattended boot.
- systemd unit files for privilege-separated web dashboard launch.
- Package lists for forensic dependencies.

{% hint style="warning" %}
**ISO Has Not Been Boot-Tested on Physical Hardware**
The development environment lacks `sudo` and `debootstrap`, which are required to run `lb build`. The ISO build scripts are complete and syntactically correct, but the resulting image has not been verified to boot on real hardware or in a Type-1 hypervisor.
{% endhint %}

**Treat the Live ISO as: scaffolded, specified, and unverified on bare metal.**

This does not affect Modules 1–4 on installed systems. Only the ISO deployment path carries this caveat.

---

## 7. What the File Carver Cannot Recover

Regardless of filesystem or image type, the following categories of data are unrecoverable by design or by physics:

| Scenario | Why It Cannot Be Recovered |
|---|---|
| **Encrypted volumes** (VeraCrypt, BitLocker, LUKS) | Encrypted blocks are computationally indistinguishable from random noise; no header signatures are present |
| **Physically overwritten data** | If sectors have been written with zeros or random data after original content, the original is gone |
| **Heavily fragmented files (no FAT chain)** | Without the allocation chain, clusters cannot be logically reassembled |
| **Bad sectors covering the target data** | Unreadable sectors produce I/O errors; data in those sectors is inaccessible |
| **FTL-managed overprovisioned blocks** | These zones are below the host-visible LBA address space |
| **Data inside compressed NTFS streams** | Compression context is partially available but full reassembly is not currently implemented |

---

## 8. When to Use Firmware Erase vs. File-Level Erase

Use this decision guide before selecting an erasure method:

```
Is the target a solid-state device (SSD, NVMe, eMMC, SD card)?
├── YES → Does the drive support NVMe Sanitize or ATA Secure Erase?
│         ├── YES → Use NVME_SANITIZE or ATA_SECURE_ERASE
│         │         (firmware-level, covers all physical blocks)
│         └── NO  → Use OVERWRITE_ZERO_1PASS + document the limitation
│                   (best effort; FTL residue is possible)
└── NO (HDD / spinning disk)
    ├── Is the data on a CoW filesystem (Btrfs, ZFS, APFS, ReFS)?
    │   ├── YES → Wipe the entire volume at block device level.
    │   │         File-level overwrite is ineffective on CoW.
    │   └── NO  (ext4, NTFS, FAT32, XFS, etc.)
    │       ├── Single file? → Use `s0 wipe --targets` (File & Folder Sanitizer)
    │       │   Note: journal residue window applies on ext4/NTFS
    │       └── Entire drive? → Use `s0 wipe --target /dev/...` (Whole-Drive Sanitizer)
    │           Select OVERWRITE_ZERO_1PASS (NIST 800-88 Clear) or
    │           OVERWRITE_RANDOM_3PASS (NIST 800-88 Purge for HDDs)
```

---

## 9. Hash Chain vs. Distributed Blockchain

s0's Audit Ledger is sometimes described as a "blockchain." This requires precise clarification.

### What s0 Has

A **local, single-authority hash chain** stored in SQLite:

- Each audit record includes the SHA-256 hash of the previous record.
- Any modification to any SQLite row breaks the hash chain continuity from that point forward.
- Chain integrity is verifiable with a single deterministic pass: `s0 audit verify`.

### What s0 Does Not Have

- **No proof-of-work** (no mining, no computational puzzle).
- **No peer-to-peer network** (no nodes, no gossip protocol).
- **No distributed consensus** (no Nakamoto consensus, no PoS validators).
- **No integration with Ethereum, Solana, or any public blockchain**.

### Why This Is the Right Design

{% hint style="info" %}
**Air-Gap Context Changes the Threat Model**
Forensic workstations operate on air-gapped networks by design. Distributed consensus requires network connectivity and introduces latency, third-party dependencies, and transaction fees — none of which add security value when the threat is local record tampering by a single actor.
{% endhint %}

The tamper-evidence guarantee of a hash chain is **mathematically equivalent** to a blockchain for single-authority forensic use: if anyone modifies a historical record, the chain breaks and `s0 audit verify` reports `CHAIN INTEGRITY FAILURE` at the exact record where tampering occurred.

Distributed consensus solves the **Byzantine generals problem** — coordinating agreement among mutually distrusting parties across a network. That problem does not exist on an air-gapped forensic workstation. The simpler, faster, auditable local hash chain is the correct tool.

---

## 10. Platform-Specific Validation Reports

Detailed breakdown of tested vs. simulated hardware capabilities across operating environments:

- [Linux Hardware & Emulation Validation Report](platforms/linux.md)
- [macOS APFS & Native Storage Validation Report](platforms/macos.md)
- [Windows NTFS & Win32 Storage Validation Report](platforms/windows.md)

