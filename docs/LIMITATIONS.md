# TrustWipe — Technical Limitations & Forensic Boundaries (NTRO / SIH26149)

**Target Authority:** National Technical Research Organisation (NTRO)  
**Commitment:** Absolute engineering honesty. We document every technical boundary across sanitization and forensic recovery.

---

## 1. Module-by-Module Capabilities & Hardware Status

| Module | Development Status | Real Hardware Behavior & Requirements |
|---|---|---|
| **Module 1: Drive Eraser** | ✅ **Fully Real & Validated** | Full overwrite on disk images & block devices. ATA/NVMe firmware paths coded & fixture-tested (real ATA/NVMe controllers required for firmware purge). |
| **Module 2: File/Folder Eraser** | ✅ **Fully Real & Validated** | Overwrites allocated clusters, zeros inode timestamps, renames directory entries. Journaling filesystems (ext4/NTFS journals) may retain metadata. |
| **Module 3: File Carver (ext4 + NTFS)** | ✅ **Fully Real & Validated** | Multi-format signature carving (JPEG, PNG, PDF, ZIP, GIF, GZIP) with Shannon entropy scoring; ext4 inode extent recovery; NTFS $MFT structure-based recovery (resident & single-run non-resident data). |
| **Module 4: Blockchain Audit** | ✅ **Fully Real & Validated** | SQLite append-only ledger with SHA-256 block hash chaining and unbroken continuity verification. |

---

## 2. NTFS Structure-Based Carving Scope & Boundaries

The NTFS structure carver (`linux/cli/trustwipe_cli/carver/ntfs_carver.py`) directly parses NTFS boot sectors and the Master File Table ($MFT) without mounting the filesystem:

1. **Supported NTFS Features:**
   - **Boot Sector Parsing:** Detects `NTFS    ` OEM identifier, cluster sizes, sector geometry, and $MFT starting cluster offset.
   - **Resident Attributes:** Full extraction of `$FILE_NAME` (UTF-16LE file naming) and resident `$DATA` attributes stored directly within the 1024-byte MFT record.
   - **Non-Resident Contiguous Runs:** Supports non-resident files mapped via single contiguous data run allocations.
   - **Unallocated Record Discovery:** Identifies MFT records whose `InUse` flag is cleared (representing deleted files whose MFT slot has not been overwritten).
2. **Documented NTFS Boundaries (Out of Scope / Future Work):**
   - **Multi-Fragment Non-Resident Runlists:** Files scattered across multiple disjoint cluster runs require full extent chain reassembly, which is bounded in v2.0.
   - **Transaction Log Replay ($LogFile):** NTFS metadata changes recorded in `$LogFile` are not replayed during raw carving.
   - **USN Journal ($UsnJrnl):** Update Sequence Number journal parsing is omitted.
   - **Alternate Data Streams (ADS):** Only default unnamed primary `$DATA` streams are extracted; named secondary data streams are bypassed.

---

## 3. Inherent Storage & Filesystem Limitations

1. **Flash Translation Layer (FTL) on Solid-State Media:**
   - Host-level file or logical sector writes cannot overwrite retired bad blocks or overprovisioned flash memory.
   - For complete purge on solid-state drives, controller-level `NVME_SANITIZE` or `ATA_SECURE_ERASE` must be used.
2. **Journaling Remnants:**
   - On ext4/ext3 or NTFS, metadata changes (file names, sizes, prior timestamps) may remain recorded in the filesystem journal until overwritten by subsequent operations.
3. **Fragmented File Reconstruction Limits:**
   - Signature carvers reconstruct contiguous files reliably. Non-contiguous fragmented files with scattered clusters require structure-based parsing or format-specific stream validation.
4. **Copy-on-Write (CoW) Filesystems (Btrfs, ZFS, APFS):**
   - File-level overwriting via POSIX file descriptors (`open("r+b")`) allocates new storage blocks on CoW filesystems rather than overwriting physical sectors in-place. The pre-wipe data clusters remain intact until reclaimed. TrustWipe detects Btrfs/ZFS mounts and includes an explicit warning in certificate notes. Complete sanitization on CoW storage requires volume or whole-device sanitization.
