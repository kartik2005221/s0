# TrustWipe — Technical Limitations & Forensic Boundaries (NTRO / SIH26149)

**Target Authority:** National Technical Research Organisation (NTRO)  
**Commitment:** Absolute engineering honesty. We document every technical boundary across sanitization and forensic recovery.

---

## 1. Module-by-Module Capabilities & Hardware Status

| Module | Development Status | Real Hardware Behavior & Requirements |
|---|---|---|
| Module | Development Status | Real Hardware Behavior & Requirements |
|---|---|---|
| **Module 1: Drive Eraser** | ✅ **Fully Real & Validated** | Full overwrite on disk images & block devices. ATA/NVMe firmware paths coded & fixture-tested (real ATA/NVMe controllers required for firmware purge). Bootable Live ISO (`linux/iso/`) for unmounted drive sanitization. |
| **Module 2: File/Folder Eraser** | ✅ **Fully Real & Validated** | Overwrites allocated clusters, zeros inode timestamps, renames directory entries. Journaling filesystems (ext4/NTFS journals) may retain metadata. Linux-native; Windows shims on forward roadmap. |
| **Module 3: File Carver (ext4 + NTFS + FAT32)** | ✅ **Fully Real & Validated** | Multi-format signature carving (JPEG, PNG, PDF, ZIP, GIF, GZIP, BMP, ELF, SQLite3, MP3) with Shannon entropy scoring; ext4 inode extent recovery; NTFS $MFT structure recovery; FAT32 directory entry (0xE5) deleted cluster recovery for USB flash drives and SD cards. |
| **Module 4: Cryptographic Hash Ledger** | ✅ **Fully Real & Validated** | SQLite append-only ledger with SHA-256 block hash chaining and Ed25519 digital signature verification. (Tamper-evident hash chain designed for single-authority forensic integrity rather than multi-node distributed consensus). |

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

## 3. FAT32 Structure-Based Carving Scope & Boundaries

The FAT32 structure carver (`linux/cli/trustwipe_cli/carver/fat_carver.py`) targets removable USB drives, flash drives, and SD memory cards:

1. **Supported FAT32 Features:**
   - **BPB Boot Sector Parsing:** Detects BIOS Parameter Block, sector size, cluster geometry, reserved sectors, and root cluster index.
   - **Deleted Directory Entry Scanning:** Identifies 32-byte directory entries marked with the `0xE5` leading deleted marker.
   - **Metadata Extraction:** Reconstructs 8.3 filenames, file sizes, and starting cluster addresses.
   - **Contiguous Cluster Data Recovery:** Recovers raw data streams starting from the unallocated cluster location.
2. **Documented FAT32 Boundaries:**
   - **Fragmented File Chains:** Deleted FAT32 files lose their File Allocation Table cluster linkage. Contiguous allocation is assumed; highly fragmented deleted files require manual boundary reconstruction.

---

## 4. Operating System Scope & Live Boot Architecture

1. **Bare-Metal Bootable Live ISO (`linux/iso/`):**
   - **Defensible Architectural Choice:** In forensic data sanitization, physical drives (particularly Windows OS system disks) cannot be safely, reliably, or verifiably purged from within the running Windows operating system due to OS file locks, virtual memory paging, Volume Shadow Copies (VSS), and kernel memory protections.
   - True data sanitization mandates booting into an independent, unmounted live environment (standard industry practice per DBAN, ShredOS, and NIST SP 800-88).
   - TrustWipe packages a minimal Debian-based Live ISO (`linux/iso/`) specifically for this purpose.
2. **Host OS Status:**
   - File/folder erasure and carver modules are implemented and validated natively for Linux.
   - Windows desktop shims and mobile wrappers are positioned on the post-hackathon engineering roadmap.

---

## 5. Cryptographic Hash Chain vs. Distributed Blockchain

1. **Architecture Rationale:**
   - TrustWipe implements an immutable, append-only hash-chained ledger where each block contains the SHA-256 hash of the preceding block (`prev_hash`), canonical RFC 8785 payload digest, and RFC 8032 Ed25519 signature.
   - In a national forensic or law-enforcement compliance architecture (such as NTRO), there is a single accredited issuing authority.
   - Distributed consensus mechanisms (Proof of Work / Proof of Stake) require multi-node peer networks and introduce latency and overhead without adding security value to a local, air-gapped forensic workstation.
   - The hash chain delivers mathematical tamper-evidence: any modification to an existing block invalidates the entire subsequent chain.

---

## 6. Inherent Storage & Filesystem Limitations

1. **Flash Translation Layer (FTL) on Solid-State Media:**
   - Host-level file or logical sector writes cannot overwrite retired bad blocks or overprovisioned flash memory.
   - For complete purge on solid-state drives, controller-level `NVME_SANITIZE` or `ATA_SECURE_ERASE` must be used.
2. **Journaling Remnants:**
   - On ext4/ext3 or NTFS, metadata changes (file names, sizes, prior timestamps) may remain recorded in the filesystem journal until overwritten by subsequent operations.
3. **Fragmented File Reconstruction Limits:**
   - Signature carvers reconstruct contiguous files reliably. Non-contiguous fragmented files with scattered clusters require structure-based parsing or format-specific stream validation.
4. **Copy-on-Write (CoW) Filesystems (Btrfs, ZFS, APFS):**
   - File-level overwriting via POSIX file descriptors (`open("r+b")`) allocates new storage blocks on CoW filesystems rather than overwriting physical sectors in-place. The pre-wipe data clusters remain intact until reclaimed. TrustWipe detects Btrfs/ZFS mounts and includes an explicit warning in certificate notes. Complete sanitization on CoW storage requires volume or whole-device sanitization.
