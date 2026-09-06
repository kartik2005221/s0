# s0 — Technical Limitations & Forensic Boundaries

**Commitment:** Absolute engineering honesty. We document every technical boundary across sanitization and forensic recovery.

---

## 1. Module-by-Module Capabilities & Hardware Status

| Module | Development Status | Real Hardware Behavior & Requirements |
|---|---|---|
| Module | Development Status | Real Hardware Behavior & Requirements |
|---|---|---|
| **Module 1: Drive Eraser** | ✅ **Fully Real & Validated** | Full overwrite on disk images & block devices. ATA/NVMe firmware paths coded & fixture-tested (real ATA/NVMe controllers required for firmware purge). Bootable Live ISO (`linux/iso/`) for unmounted drive sanitization. |
| **Module 2: File/Folder Eraser** | ✅ **Fully Real & Cross-Platform** | Overwrites allocated clusters, zeros inode/file timestamps, cleanses attributes/ADS, renames directory entries. Natively implemented and verified across Linux (Btrfs/ZFS CoW warnings, extents), Windows (`windows/` with Win32 FlushFileBuffers, ADS scrubbing, ReFS CoW warnings), and macOS (`macos/` with `fcntl(F_FULLFSYNC)`, APFS CoW warnings, and xattr stripping). |
| **Module 3: File Carver (ext4, NTFS, FAT32, exFAT, & Fragmentation)** | ✅ **Fully Real & Validated** | Multi-format signature carving (JPEG, PNG, PDF, ZIP, GIF, GZIP, BMP, ELF, SQLite3, MP3) with Shannon entropy scoring; ext4 inode extent recovery; NTFS $MFT multi-run fragmented recovery; FAT32 directory entry recovery; exFAT directory entry set parsing (SD cards/USB); and multi-fragment/bifragment heuristic reassembly. |
| **Module 4: Cryptographic Hash Ledger** | ✅ **Fully Real & Validated** | SQLite append-only ledger with SHA-256 block hash chaining and Ed25519 digital signature verification. (Tamper-evident hash chain designed for single-authority forensic integrity rather than multi-node distributed consensus). |

---

## 2. NTFS Structure-Based Carving & Fragmented Reconstruction

The NTFS structure carver (`linux/cli/s0_cli/carver/ntfs_carver.py`) directly parses NTFS boot sectors and the Master File Table ($MFT) without mounting the filesystem:

1. **Supported NTFS Features:**
   - **Boot Sector Parsing:** Detects `NTFS    ` OEM identifier, cluster sizes, sector geometry, and $MFT starting cluster offset.
   - **Resident Attributes:** Full extraction of `$FILE_NAME` (UTF-16LE file naming) and resident `$DATA` attributes stored directly within the 1024-byte MFT record.
   - **Multi-Fragment Non-Resident Runlists:** Fully reassembles files scattered across multiple discontiguous cluster runs by traversing the entire runlist sequence, accumulating relative LCN deltas, and reconstructing disjoint cluster fragments.
   - **Sparse Run Handling:** Accommodates sparse cluster runs (`offset_bytes_count == 0`) with zero-fill padding.
   - **Unallocated Record Discovery:** Identifies MFT records whose `InUse` flag is cleared (representing deleted files whose MFT slot has not been overwritten).
2. **Documented NTFS Boundaries:**
   - **Transaction Log Replay ($LogFile):** NTFS metadata changes recorded in `$LogFile` are not replayed during raw carving.
   - **USN Journal ($UsnJrnl):** Update Sequence Number journal parsing is omitted.
   - **Alternate Data Streams (ADS):** Default unnamed primary `$DATA` streams are extracted; secondary named streams are bypassed during carver recovery.

---

## 3. FAT32 & exFAT Structure-Based Carving Scope

Targeted at removable media, USB flash drives, and high-capacity SD cards (SDXC/SDUC):

1. **FAT32 Carving (`fat_carver.py`):**
   - **BPB Boot Sector Parsing:** Detects BIOS Parameter Block, sector size, cluster geometry, reserved sectors, and root cluster index.
   - **Deleted Directory Entry Scanning:** Identifies 32-byte directory entries marked with the `0xE5` leading deleted marker.
   - **Metadata Extraction:** Reconstructs 8.3 filenames, file sizes, and starting cluster addresses.
   - **Contiguous Cluster Data Recovery:** Recovers raw data streams starting from the unallocated cluster location.
2. **exFAT Carving (`exfat_carver.py`):**
   - **VBR Boot Sector Parsing:** Detects `EXFAT   ` OEM magic, sector/cluster bit-shifts, Cluster Heap offset, and root directory cluster.
   - **Directory Entry Set Reconstruction:** Parses 32-byte directory entry sets: File Directory Entry (`0x05` deleted / `0x85` active), Stream Extension (`0x40` deleted / `0xC0` active), and multi-entry UTF-16LE File Names (`0x41` deleted / `0xC1` active).
   - **Cluster Heap Recovery:** Accurately extracts file data clusters from the Cluster Heap, following FAT chains or contiguous cluster allocations up to logical file length.

---

## 4. Operating System Scope & Cross-Platform Architecture

1. **Cross-Platform File & Folder Erasure (Module 2):**
   - **Linux (`linux/cli/s0_cli/file_eraser.py`):** POSIX in-place overwrite, `fsync()`, `filefrag -v` extent inspection, `/proc/mounts` Btrfs/ZFS CoW warnings, timestamp zeroing, directory scrambling.
   - **Windows (`windows/s0_eraser.py`, `.bat`, `.ps1`):** Native Win32 direct file IO with `FlushFileBuffers`, Alternate Data Stream (`:Zone.Identifier`) discovery & destruction, Read-Only/Hidden attribute stripping via `SetFileAttributesW`, ReFS CoW detection via `GetVolumeInformationW`.
   - **macOS (`macos/s0_eraser.py`, `.sh`):** Apple Darwin hardware flush via `fcntl(fd, F_FULLFSYNC, 0)`, Extended Attribute (`xattr -c`) cleansing, APFS CoW detection and Time Machine snapshot warnings.
2. **Bare-Metal Bootable Live ISO (`linux/iso/`):**
   - In forensic data sanitization, physical drives (particularly Windows OS system disks) cannot be safely, reliably, or verifiably purged from within the running Windows operating system due to OS file locks, virtual memory paging, Volume Shadow Copies (VSS), and kernel memory protections.
   - True whole-drive data sanitization mandates booting into an independent, unmounted live environment (standard industry practice per DBAN, ShredOS, and NIST SP 800-88). s0 packages a minimal Debian-based Live ISO (`linux/iso/`) specifically for this purpose.

---

## 5. Cryptographic Hash Chain vs. Distributed Blockchain

1. **Architecture Rationale:**
   - s0 implements an immutable, append-only hash-chained ledger where each block contains the SHA-256 hash of the preceding block (`prev_hash`), canonical RFC 8785 payload digest, and RFC 8032 Ed25519 signature.
   - In forensic and law-enforcement compliance architectures, there is a single accredited issuing authority.
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
   - File-level overwriting via POSIX file descriptors (`open("r+b")`) allocates new storage blocks on CoW filesystems rather than overwriting physical sectors in-place. The pre-wipe data clusters remain intact until reclaimed. s0 detects Btrfs/ZFS mounts and includes an explicit warning in certificate notes. Complete sanitization on CoW storage requires volume or whole-device sanitization.
