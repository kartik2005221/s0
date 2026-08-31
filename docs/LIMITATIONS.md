# TrustWipe — Technical Limitations & Forensic Boundaries (NTRO / SIH26149)

**Target Authority:** National Technical Research Organisation (NTRO)  
**Commitment:** Absolute engineering honesty. We document every technical boundary across sanitization and forensic recovery.

---

## 1. Module-by-Module Capabilities & Hardware Status

| Module | Development Status | Real Hardware Behavior & Requirements |
|---|---|---|
| **Module 1: Drive Eraser** | ✅ **Fully Real & Validated** | Full overwrite on disk images & block devices. ATA/NVMe firmware paths coded & fixture-tested (real ATA/NVMe controllers required for firmware purge). |
| **Module 2: File/Folder Eraser** | ✅ **Fully Real & Validated** | Overwrites allocated clusters, zeros inode timestamps, renames directory entries. Journaling filesystems (ext4/NTFS journals) may retain metadata. |
| **Module 3: File Carver** | ✅ **Fully Real & Validated** | Signature carving (JPEG, PNG, PDF, ZIP, GIF, GZIP) with Shannon entropy scoring; ext4 structure-based recovery. Severely fragmented files without headers cannot be reconstructed without heuristic guessing. |
| **Module 4: Blockchain Audit** | ✅ **Fully Real & Validated** | SQLite append-only ledger with SHA-256 block hash chaining and unbroken continuity verification. |

---

## 2. Inherent Storage & Filesystem Limitations

1. **Flash Translation Layer (FTL) on Solid-State Media:**
   - Host-level file or logical sector writes cannot overwrite retired bad blocks or overprovisioned flash memory.
   - For complete purge on solid-state drives, controller-level `NVME_SANITIZE` or `ATA_SECURE_ERASE` must be used.
2. **Journaling Remnants:**
   - On ext4/ext3 or NTFS, metadata changes (file names, sizes, prior timestamps) may remain recorded in the filesystem journal until overwritten by subsequent operations.
3. **Fragmented File Reconstruction Limits:**
   - Signature carvers reconstruct contiguous files reliably. Non-contiguous fragmented files with scattered clusters require structure-based parsing or format-specific stream validation.
