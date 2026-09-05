# TrustWipe — macOS Secure File & Folder Eraser (Module 2)

**Problem Statement ID:** 26149 (NTRO — Digital Forensics & Data Sanitization)  
**Supported Operating Systems:** macOS Catalina (10.15) through macOS Sequoia (15.x+)  
**Supported Filesystems:** APFS, HFS+, FAT32, exFAT

---

## 1. Forensic Engineering on macOS

Sanitizing files reliably on Apple macOS involves hardware and filesystem considerations:
1. **Physical Drive Cache Flushing (`F_FULLFSYNC`):**
   - On Darwin / macOS, standard POSIX `fsync()` only flushes dirty data from the kernel buffer to the drive's volatile on-board cache. It does *not* force the drive controller to commit bytes to non-volatile NAND flash.
   - TrustWipe issues `fcntl(fd, F_FULLFSYNC, 0)` (opcode 51), which executes an ATA/NVMe flush cache command to ensure overwritten data is permanently committed to physical media.
2. **Extended Attributes (xattr) & Quarantine Metadata:**
   - macOS stores provenance, security, and metadata in Extended Attributes (e.g. `com.apple.quarantine`, `com.apple.metadata:*`).
   - Standard file deletion can leave extended attribute records in directory and filesystem metadata. TrustWipe invokes `xattr -c` and strips all metadata prior to unlinking.
3. **Copy-on-Write (CoW) on Apple File System (APFS):**
   - APFS is a modern Copy-on-Write filesystem. In-place overwriting allocates new extent blocks while old blocks remain intact until reclaimed or pruned from local Time Machine snapshots.
   - TrustWipe detects APFS mounts via `mount` / `statvfs` and flags an explicit CoW warning in the certificate.
4. **Metadata & Directory Obfuscation:**
   - Inode timestamps are reset to Unix epoch (0), and filenames are scrambled to random 32-character hexadecimal tokens before unlinking.

---

## 2. Usage

### Terminal:
```bash
./macos/trustwipe-eraser.sh ~/Documents/confidential.pdf 1 zero
```

### Python Direct:
```bash
python3 macos/trustwipe_eraser.py --targets ~/Documents/FolderToWipe --passes 1 --pattern zero --out-dir ./sanitization_reports
```
