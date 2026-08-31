# TrustWipe — Technical Limitations & Environment Transparency

**Commitment:** Absolute engineering honesty. We document every platform constraint, VM limitation, and physical storage boundary clearly so auditors, evaluators, and engineers know exactly what is verified here versus what requires specific hardware or elevated privilege.

---

## 1. Matrix of Capabilities & Validation Status

| Capability / Feature | Status in Development Environment | Real Hardware Behavior & Requirements | Impact & Honesty Notice |
|---|---|---|---|
| **Sparse Image Sanitization (Demo Spine)** | ✅ **Fully Real & Validated** | Identical byte-level I/O to physical block devices post-open. | Exercised in `demo_e2e.sh` and unit tests without root privileges. |
| **Pure Crypto & Canonical JSON** | ✅ **Fully Real & Validated** | Byte-identical across Python and JavaScript. | Ed25519 signatures, tamper matrix, and golden vectors 100% verified. |
| **Verification Portal** | ✅ **Fully Real & Validated** | Pure client-side static HTML/JS (zero backend). | Runs in any modern browser offline via `file://`. |
| **ATA Security Erase (`hdparm`)** | ⚠️ **Coded & Fixture-Tested** | Requires real SATA controller + drive; subject to BIOS frozen state. | Command sequences follow ATA-8 specifications; firmware completion timing not observable in virtual machine. |
| **HPA / DCO Detection & Removal** | ⚠️ **Coded & Fixture-Tested** | Requires ATA drive with Host Protected Area or Device Configuration Overlay. | Output parsing validated against realistic fixtures; loop devices and VM disks do not expose HPA/DCO. |
| **NVMe Sanitize / Format (`nvme-cli`)** | ⚠️ **Coded & Scripted** | Requires physical NVMe controller with Sanitize/Format command set support. | Command construction and result parsing coded; requires `nvme-cli` and root privileges on bare metal. |
| **Kernel `BLKDISCARD` ioctl** | ⚠️ **Coded (ctypes ioctl)** | Requires SSD with TRIM support attached as a block device. | Operates on loop devices once `sudo` is granted (`scripts/make_loop_target.sh`). |
| **Bootable Live ISO** | ⚠️ **Scripted & Configured** | Requires `live-build`, `xorriso`, and `sudo` on Debian/Ubuntu to compile image. | Full Debian `live-build` configurations provided in `linux/iso/`; build instructions documented in `HANDOVER.md`. |
| **Windows Application (.NET 8)** | ⚠️ **Source-Level Architecture** | Requires Windows OS with .NET 8 runtime for compilation and execution. | Architecture, command wrappers (`diskpart clean all`, `cipher /w`, BitLocker SED key purge), and limitations documented. |
| **Android Application (Kotlin)** | ⚠️ **Source-Level Architecture** | Requires Android 7.0+ physical device with Device Owner provisioning. | Architecture utilizes `DevicePolicyManager.wipeData()`; certificate records `result: "reset_triggered"` because app cannot survive wipe. |

---

## 2. Inherent Physical Storage Limitations (True on Real Hardware)

These limitations stem from the physics and firmware architecture of modern storage devices, applicable to all wiping software:

### 2.1 Solid-State Drive (SSD) Overprovisioning & Flash Translation Layer (FTL)
- **Constraint:** SSD controllers maintain an internal address map (Flash Translation Layer). When a host writes to Logical Block Address (LBA) 1000, the controller writes to an arbitrary physical NAND block. Overwritten data is marked stale and reclaimed during background garbage collection.
- **Consequence:** Software overwrite passes (`dd`, `shred`) can never guarantee erasure of data lingering in overprovisioned areas, wear-leveling buffers, or retired bad blocks.
- **Classification:** Software overwrite on solid-state media is strictly **NIST Clear**. To achieve **NIST Purge**, operators must issue firmware-level commands (`NVME_SANITIZE`, `ATA_SECURE_ERASE`) or hardware cryptographic key destruction.

### 2.2 BLKDISCARD and Non-Deterministic TRIM (DRAT / RZAT)
- **Constraint:** The ATA/SCSI/NVMe specifications do not universally mandate that blocks discarded via TRIM/UNMAP immediately return zeros. Some drives return stale data until garbage collection runs; other drives support Deterministic Read After Trim (DRAT) or Read Zero After Trim (RZAT).
- **Consequence:** `BLKDISCARD` alone cannot claim **NIST Purge** unless the drive explicitly advertises DRAT/RZAT in its firmware identify block. TrustWipe requires documented deterministic read justification in certificate notes before allowing `BLKDISCARD` to claim Purge.

### 2.3 BIOS Frozen State on SATA Drives
- **Constraint:** Modern motherboard BIOS/UEFI firmware sends an ATA `SECURITY FREEZE LOCK` command to all SATA ports at boot time. This prevents malicious boot-sector rootkits from setting drive passwords, but also blocks data wiping utilities.
- **Workaround:** Suspending the computer to RAM (sleep) and immediately resuming resets the SATA controller and clears the freeze lock without triggering BIOS re-lock. TrustWipe detects frozen state and guides the operator accordingly.

---

## 3. Operating System & Platform Specific Constraints

### 3.1 Android Security Boundaries
- **No Direct Block Device Access:** On unrooted Android, apps run in sandboxed user-space and cannot access `/dev/block/` raw storage.
- **Flash Overwriting Inefficacy:** Attempting to overwrite user files in Android storage is ineffective due to wear leveling and journaling filesystems (F2FS / ext4).
- **The Correct Solution (FBE Destruction):** Triggering `DevicePolicyManager.wipeData()` destroys the File-Based Encryption (FBE) master keys in the hardware keystore, achieving an authentic cryptographic **Purge**.
- **Survivability:** An Android app cannot execute code after its own host OS is wiped. Consequently, TrustWipe Android certificates are generated immediately before triggering `wipeData()` with `status: "reset_triggered"`.

### 3.2 Windows Platform Realities
- **Volume Overwrite vs Disk Wipe:** `cipher /w` only wipes unallocated clusters on mounted NTFS volumes; it leaves operating system and active file structures intact.
- **`diskpart clean all`:** Sequentially writes zeros to every addressable sector, achieving **NIST Clear** across the physical disk.
- **Self-Encrypting Drives (SED):** On BitLocker/SED hardware, purging the TPM/SED encryption keys instantly renders all disk content unrecoverable (**NIST Purge**).
