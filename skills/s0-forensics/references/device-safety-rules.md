# Device Safety, Mount Guards & OS Path Architecture

This reference details how `s0` interacts with operating system device nodes, guards against accidental system destruction, and handles low-level hardware registers.

---

## 1. Operating System Device Paths

Target paths vary across host operating systems:

### Linux
- **NVMe SSDs**: `/dev/nvme0n1`, `/dev/nvme1n1`
- **SATA / USB Disks**: `/dev/sda`, `/dev/sdb`, `/dev/sdc`
- **Partitions**: `/dev/sda1`, `/dev/nvme0n1p1`
- **Loopback Devices**: `/dev/loop0`, `/dev/loop1`
- **Raw Disk Images**: `/path/to/evidence.raw`, `/evidence/disk.img` (no root required)

### Windows
- **Physical Drives**: `\\.\PhysicalDrive0`, `\\.\PhysicalDrive1`
- **Drive Letters**: `D:`, `E:`, `\\.\D:`
- **Forensic Raw Images**: `C:\Evidence\disk.raw`

### macOS
- **Raw Character Disks (Fast I/O)**: `/dev/rdisk2`, `/dev/rdisk3`
- **Standard Block Disks**: `/dev/disk2`, `/dev/disk3`
- **Internal System Disk (Protected)**: `/dev/disk0`, `/dev/disk1`

---

## 2. Safety Interlocks & Refusals

`s0` evaluates four safety rules before executing `wipe` or `plan`:

1. **Root Filesystem Protection**:
   `s0` inspects `/proc/mounts` (Linux) and system volumes (Windows/macOS). If a target contains the root mount (`/` or `C:\`), execution is immediately aborted with `SafetyError: Refusing to sanitize active operating system drive`.
2. **Active Mount Guard**:
   If any partition on the target device is mounted, `s0` halts. The operator must unmount the device cleanly (`umount /dev/sdb*`) before continuing.
3. **Safety Override (`--force`)**:
   Passing `--force` bypasses the mount guard. **Agents must NEVER supply `--force` automatically.** Only human operators working in dedicated air-gapped forensic environments should invoke `--force`.
4. **Interactive `WIPE` Guard**:
   By default, `s0 wipe` prompts the operator to explicitly type `WIPE`. Agents running in automated CI/CD pipelines should pass `--yes` only after verified programmatic selection.

---

## 3. Hardware State Invariants

### ATA Security Frozen State
Modern PC motherboards issue an ATA Security Freeze Lock command during BIOS/UEFI POST to prevent malicious bootkits from setting drive passwords. When frozen, the drive rejects `ATA_SECURE_ERASE`.
- **Detection**: `hdparm -I /dev/sda` shows `supported: enhanced erase` but `frozen`.
- **Remediation**:
  1. Suspend / sleep the computer for 5 seconds to power-cycle the SATA PHY bus (`systemctl suspend`).
  2. Or hot-unplug the SATA power cable and reconnect while the system is running.

### HPA / DCO Hidden Partitions
- **HPA (Host Protected Area)**: A reserved disk area configured via ATA `SET_MAX_ADDRESS`.
- **DCO (Device Configuration Overlay)**: Vendor area configured via `DEVICE_CONFIGURATION_SET`.
- **Sanitization Impact**: Software overwriting (`OVERWRITE_ZERO_1PASS`) only reaches user-addressable LBAs, missing HPA/DCO. Controller firmware commands (`NVME_SANITIZE`, `ATA_SECURE_ERASE_ENHANCED`) cover the entire physical medium including HPA/DCO.
