# s0 Bare-Metal Bootable Live ISO — Build & Deployment Guide

> **Compliance Reference:** NIST SP 800-88 Rev. 1 §2.4 (Independent Sanitization Environments)  
> **Target Architecture:** x86_64 (amd64) Hybrid ISO (UEFI + Legacy BIOS)  
> **Base Distribution:** Debian 12 (Bookworm) Minimal Live System  
> **Interface:** Automated Chromium Kiosk UI pointed at local root-privileged sanitization daemon (`127.0.0.1:8080`)

---

## 1. Why a Bootable Live ISO is Required

Under NIST SP 800-88 Rev. 1 and DoD 5220.22-M, **in-place software sanitization of an active operating system's boot drive is forensically impossible** from within that running operating system:
1. **Kernel & Memory Protections:** The operating system locks critical disk blocks containing virtual memory pagefiles (`pagefile.sys`, swap partitions), kernel hibernation files, and system registries.
2. **Volume Shadow Copies & CoW:** Filesystem-level overwrite tools cannot touch unallocated sectors, Volume Shadow Copies (VSS), or retired flash blocks managed by the OS driver stack.
3. **Firmware Command Access:** Modern purge methods—such as `ATA SECURE ERASE`, `NVMe SANITIZE`, and `NVMe FORMAT (Crypto Erase)`—require direct, exclusive hardware ioctl access that host operating systems (especially Windows and macOS) refuse to grant to user-space software on active system disks.

The **s0 Live ISO** solves this by booting the computer from a dedicated, self-contained USB flash drive into an independent Linux environment. The internal drives remain completely unmounted, allowing direct block-level and firmware-level cryptographic sanitization.

---

## 2. Architecture & Privilege Posture

The ISO image is constructed using Debian's native `live-build` framework:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        s0 Bare-Metal Appliance                          │
├─────────────────────────────────────────────────────────────────────────┤
│ [User Space - Unprivileged: 's0']                                      │
│   Chromium Kiosk (Wayland/X11) ───────────┐                             │
│   (Fullscreen, no address bar, no shell)   │ HTTP (127.0.0.1:8080)       │
│                                           ▼                             │
│ [Daemon Space - Loopback Root: 'root']                                  │
│   s0-gui.service (Uvicorn / FastAPI)                                    │
│   ├── s0_cli (Device discovery, partition unmounting)                  │
│   ├── s0_core (Canonical JSON v1, Ed25519 signing, PDF generation)     │
│   └── Kernel Block & Firmware Access:                                   │
│       ├── ioctl(BLKDISCARD) ────────────────► Raw SSD Discard          │
│       ├── hdparm --security-erase ──────────► ATA Controller Purge     │
│       └── nvme sanitize / format ───────────► NVMe Controller Purge    │
└─────────────────────────────────────────────────────────────────────────┘
```

- **Loopback Isolation:** The REST backend binds exclusively to `127.0.0.1:8080`. It never listens on external network interfaces.
- **Privilege Separation:** The browser kiosk runs under the unprivileged `s0` user. The wipe daemon runs as `root` so it can issue hardware ioctls and open raw block devices (`/dev/sd*`, `/dev/nvme*`).
- **Air-Gapped & Offline:** All UI assets, fonts (Fira Sans / Fira Code), and cryptographic libraries are pre-packaged. No internet connection is needed or used at runtime.

---

## 3. Host System Prerequisites

To build the ISO, you need a machine with root/sudo access and an active internet connection (to download Debian packages during staging).

### Supported Build Hosts
- Debian 12 (Bookworm) / Debian 11 (Bullseye)
- Ubuntu 22.04 LTS / 24.04 LTS
- Kali Linux / Linux Mint
- Any Debian-based VM (e.g. VMware, VirtualBox, Proxmox, QEMU/KVM)

### Required Toolchain Packages
Install the required build utilities:

```bash
sudo apt update
sudo apt install -y \
    live-build \
    debootstrap \
    xorriso \
    isolinux \
    syslinux-efi \
    grub-pc-bin \
    grub-efi-amd64-bin \
    mtools \
    dosfstools \
    qemu-system-x86_64
```

> **Note on Storage Space:** The build process downloads ~1 GB of Debian `.deb` packages and requires approximately **6 GB to 8 GB** of free space during temporary chroot creation.

---

## 4. Step-by-Step Build Instructions

### Step 1: Clone the Repository
```bash
git clone https://github.com/kartik2005221/s0.git
cd s0
```

### Step 2: Navigate to the ISO Directory
```bash
cd linux/iso
```

The directory structure is organized as follows:
```
linux/iso/
├── build.sh                                    # Top-level executable build wrapper
├── auto/
│   └── build.sh                                # live-build invocation script
├── qemu-test.sh                                # Automated headless smoke test
├── config/
│   ├── package-lists/
│   │   └── s0.list.chroot                      # Required packages (Python, Chromium, hdparm, etc.)
│   ├── hooks/
│   │   └── live/
│   │       └── 9000-s0.hook.chroot             # Code snapshot installation & service hooks
│   └── includes.chroot/
│       └── etc/systemd/system/
│           ├── s0-gui.service                  # Loopback backend wipe daemon
│           └── s0-kiosk.service                # Auto-starting Chromium kiosk
└── README.md
```

### Step 3: Run the Build
Run the build script with root privileges:

```bash
sudo ./build.sh
```

### What Happens During the Build:
1. **Repository Snapshot:** Copies the clean `core/` and `linux/` codebase into a temporary build staging path.
2. **Configuration (`lb config`):** Configures Debian Bookworm `amd64`, hybrid ISO mode, and live bootloader parameters.
3. **Debootstrap (`lb bootstrap`):** Fetches the minimal Debian base system.
4. **Chroot Staging (`lb chroot`):**
   - Installs system dependencies from `config/package-lists/s0.list.chroot` (e.g. `python3`, `chromium`, `hdparm`, `nvme-cli`, `util-linux`, `parted`).
   - Executes `config/hooks/live/9000-s0.hook.chroot` to copy the `s0` code into `/opt/s0`, sets up the `s0` CLI wrapper on `/usr/local/bin/s0`, and configures the `s0` user.
   - Registers `s0-gui.service` and `s0-kiosk.service` in systemd.
5. **Binary Packaging (`lb binary`):** Compresses the root filesystem into a SquashFS image and packages it into a bootable hybrid ISO (`live-image-amd64.hybrid.iso`).

The completed image will be saved at:
```
linux/iso/live-image-amd64.hybrid.iso
```

---

## 5. Provisioning Forensic Signing Keys

To prevent unauthorized parties from forging certificates, **s0 images ship with no private signing keys by default**.

An accredited lab or enterprise auditor must provision their accredited Ed25519 private key.

### Option A: Out-of-Band Key Provisioning (Recommended)
1. Generate an Ed25519 key pair on a secure, air-gapped machine:
   ```bash
   python3 -m s0_core.cli keygen --out-dir /secure/keys
   ```
2. Place the generated `issuer_private.pem` onto a secondary encrypted USB drive or persistent partition.
3. Once booted into the live station, the wipe daemon looks for the private key at:
   ```
   /opt/s0/keys/issuer_private.pem
   ```
   If no key is provisioned, wipes can still be performed, but cryptographic certificate issuance will clearly report `NO_PRIVATE_KEY` rather than forging a mock signature.

### Option B: Build-Time Key Baking (For Lab-Internal Media)
If you are producing physical USB sticks exclusively for your own accredited facility:
1. Copy your lab's `issuer_private.pem` into:
   ```bash
   mkdir -p config/includes.chroot/opt/s0/keys/
   cp /secure/keys/issuer_private.pem config/includes.chroot/opt/s0/keys/
   chmod 600 config/includes.chroot/opt/s0/keys/issuer_private.pem
   ```
2. Re-run `sudo ./build.sh`. The ISO will now contain your lab's key locked with read-only root permissions.

---

## 6. Testing the ISO (QEMU Virtual Machine)

Before burning to physical USB, always verify that the ISO boots cleanly.

### Automated Headless Smoke Test
Run the included smoke test script:
```bash
./qemu-test.sh live-image-amd64.hybrid.iso
```
This boots the ISO in headless mode via QEMU, captures the serial console log, and asserts that systemd reaches userspace with zero kernel panics.

### Interactive GUI Test with a Virtual Target Drive
To test the full user experience, create a dummy 1 GB virtual drive and boot the ISO interactively:

```bash
# 1. Create a virtual target disk to test wiping
qemu-img create -f raw test_drive.img 1G

# 2. Boot the ISO with QEMU (KVM hardware acceleration enabled)
qemu-system-x86_64 \
    -enable-kvm \
    -m 2048 \
    -smp 2 \
    -cdrom live-image-amd64.hybrid.iso \
    -drive file=test_drive.img,format=raw,if=virtio \
    -vga virtio \
    -usb \
    -device usb-tablet
```

When the VM starts:
1. The Debian boot menu appears. Select `Live System (amd64)` or wait 5 seconds.
2. The operating system boots silently into userspace.
3. The Chromium kiosk opens automatically in fullscreen, displaying the **s0 Forensic & Sanitization Workstation** dashboard.
4. The test drive (`test_drive.img` / `/dev/vda`) will appear in the target drive selector, ready for testing.

---

## 7. Flashing the ISO to a USB Drive

Once verified, write the ISO to a physical USB thumb drive (minimum 4 GB capacity).

### On Linux
Identify your USB device using `lsblk` (e.g. `/dev/sdb` — **do NOT select your system drive**):
```bash
# Ensure drive is unmounted
sudo umount /dev/sdb* 2>/dev/null || true

# Write raw hybrid ISO
sudo dd if=live-image-amd64.hybrid.iso of=/dev/sdb bs=4M status=progress oflag=sync
```

### On Windows
1. Download **Rufus** (https://rufus.ie/) or **Ventoy** (https://www.ventoy.net/).
2. Select your USB flash drive.
3. Select `live-image-amd64.hybrid.iso`.
4. When prompted by Rufus, select **Write in DD Image mode** to preserve the hybrid partition table and dual UEFI/BIOS bootloaders.

### On macOS
Identify the disk number with `diskutil list` (e.g. `/dev/disk2`):
```bash
diskutil unmountDisk /dev/disk2
sudo dd if=live-image-amd64.hybrid.iso of=/dev/rdisk2 bs=4m status=progress
diskutil eject /dev/disk2
```

---

## 8. Booting on Target Hardware & Performing a Wipe

1. **Insert USB:** Plug the prepared USB drive into the laptop or desktop to be decommissioned.
2. **Open Boot Menu:** Power on the machine and press the boot key:
   - **Dell:** `F12`
   - **HP:** `F9` or `Esc`
   - **Lenovo / ThinkPad:** `F12` or `Enter`
   - **Apple Mac (Intel):** Hold `Option / Alt` at startup
   - **ASUS / Acer:** `F8` or `F12`
3. **Select USB:** Choose `UEFI: USB Flash Drive` or `Legacy USB`.
4. **Wipe Station Operations:**
   - The station automatically loads the s0 dashboard.
   - Select the target drive (e.g. `NVMe SSD 512 GB` or `Hitachi 1 TB HDD`).
   - Choose the sanitization profile:
     - **Clear (NIST SP 800-88):** 1-pass zero or pseudo-random overwrite.
     - **Purge (NIST SP 800-88):** Firmware cryptographic erase (`NVME_FORMAT_CRYPTO_ERASE`) or block sanitize (`ATA_SECURE_ERASE`).
   - Confirm by typing the safety phrase (`CONFIRM-WIPE`).
   - Monitor real-time progress, read/write throughput, and drive temperature.
   - Upon completion, the tool issues an **Ed25519-signed sanitization certificate** and generates a tamper-evident PDF with QR code verification.
   - Save the certificate to an external USB or scan the on-screen QR code using any smartphone or the offline [Verification Portal](VERIFICATION_AND_DEPLOYMENT.md#3-how-offline-verification-is-performed).

---

## 9. Troubleshooting & Build Maintenance

### Cleaning Build State
If a previous build failed due to network interruption or missing dependencies, clean the staging tree thoroughly before rebuilding:
```bash
cd linux/iso
sudo lb clean --purge
```

### Debian Mirror Selection
If you experience slow package downloads or network timeout errors during `debootstrap`, specify a regional mirror in `auto/build.sh`:
```bash
lb config noauto \
    --mirror-bootstrap "http://deb.debian.org/debian" \
    --mirror-binary "http://deb.debian.org/debian" \
    ...
```

### Missing Non-Free Hardware Firmware
If the target computer has specialized network or disk controller chipsets, include Debian's non-free firmware package in `config/package-lists/s0.list.chroot`:
```
firmware-linux-free
firmware-misc-nonfree
```
And ensure `--archive-areas "main contrib non-free non-free-firmware"` is set in `auto/build.sh`.
