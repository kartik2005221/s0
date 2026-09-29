# Bare-Metal Live ISO — Build & Deployment Guide

> **Compliance Reference:** NIST SP 800-88 Rev. 1 §2.4 — Independent Sanitization Environments
> **Target Architecture:** x86_64 (amd64) Hybrid ISO (UEFI + Legacy BIOS)
> **Base Distribution:** Debian 12 (Bookworm) Minimal Live System
> **Interface:** Automated Chromium Kiosk UI → local root-privileged sanitization daemon (`127.0.0.1:8000`)

---

## Why You Need a Bootable USB

When you need to sanitize or forensically carve the system drive of a computer — whether a Windows workstation, a Linux server, or a Mac being decommissioned — you face a fundamental barrier: **the operating system is using that storage device right now**.

File locks, active paging/swap, background journal writes, and continuous SSD TRIM commands interfere with low-level disk operations. On live systems:
- Direct firmware sanitization (`NVME_SANITIZE`, `ATA_SECURE_ERASE`) is blocked by the host OS kernel.
- File carving yield degrades rapidly because background OS writes overwrite deleted clusters before they can be extracted.

The industry-standard solution is to boot from an independent USB drive into a dedicated live environment where internal drives are **unmounted, isolated, and fully accessible** for direct firmware-level sanitization (`s0 wipe`), raw bit-stream acquisition (`s0 image`), and deep evidence carving (`s0 carve`).

s0 provides a complete Debian-based Live ISO recipe that boots into an automatic Chromium kiosk displaying the full s0 forensic workstation — ready to wipe or carve.

{% hint style="success" %}
**Automated Cloud Builds on GitHub Releases**
Pre-compiled, ready-to-flash hybrid bootable ISO images are automatically built and published with every official release via GitHub Actions (`.github/workflows/build-iso.yml`). You can download the latest official ISO directly from [GitHub Releases](https://github.com/kartik2005221/s0/releases) without compiling it locally.
{% endhint %}

---

## Recommended Workflow: Automated `s0 live` Command Suite

The fastest and safest way to acquire and deploy the Live ISO is using the built-in `s0 live` command suite:

```bash
s0 live download

s0 live devices

sudo s0 live flash --target /dev/sdb
```

---

## Alternative: Manual Download from GitHub Releases

You can also manually download the versioned bootable hybrid ISO (`s0-live-v2.4.3-amd64.hybrid.iso`) and accompanying cryptographic hashes:

### 1. Download via GitHub CLI
```bash
gh release download v2.4.3 -R kartik2005221/s0 -p "s0-live-*.hybrid.iso*"
```

### 2. Manual Download & Verification

{% tabs %}
{% tab title="Linux/MacOS" %}
```bash
# Download ISO and SHA-256 checksum
curl -fSL -o s0-live-v2.4.3-amd64.hybrid.iso https://github.com/kartik2005221/s0/releases/download/v2.4.3/s0-live-v2.4.3-amd64.hybrid.iso
curl -fSL -o s0-live-v2.4.3-amd64.hybrid.iso.sha256 https://github.com/kartik2005221/s0/releases/download/v2.4.3/s0-live-v2.4.3-amd64.hybrid.iso.sha256

# Verify integrity
sha256sum -c s0-live-v2.4.3-amd64.hybrid.iso.sha256
```
{% endtab %}
{% tab title="Windows (PowerShell)" %}
```powershell
# Download ISO and SHA-256 checksum
Invoke-WebRequest -Uri "https://github.com/kartik2005221/s0/releases/download/v2.4.3/s0-live-v2.4.3-amd64.hybrid.iso" -OutFile "s0-live-v2.4.3-amd64.hybrid.iso"
Invoke-WebRequest -Uri "https://github.com/kartik2005221/s0/releases/download/v2.4.3/s0-live-v2.4.3-amd64.hybrid.iso.sha256" -OutFile "s0-live-v2.4.3-amd64.hybrid.iso.sha256"

# Verify integrity
(Get-FileHash s0-live-v2.4.3-amd64.hybrid.iso -Algorithm SHA256).Hash -eq (Get-Content s0-live-v2.4.3-amd64.hybrid.iso.sha256).Split(" ")[0].ToUpper()
```
{% endtab %}
{% tab title="Windows (CMD)" %}
```cmd
rem Download ISO and SHA-256 checksum
curl -fSL -o s0-live-v2.4.3-amd64.hybrid.iso https://github.com/kartik2005221/s0/releases/download/v2.4.3/s0-live-v2.4.3-amd64.hybrid.iso
curl -fSL -o s0-live-v2.4.3-amd64.hybrid.iso.sha256 https://github.com/kartik2005221/s0/releases/download/v2.4.3/s0-live-v2.4.3-amd64.hybrid.iso.sha256

rem Verify integrity
certutil -hashfile s0-live-v2.4.3-amd64.hybrid.iso SHA256
```
{% endtab %}
{% endtabs %}

### 3. Flash to USB Drive
```bash
sudo dd if=s0-live-v2.4.3-amd64.hybrid.iso of=/dev/sdX bs=4M status=progress oflag=sync
```

---

## Architecture & Privilege Model

The ISO uses a deliberate privilege separation model:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        s0 Bare-Metal Appliance                          │
├─────────────────────────────────────────────────────────────────────────┤
│ [User Space — Unprivileged: 's0' user (group 's0-kiosk')]              │
│   Chromium Kiosk (Wayland/X11) ──────────────┐                          │
│   Fullscreen, no address bar, no shell        │ HTTP (127.0.0.1:8000)   │
│                                               ▼                          │
│ [Daemon Space — Loopback Root: 'root']                                  │
│   s0-web.service (Uvicorn / FastAPI)                                    │
│   ├── s0_cli (Device discovery, partition unmounting)                   │
│   ├── s0_core (Canonical JSON v1, Ed25519 signing, PDF generation)      │
│   └── Kernel Block & Firmware Access:                                   │
│       ├── ioctl(BLKDISCARD) ────────────────► Raw SSD Discard           │
│       ├── hdparm --security-erase ──────────► ATA Controller Purge      │
│       └── nvme sanitize / format ───────────► NVMe Controller Purge     │
└─────────────────────────────────────────────────────────────────────────┘
```

**Key design decisions:**

- **Loopback isolation:** The REST backend binds exclusively to `127.0.0.1:8000`. No external network exposure.
- **Privilege separation:** The Chromium kiosk runs as the unprivileged `s0` user. The wipe daemon runs as `root` to issue hardware ioctls and open raw block devices (`/dev/sd*`, `/dev/nvme*`).
- **Fully offline:** All UI assets, fonts (Fira Sans / Fira Code), and cryptographic libraries are pre-packaged. No internet connection is required or used at runtime.
- **Kiosk Trust Boundary:** To enable the unprivileged browser kiosk to interact with the authenticated root REST daemon, the session token is placed in `/run/s0/web_auth_token` with file permissions `0640` and group ownership assigned to `s0-kiosk`. Membership in `s0-kiosk` is intentionally equivalent to wipe authority on the appliance.

---

## Host System Prerequisites

To build the ISO, you need a machine with **root/sudo access** and an internet connection (to download Debian packages during staging).

### Supported Build Hosts

| Host OS | Status |
|---|---|
| Debian 12 (Bookworm) | Recommended (Native) |
| Debian 11 (Bullseye) | Supported |
| Ubuntu 22.04 / 24.04 LTS | Supported |
| Fedora 38 / 39 / 40+ | Supported via Podman or Docker (`scripts/build_iso.sh`) |
| RHEL / CentOS Stream 9+ | Supported via Podman (`scripts/build_iso.sh`) |
| Windows 10 & 11 | Supported via Docker Desktop or WSL2 (`scripts/build_iso.ps1`) |
| macOS | Supported via Docker (`linux/iso/Dockerfile` or `scripts/build_iso.sh`) |
| Debian-based VM | Supported |

### Install Required Toolchain

{% tabs %}
{% tab title="Debian / Ubuntu (Native)" %}

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
{% endtab %}
{% tab title="Fedora / RHEL (Podman & QEMU)" %}

Fedora uses RPM packages and does not have Debian's `live-build` natively in `dnf`. Use Fedora's native **Podman** container engine to build the Debian Live ISO, and install QEMU for virtualization testing:

```bash
sudo dnf install -y podman qemu-system-x86 qemu-img
```
{% endtab %}
{% tab title="Docker (Universal Linux/MacOS)" %}

```bash
docker --version
```
{% endtab %}
{% endtabs %}

{% hint style="info" %}
**Disk Space Requirement**
The build process downloads approximately 1 GB of Debian packages and requires **6–8 GB** of free disk space for the temporary chroot environment.
{% endhint %}

---

## Directory Structure

```
linux/iso/
├── build.sh                                    # Top-level executable build wrapper
├── auto/
│   └── build.sh                                # live-build invocation script (lb config)
├── qemu-test.sh                                # Automated headless smoke test
├── config/
│   ├── package-lists/
│   │   └── s0.list.chroot                      # Required packages (Python, Chromium, hdparm, etc.)
│   ├── hooks/
│   │   └── live/
│   │       └── 9000-s0.hook.chroot             # Code snapshot install & systemd service hooks
│   └── includes.chroot/
│       └── etc/systemd/system/
│           ├── s0-web.service                  # Loopback backend wipe daemon (runs as root)
│           └── s0-kiosk.service                # Auto-starting Chromium kiosk (runs as s0 user)
└── README.md
```

---

## Step-by-Step Build

### Step 1: Clone the Repository

```bash
git clone https://github.com/kartik2005221/s0.git
cd s0/linux/iso
```

### Step 2: Run the Build

```bash
sudo ./build.sh
```

### What Happens During the Build

The build script runs through five stages:

1. **Repository Snapshot** — Copies the clean `core/` and `linux/` codebase into a temporary staging path
2. **Configuration (`lb config`)** — Configures Debian Bookworm `amd64`, hybrid ISO mode, and live bootloader parameters
3. **Debootstrap (`lb bootstrap`)** — Fetches the minimal Debian base system from the internet
4. **Chroot Staging (`lb chroot`)**:
    - Installs system dependencies from `config/package-lists/s0.list.chroot` (Python 3, Chromium, hdparm, nvme-cli, util-linux, parted)
    - Executes `config/hooks/live/9000-s0.hook.chroot` — copies s0 code to `/opt/s0`, sets up `/usr/local/bin/s0` wrapper, configures `s0` user
    - Registers `s0-web.service` and `s0-kiosk.service` in systemd
5. **Binary Packaging (`lb binary`)** — Compresses root filesystem into SquashFS, packages into bootable hybrid ISO

### Output Location

```text
linux/iso/live-image-amd64.hybrid.iso
```

This is a hybrid ISO that boots on both UEFI and Legacy BIOS systems.

---

## Building from Fedora & RHEL (Podman & Containerization)

Fedora and RHEL use the RPM package format and do not carry Debian's `live-build` natively in `dnf`. However, you do **not** need a separate Debian workstation. S0 provides first-class support for Fedora using **Podman** (Fedora's default container engine) with automated SELinux volume relabeling.

### Option 1: Automated Script (`scripts/build_iso.sh`)

Run the universal build orchestrator:

```bash
./scripts/build_iso.sh
```

### Option 2: Direct Podman Commands

If you prefer executing the container steps manually:

```bash
podman build -t s0-live-builder -f linux/iso/Dockerfile linux/iso

podman run --rm --privileged -v "$PWD":/workspace:z s0-live-builder
```

The resulting `s0-live-amd64.hybrid.iso` is generated directly into your current directory.

### Testing with QEMU on Fedora

```bash
sudo dnf install -y qemu-system-x86 qemu-img

qemu-img create -f raw test_drive.img 1G

qemu-system-x86_64 \
    -enable-kvm \
    -m 2048 \
    -smp 2 \
    -cdrom s0-live-amd64.hybrid.iso \
    -drive file=test_drive.img,format=raw,if=virtio \
    -vga virtio \
    -usb -device usb-tablet
```

---

## Building from Windows (Docker & WSL2 Orchestration)

Because Debian Live systems require Linux kernel features (`debootstrap`, `losetup` loopback devices, and root `chroot`), native Win32 cannot build the ISO directly without a Linux runtime.

S0 provides automated solutions for Windows developers and field operators:

### Option 1: Automated PowerShell Builder (`scripts/build_iso.ps1`)

The script automatically detects if **Docker Desktop** or **WSL2** is running and executes the build inside an isolated Debian container:

```powershell
.\scripts\build_iso.ps1
```

1. **If Docker Desktop is running:** Builds the container using `linux/iso/Dockerfile` in privileged mode and outputs `s0-live-amd64.hybrid.iso` to your project root.
2. **If WSL2 is installed:** Translates Windows paths and invokes Debian live-build inside your WSL environment.

### Option 2: Docker Desktop (Direct Command)

If you prefer running Docker directly without PowerShell scripts:

```cmd
docker build -t s0-live-builder -f linux/iso/Dockerfile linux/iso
docker run --rm --privileged -v "%cd%":/workspace s0-live-builder
```

The resulting `s0-live-amd64.hybrid.iso` will be generated directly into your current directory.

### Option 3: Download Pre-Built Verified ISO (1-Line Command)

If you do not have Docker or local build tools installed, you can download the latest official release directly with automatic SHA-256 integrity verification:

{% tabs %}
{% tab title="Windows (PowerShell)" %}
```powershell
irm https://s0-install.pages.dev/download-iso-ps1 | iex
```
{% endtab %}
{% tab title="Linux/MacOS (Bash)" %}
```bash
curl -fsSL https://s0-install.pages.dev/download-iso-sh | bash
```
{% endtab %}
{% endtabs %}

### Flashing from Windows (Rufus)

1. Download **Rufus** (portable executable from [rufus.ie](https://rufus.ie/)).
2. Connect a USB flash drive (minimum 4 GB).
3. Select your device and choose `s0-live-amd64.hybrid.iso`.
4. When prompted, select **Write in DD Image mode** (this preserves the hybrid ISO boot sector and UEFI partition map).
5. Click **Start**.

---

## Provisioning Signing Keys

s0 ISO images ship with **no private signing keys** by default. This is intentional — pre-baking unknown keys would create certificates from an untrusted authority.

An accredited lab must provision their own Ed25519 private key.

### Option A: Out-of-Band Key Provisioning (Recommended)

1. Generate an Ed25519 key pair on a secure, air-gapped machine:
   ```bash
   s0 keygen --out-dir /secure/keys --name lab_issuer
   ```

2. Place `lab_issuer_private.pem` onto an encrypted USB drive or persistent partition.

3. When booted into the live station, the wipe daemon looks for the private key at:
   ```text
   /opt/s0/keys/issuer_private.pem
   ```
   If no key is present, wiping still works — but the certificate's status will report `NO_PRIVATE_KEY` rather than forging a mock signature.

4. Register the corresponding `lab_issuer_public.pem` in the verification portal's `keys.json` to enable green "Accredited Authority" verification.

### Option B: Build-Time Key Baking (Lab-Internal Media Only)

If producing USB sticks exclusively for your own accredited facility:

```bash
mkdir -p config/includes.chroot/opt/s0/keys/
cp /secure/keys/lab_issuer_private.pem config/includes.chroot/opt/s0/keys/issuer_private.pem
chmod 600 config/includes.chroot/opt/s0/keys/issuer_private.pem
sudo ./build.sh
```

{% hint style="danger" %}
**Security Warning**
Build-time key baking embeds the private key in the ISO. This is only appropriate for physically controlled, single-organization deployments. Never distribute such an ISO publicly.
{% endhint %}

---

## Testing the ISO (QEMU)

Before burning to physical USB, always verify that the ISO boots cleanly in a virtual machine.

### Automated Headless Smoke Test

```bash
./qemu-test.sh live-image-amd64.hybrid.iso
```

This boots the ISO headlessly via QEMU, captures the serial console log, and asserts that systemd reaches userspace with zero kernel panics.

### Interactive GUI Test with a Virtual Target Drive

```bash
qemu-img create -f raw test_drive.img 1G

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

1. The Debian boot menu appears — select **Live System (amd64)** or wait 5 seconds
2. The OS boots silently into userspace
3. Chromium opens automatically in fullscreen, displaying the **s0 Forensic & Sanitization Workstation** dashboard
4. The test drive (`/dev/vda`) appears in the device selector — ready for testing

---

## Flashing to USB

Once verified, write the ISO to a physical USB drive (minimum **4 GB** capacity).

{% tabs %}
{% tab title="Linux" %}

Identify your USB device with `lsblk` first — **do NOT select your system drive**.

```bash
sudo umount /dev/sdb* 2>/dev/null || true

sudo dd if=s0-live-amd64.hybrid.iso of=/dev/sdb bs=4M status=progress oflag=sync
```
{% endtab %}
{% tab title="Windows" %}

Use **Rufus** (https://rufus.ie/) or **Ventoy** (https://www.ventoy.net/):

1. Select your USB flash drive
2. Select `live-image-amd64.hybrid.iso`
3. When prompted by Rufus: select **Write in DD Image mode** — this is critical to preserve the hybrid partition table and dual UEFI/BIOS bootloaders. The default ISO mode will NOT work correctly.
{% endtab %}
{% tab title="macOS" %}

Identify the disk number with `diskutil list` (e.g. `/dev/disk2`):

```bash
diskutil unmountDisk /dev/disk2
sudo dd if=live-image-amd64.hybrid.iso of=/dev/rdisk2 bs=4m status=progress
diskutil eject /dev/disk2
```

{% hint style="success" %}
Use `/dev/rdisk2` (raw device, not `/dev/disk2`) for significantly faster write speeds on macOS.
{% endhint %}
{% endtab %}
{% endtabs %}

---

## Booting on Target Hardware

### BIOS Boot Key Reference

| Manufacturer | Boot Key |
|---|---|
| Dell | `F12` |
| HP | `F9` or `Esc` |
| Lenovo / ThinkPad | `F12` or `Enter` |
| ASUS / Acer | `F8` or `F12` |
| Apple Mac (Intel) | Hold `Option` / `Alt` at startup |
| Gigabyte | `F12` |
| MSI | `F11` |

### Wipe Procedure

1. Insert the prepared USB drive into the machine to be decommissioned
2. Power on and press the boot key above
3. Select **UEFI: USB Flash Drive** (or Legacy USB if UEFI is unavailable)
4. Wait for the kiosk to load (30–60 seconds on first boot)
5. In the dashboard:
    - Select the target drive (e.g. `NVMe SSD 512 GB`)
    - Choose sanitization profile:
        - **Clear (NIST SP 800-88):** 1-pass zero or pseudo-random overwrite
        - **Purge (NIST SP 800-88):** Firmware cryptographic erase (`NVME_FORMAT_CRYPTO_ERASE`) or block sanitize (`ATA_SECURE_ERASE`)
    - Enter operator ID and organization name
    - Type `WIPE` to confirm
6. Monitor real-time progress (throughput + temperature)
7. Download the Ed25519-signed certificate + PDF when complete
8. Scan the QR code to verify offline

---

## Troubleshooting

### Clean Build State After Failure

If a previous build failed due to network interruption or missing dependencies:

```bash
cd linux/iso
sudo lb clean --purge
sudo ./build.sh
```

### Slow Package Downloads / Mirror Timeout

Specify a regional Debian mirror in `auto/build.sh`:

```bash
lb config noauto \
    --mirror-bootstrap "http://deb.debian.org/debian" \
    --mirror-binary "http://deb.debian.org/debian" \
    ...
```

Replace with a geographically closer mirror for faster builds.

### Missing Hardware Firmware

If the target machine has specialized network or disk controller chipsets not covered by Debian's `firmware-linux-free` package:

1. Add to `config/package-lists/s0.list.chroot`:
   ```
   firmware-linux-free
   firmware-misc-nonfree
   ```

2. Ensure `--archive-areas "main contrib non-free non-free-firmware"` is set in `auto/build.sh`

### UEFI Secure Boot

The current ISO recipe does **not** support UEFI Secure Boot. If the target machine has Secure Boot enabled:

1. Temporarily disable Secure Boot in BIOS/UEFI settings
2. Boot the ISO
3. After wiping, you may re-enable Secure Boot before installing the new OS
