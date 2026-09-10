# s0 bootable ISO (offline wipe station)

Boots a minimal Debian live system straight into the s0 GUI in kiosk
mode, for "wipe this laptop from USB before recycling" use with no OS on the
machine and no network needed.

## STATUS IN THIS REPO — read before trusting it

The development environment has **no sudo**, so `live-build`, `xorriso` and
`qemu-system-x86_64` could not be installed and this ISO has **never been
built or boot-tested here**. Everything below is complete build
configuration written against Debian live-build's documented interface.
### Build Quickstart by Distribution

**Debian / Ubuntu (Native):**
```bash
sudo apt install live-build xorriso debootstrap qemu-system-x86_64
./build.sh && ./qemu-test.sh
```

**Fedora / RHEL / CentOS (Podman containerized):**
```bash
sudo dnf install -y podman qemu-system-x86 qemu-img
../../scripts/build_iso.sh
```

**Universal (Docker Desktop / any Linux with Docker):**
```bash
../../scripts/build_iso.sh
```

Until verified on physical hardware, treat this component as unverified on bare metal.

> 📖 **Complete Step-by-Step Guide:** For a full, zero-to-one walkthrough covering prerequisites, Fedora Podman staging, Debian live-build, Windows Rufus flashing, QEMU smoke-testing, and BIOS/UEFI deployment, read [docs/LIVE_ISO_BUILD_GUIDE.md](../../docs/LIVE_ISO_BUILD_GUIDE.md).

## Layout

- `build.sh`           top-level build executable (calls `auto/build.sh`)
- `auto/build.sh`      wrapper invoking `lb config`/`lb build` reproducibly
- `config/package-lists/s0.list.chroot`  everything the station needs
- `config/hooks/live/9000-s0.hook.chroot`  installs s0 code,
  generates nothing secret, registers the kiosk autostart service
- `config/includes.chroot/etc/systemd/system/s0-gui.service`  the service:
  auto-login user `s0`, starts the local GUI, launches chromium kiosk
- `qemu-test.sh`       headless boot smoke test (VNC screenshot after N seconds)

## Why kiosk chromium and not GTK

A browser pointed at localhost needs zero additional UI toolkits beyond what
chromium pulls in, matches the Linux GUI exactly (same single-page app), and
is the least code to maintain on an offline image.

## Security posture of the image

- The signing private key is NEVER in the image. Certificates produced by the
  station are signed by whatever issuer key the operator provisions onto the
  boot media themselves (`/opt/s0/keys/issuer_private.pem`), which they
  create out-of-band per core/keys/README.md. Without provisioning, wipes run
  but certificate issuance fails loudly rather than silently self-signing.
- Wipes target only explicit operator-selected devices; the root filesystem is
  protected by the CLI's safety refusals (check_safety), same as everywhere.
