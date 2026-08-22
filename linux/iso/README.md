# TrustWipe bootable ISO (offline wipe station)

Boots a minimal Debian live system straight into the TrustWipe GUI in kiosk
mode, for "wipe this laptop from USB before recycling" use with no OS on the
machine and no network needed.

## STATUS IN THIS REPO — read before trusting it

The development environment has **no sudo**, so `live-build`, `xorriso` and
`qemu-system-x86_64` could not be installed and this ISO has **never been
built or boot-tested here**. Everything below is complete build
configuration written against Debian live-build's documented interface.
Until someone runs:

    sudo apt install live-build xorriso qemu-system-x86_64
    ./build.sh && ./qemu-test.sh

and confirms a clean QEMU boot, treat this component as UNVERIFIED. It is
listed that way in docs/LIMITATIONS.md and scripts/build_all.sh skips it
with an explanatory log line rather than pretending.

## Layout

- `auto/build.sh`      wrapper invoking `lb config`/`lb build` reproducibly
- `config/package-lists/trustwipe.list.chroot`  everything the station needs
- `config/hooks/live/9000-trustwipe.hook.chroot`  installs TrustWipe code,
  generates nothing secret, registers the kiosk autostart service
- `config/includes.chroot/etc/systemd/system/trustwipe-gui.service`  the service:
  auto-login user `trustwipe`, starts the local GUI, launches chromium kiosk
- `qemu-test.sh`       headless boot smoke test (VNC screenshot after N seconds)

## Why kiosk chromium and not GTK

A browser pointed at localhost needs zero additional UI toolkits beyond what
chromium pulls in, matches the Linux GUI exactly (same single-page app), and
is the least code to maintain on an offline image.

## Security posture of the image

- The signing private key is NEVER in the image. Certificates produced by the
  station are signed by whatever issuer key the operator provisions onto the
  boot media themselves (`/opt/trustwipe/keys/issuer_private.pem`), which they
  create out-of-band per core/keys/README.md. Without provisioning, wipes run
  but certificate issuance fails loudly rather than silently self-signing.
- Wipes target only explicit operator-selected devices; the root filesystem is
  protected by the CLI's safety refusals (check_safety), same as everywhere.
