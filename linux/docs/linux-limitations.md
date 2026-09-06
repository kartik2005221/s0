# Linux platform — validated vs. not validated

Development environment: an unprivileged x86_64 VM (no real SATA/NVMe hardware,
no sudo). Everything below was true on 2026-08-22 and is re-checked whenever
this file changes.

## Fully exercised here (real bytes, real effects)

| Capability | Evidence |
|---|---|
| Overwrite wipe of image files | `linux/cli/tests/test_e2e_demo.py`; planted confidential markers unrecoverable by raw byte-search afterwards |
| Sampled read-back verification | same tests; 64 × 4 KiB samples checked against expected post-wipe state |
| Certificate issuance → PDF/QR | demo run in `linux/cli/demo_e2e.sh`; independent `s0-verify` passes; tampered copy fails |
| BLKDISCARD ioctl code path | compiled + negative-tested (rejects non-block targets); loop-device exercise documented in HANDOVER.md as a user-run sudo step |
| Safety refusals (mounted/root FS) | unit tests with simulated mount tables; logic identical for block devices |

## Coded + fixture-tested, NOT executed against the real thing here

| Capability | What exists | Why untested | How to validate for real |
|---|---|---|---|
| ATA Security Erase / Enhanced | full hdparm workflow incl. frozen-state detection, temp-password hygiene | no SATA drive in dev env; hdparm absent of hardware returns errors we handle but can't prove erase semantics | boot ISO on a sacrificial SATA machine, verify with a forensics lab sample set |
| HPA/DCO detect & remove | `hdparm -N` / `--dco-identify` parsing, restore commands | loop/image targets never exhibit HPA/DCO | same sacrificial-machine pass |
| NVMe Sanitize / Format (incl. crypto erase) | nvme-cli command construction, sanitize-log polling parser, capability gating (refuses crypto claim without OACS bit) | no NVMe controller; QEMU's emulated NVMe does not implement Sanitize | real NVMe drive test rig |
| Bootable live ISO | complete live-build config + QEMU smoke-test script | `live-build`/`xorriso`/`qemu` need sudo to install | `sudo apt install live-build xorriso qemu-system-x86_64`, then `auto/build.sh && ./qemu-test.sh` |

## Known behavioral caveats (true on real hardware too)

- `/dev/vda` in this VM reports `rotational=1` via /sys, so it classifies as
  HDD — classification follows what the kernel says, which is honest but not
  clairvoyant. Operators see the classification before confirming.
- Overwrite never claims Purge regardless of pass count (enforced in the
  certificate validator itself, not just docs).
- BLKDISCARD defaults to Clear; Purge requires operator-supplied deterministic-
  TRIM evidence recorded in certificate notes.
- The GUI binds to 127.0.0.1 only. A network-exposed "wipe my disk" API would
  be a remote-code-execution-adjacent liability; don't expose it.
- Progress rates shown during overwrite are host-side write throughput; on
  firmware erases (ATA SE) progress is firmware-reported completion states,
  which can take hours on large drives.
