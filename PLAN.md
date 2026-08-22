# TrustWipe — Phase 0 Plan

**Project:** Secure data wiping suite — SIH problem statement, Ministry of Mines / JNARDDC.
**Status:** Phase 0 (plan). No implementation code written yet. This file is the contract for
everything that follows; deviations from it get documented, not silently made.

---

## 0. Environment survey — what this VM actually gives us

Probed on 2026-08-22. The plan below is built around these facts, not assumptions.

| Capability | Status | Consequence for the plan |
|---|---|---|
| Python 3.14.4, pip → PyPI | ✅ works | Core CLI + crypto in Python; `cryptography` (Ed25519) preinstalled |
| Rust / Node / Java / .NET toolchains | ❌ absent | CLI will not be Rust unless user installs toolchain; verification portal must be **pure static HTML/JS with vendored libs** (no npm build step); Windows/Android are source-only deliverables |
| `hdparm`, `blkdiscard`, `shred`, `lsblk`, `wipefs`, `losetup` | ✅ present | Linux wipe methods callable for real |
| `nvme-cli`, `qemu-system-x86_64`, `xorriso`, `live-build`/`debootstrap` | ❌ absent, `apt` present but **no passwordless sudo** | NVMe + ISO paths are *coded and scripted* here, *built/tested only if the user runs the sudo install step* (documented one-liner in HANDOVER.md) |
| Loop device attach (`losetup -a`) | ❌ needs root (user is uid 1000, in `sudo` group but password-gated) | Primary test target is a **sparse image file** — real bytes on real disk, no root needed. Loop-device path is the same code after `open()`, exercised when sudo is available |
| `reportlab` + `qrcode` + Pillow | ✅ installed | Signed cert → PDF + QR works today |
| Network | ✅ works | Dependency installs fine |

**Design consequence:** every wipe backend accepts `--target <blockdev|image-file>`.
The code path after opening the target is identical; only attachment differs. This gives a
root-free, fully-real end-to-end demo (overwrite wipe of a file-backed image + forensic
verification + certificate), with the block-device/ATA/NVMe tiers layered on top and
honestly labelled.

---

## 1. Repo layout

Keeping the suggested monorepo structure, with these concrete adjustments (justified):

```
trustwipe/  (this repo)
├── README.md
├── PLAN.md                          # this file
├── core/
│   ├── standards/nist_800_88_mapping.md
│   ├── cert_schema.json             # machine-readable schema + field-classification table
│   ├── CANONICAL_JSON.md            # the canonicalization spec every platform implements
│   ├── python/trustwipe_core/       # the one shared implementation (see below)
│   │   ├── canonical.py             # canonical JSON serializer (spec above)
│   │   ├── crypto.py                # keygen / sign / verify (Ed25519 via `cryptography`)
│   │   ├── certificate.py           # build/parse/validate cert dicts against schema
│   │   ├── pdfgen.py                # signed JSON → human PDF + QR (reportlab + qrcode)
│   │   └── cli.py                   # `trustwipe-keygen`, `trustwipe-sign`, `trustwipe-verify`
│   ├── keys/
│   │   ├── issuer_public_key.pem    # committed — what verifiers pin
│   │   └── README.md                # private key NEVER lives in the repo or any app bundle
│   └── tests/                       # sign/verify, tamper matrix, canonical-form vectors
├── linux/
│   ├── cli/trustwipe/               # the real, working tool (Python; ctypes for ioctls)
│   │   ├── devices.py               # lsblk -J + /sys probe → typed device inventory
│   │   ├── hpa_dco.py               # hdparm -N / --dco-identify detection + removal offers
│   │   ├── methods/                 # nvme_sanitize, ata_secure_erase, blkdiscard, overwrite
│   │   ├── wipe.py                  # method selection, progress, verification sampling
│   │   └── main.py                  # argparse CLI incl. --dry-run / --target / --image
│   ├── cli/tests/                   # incl. end-to-end demo test on a file-backed image
│   ├── gui/                         # local web GUI: FastAPI + single-page frontend
│   ├── iso/                         # live-build config + build.sh + qemu-test.sh
│   └── docs/linux-limitations.md
├── windows/
│   ├── app/                         # C#/.NET 8 console+wrapper source (no toolchain here)
│   └── docs/windows-limitations.md
├── android/
│   ├── app/                         # Kotlin source (no SDK here)
│   └── docs/android-limitations.md
├── verification-portal/
│   ├── index.html                   # pure static; vendored noble-ed25519 (no build step)
│   ├── verify.js                    # re-implements CANONICAL_JSON.md + Ed25519 verify
│   └── tests/                       # cross-language: same certs verify in Python AND JS
├── docs/                            # ARCHITECTURE, USER_MANUAL, COMPLIANCE, TEST_PLAN,
│                                    # LIMITATIONS, HANDOVER, PITCH_OUTLINE (Phase 6)
└── scripts/build_all.sh
```

**Why this layout:** the certificate is only as trustworthy as the canonicalization + signature
logic being identical everywhere it runs. One canonical spec (`core/CANONICAL_JSON.md`) plus one
reference implementation (`core/python`) that every other platform re-implements *and is tested
against* (the portal's JS verifier must verify the exact certs Python produced — that
cross-language test is a deliberate credibility feature, not an accident). Monorepo because the
schema cannot be allowed to drift between platforms between SIH commits.

---

## 2. What "secure wipe" concretely means, per platform

**Linux (the platform we make fully real).** A wipe is complete when no readable copy of the
target's data remains reachable through the device's normal address space. Concretely, in
ascending strength: (a) **Clear** — every addressable logical sector overwritten once with a
fixed or random pattern (`shred -n1`, `dd`), sufficient on modern drives per NIST SP 800-88;
(b) **Purge** — the drive's own firmware performs the erasure: ATA Security Erase /
Erase-Enhanced (`hdparm --security-erase[-enhanced]`) for SATA, Sanitize or Format-NVM with
cryptographic erase (`nvme sanitize` / `nvme format`) for NVMe, or `BLKDISCARD` on
self-encrypting/deterministic-TRIM SSDs. Purge is preferred because firmware-level erase covers
reallocated/overprovisioned areas host writes cannot reach. (c) **Destroy** — physical
destruction; out of software scope, documented and deferred to process. Method selection is by
probed device type, with the chosen method and its NIST tier recorded in the certificate.

**Windows.** Realistic tiers: `diskpart clean all` / `Format-Volume -Full` / `cipher /w` are
**Clear** (host overwrite; `cipher /w` only free space, so only for volumes that must stay
bootable). Hardware Purge on Windows is only reachable via OEM/vendor utilities or if the disk
is self-encrypting — in which case destroying the BitLocker/SED keys is a **cryptographic
Purge**, and that is the honest enterprise-grade path we document. The app is C#/.NET source,
structured and documented for someone with a Windows machine to build and validate; we cannot
compile or execute it in this VM, and the docs say so in the first paragraph.

**Android.** A non-rooted app cannot touch raw blocks — full stop. What a factory reset does on
modern (Android 7+) FBE devices is destroy the per-user file-based-encryption keys, rendering
all encrypted data cryptographically unrecoverable. That is **Purge via cryptographic key
destruction** under NIST 800-88 — a *stronger* guarantee than overwriting would be, and we
explain why in COMPLIANCE.md. The app: best-effort user-space secure delete of accessible files
first (documented as unreliable due to flash wear leveling/journaling — included for user
confidence and legacy unencrypted devices only), then `DevicePolicyManager.wipeData()` as
Device Owner, then a certificate generated **before** the reset with
`result: "reset_triggered"` — the app cannot survive its own wipe to confirm, and we say so
rather than pretend. Device-Owner provisioning friction (ADB/QR/MDM) is flagged, not papered over.

**Verification portal.** Not a wipe tier — it's the integrity layer: pure client-side Ed25519
verification of the certificate against pinned issuer public keys. No backend, no database:
"trust the math, not our server" is the stronger story and we make it explicitly.

---

## 3. Real vs. simulated in this environment

### Real, runnable, and verifiable here (the demo spine)
- Full wipe of a **file-backed sparse image**: real bytes, planted known patterns at known
  offsets, wiped, then verified by sampled read-back *and* raw grep for planted patterns
  (forensic-style proof nothing recoverable remains).
- Overwrite method engine (single-pass zero / random / N-pass), progress streaming, resumable logs.
- `BLKDISCARD` ioctl path via ctypes — exercisable on a loop device once sudo is granted.
- Complete crypto chain: Ed25519 keygen, canonical JSON, sign, verify; **tamper-evidence
  matrix test** proving a single-byte edit to *any* signed field fails verification (demoable
  on stage).
- PDF certificate with QR (offline full-JSON QR + verification-URL variant).
- Verification portal (static, vendored Ed25519) verifying certs produced by the Python core —
  cross-language canonicalization proof.
- GUI flow end-to-end against an image target.

### Coded + scripted here, validated only with hardware/privilege we don't have
| Item | What exists | What's missing | Where documented |
|---|---|---|---|
| ATA Security Erase | `hdparm --security-erase` invocation + safety checks | Real SATA firmware timing/completion behavior | LIMITATIONS.md, code comments |
| HPA/DCO detect+remove | `hdparm -N` / `--dco-identify` / `--dco-restore` paths | Real ATA drives (loop devices exhibit neither) | LIMITATIONS.md |
| NVMe sanitize / format | `nvme-cli` command construction + result parsing | `nvme-cli` install (sudo) and a real controller; QEMU NVMe emulation may cover `format`, likely not `sanitize` | LIMITATIONS.md |
| Loop-device block target | Full code path post-open; attach script provided | `sudo` to attach (`scripts/make_loop_target.sh`) | HANDOVER.md |
| Bootable ISO | live-build config + build.sh + QEMU smoke-test script | `live-build`, `xorriso`, `qemu` (sudo install) | HANDOVER.md, LIMITATIONS.md |
| Windows execution | Complete C# source | Any Windows/.NET environment | windows-limitations.md |
| Android wipeData | Kotlin source + provisioning docs | Device/emulator with FBE; Device Owner provisioning | android-limitations.md |

### Inherent limits (true on real hardware too — stated up front, not buried)
- Host overwrite can never reach SSD overprovision/reallocated sectors; only firmware Purge can.
- `BLKDISCARD` alone is only a Purge on drives guaranteeing deterministic read-after-TRIM;
  otherwise it is best classified Clear-adjacent. We classify per-drive and record it.
- Multi-pass overwrite on modern drives is legacy theater; NIST Clear needs one pass. We
  default to one pass and offer passes for policy compliance, saying exactly that in the UI/docs.
- Android cert says "reset_triggered", never "verified wiped" — the device's own audit log is
  the final word where one exists.

---

## 4. Certificate schema v1 (fields, signing, canonical form)

Full machine-readable schema: `core/cert_schema.json`. Shape:

```json
{
  "schema_version": "1.0.0",
  "cert_uuid": "3f2c8a1e-…",
  "issued_at": "2026-08-22T10:15:00Z",
  "issuer": { "organization": "…", "operator_id": "op-…" },
  "tool":   { "name": "trustwipe-cli", "version": "0.1.0", "platform": "linux", "os_kernel": "…" },
  "device": {
    "device_id": "<serial|WWN|IMEI|sha256(path) for file targets>",
    "device_type": "internal_disk | removable | image_file | phone",
    "storage_type": "HDD | SSD | NVMe | eMMC | UFS | IMAGE_FILE",
    "model": "…", "serial_number": "…",
    "capacity_bytes": 268435456, "sector_size": 512
  },
  "wipe": {
    "method": "SHRED_1PASS | SHRED_3PASS | ATA_SECURE_ERASE | ATA_SECURE_ERASE_ENHANCED | NVME_SANITIZE | NVME_FORMAT_CRYPTO_ERASE | BLKDISCARD | ANDROID_FACTORY_RESET | WINDOWS_CLEAN_ALL | CIPHER_W",
    "nist_category": "Clear | Purge | Destroy",
    "passes": 1, "pattern": "random | zero",
    "start_time": "…", "end_time": "…", "bytes_processed": 268435456
  },
  "result": {
    "status": "success | failure | partial | reset_triggered",
    "errors": [],
    "verification": {
      "method": "sampled_readback",
      "samples_checked": 64, "sample_bytes_each": 4096,
      "all_samples_match_wipe_pattern": true,
      "planted_pattern_hits_after": 0,
      "pre_wipe_sample_hash": "sha256:…"
    }
  },
  "notes": ["…"],
  "signature": {
    "algorithm": "Ed25519",
    "public_key_fingerprint": "sha256:…",
    "signature_base64url": "…",
    "signed_payload_hash": "sha256:…"
  }
}
```

**Signed vs. informational.** The **signature covers the entire certificate except the
`signature` object itself**, computed over the canonical form of the payload. Everything a
verifier should trust — device identity, method, NIST tier, times, result, verification
sampling — is inside the signed payload. `signed_payload_hash` inside the signature block is a
convenience annotation; verifiers recompute the canonical form and check the Ed25519 signature
directly (trust the math, not the annotation). The QR's verification-URL variant encodes an
unsigned locator (the URL is transport, not evidence); the offline QR variant encodes the full
signed certificate, which *is* self-verifying.

**Canonical form (TrustWipe Canonical JSON v1, spec'd in `core/CANONICAL_JSON.md`):**
UTF-8; object keys sorted recursively by Unicode code point; no insignificant whitespace;
`json.dumps(..., ensure_ascii=False, separators=(",", ":"), sort_keys=True)`-equivalent escaping
in every language; **integers only — no float fields exist in schema v1** (sizes in bytes,
durations in seconds), which deliberately sidesteps cross-language float-formatting divergence
(this is a documented deviation from RFC 8785, chosen so a JS re-implementation cannot silently
mismatch Python on number formatting).

**Key management.** `trustwipe-keygen` is a one-time, out-of-band step. The private key is held
by the issuing authority (JNARDDC / accredited recycler) and **never committed, never shipped in
any app bundle** (`.gitignore` enforces; `core/keys/README.md` states policy). The repo carries
the issuer *public* key that verifiers pin, plus a clearly-labelled demo keypair for development.

---

## 5. Phase sequence and exit criteria

| Phase | Deliverable | Exit test |
|---|---|---|
| 1 Core | mapping doc, schema, canonical spec, crypto lib, PDF+QR, tests | pytest green: sign/verify roundtrip; tamper matrix over every field fails verify; key-reorder still verifies; wrong key fails |
| 2 Linux | CLI + GUI + ISO config; e2e demo | `demo_e2e.sh`: 256 MB image with planted patterns → wipe → sampled read-back + grep = 0 hits → cert → verify OK; tampered cert rejected. GUI flow completes on image target. ISO: config committed, build/QEMU run if sudo granted, else marked pending |
| 3 Windows | C# source + limitations doc | Source review complete; doc states plainly it was never compiled here |
| 4 Android | Kotlin source + limitations doc | Same honesty bar |
| 5 Portal | static verify page | Same cert JSON verifies in JS and Python; tampered cert fails in both |
| 6 Docs | all seven docs | Every simulated/unvalidated item from this plan appears in LIMITATIONS.md |
| 7 Packaging | `scripts/build_all.sh` | Builds everything buildable here; logs each skip with reason |

Git: commit after each phase, clear messages, monorepo.

---

## 6. Decisions taken vs. open

Taken (with rationale above): Python for the core (only viable toolchain present; `cryptography`
already installed); static no-build verification portal (no Node here, and no-build is the
stronger trust story anyway); file-backed image targets as the primary test medium (no sudo);
GUI as local web app (FastAPI + one page).

Open — needs the user's call before Phase 1:
1. CLI language: Python now vs. installing a Rust toolchain (rustup needs no sudo, but Rust
   slows iteration on a prototype whose value is the working end-to-end flow).
2. Proceed scope after approval: straight through Phases 1–7, or Phase 1 + 2 then review.
