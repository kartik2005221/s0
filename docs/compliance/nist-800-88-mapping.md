# NIST SP 800-88 Rev. 2 mapping — s0 method registry

**Status of this document:** it maps s0's implemented methods to the sanitization
categories defined in *NIST SP 800-88 Rev. 2, Guidelines for Media Sanitization*. It does **not**
claim NIST certification — no software tool can be "NIST certified"; 800-88 is a decision
framework an organization applies. Where a method's tier depends on hardware behavior we could
not observe in the development environment, this document says so, and `docs/compliance/nist-compliance.md`
carries the same caveat in table form.

---

## 1. The three tiers

| Tier | 800-88 definition (paraphrased) | s0's reading |
|---|---|---|
| **Clear** | Logical techniques applied to all user-addressable storage, protecting against simple non-invasive recovery (e.g. overwrite of the raw address space). | Every sector the OS can address is overwritten. Does **not** reach reallocated or overprovisioned areas. |
| **Purge** | Physical or logical techniques rendering data unrecoverable even against advanced laboratory attacks — includes firmware-level erase and **cryptographic erase (destruction of encryption keys)**. | The drive's own firmware performs the erasure (ATA Security Erase, NVMe Sanitize/Format), or the encryption keys protecting the data are destroyed (FBE reset on Android, SED key destruction). |
| **Destroy** | Physical destruction to the point rendering the medium unusable (shredding, disintegration, incineration). | Out of software scope by definition. s0 never claims Destroy; certified destruction facilities perform this as a physical process. |

The key distinction for honesty in this project: **Clear protects against software recovery;
Purge protects against hardware/laboratory recovery.** Overwriting can never be Purge, because
host writes cannot reach sectors the drive has remapped away.

## 2. Cryptographic erase as Purge

SP 800-88 explicitly recognizes destroying encryption keys as a Purge technique when the
encryption strength is adequate (modern AES-XTS class). This matters twice:

1. **Android:** on FBE devices (Android 7+, mandatory since Android 10), a factory reset
   destroys the per-user file-based-encryption keys. All previously encrypted content becomes
   irrecoverable ciphertext regardless of what remains in flash cells. That is Purge by
   cryptographic erase — *stronger* than any overwrite a non-rooted app could attempt, because
   overwrite cannot defeat wear-leveling remapping. On legacy non-FBE devices there is no key to
   destroy and user-space overwrite is Clear-at-best; the app detects and reports which case
   applies.
2. **Self-encrypting drives / BitLocker:** destroying volume keys renders plaintext
   unrecoverable without touching a single data sector. Windows uses this path where available.

## 3. Method registry

`wipe_method` values used in certificates, with the tier each is allowed to claim:

| `wipe_method` | Mechanism | Claimed tier | Platform | Validated in dev env? |
|---|---|---|---|---|
| `OVERWRITE_ZERO_1PASS` | single pass of zeros over full addressable space | Clear | Linux CLI/GUI, image-file targets | ✅ yes (image targets, loop device) |
| `SHRED_RANDOM_NPASS` | N random passes (`shred`) | Clear | Linux CLI/GUI | ✅ yes |
| `BLKDISCARD` | kernel `BLKDISCARD` ioctl → drive trim/unmap | Conditional¹ | Linux CLI (SSD/thin) | ✅ ioctl path on loop device; drive semantics vary |
| `ATA_SECURE_ERASE` | `hdparm --security-erase` (firmware) | Purge² | Linux boot media | ❌ coded, needs real SATA drive |
| `ATA_SECURE_ERASE_ENHANCED` | `hdparm --security-erase-enhanced` | Purge² | Linux boot media | ❌ coded, needs real SATA drive |
| `NVME_FORMAT_USER_DATA_ERASE` | `nvme format -s 1` | Purge² | Linux boot media | ❌ coded, needs NVMe controller |
| `NVME_FORMAT_CRYPTO_ERASE` | `nvme format -s 2` | Purge³ | Linux boot media | ❌ coded, needs SED-capable NVMe |
| `NVME_SANITIZE_BLOCK_ERASE` | `nvme sanitize --block-erase` | Purge | Linux boot media | ❌ coded, needs real NVMe |
| `NVME_SANITIZE_CRYPTO_ERASE` | `nvme sanitize --crypto-erase` | Purge³ | Linux boot media | ❌ coded, needs SED-capable NVMe |
| `WINDOWS_CLEAN_ALL` | `diskpart clean all` (zero-fill whole disk) | Clear | Windows app | ❌ source only |
| `WINDOWS_CIPHER_W` | `cipher /w` free-space overwrite | Clear⁴ | Windows app | ❌ source only |
| `WINDOWS_SED_KEY_DESTROY` / BitLocker key destruction | cryptographic erase | Purge³ | Windows app | ❌ source only |
| `ANDROID_FACTORY_RESET_FBE` | `DevicePolicyManager.wipeData()` on FBE device | Purge³ | **none — not in this repository** | ⚠️ reserved enum value only; no Android implementation exists here |
| `ANDROID_USER_SPACE_OVERWRITE` | best-effort file overwrite pre-reset | Clear-at-best | **none — not in this repository** | ⚠️ reserved enum value only; no Android implementation exists here |
| `ATA_SANITIZE_BLOCK_ERASE` | ATA-4/ACS-4 **Device Configuration / Sanitize** feature set, command `0xB4`, FEATURE `0x0012` ("BkEr") | Purge | Linux boot media | 📋 registered; driver not yet implemented |
| `ATA_SANITIZE_CRYPTO_SCRAMBLE` | `0xB4` FEATURE `0x0011` ("Cryp") | Purge³ | Linux boot media | 📋 registered; driver not yet implemented |
| `ATA_SANITIZE_OVERWRITE` | `0xB4` FEATURE `0x0014`; `LBA[47:32]="OW"`, NSECT = pass count (**0 means 16 passes**) | Purge | Linux boot media | 📋 registered; driver not yet implemented |
| `NVME_SANITIZE_OVERWRITE` | NVMe **admin opcode `0x84`**, SANACT `0x03`, CDW11 = OVRPAT, CDW10[7:4] = OWPASS (`0` ⇒ 16) | Purge | Linux boot media | 📋 registered; driver not yet implemented |
| `NVME_SANITIZE_PURGE_REQUIRED` | `0x84`, SANACT `0x06` + SPRRS — the only NVMe option that asserts IEEE 2883 conformance | Purge | Linux boot media | 📋 registered; driver not yet implemented |
| `SCSI_SANITIZE_BLOCK_ERASE` | SCSI **opcode `0x48`**, service action `0x02` | Purge | Linux boot media | 📋 registered; driver not yet implemented |
| `SCSI_SANITIZE_CRYPTOGRAPHIC_ERASE` | `0x48`, service action `0x03` | Purge³ | Linux boot media | 📋 registered; driver not yet implemented |
| `SCSI_SANITIZE_OVERWRITE` | `0x48`, service action `0x01` + pass count / IPL parameter list | Purge | Linux boot media | 📋 registered; driver not yet implemented |
| `SCSI_UNMAP` | `0x42` deallocate-LBA descriptors (max 4095 per command) | Clear⁵ | Linux boot media | 📋 registered; driver not yet implemented |
| `LUKS_KEYSLOT_ERASE` | `cryptsetup luksErase` — destroys every keyslot, volume key unrecoverable | Purge³ | Linux boot media | 📋 registered; driver not yet implemented |
| `OPAL_CRYPTO_ERASE` | TCG Opal SSC GenKey/Erase via ATA TRUSTED SEND/RECEIVE (`0x5E`/`0x5C`) | Purge³ | Linux boot media | 📋 registered; driver not yet implemented |
| `FDE_KEY_DESTROY` | platform FDE key destruction (BitLocker protector delete, FileVault cryptoUser removal) | Purge³ | Windows / macOS | 📋 registered; driver not yet implemented |
| `VENDOR_SECURE_ERASE` | vendor toolchain firmware erase (Intel SSD Toolbox, Samsung Magician, Crucial) | Purge⁶ | Windows / macOS | 📋 registered; driver not yet implemented |
| `RAID_CONTROLLER_PASSTHROUGH_SANITIZE` | issue SANITIZE to the physical member drive through the controller (`storcli`/`ssacli`/`perccli`) | Purge⁷ | Linux boot media | 📋 registered; driver not yet implemented |

> **Opcode correction.** Several secondary sources list the NVMe Sanitize admin opcode as
> `0xF4`. It is **`0x84`** (`nvme_admin_sanitize_nvm` in the Linux `nvme.h` UAPI header, and the
> NVMe 1.4/2.0 admin opcode table). `0xF4` is not an NVMe admin command. The registry above uses
> `0x84`.

¹ **Conditional:** a discard is a Purge only if the drive guarantees deterministic read-after-
   discard (DRAT/RZAT per its specification). Otherwise treat the outcome as Clear-equivalent at
   most. s0 records the classification it applied and why in the certificate `notes`.
² Firmware erase timing/completion behavior on real controllers was **not observable** in the
   development environment; the command construction and result parsing are implemented and
   unit-tested against recorded output fixtures.
³ Cryptographic erase requires the medium to have actually been encrypted with adequate strength
   beforehand. If precondition fails, the claimed tier drops and the certificate says so.
⁴ Free-space only — cannot wipe files still allocated; documented as partial coverage.
⁵ UNMAP is deallocation, not destruction. It reaches only the thin-provisioning layer and is
   Clear at most; a Purge claim requires the device to guarantee deterministic
   read-after-discard, exactly as for `BLKDISCARD`.
⁶ Vendor tools report success but expose no machine-readable attestation s0 can pin;
   the vendor, tool version and firmware revision must be recorded in `notes`.
⁷ Behind a RAID controller, sanitize must reach the physical member drive. Controller
   write cache and a failing member mean the array must not be certified until every
   member reports success.

## 3.1 Standards currency (2026)

The registry above is written against **NIST SP 800-88 Rev. 2** (published 2025-09-26, which
withdrew Rev. 1 the same day) and **IEEE 2883-2022**. Two changes matter operationally:

1. Rev. 2 explicitly states that **multi-pass overwrite is not needed** for Clear and names
   the DoD 5220.22-M pass-count requirement as obsolete. s0's one-pass default (section 4) is
   the current guidance, not a shortcut.
2. Rev. 2 splits **Verification** ("did the operation run and complete") from **Validation**
   ("was the chosen technique sufficient for this data"), and treats an operator selecting a
   technique the medium cannot support as a validation failure rather than a warning.
   s0 therefore refuses to silently downgrade a requested tier; see `docs/project/industry-plan.md`.

Rev. 1's per-media technique tables were replaced by IEEE 2883 in Rev. 2; the Rev. 1 Appendix A
tables remain in this file as engineering reference only.


## 4. Overwrite passes: the honest position

NIST 800-88 Rev. 2 requires **one** overwrite pass for Clear on modern drives; multi-pass
patterns (DoD 5220.22-M etc.) are legacy policy artifacts from MFM/RLL-era physics and add no
measurable security on current hardware. s0 defaults to one pass and offers multi-pass
only as an explicit policy option, labeled in the UI as compliance theater rather than added
security. A wiping tool that implies "more passes = more secure" is selling folklore; we would
rather explain the trade-off than flatter it.

## 5. HPA / DCO

Host Protected Area and Device Configuration Overlay can hide sectors from host-addressable
overwrites. Before any overwrite-based wipe of an ATA drive on Linux, `s0 wipe` detects HPA/DCO via
`hdparm -N` / `hdparm --dco-identify`. If HPA or DCO is present, the wipe is refused unless `--force`
is passed, and the operator is provided the exact command to remove the hidden area
(`hdparm -N p<native>` / `--dco-restore`). The operator must execute the removal command manually
before re-running the wipe; s0 does not auto-execute `hdparm` modifications. On macOS and Windows,
HPA/DCO detection is not currently performed as native ATA pass-through tools equivalent to `hdparm`
are not available. Loop devices and image files exhibit neither, so this path is coded and fixture-tested
but **not validated against real ATA firmware**.

## 6. Verification approach

Post-wipe verification samples pseudo-randomly selected logical sectors (default 64 × 4096 B),
reads them back through the same path used for writing, and checks they match the expected
post-wipe state (zeros/random pattern). For demo targets with planted known patterns, a raw
grep for the planted bytes across the whole target must return zero hits. Sampling is
statistically strong but not exhaustive — certificates record exactly what was checked
(`result.verification`), never more.

### About the two Android rows

There is **no Android application in this repository**, and nothing here can execute
either method. `ANDROID_FACTORY_RESET_FBE` and `ANDROID_USER_SPACE_OVERWRITE` are
present only as members of the certificate schema's `method` enum
(`src/s0/certificate.py`), so a certificate minted by some *other* implementation can
be parsed, validated and verified here rather than rejected as malformed. They are a
reserved vocabulary, not a roadmap item.

They were previously marked "planned", which reads as a commitment this project has not
made. If an Android implementation is ever wanted it belongs in its own repository, and
these rows should be revisited then.

## 7. What s0 does not claim

- No NIST/CSEC/"certified wipe" branding — 800-88 is a framework we follow and report against.
- No Destroy tier.
- No claim of Purge for any host-overwrite method, anywhere, ever.
- No post-wipe confirmation on Android (the wiped device cannot attest itself); certificates
  say `reset_triggered`.
- Firmware erase commands are constructed per ATA-8/ACPI and NVMe specs but their on-firmware
  execution was not observed in development; see `docs/compliance/limitations.md`.
