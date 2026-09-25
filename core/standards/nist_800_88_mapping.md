# NIST SP 800-88 Rev.1 mapping — s0 method registry

**Status of this document:** it maps s0's implemented methods to the sanitization
categories defined in *NIST SP 800-88 Rev.1, Guidelines for Media Sanitization*. It does **not**
claim NIST certification — no software tool can be "NIST certified"; 800-88 is a decision
framework an organization applies. Where a method's tier depends on hardware behavior we could
not observe in the development environment, this document says so, and `docs/COMPLIANCE.md`
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
| `ANDROID_FACTORY_RESET_FBE` | `DevicePolicyManager.wipeData()` on FBE device | Purge³ | Android app | 📋 planned — not yet implemented |
| `ANDROID_USER_SPACE_OVERWRITE` | best-effort file overwrite pre-reset | Clear-at-best | Android app | 📋 planned — not yet implemented |

¹ **Conditional:** a discard is a Purge only if the drive guarantees deterministic read-after-
   discard (DRAT/RZAT per its specification). Otherwise treat the outcome as Clear-equivalent at
   most. s0 records the classification it applied and why in the certificate `notes`.
² Firmware erase timing/completion behavior on real controllers was **not observable** in the
   development environment; the command construction and result parsing are implemented and
   unit-tested against recorded output fixtures.
³ Cryptographic erase requires the medium to have actually been encrypted with adequate strength
   beforehand. If precondition fails, the claimed tier drops and the certificate says so.
⁴ Free-space only — cannot wipe files still allocated; documented as partial coverage.

## 4. Overwrite passes: the honest position

NIST 800-88 Rev.1 requires **one** overwrite pass for Clear on modern drives; multi-pass
patterns (DoD 5220.22-M etc.) are legacy policy artifacts from MFM/RLL-era physics and add no
measurable security on current hardware. s0 defaults to one pass and offers multi-pass
only as an explicit policy option, labeled in the UI as compliance theater rather than added
security. A wiping tool that implies "more passes = more secure" is selling folklore; we would
rather explain the trade-off than flatter it.

## 5. HPA / DCO

Host Protected Area and Device Configuration Overlay can hide sectors from host-addressable
overwrites. Before any overwrite-based wipe of an ATA drive, s0 detects HPA/DCO via
`hdparm -N` / `hdparm --dco-identify` and offers removal (`-N p<visible>` / `--dco-restore`)
so the subsequent wipe covers the full medium. Loop devices and image files exhibit neither,
so this path is coded and fixture-tested but **not validated against real ATA firmware**.

## 6. Verification approach

Post-wipe verification samples pseudo-randomly selected logical sectors (default 64 × 4096 B),
reads them back through the same path used for writing, and checks they match the expected
post-wipe state (zeros/random pattern). For demo targets with planted known patterns, a raw
grep for the planted bytes across the whole target must return zero hits. Sampling is
statistically strong but not exhaustive — certificates record exactly what was checked
(`result.verification`), never more.

## 7. What s0 does not claim

- No NIST/CSEC/"certified wipe" branding — 800-88 is a framework we follow and report against.
- No Destroy tier.
- No claim of Purge for any host-overwrite method, anywhere, ever.
- No post-wipe confirmation on Android (the wiped device cannot attest itself); certificates
  say `reset_triggered`.
- Firmware erase commands are constructed per ATA-8/ACPI and NVMe specs but their on-firmware
  execution was not observed in development; see docs/LIMITATIONS.md.
