# Frequently Asked Questions (FAQ)

<a id="0-legal-ethical-use"></a>
<a id="legal-ethical-use"></a>
## 0. Legal & Ethical Use

### Am I legally allowed to wipe or recover data from any device with s0?
**No.** s0 is a digital forensic sanitization and recovery tool. You are legally required to only operate on storage media and files that you **own** or have **explicit, documented written authorization** to process. Operating on unauthorized devices may constitute a severe criminal offense.

### Which computer crime laws apply?
Depending on your jurisdiction, unauthorized wiping or unauthorized data recovery may violate:
- **United States:** Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030 (unauthorized access and damage to protected computers).
- **United Kingdom:** Computer Misuse Act 1990 (unauthorized acts with intent to impair operation of a computer).
- **European Union:** Directive 2013/40/EU on attacks against information systems.
- **India:** Information Technology Act 2000, Section 43 (penalty for damage to computer system) and Section 66 (computer related offenses).
- **International:** Budapest Convention on Cybercrime.

### What should organizations do prior to sanitizing or imaging media?
1. **Chain of Custody:** Ensure an asset transfer form or legal clearance document is signed by the device owner or IT asset custodian.
2. **Litigation Hold Check:** Verify that the media is not subject to a preservation order, court subpoena, or pending legal dispute before initiating `s0 wipe`.
3. **Key Management:** Maintain accredited Ed25519 signing keys for non-repudiation in audit trails.

---

## 1. General & Architecture

### What is s0, and what does the name mean?
**s0** stands for **Sector Zero** — the first logical sector (LBA 0) of a storage drive where partition tables and Master Boot Records reside. It represents the starting boundary of all digital media. s0 provides an integrated digital forensic suite combining defensive data sanitization (wiping) and offensive evidence extraction (carving) with mathematical non-repudiation.

### Why combine drive wiping and file recovery in a single tool?
Traditionally, forensic practitioners and IT security teams are forced to deploy two disjoint toolsets: expensive commercial sanitization software (such as Blancco) and complex digital forensics platforms (such as FTK or Autopsy). 

By uniting these capabilities into a single open-source platform:
1. **Verification of Destruction:** You can immediately test your own sanitization jobs by running the carver on wiped media to verify that zero recoverable artifacts remain.
2. **Unified Chain of Custody:** Both evidence collection and media decommissioning are recorded in the exact same cryptographic audit ledger.
3. **Open Standards:** Replaces proprietary, closed-source wipe algorithms with transparent, peer-reviewed implementations of NIST SP 800-88 Rev. 2 and RFC 8032.

### Is s0 free and open source?
Yes. s0 is licensed under the permissive **MIT License**. It can be deployed across commercial enterprises, government agencies, and research laboratories without licensing fees.

---

## 2. Secure Data Sanitization (Drive & File Sanitization)

### Is a single-pass zero overwrite really enough to destroy data?
**Yes.** According to **NIST SP 800-88 Rev. 2 (Appendix A)**:
> *"For ATA hard drives manufactured after 2001 (capacities greater than 15 GB), clearing the read/write heads by writing zeros to all addressable locations is sufficient to prevent recovery using Magnetic Force Microscopy (MFM) and other laboratory techniques."*

The common myth that 7-pass or 35-pass (Gutmann) overwriting is required originated in the 1990s when hard disk tracks were wide enough for magnetic residue analysis. On modern high-density magnetic and solid-state media, single-pass zeroing satisfies the **NIST Clear** tier.

### Why does s0 refuse to wipe my current drive?
s0 includes rigorous **safety interlocks** (`src/s0/cli/devices.py`). It examines `/proc/mounts`, kernel boot parameters, and volume layouts to prevent an operator from accidentally wiping the active root filesystem (`/`), boot partition (`/boot`), or critical system drives. 

To sanitize an internal boot drive, boot the computer into the [s0 Bare-Metal Live ISO](../guides/live-iso.md), where all internal drives remain unmounted.

### What is the difference between NIST Clear and NIST Purge?
- **Clear (Logical Protection):** Overwriting data across all user-accessible logical blocks using standard read/write commands. Protects against simple, software-based recovery attacks.
- **Purge (Physical/Firmware Protection):** Executes internal controller commands (`NVME_SANITIZE`, `ATA_SECURE_ERASE`) that reset flash cell voltages or sanitize overprovisioned, retired, and wear-leveled flash blocks inaccessible to standard OS write commands. Protects against advanced laboratory hardware attacks.

### Does s0 wipe data hidden in HPA (Host Protected Area) or DCO (Device Configuration Overlay)?
Yes. When evaluating SATA drives via `hdparm`, s0 probes for active HPA and DCO boundaries. If hidden sectors are detected, s0 reports the exact sector delta, prints the kernel commands required to remove the restriction prior to wiping, and recommends `ATA_SECURE_ERASE_ENHANCED`, which commands the drive controller to sanitize HPA sectors automatically.

### Can s0 securely erase files on Copy-on-Write (CoW) filesystems (Btrfs, ZFS, APFS)?
On CoW filesystems, writing to an existing file allocates **new** disk blocks rather than overwriting physical sectors in-place. The pre-wipe data clusters remain intact until reclaimed by filesystem garbage collection.

s0 inspects `/proc/mounts` on Linux and volume attributes on Windows/macOS. When target files reside on Btrfs, ZFS, APFS, or ReFS volumes, s0 automatically logs an explicit **CoW Advisory Warning** in the signed certificate. For absolute sanitization on CoW storage, volume-level or whole-device sanitization is required.

---

## 3. Forensic File Carving & Evidence Recovery

### Can s0 recover deleted files from a freshly formatted drive?
**Yes.** Standard "Quick Format" operations merely rebuild the filesystem partition table, boot sector, and root metadata index; they do not overwrite the underlying data clusters. As long as new files have not been written to the media, s0's carving engines can extract and reconstruct the original files.

### How does structure-based carving work, and why is it faster than signature carving?
- **Raw Signature Carving:** Scans every single byte on the disk looking for magic headers (`FF D8 FF` for JPEG, `%PDF-` for PDF). On a 1 TB drive, this requires reading 1 terabyte of data (taking 1.5 to 2 hours).
- **Structure-Based Carving (ext4 & NTFS):** Directs the scan to filesystem metadata tables (such as the NTFS Master File Table `$MFT` or ext4 Inode Tables). It parses deleted records, extracts non-resident cluster runlists, and jumps directly to the target file clusters. A 1 TB drive can be indexed and carved in **under 15 seconds**.

### What does the forensic confidence score (0–100%) mean?
Every carved artifact is evaluated by `src/s0/carve/scoring.py` across four objective criteria:
1. **Magic Header Match (30 points):** Verified starting byte signature.
2. **Footer / Terminator Match (30 points):** Verified EOF boundary pattern.
3. **Size Plausibility (20 points):** File length falls within standard format bounds.
4. **Shannon Entropy Analysis (20 points):** 3-point sampled entropy matches expected format characteristics (e.g. high entropy for compressed JPEG/ZIP; medium for text/PDF).

Files scoring below your `--min-confidence` threshold (default 50%) are filtered out to eliminate corrupted candidates.

### Can s0 recover files from encrypted drives (BitLocker, LUKS, VeraCrypt)?
No. Proper modern encryption algorithms (AES-XTS) produce ciphertext that is mathematically indistinguishable from random noise (maximum Shannon entropy ~8.0). Without the decryption passphrase or master key, forensic carving cannot detect file headers or reconstruct file structures.

---

## 4. Certificates, Verification & Cryptography

### Do I need an active internet connection to verify a certificate?
**No.** s0 is engineered from the ground up for **air-gapped defense and crime laboratory environments**:
- **Offline CLI:** Run `s0 verify certificate.json --key pubkey.pem`
- **Offline Browser:** Double-click `site/verify/index.html` on any air-gapped machine. It uses pure in-browser JavaScript (TweetNaCl WebCrypto) without external network requests or CDN dependencies.

### What does the amber warning badge mean in the Verification Portal?
The Verification Portal distinguishes between mathematical authenticity and organizational accreditation:
- **Green Badge (Accredited Authority):** The certificate is mathematically valid AND the public key fingerprint matches an accredited lab pinned in `keys.json`.
- **Amber Badge (Valid but Unaccredited):** The certificate signature is mathematically authentic and untampered, but the signing key is unknown or self-generated.
- **Red Badge (Tamper Detected):** The signature does not match the payload. One or more bytes have been modified post-issuance.

### Where is my private signing key stored?
Private keys are never uploaded or transmitted. They remain exclusively on your local forensic workstation (or live ISO USB drive) at a location you designate (e.g. `/secure/keys/issuer_private.pem`). You can generate an accredited keypair anytime using `s0 keygen`.

---

## 5. Hash-Chained Audit Ledger

### Is the audit ledger a public blockchain like Ethereum or Solana?
**No.** In national security and forensic operations, deploying a public, distributed blockchain introduces severe security and operational violations:
1. **Air-Gap Compliance:** Forensic workstations in classified facilities cannot communicate with external peer-to-peer cryptocurrency nodes.
2. **Confidentiality:** Public ledgers broadcast drive serial numbers, operator names, and case identifiers to the public internet.
3. **Single Issuing Authority:** Law enforcement laboratories require authoritative, single-authority attestation rather than decentralized consensus.

s0 implements a **local, append-only SQLite ledger chained by SHA-256 block hashes**. Any modification to past records severs the mathematical continuity, detected instantly by `s0 audit verify`.

### What happens if an insider tampers with an audit row in SQLite?
If an unauthorized user modifies any database column (such as editing an operator name or target serial number), the `block_hash` of that record will no longer match its contents, and the `prev_hash` of all subsequent blocks will fail verification. Running `s0 audit verify` will flag the exact block index of the tampering event.
