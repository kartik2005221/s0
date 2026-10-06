# Decision Guidance: Why s0's Defaults Are What They Are

When configuring parameters for `s0`, follow these engineering rules:

### A. Overwrite Pattern (`--pattern zero` vs `random`)
- **Recommendation**: Use `zero` (the default) for speed, but **do not describe the
  result as "fully sanitized"**.
- **Rationale**: A single zero pass is the fastest option — sequential bus
  throughput rather than CSPRNG generation — and it is what SP 800-88 Rev. 2
  Clear is normally understood to mean. It is **not** a statement about the
  medium's spare area, wear-levelled remapping or on-device caches, none of
  which a host-level overwrite reaches. Say "a single zero pass was performed and
  readback sampled", and let the certificate's tier field carry the claim. Use
  `random` when a contract mandates it.

### B. Overwrite Pass Count (`--passes 1`)
- **Recommendation**: Use `1` pass (the default) unless a contract says otherwise.
- **Rationale**: Multi-pass wiping (DoD 5220.22-M 3-pass or 7-pass) was designed
  for 1980s stepper drives prone to track drift. One pass is the norm now, and
  extra passes cost real flash write-endurance on SSDs and hours on a
  multi-terabyte drive. State this as the rationale, never as a claim that extra
  passes would add nothing.

### C. Firmware Commands vs Overwrite (`--no-firmware`)
- **Recommendation**: Allow s0 to auto-select firmware commands (do not pass `--no-firmware` unless troubleshooting).
- **Rationale**: Firmware commands (NVMe Sanitize, ATA Secure Erase) operate at the internal controller level, purging flash cells, over-provisioned blocks, and reallocated bad blocks that host LBA overwriting cannot reach. This achieves NIST **Purge** tier in seconds to minutes. Use `--no-firmware` only if connected through an unstable USB-to-SATA bridge that drops connections during SCSI/ATA pass-through.

### D. Carver Confidence Threshold (`--min-confidence 50`)
- **Recommendation**: Use `50` (the CLI default) for standard triage and
  `75`–`90` for court-admissible automated pipelines. **Lowering it does not
  recover anything the structural gates rejected** — see the warning below.
- **Rationale**: A score of 50 requires a magic header, an independently
  resolved end of file, and a plausible size; above that, entropy and boundary
  method separate a good recovery from a merely possible one.

> **WARNING — `--min-confidence` is a rank, not an override.**
>
> Two gates run *before* any candidate is scored, and neither is a score
> component:
>
> 1. **Boundary resolution.** A candidate whose end cannot be derived is dropped
>    before it is ever read.
> 2. **Structural validation** (`s0.carve.boundary.validate_structure`). A
>    candidate that does not parse as its claimed format is dropped.
>
> `--min-confidence 0` changes neither. A truncated or corrupted file is refused
> with a reason in `recovery_index.json`, not admitted at zero confidence. So
> there is **no confidence value that recovers a structurally damaged file**:
> lower the number only to admit *well-formed but lower-scoring* files — a small
> text document, a truncated-but-valid container, a repetitive image.
>
> **What actually helps on corrupted media:**
>
> - Read `recovery_index.json` → `rejection_summary` and
>   `rejected_candidates_sample`. They name the gate and the reason, so you can
>   tell a damaged file from a signature that was never there.
> - Narrow `--extensions` to the formats present, so the budget is not spent on
>   2-byte magics like MP3 frame sync that match inside random data.
> - Re-acquire the source from the original medium. A carve cannot restore bytes
>   the image does not contain.
> - Report the refusal. Do not tune a threshold until something appears.

### E. Acquisition Buffer Size (`--block-size 1048576`)
- **Recommendation**: Use `1048576` (1MB, default) for general acquisition; use `4194304` (4MB) when capturing PCIe Gen4/Gen5 NVMe targets.
- **Rationale**: Optimizes kernel buffer efficiency and hardware queue depth without thrashing memory.

### G. Target Type Disambiguation (`--as-file` vs `--as-image`)
- **Recommendation**: Specify `--as-file` or `--as-image` when `--target` is ambiguous.
- **Rationale**: When `--target` points to a regular file, s0 defaults to a 64 MiB heuristic: files ≤ 64 MiB are treated as individual files (overwritten, metadata scrubbed, and unlinked), while files > 64 MiB are treated as raw disk images (overwritten in-place without unlinking). Use `--as-file` to force shredding and unlinking on large files (> 64 MiB). Use `--as-image` to preserve and overwrite in-place small disk images (≤ 64 MiB).

### H. Carving Scope & Custom Signatures (`--all-space`, `--custom-sig`, `--limit`)
- **Recommendation**: Use `--all-space` when volume filesystem tables are corrupted or when searching for embedded artifacts within live files.
- **Rationale**: On structured filesystems (FAT, exFAT, NTFS, ext4), `s0 carve` by default scans unallocated cluster blocks. Passing `--all-space` forces scanning across the entire partition volume.
- **Custom Signatures (`--custom-sig`)**: Add user-defined magic bytes at runtime formatted as `ext:magic_hex:max_size` (e.g. `dmp:50414745:10485760`).
- **Recovery Limit (`--limit`)**: Restrict maximum number of carved artifacts recovered to prevent disk exhaustion.

### I. Attestation Output & Verification Controls (`--no-pdf`, `--plant-markers`, `--portal-url`, `--qr-url-template`)
- **`--no-pdf`**: Suppresses generating ReportLab PDF certificates, outputting only the canonical JSON attestation (`certificate_*.json`).
- **`--plant-markers`**: Plants deterministic cryptographic markers across sectors prior to wipe to verify post-sanitization non-readability.
- **`--portal-url` / `--qr-url-template`**: Customizes the online verification URL encoded in the certificate QR code.

### J. Cryptographic Identity & Metadata (`--key` / `--signing-key`, `--operator`, `--operator-id`, `--organization`, `--hash-algorithms`)
- **`--key` / `--signing-key`**: Specifies the Ed25519 private key PEM file for signing certificates and ledger blocks, or public key PEM for `s0 verify` / `s0 audit verify`.
- **`--operator` / `--operator-id`**: Operator identity recorded in certificate attestations.
- **`--organization`**: Organization name recorded in signed certificates and audit logs.
- **`--hash-algorithms`**: Selected hashing suites during acquisition (e.g. `sha256,md5`).

### K. Environment & Maintenance (`--host`, `--port`, `--branch`, `--firmware`, `--version`)
- **`--host`, `--port`**: Binds the `s0 web` operator console (defaults to loopback `127.0.0.1:8669`).
- **`--branch`**: Specifies git ref for `s0 upgrade` (e.g. `master` or a release tag).
- **`--firmware`**: Enables firmware-mediated erasure probing (the default; invert with `--no-firmware`).
- **`--version`**: Emits installed version string and commit hash.

---

