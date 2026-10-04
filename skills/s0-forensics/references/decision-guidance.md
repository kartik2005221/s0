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

### F. Fault-Tolerant Sector Recovery (`--no-recovery`)
- **Recommendation**: Omit `--no-recovery` when imaging suspect media.
- **Rationale**: Faulty drives frequently have bad sectors. `s0 image` replaces unreadable sectors with zeros (ddrescue-style) and logs the bad sector offsets into the manifest, capturing all surviving sectors. Only use `--no-recovery` when evaluating pristine master drives.

---
