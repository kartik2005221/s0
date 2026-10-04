# Error Handling & Edge Cases

Every string in the "as printed" column below was checked against
`src/s0/cli/main.py`, `src/s0/cli/devices.py`, `src/s0/safety.py` and
`src/s0/audit/verify.py`. Quote them back to the user as they appear; do not
paraphrase them into a different failure.

| As printed | Exit | Root cause | Mandatory agent remediation |
|---|---|---|---|
| `REFUSED: <path> has mounted filesystems (<hits>). Unmount them first, or pass --force if you truly mean it.` | 2 | A partition on the target is in active use | Refuse to wipe. Ask the user to unmount (`umount /dev/sdX*`) or boot the s0 Live ISO. **Never** supply `--force` on a system mount. `s0 plan` prints the same refusal and exits **77**, not 0: a refused plan planned nothing. |
| `REFUSED: <path> hosts the running ROOT filesystem. The tool refuses this without --force; if you mean it, boot the s0 ISO instead.` | 2 | The target hosts `/` | Refuse. The only correct path is the Live ISO. Do not pass `--force`. |
| `error: Refusing to target system path: <path>` | 77, for both `--target` and `--targets` | The shared path guard protects `/etc`, `/usr`, the filesystem root, `$HOME` itself and s0's own state directory | Refuse. Report which guard fired; do not retry with `--force`. |

> Quote these strings back as they appear. Both `--target` and `--targets` exit **77**
> on a protected path, the message is prefixed `error:` (not `REFUSED:`), and a
> `==> Target items (N): [...]` banner is printed first — so an agent expecting a
> different exit code or prefix will misread a successful refusal as something else.
> The code 77 means "s0 declined", not specifically "insufficient privilege": the
> same code covers `image`/`clone` onto an existing destination without `--force`.
| `Cannot verify whether <path> hosts the running ROOT filesystem (findmnt unavailable and /proc/mounts could not be verified). Refusing to proceed without --force.` | 2 | `findmnt` and `/proc/mounts` both unreadable, so the root-filesystem check cannot be made | Refuse. Report that the guard could not evaluate, not that the target is safe. |
| `<path> reports no firmware-mediated Purge method (no ATA Sanitize, no NVMe Sanitize, no SCSI SANITIZE, no FDE key destruction). … s0 will not issue a Purge claim it cannot substantiate …` | 75 | `--require-tier Purge` on a device that cannot reach Purge (`s0 wipe` and `s0 plan` both refuse) | Report the downgrade. Only proceed with `--allow-downgrade`, which records the decision on the certificate — and then report the **achieved** tier, not the requested one. |
| `drive security state is FROZEN — BIOS froze it to block hot-attach attacks; warm-sleep/resume (suspend the machine, resume) then retry` | 1 | BIOS/UEFI issued an ATA Security Freeze Lock during POST | Ask the user to suspend and resume the machine, or power-cycle the drive on the SATA power header. Do not keep retrying in a loop. In `s0 plan` this appears as the alternative `ATA Security Erase unavailable: drive security state is FROZEN`. |
| `controller lacks sanitize capability` / `nvme-cli not installed` / `crypto erase capability unconfirmed` (listed under `Alternatives` in `s0 plan`) | 0 | NVMe firmware does not advertise Sanitize, or `nvme-cli` is absent, or the probe was inconclusive | s0 falls back to NVMe Format, then to a single-pass overwrite. Report the **fallback that was chosen** and its tier. Do not describe the result as a Purge sanitize. |
| `CHAIN INTEGRITY FAILURE` (`s0 audit verify`) | 1 | Hash-chain continuity or a block signature failed | Alert the operator immediately and stop issuing certificates from this station. Preserve the ledger; do not delete or rebuild it. |
| `UNVERIFIABLE - SIGNING KEY NOT IN THE TRUST SET` (`s0 audit verify`) | 1 | The ledger hashes verify, but the signing key is not among the keys `--key` / `~/.s0/keys` supplied | **This is the first state most users hit, and it is a refusal, not a pass.** The chain is continuous; continuity is not authenticity, because anyone can recompute a SHA-256 block hash. Re-run with `--key <issuer_public.pem>` (repeatable; a directory of `*.pem` also works) and report the result. Never write "audit chain verified" on this state alone. |
| `VALID & CONTINUOUS - SIGNED WITH UNACCREDITED DEMO KEY` (`s0 audit verify`) | 0 | The chain is intact but was signed with the bundled `demo_issuer_private.pem` | Report it as cryptographically continuous **and** unusable for legal chain of custody. |
| `VERIFICATION FAILED` (`s0 verify`) | 1 | Signature does not match the payload, or the issuer fingerprint is not pinned | Treat the certificate as suspect. `Reason` distinguishes `signature does NOT match payload — the certificate content has been modified after signing` from `unknown issuer key fingerprint … — certificate was not issued by any pinned authority`. The second is an unknown *authority*, not tampering; say which one it is. |
| `AUTHENTIC - but signed with an unaccredited demonstration key` (`s0 verify`) | 75 | Valid signature, but signed with the bundled `demo_issuer_private.pem` | Report it as authentic but **not accredited**, and as a failure to obtain an accredited attestation — 75 is `EX_TEMPFAIL`, not a pass. It is non-zero in every output format, so a pipeline cannot read it as success by accident. |
| `no trusted public key available; pass --key <issuer_public.pem>` | 78 | No key at all, so nothing could be checked | Report that verification did not happen. Do not report it as a pass or a fail. |
| `Verification  <n> read-back sample(s) - MISMATCH` followed by `sanitization did not complete cleanly: the certificate records the failure and must not be presented as a completed wipe.` | 1 | Post-wipe readback did not match the pattern | The wipe failed. Report the failure and the certificate's `result.status`. Do not re-run `s0 plan` and describe the retry as success until its own readback matches. |
| `Planted markers  <n> hit(s) after sanitization` | 0 or 1 — the line is printed unconditionally, so read `result.status` and the `Verification` line above it for the verdict | A known pre-wipe needle is still readable. This is recorded on demo/test targets, where the pre-wipe content was known | Report it regardless of the exit code. It is the strongest single indication that data survived, and a wipe can still exit 0 with it present. |
| `WIPE INTERRUPTED (Ctrl+C). The target may be partially overwritten and must not be released. Re-run s0 wipe to completion, or escalate to a physical destruction method.` | 130 | The operator interrupted the run | Report the target as **partially** sanitized. Never describe it as sanitized, and never release the media. |

---
