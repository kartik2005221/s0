# Signing keys — policy

## The rule

**A real issuer's private signing key must never live in this repository and must never
ship inside any application bundle.** A wiping tool whose signing key ships with its app
is a forgery kit: anyone could mint "certified wiped" certificates for a drive they never
touched. That failure mode would invalidate every certificate the project has ever
issued, so it is treated as unacceptable rather than unlikely.

`.gitignore` blocks `*private*.pem` / `*private*.key` repo-wide as a mechanical backstop.

## What that rule does *not* currently hold for: the demo key

**The demo private key is committed, packaged, and is the default signer.** This section
states exactly where it goes, because the previous version of this file claimed the
opposite and was wrong.

| Where | `demo_issuer_private.pem` present? |
|---|---|
| Git repository | **Yes.** Tracked at `src/s0/data/keys/demo_issuer_private.pem`, opted back in with `!src/s0/data/keys/demo_issuer_private.pem` in `.gitignore`. |
| Built wheel / `pip install s0` | **Yes.** `pyproject.toml` has `"s0.data" = ["*.json", "*.pem", "keys/*.pem"]`, so it is package data. Verified present in a built `s0-3.0.0-py3-none-any.whl`. |
| Editable install (`pip install -e .`) | **Yes** — it is the file in the checkout. |
| The bootable Live ISO | **No.** `iso/auto/build.sh` stages `src/` and then runs `find "$STAGING_DIR/src" -type f \( -name '*private*.pem' -o -name '*private*.key' \) -delete`. |
| Windows and macOS installers | They install from source or the wheel, so **yes** — see the previous row. |
| Android APK | Does not exist. There is no Android application in this repository. |

It is also the **default signer**: `s0_config.json` sets
`"default_key_path": "src/s0/data/keys/demo_issuer_private.pem"`, so `s0 wipe` with no
`--key` signs with it, and `s0 verify` with no `--key` trusts its public half.

### Why it is still here, and what it costs

It is here so that `pip install s0` produces a working toolchain: a fresh install can
issue and verify a certificate without an out-of-band key ceremony first. That is a real
benefit and it is also a real cost, and both are stated rather than reconciled.

The cost is concrete, and it has been demonstrated: anyone who downloads the release can
re-sign a certificate claiming NIST Purge via NVMe crypto-erase, and `s0 verify` accepts
it with exit 0 and a warning banner. The cryptography is working correctly — the
signature is valid — and the signature is worth nothing, because the key is public. This
is why every surface that reports such a certificate says *unaccredited demonstration
key* rather than *valid*, and why `s0 verify` exits **75** (`EX_TEMPFAIL`) rather than 0
for it, in every output format.

### What is not being claimed

- Not that a demo-key certificate is worthless. It is worth exactly what a signature by a
  key anyone can read is worth: it proves the document was not altered *after* it was
  written, and nothing about who wrote it.
- Not that the ISO exclusion extends to the wheel. It does not. The ISO removes the key;
  the wheel keeps it.

## Real deployment

- `s0 keygen` runs **once, out-of-band**, on the issuing authority's own machine (an
  accredited forensic authority), never as part of an install.
- The private key stays on that machine, offline where possible, backed up under the
  organization's key-management policy. Losing it means re-keying; leaking it means
  distrusting every prior certificate.
- Pass it explicitly: `s0 wipe --key /path/to/issuer_private.pem`. Every signing command
  accepts `--key`.
- The **public key** is what gets distributed: pinned in the verification portal
  (`site/verify/keys.json`) and shipped read-only with verifiers.
- Rotation: publish the new public key alongside the old during a transition window;
  certificates record `public_key_fingerprint`, so old certs stay verifiable against the
  old pinned key.

## Changing the default

The proposal for per-install key generation as the 3.0 default is in
[`docs/architecture/signing-key-policy.md`](../../../docs/architecture/signing-key-policy.md).
It is a proposal: this file describes what the code does today, and that code does not
change until the proposal is adopted.

## What this does NOT protect against

Certificate signing proves *who issued a claim*, not that the claim is true. A signed
certificate from an operator who pointed the tool at the wrong disk is a perfectly signed
lie. Chain-of-custody around the operator remains a human process; the certificate makes
it auditable, not foolproof.
