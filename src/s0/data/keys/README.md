# Signing keys — policy

## The rule

**The private signing key never lives in this repository and is never shipped inside any
application bundle.** Not the Linux ISO, not the Windows installer, not the Android APK.
A wiping tool whose private key ships with its app is a forgery kit: anyone could mint
"certified wiped" certificates. That failure mode would invalidate every certificate this
project has ever issued, so it is treated as unacceptable rather than unlikely.

`.gitignore` blocks `*private*.pem` / `*private*.key` repo-wide as a mechanical backstop.

## Real deployment

- `s0-keygen` runs **once, out-of-band**, on the issuing authority's own machine
  (an accredited forensic authority).
- The private key stays on that machine, offline where possible, backed up under the
  organization's key-management policy. Losing it means re-keying; leaking it means
  distrusting every prior certificate.
- The **public key** is what gets distributed: pinned in the verification portal
  (`verification-portal/keys.json`) and shipped read-only with verifiers.
- Rotation: publish the new public key alongside the old during a transition window;
  certificates record `public_key_fingerprint`, so old certs stay verifiable against the
  old pinned key.

## In this repository (development)

- `demo_issuer_public.pem` — placeholder demo issuer public key, committed so verifiers have
  something to pin in demos. Clearly labelled DEMO.
- The matching demo private key is committed at `demo_issuer_private.pem` for tests and local demos.
  It is intentionally un-gitignored via `!src/s0/data/keys/demo_issuer_private.pem` in `.gitignore`.
  Anyone can regenerate it — it guards nothing but demo authenticity.

## What this does NOT protect against

Certificate signing proves *who issued a claim*, not that the claim is true. A signed
certificate from an operator who pointed the tool at the wrong disk is a perfectly signed lie.
Chain-of-custody around the operator remains a human process; the certificate makes it
auditable, not foolproof.
