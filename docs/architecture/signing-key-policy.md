# Signing key policy — proposal for 3.0

**Status: proposal. Nothing here is implemented.** This document exists because the
current default is wrong in a way that cannot be fixed by documentation, and because the
fix changes what an operator has to do on day one. It is written down first so the change
is a decision rather than a patch.

The current behaviour is described in `src/s0/data/keys/README.md`. The short version:
`demo_issuer_private.pem` is committed, is package data in the wheel, and is the default
signer, so anyone who installs s0 can mint certificates that `s0 verify` accepts.

## The problem, precisely

`s0 verify` exits **0** for a certificate signed by a key that is published in the
release. It prints a warning and marks the document unaccredited, but the exit code is
the machine contract, and a pipeline that reads the exit code reads a pass.

This has been demonstrated, not hypothesised: a certificate claiming NIST Purge via NVMe
crypto-erase, re-signed with the bundled key using the project's own tooling, verifies
successfully. The signature check is doing its job. The key is the problem.

Two properties make it worse than an ordinary "demo mode" wart:

- It is the **default**. `s0 wipe` with no `--key` uses it, so the insecure path is the
  path of least resistance and produces a normal-looking certificate.
- It is **in the wheel**. A user who never reads the source and never opens a git clone
  still has the signing key on disk.

## Options considered

### A. Per-install key generation on first use — recommended

On first signing operation with no `--key` and no configured key, `s0 keygen` runs
implicitly: a fresh Ed25519 keypair is written to `~/.s0/keys/`, the public half is
recorded, and every subsequent certificate from that install is signed by it.

- The key exists only on the machine that generated it.
- A certificate becomes attributable to *an install*, which is a real improvement even if
  that install is not yet attributable to an *organisation*.
- Nothing changes for an operator who already passes `--key`.

### B. Require `--key`, refuse to sign otherwise

`s0` becomes useless out of the box: fresh install (`pip install .`) and immediately wipe a drive with no
certificate at all. Every user has to run a key ceremony before their first operation.

Correct for a tool whose only purpose is producing defensible evidence. Wrong as a default
for a tool that also has a CLI you can try.

### C. Keep the demo key, require `--no-certificate` to acknowledge it

Add a flag, or require acknowledgement, when the demo key would be used. Cheap, but it
keeps the forgeable key as the default and relies on the operator reading a prompt.

Rejected: it makes the insecure path one keystroke long and keeps the artefact in the
wheel.

### D. Generate at install time and have the installer do the ceremony

Best of A, but the installer is `curl | sh` over a network, and generating a signing key
as a side effect of an install script makes the key's provenance depend on trusting the
install path. Rejected on that basis.

## Recommendation

**A**, with **B** as the behaviour when key generation is unavailable.

Concretely:

1. `default_issuer_key()` returns the per-install key if one exists.
2. If none exists, it generates one on first use, at `~/.s0/keys/local_issuer_{fpr8}.pem`,
   mode `0600`, in a `0700` directory.
3. The certificate records the fingerprint, as it already does, so an operator can pin
   it later.
4. The ISO build removes `*private*.pem` from staging as it does today, and the appliance
   generates its own key on first boot — the appliance is the case where a per-machine key
   is *most* correct, because the machine is the evidence station.
5. `demo_issuer_private.pem` remains in the repository for tests, for
   `tools/gen_carving_reference.py`, and for anyone who wants to reproduce a demo — but it
   is no longer reachable as a default. Reaching it becomes an explicit
   `--key src/s0/data/keys/demo_issuer_private.pem`.

## Migration

For an existing install:

- Existing certificates are unaffected. They record the fingerprint of whatever signed
  them, and `s0 verify` still validates them against a pinned key.
- The first operation after upgrading generates a local key and starts signing with it.
  Certificates before and after will have different fingerprints, which is visible in the
  ledger and expected.
- An operator who wants continuity across the upgrade runs `s0 keygen` first and passes
  `--key`, and should treat the key they were using before as the key they keep using.
- Anyone currently relying on the demo key as the default — demos, CI, the Live ISO
  screenshots — must pass `--key` explicitly. This is the breaking part, and it is the
  point.

## Risks, honestly

- **It removes a zero-setup path.** A user who wants a certificate in the first thirty
  seconds after installing now runs a keygen, or accepts that the certificate identifies
  an anonymous local install. For a forensic tool the second option is arguably correct;
  for a first impression it is a step.
- **Anonymous by default.** A per-install key proves "this install signed it", which
  proves very little until the operator publishes the fingerprint. A determined forgery is
  still a forgery, just a fresh one. This must not be described as identity.
- **Key loss is silent-ish.** Lose `~/.s0/keys/` and the old fingerprints can no longer be
  attributed to anything, unless the public key was published somewhere. The fingerprint
  needs to be surfaced somewhere durable — this document does not solve that, and
  `docs/architecture/security-model.md` should say what does.
- **Multi-machine operators** get a different key per machine, so a certificate's issuer
  varies by which workstation ran the wipe. Whether that is acceptable depends entirely on
  the organisation's chain of custody, and for most it is not — which is why `--key`
  remains the documented path for real deployment.
- **It does not fix the ISO's config.** The appliance needs the same treatment or it will
  sign with whatever its config points at. That is build-side work, not CLI work.

## What this proposal deliberately does not do

- It does not remove the demo key from the repository. Tests and the carving reference
  need it, and removing it would make the test fixtures forgeable in a different way.
- It does not claim to make certificates non-forgeable. Signing proves provenance, not
  truth.
- It does not decide how an organisation distributes its issuer key. That is a key
  management policy question, and the answer is not "ship it in the installer".
