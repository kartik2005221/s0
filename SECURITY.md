# Security Policy

## What this tool does, and what that means for a report

s0 acquires, recovers, and sanitizes storage. Two of its outputs are relied on
by people who were not there: a recovered file becomes evidence, and a wipe
certificate becomes a claim that data was destroyed. Both are treated here as
statements that have to be defensible, not merely produced.

That shapes what counts as a vulnerability in this project.

**Highest severity — a false claim.** A wipe certificate that asserts a tier the
device did not achieve; a sanitize recorded as successful when the controller
reported failure; a recovery index that states a boundary the structure does not
support. These are worse than a crash, because they are believed. Two real
instances of this class were found and fixed during development: an NVMe
Sanitize Status field decoded as a bit set rather than as a status code, which
attested a *failed* sanitize as successful; and a test that pinned that
misreading, so the suite agreed with the bug.

**High — silent under-recovery or over-recovery.** Emitting bytes as a file that
are not a file; silently dropping a recovery the operator asked for; carving
with unrelated evidence glued to the end of a file and reporting the result as
the file.

**Also a vulnerability — anything that writes outside its output directory.**
s0 takes a device path and a delete-everything method in the same invocation.
Path handling, output sanitisation, and the refusal to act on an unrecognised
target are security boundaries, not conveniences.

## Reporting a vulnerability

Report privately. Do not open a public issue for anything exploitable.

    security@your-domain.example

If you prefer, use GitHub's private vulnerability reporting on this repository.

Please include: the version or commit, the exact command, what you expected, what
happened, and the output. A minimal reproducer is worth more than a
description. If the issue is a false claim in a certificate, the certificate
JSON is the artifact of interest.

We aim to acknowledge within 3 working days and to give a fix or a mitigation
plan within 14. We will tell you when the fix lands and credit you unless you
would rather we did not.

## Scope

**In scope.** Everything in `src/s0/`, the CLI, the portals, the ISO and the
standalone launchers; the recovery, wipe and acquisition code paths; the signing
and certificate generation; the installers and packaging.

**Out of scope.** Vulnerabilities in upstream dependencies — report those
upstream, though we will track the fix here. Issues in `ffmpeg` reachable only
through a hostile media file, where we already refuse the file and say why.
Denial of service from a hostile image, *unless* it defeats the budget and
allocation guards rather than merely being slow.

## What we will not accept as a vulnerability

**A refusal.** s0 declines to size a format when the format does not state its
size. If a report says "s0 will not carve X", the answer is that this is
intended, and the reason is in the boundary notes. A refusal with a stated
reason is the tool working.

**A recovery that differs from an original by a byte.** Reassembling a
fragmented file involves inference. Where the inference is not evidence-backed,
s0 refuses rather than guesses. A request to guess anyway is a feature request.

**A certificate tier the device did not support.** s0 will not claim a tier it
cannot evidence, and will not accept one on request. This is invariant 2 of the
project's own plan and is not negotiable through a bug report.

## Keys

Only the demonstration issuer key is committed, so the tool runs out of the box
and the unaccredited nature of its certificates is visible in the output. A real
issuing authority key is generated out of band and stays out of band; the policy
is documented in `src/s0/data/keys/README.md` and enforced by `.gitignore` and
a pre-commit `detect-private-key` hook.

If you find a private key committed anywhere in this repository, that is a
vulnerability: report it, and do not attempt to use it.

## Hardening notes for operators

- Run against a hardware write blocker, or an image, for anything beyond a
  rehearsal. s0's own output is a report; it does not make acquisition safe.
- Verify certificates offline against the public key. The key is
  `s0_verify_certificate`.
- Treat a wipe as unverified unless the certificate carries the device's own
  attestation. For NVMe that is the Global Data Erased bit; a sampling proof
  bounds only what it sampled, and the bound is printed in the certificate.
