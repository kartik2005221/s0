# s0 Canonical JSON v1

Every component that signs or verifies an s0 certificate — the Python core (`src/s0/canonical.py`)
and the static verification portal (`site/verify/verify.js`) — MUST produce byte-identical canonical
form for the same logical object. This document is the contract. Each implementation is tested against the
golden vectors in `tests/core/data/canonical_vectors.json` and against certificates produced by the reference
implementation.

*(Future roadmap: Windows native C# app and Android Kotlin app will implement this same spec when delivered.)*

## Rules

Given a parsed JSON value, serialize as follows:

1. **Encoding.** UTF-8, no BOM.
2. **Objects.** Keys sorted lexicographically by Unicode code point, recursively at every depth.
3. **Whitespace.** None beyond required syntax: separators `,` between items and `:` between
   key and value; no newlines, no indentation, no trailing newline.
4. **Strings.** Minimal escaping: `"` → `\"`, `\` → `\\`, and control characters U+0000–U+001F
   using `\b \f \n \r \t` for those five and `\u00XX` (lowercase hex) for the rest. All other
   characters appear literally (non-ASCII characters are NOT `\uXXXX`-escaped).
   This matches ECMAScript `JSON.stringify` and Python `json.dumps(ensure_ascii=False)` for all
   well-formed strings.
5. **Numbers.** Integers only, base-10, no leading zeros, optional leading `-`, no exponent,
   no fraction. **Schema v1 defines no float fields anywhere** — sizes are integer bytes,
   durations integer seconds. An implementation encountering a float while canonicalizing a
   certificate payload MUST refuse rather than guess a format. This rule exists because float
   formatting is where independent implementations diverge; removing floats removes the entire
   problem class. (Deliberate deviation from RFC 8785/JCS, which specifies ES6 number
   formatting — we chose schema-level avoidance over implementing ES6 double-formatting in four
   languages.)

     **Integers are additionally bounded at 2^53 - 1 inclusive.** A JavaScript `Number` is an
     IEEE-754 double, so `JSON.parse` silently rounds anything larger and re-serialising produces
     different bytes. A certificate carrying `12345678901234567890` was therefore hashed
     correctly by the Python verifier and reported `TAMPERED_OR_CORRUPT` by the browser portal:
     two implementations of this specification giving opposite answers about the same signed
     bytes. An implementation MUST refuse an integer outside +/-(2^53 - 1) rather than
     canonicalize it. This costs nothing real: at 512-byte sectors, 2^53 bytes is 8 PiB, far
     beyond any medium that exists. Both `src/s0/canonical.py` and `site/verify/verify.js`
     enforce this, and the golden vector `integer_above_exact_range_is_refused` in
     `tests/core/data/canonical_vectors.json` pins the behaviour.
6. **Literals.** `true`, `false`, `null`.
7. **Arrays.** Order preserved as-is (arrays are ordered by design).

Reference implementation: `src/s0/canonical.py`.

## Signing scheme

- Signature algorithm: **Ed25519** (RFC 8032), pure Ed25519 (not Ed25519ph/ctx).
- Payload: the canonical form (per above) of the certificate object **excluding the entire
  `signature` member**.
- Signature encoding: base64url (RFC 4648 §5), padding stripped.
- Public key distribution: PEM SubjectPublicKeyInfo; identified by fingerprint =
  `"sha256:" + lowercase hex of SHA-256 over the DER-encoded SubjectPublicKeyInfo`.
- The signature block records `signed_payload_hash` (`"sha256:<hex>"` of the payload) for human
  display only. Verifiers MUST recompute the canonical payload and check the Ed25519 signature;
  the hash field is an annotation, not evidence.

```text
payload_bytes = canonicalize(cert_minus_signature)
sig           = ed25519.sign(private_key, payload_bytes)
cert.signature = {algorithm: "Ed25519",
                  public_key_fingerprint: fp(public_key),
                  signature_base64url: b64url_unpadded(sig),
                  signed_payload_hash: "sha256:" + sha256hex(payload_bytes)}

verify: recompute payload_bytes from received cert (minus signature),
        ed25519.verify(pinned_public_key, payload_bytes, sig) == true
```

Tamper property: any change to any signed field — one byte, one key name, whitespace inside a
string value — changes the canonical payload and invalidates the signature. Re-serializing the
same object with different key order produces identical bytes, so legitimate re-encoding never
breaks verification. Both properties are enforced by tests: `tests/core/test_tamper.py` walks
every leaf of a valid certificate, mutates each, and asserts failure.
