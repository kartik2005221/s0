# Canonical JSON v1, Ed25519 Signatures & Audit Ledger

This reference defines the cryptographic standards, deterministic serialization rules, and blockchain ledger architecture implemented in `s0`.

---

## 1. s0 Canonical JSON v1 (RFC 8785)

Digital signatures require deterministic, bit-for-bit identical byte representation regardless of runtime language, operating system, or JSON parser. `s0` implements strict deterministic canonicalization:

1. **Object Keys Sorted Lexicographically**:
   Keys are sorted strictly by Unicode code point values: `keys.sort()`.
2. **Whitespace Stripped**:
   No spaces after delimiters: separators are strictly `(',', ':')`.
3. **Floating Point Normalization**:
   Integers are formatted without decimal points; floating-point values follow IEEE 754 shortest representation.
4. **UTF-8 Encoding**:
   Output is encoded strictly as UTF-8 bytes without BOM.
5. **Signature Field Exclusion**:
   When computing or verifying signatures, the `signature` key itself is omitted from the canonicalized payload.

---

## 2. Ed25519 Digital Signatures (RFC 8032)

Every certificate emitted by `s0` is signed using Ed25519:
- **Algorithm**: PureEd25519 (Ed25519ph not used; raw message is signed).
- **Curve**: Curve25519 with SHA-512 digest.
- **Key Length**: 32-byte private seed; 32-byte public key.
- **Fingerprint**: Hex-encoded SHA-256 digest of the DER-encoded `SubjectPublicKeyInfo` structure:
  ```text
  # SubjectPublicKeyInfo fingerprint format
  sha256:<hex_digest>
  ```

---

## 3. Blockchain Audit Ledger Hash Formula

Every operation appends an immutable block to `~/.s0/s0_audit.db`. The `block_hash` is computed as:

```text
block_hash = SHA256(
    index            || ":" ||
    timestamp        || ":" ||
    operation_type   || ":" ||
    target_id        || ":" ||
    operator_id      || ":" ||
    cert_uuid        || ":" ||
    payload_hash     || ":" ||
    signature        || ":" ||
    previous_hash
)
```

### Tamper-Evidence Invariant:
If an attacker modifies a database record in row $N$, its recomputed `block_hash` will fail to match. Furthermore, because block $N+1$ incorporates block $N$'s hash into its own digest, the hash continuity of every subsequent block in the chain breaks simultaneously.
`s0 audit verify` recomputes the entire chain from genesis (block 0) and asserts mathematical continuity.
