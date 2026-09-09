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

Every operation appends a cryptographically chained block to `~/.s0/s0_audit.db`. The `block_hash` is computed as:

```text
block_hash = SHA256(
    block_index      || "|" ||
    timestamp        || "|" ||
    operation_type   || "|" ||
    target_id        || "|" ||
    operator_id      || "|" ||
    organization     || "|" ||
    cert_uuid        || "|" ||
    payload_hash     || "|" ||
    signature        || "|" ||
    prev_hash
)
```

### Tamper-Evidence & Block Signing Invariants:
1. **In-Place Modification Detection:** If an attacker modifies any field in block $N$, its recomputed `block_hash` fails to match the stored digest. Furthermore, because block $N+1$ incorporates block $N$'s hash into its own digest via `prev_hash`, the hash continuity of every subsequent block breaks simultaneously.
2. **Deletion & Replacement Defense:** Each block's `block_hash` is signed with the authority's Ed25519 private key (`block_signature`). An attacker with local database access who deletes an incriminating block and renumbers/recomputes downstream hashes cannot generate valid block signatures without possessing the Ed25519 private key.
3. `s0 audit verify [--key <path>]` traverses genesis→tip, asserting hash continuity, canonical certificate payload integrity, and Ed25519 block signature authenticity against pinned authority keys.
