/**
 * s0 Offline Pinned Keys and Sample Certificate Data
 *
 * Pre-populates trusted keys and sample data to enable 100% offline file:/// execution
 * without encountering browser CORS null-origin restrictions on fetch().
 */
window.S0_TRUSTED_KEYS = [
  {
    "issuer": "s0 Demo Lab (unaccredited development key)",
    "fingerprint": "sha256:8396af8c07a7d40f98ba492cf2b61e23fa768e66a9f627b02a9caff464e48c06",
    "public_key_spki_pem": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA4viQlkj0bHna+uhXpU+r4LjzhKG5nq3tGMih9VoR7K0=\n-----END PUBLIC KEY-----",
    "public_key_raw_hex": "e2f8909648f46c79dafae857a54fabe0b8f384a1b99eaded18c8a1f55a11ecad",
    "status": "active"
  }
];
