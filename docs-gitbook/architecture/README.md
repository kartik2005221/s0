---
description: "Core architecture, mathematical non-repudiation, threat modeling, and cryptographic specifications."
---

# System Architecture & Cryptography

Deep technical documentation detailing the internal design, security architecture, cryptographic contracts, and empirical performance metrics of s0.

---

## Architectural Core

<table data-view="cards">
  <thead>
    <tr>
      <th></th>
      <th></th>
      <th data-hidden data-card-target data-type="content-ref"></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>System Architecture</strong></td>
      <td>Three-tier architecture blueprint: UI presentation layer, core operational modules, and zero-trust cryptographic core.</td>
      <td><a href="system-architecture.md">System Architecture</a></td>
    </tr>
    <tr>
      <td><strong>Security Model &amp; Threat Matrix</strong></td>
      <td>Formal adversary capabilities, mitigations, key lifecycles, and physical hardware boundaries (FTL, CoW, journaling).</td>
      <td><a href="security-model.md">Security Model</a></td>
    </tr>
    <tr>
      <td><strong>Certificate Schema &amp; Canonical JSON</strong></td>
      <td>s0-cert-v1.0.0 JSON schema, pure Ed25519 digital signatures, and the 7 deterministic serialization rules of Canonical JSON v1.</td>
      <td><a href="certificate-spec.md">Certificate Specification</a></td>
    </tr>
    <tr>
      <td><strong>Verification &amp; Air-Gapped Trust</strong></td>
      <td>Air-gapped verification architecture, 100% in-browser WebCrypto execution, and optical QR trust workflows.</td>
      <td><a href="verification.md">Verification Architecture</a></td>
    </tr>
    <tr>
      <td><strong>Performance Benchmarks</strong></td>
      <td>Empirical I/O bus throughput benchmarks, NVMe bus saturation, and constant-memory (38-65 MiB RSS) streaming metrics.</td>
      <td><a href="performance.md">Performance Benchmarks</a></td>
    </tr>
  </tbody>
</table>
