---
description: "Regulatory compliance matrices, legal standards, technical limitations, and cross-platform validation."
---

# Compliance, Limitations & Platforms

Regulatory mapping to international sanitization standards (NIST SP 800-88, IEEE 2883-2022, ISO/IEC 27037) alongside honest technical boundary disclosures and platform validation tables.

---

## Sections

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
      <td><strong>NIST SP 800-88 Compliance</strong></td>
      <td>Detailed mapping of s0 methods to Clear and Purge sanitization categories, retention rules, and legal court checklists.</td>
      <td><a href="nist-compliance.md">Compliance Guide</a></td>
    </tr>
    <tr>
      <td><strong>Technical Limitations</strong></td>
      <td>Honest disclosures regarding SSD Flash Translation Layer overprovisioning, Copy-on-Write redirections, and journal remnants.</td>
      <td><a href="limitations.md">Technical Limitations</a></td>
    </tr>
    <tr>
      <td><strong>Linux Platform Validation</strong></td>
      <td>Linux kernel 6.8+ storage operations, ioctl interfaces, BLKDISCARD behavior, and validation test status.</td>
      <td><a href="platforms/linux.md">Linux Validation</a></td>
    </tr>
    <tr>
      <td><strong>macOS Platform Validation</strong></td>
      <td>Darwin raw disk access (/dev/rdiskX), APFS snapshot persistence, SIP boundaries, and F_FULLFSYNC validation.</td>
      <td><a href="platforms/macos.md">macOS Validation</a></td>
    </tr>
    <tr>
      <td><strong>Windows Platform Validation</strong></td>
      <td>Win32 physical drive handles, NTFS Alternate Data Streams (ADS) scrubbing, and ReFS validation status.</td>
      <td><a href="platforms/windows.md">Windows Validation</a></td>
    </tr>
  </tbody>
</table>
