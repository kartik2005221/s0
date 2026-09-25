---
description: "Comprehensive guides and operator manuals for sanitization, carving, disk acquisition, web dashboard, and CLI."
---

# Guides & Operator Manuals

Practical operational manuals and engineering guides for forensic technicians, examiners, and system administrators using the s0 toolchain.

---

## Guide Directory

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
      <td><strong>User &amp; Operator Manual</strong></td>
      <td>Authoritative manual covering all four primary modules: drive erasure, in-place cluster sanitization, file carving, and disk imaging.</td>
      <td><a href="user-manual.md">User Manual</a></td>
    </tr>
    <tr>
      <td><strong>Secure Data Erasure Guide</strong></td>
      <td>Detailed engineering analysis of firmware sanitization (NVMe Sanitize, ATA Secure Erase), BLKDISCARD, and surgical file unlinking.</td>
      <td><a href="secure-erasure.md">Erasure Guide</a></td>
    </tr>
    <tr>
      <td><strong>Forensic File Carving Guide</strong></td>
      <td>Recover deleted evidence using 5 filesystem engines (ext4, NTFS, FAT32, exFAT, and raw magic bytes) with confidence scoring.</td>
      <td><a href="forensic-carving.md">Carving Guide</a></td>
    </tr>
    <tr>
      <td><strong>Bare-Metal Live ISO Guide</strong></td>
      <td>Build and deploy the Debian 12 Bookworm bootable appliance for offline host-level drive sanitization.</td>
      <td><a href="live-iso.md">Live ISO Guide</a></td>
    </tr>
    <tr>
      <td><strong>Web Dashboard Console</strong></td>
      <td>Guide for the local FastAPI console (127.0.0.1:8669) featuring interactive wipe confirmation and telemetry graphs.</td>
      <td><a href="web-dashboard.md">Dashboard Guide</a></td>
    </tr>
    <tr>
      <td><strong>CLI Reference</strong></td>
      <td>Complete flag-by-flag documentation for all subcommands (list, plan, wipe, image, clone, carve, audit, verify, keygen).</td>
      <td><a href="cli-reference.md">CLI Reference</a></td>
    </tr>
  </tbody>
</table>
