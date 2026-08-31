# TrustWipe — SIH 2026 Pitch Deck & Live Demo Script

**Problem Statement:** Secure Data Wiping & Verifiable Certification for E-Waste Management  
**Organization:** Ministry of Mines / JNARDDC (Jawaharlal Nehru Aluminium Research Development and Design Centre)  
**Team / Project:** TrustWipe  
**Format:** 5-Minute Pitch + 3-Minute Live Interactive Demonstration

---

## 1. The Crisis: Why Current E-Waste Sanitization is Broken

### The Context
India generates over **1.71 million metric tonnes of e-waste annually** (CPCB 2023). Under the *E-Waste (Management) Rules 2022* and *Digital Personal Data Protection Act (DPDPA 2023)*, government ministries, mining PSUs (e.g., NALCO, HCL, MECL), defense establishments, and corporate enterprises are legally obligated to sanitize retired IT storage devices prior to recycling or disposal.

### The Fatal Flaw in Existing Solutions:
1. **The PDF Forgery Epidemic:** Traditional wiping tools (and uncertified recyclers) issue standard PDF or printed certificates. Anyone can open these PDFs in Acrobat or Photoshop, change the drive serial number, alter "Failed" to "Passed", and fraudulently certify stolen or improperly erased drives.
2. **Proprietary Vendor Lock-in:** Commercial solutions (Blancco, BitRaser) charge high per-wipe licensing fees and store certificates on centralized vendor servers—creating single points of failure, privacy leakage, and recurring costs for government bodies.
3. **Misleading Compliance Claims:** Many tools advertise "DoD 7-pass wipe" on modern NVMe/SSDs—a legacy 1990s method that destroys hardware lifespan while failing to erase overprovisioned flash memory.

---

## 2. The Innovation: What TrustWipe Delivers

**TrustWipe** is an open-source, mathematically unforgeable, standards-compliant data sanitization and certification suite.

```
┌────────────────────────────────────────────────────────────────────────┐
│                        THE TRUSTWIPE ADVANTAGE                         │
├──────────────────────────────────┬─────────────────────────────────────┤
│ 1. NIST SP 800-88 & IEEE 2883   │ Real firmware-level Purge (NVMe,    │
│    Compliant Sanitization        │ ATA) & 1-pass Clear + FBE Destroy   │
├──────────────────────────────────┼─────────────────────────────────────┤
│ 2. Unforgeable Cryptography      │ Ed25519 digital signatures over     │
│                                  │ strict TrustWipe Canonical JSON v1  │
├──────────────────────────────────┼─────────────────────────────────────┤
│ 3. Zero-Trust Verification       │ Pure client-side static web portal  │
│    Portal (Zero Server / Cloud)  │ (offline, math-only verification)   │
├──────────────────────────────────┼─────────────────────────────────────┤
│ 4. Forensic Readback Assurance   │ Multi-point sampled readback + raw  │
│                                  │ grep scanning for planted markers   │
├──────────────────────────────────┼─────────────────────────────────────┤
│ 5. Universal Deployment Formats  │ CLI, Local Web GUI, & Bootable Live │
│                                  │ ISO for air-gapped field operations │
└──────────────────────────────────┴─────────────────────────────────────┘
```

---

## 3. Competitive Feature Matrix

| Feature | TrustWipe | Blancco / BitRaser | DBAN (Legacy) | Basic Overwrite Scripts |
|---|---|---|---|---|
| **Cryptographic Tamper-Evidence** | ✅ **Ed25519 Signed JSON** | ⚠️ Proprietary PDF/Server | ❌ None | ❌ None |
| **Verification Architecture** | ✅ **Zero-Trust Client-Side** | ❌ Centralized Cloud | ❌ None | ❌ None |
| **Forensic Sampling Readback** | ✅ **Automated 64-Block Scan** | ⚠️ Optional / Slow | ❌ None | ❌ None |
| **NIST 800-88 Method Enforcement** | ✅ **Schema-Level Constraints** | ⚠️ Marketing Claims | ❌ Outdated DoD | ❌ None |
| **Bootable Air-Gapped Kiosk** | ✅ **Debian Live ISO** | ✅ Proprietary ISO | ⚠️ CD/BIOS Only | ❌ Manual |
| **Licensing & Recurring Cost** | ✅ **100% Free / Open Source** | ❌ Expensive Per-Seat | ❌ Abandonware | ✅ Free |
| **Cross-Platform Architecture** | ✅ **Linux, Win, Android, Web** | ⚠️ OS Dependent | ❌ x86 Only | ❌ OS Specific |

---

## 4. Live 3-Minute Demonstration Script

### Minute 1: The Wipe & Forensic Proof
- **Presenter:** *"Judges, let us wipe a storage target containing simulated confidential mining telemetry and Aadhaar records."*
- **Action:** Execute `demo_e2e.sh`.
- **Display:**
  * Terminal displays 16 planted confidential markers.
  * TrustWipe CLI performs 1-pass zero wipe at high throughput with real-time throughput display.
  * Automated forensic audit runs: **0 marker hits remaining** across the entire drive.

### Minute 2: The Cryptographic Certificate & The Attack
- **Presenter:** *"The tool produces a signed JSON certificate and a formatted PDF with embedded QR code. Now, let us play the role of a malicious recycler who modifies the capacity or serial number on the certificate."*
- **Action:** Show the single-byte modification in `certificate.tampered.json`.
- **Result:** `trustwipe-verify` instantly outputs:
  ```text
  FAIL: signature does NOT match payload — the certificate content has been modified after signing
  ```
- **Presenter:** *"The mathematics of Ed25519 make tampering physically and cryptographically impossible."*

### Minute 3: The Zero-Trust Verification Portal
- **Presenter:** *"How does an auditor or ministry inspector verify this in the field without trusting our servers?"*
- **Action:** Open `verification-portal/index.html` in browser (offline).
  * Drag & drop authentic certificate -> **Shield turns GREEN: "AUTHENTIC & VERIFIED"**.
  * Drag & drop tampered certificate -> **Shield turns RED: "TAMPER DETECTED"**.
- **Presenter:** *"Trust the math, not our server."*

---

## 5. National Impact & JNARDDC Deployment Roadmap

```
Phase 1: SIH Prototype ──▶ Phase 2: Pilot Testing ──▶ Phase 3: National Standard
(Completed Core & ISO)    (JNARDDC ITAD Center)       (CPCB / Ministry Accreditation)
```

1. **Immediate Adoption for JNARDDC:** Deploy TrustWipe Live ISO across JNARDDC e-waste recycling pilot plants in Nagpur.
2. **Standardization for Ministry of Mines PSUs:** Mandate TrustWipe cryptographic certificates for all decommissioned IT assets across NALCO, HCL, and MECL.
3. **Ecosystem Enablement:** Provide the Verification Portal as a public service for banks, government departments, and citizens to verify recycled electronics authenticity.
