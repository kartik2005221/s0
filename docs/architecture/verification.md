# s0 — Verification Portal & Air-Gapped Verification Architecture  

---

## 1. What to Deploy to a Public Domain

The s0 Verification Portal is located in `site/verify/`. It is engineered as a **100% client-side, zero-backend, static web application**.

### 1.1 Deployment Bundle
Deploy the contents of the `site/verify/` directory:
```
site/verify/
├── index.html              # Interactive verification UI (drag-and-drop, QR scanner, payload viewer)
├── css/portal.css          # Modular portal stylesheet with light/dark themes
├── js/portal.js            # Client-side controller (PDF rendering, optical QR decode, theme toggle)
├── verify.js               # Pure JS verifier (s0 Canonical JSON v1 + Ed25519 validator)
├── keys.json               # Trusted authority public key registry (pinned keys & fingerprints)
├── fonts/                  # Self-hosted offline fonts (Rubik & JetBrains Mono woff2)
└── vendor/
    ├── crypto-bundle.js    # Self-contained crypto primitives (no CDN or external network needed)
    ├── pdf.min.js          # Pure client-side PDF document parser (PDF.js 3.11)
    ├── pdf.worker.min.js   # PDF.js Web Worker
    └── jsqr.min.js         # Pure client-side optical QR image decoder (jsQR 1.4)
```

### 1.2 Deployment Options (Zero-Backend Static Hosting)
Because the portal contains no server execution code (no Node, no Python, no PHP, no SQL):

1. **Cloudflare Pages (Official Production):**
   - *Production instance live at:* [https://sector-zero.pages.dev/verify/](https://sector-zero.pages.dev/verify/)
   - Connect repository or upload `site/verify/` folder.
   - Build command: *(leave empty / static)*
   - Output directory: `site/verify`
2. **GitHub Pages:**
   - In repo Settings -> Pages -> Source: Deploy from branch -> Folder: `/site/verify` (or copy to root of a `gh-pages` branch).
3. **Static Edge / Netlify Hosting:**
   - Framework preset: *Other / Static HTML*
   - Root directory: `site/verify`
4. **Self-Hosted Air-Gapped / Intranet Nginx:**
   ```nginx
   server {
       listen 80;
       server_name verify.s0.gov.in;
       root /var/www/s0/site/verify;
       index index.html;
       add_header X-Content-Type-Options nosniff;
       add_header Content-Security-Policy "default-src 'self' 'unsafe-inline' data: blob:;";
   }
   ```

---

## 2. Air-Gapped Forensic Reality & Offline Verification

### 2.1 The Air-Gapped Requirement in Secure Operations
In national security, defense agencies, and police cyber-cells, forensic laboratories and sanitized machines are strictly **air-gapped** (isolated from the internet and local networks):
- If certificate verification required a live cloud server or an online public blockchain (e.g. Ethereum or Solana), **the tool would be completely unusable inside an air-gapped facility**.
- Furthermore, transmitting certificates over the public internet exposes classified drive serial numbers, forensic image hashes, and case identifiers to third parties.

### 2.2 Why Cryptographic Key Verification is the Correct Architecture

s0 solves this by separating **Attestation** from **Verification** using asymmetric public-key cryptography (RFC 8032 Ed25519):

```
┌────────────────────────────────────────────────────────┐
│             AIR-GAPPED FORENSIC WORKSTATION            │
│                                                        │
│  [ Sanitization / Carving ]                            │
│             │                                          │
│             ▼                                          │
│  [ s0 Canonical JSON v1 Payload ]                     │
│             │                                          │
│             ▼                                          │
│  [ Ed25519 Sign with Private Key ] (Offline Key)       │
│             │                                          │
│             ▼                                          │
│  Outputs: certificate_xxxx.json / certificate_xxxx.pdf │
└────────────────────────────────────────────────────────┘
                           │
             (Air-gapped export via USB / QR)
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│             VERIFICATION PORTAL (ONLINE OR OFFLINE)    │
│                                                        │
│  • Pinned Public Key (keys.json)                       │
│  • Pure WebCrypto / TweetNaCl in Browser               │
│                                                        │
│  1. Compute SHA-256 of Canonical JSON Payload          │
│  2. Verify Ed25519(pinned_public_key, hash, signature) │
│                                                        │
│  Result: MATHEMATICAL PROOF OF INTEGRITY & AUTHORSHIP  │
│  (Zero Server Calls, Zero Leakage, Fully Air-Gapped)   │
└────────────────────────────────────────────────────────┘
```

### 2.3 Mathematical Proof of Non-Repudiation
1. **Deterministic Canonicalization (s0 Canonical JSON v1):**
   - Key order, whitespace, and string escaping are deterministically canonicalized into an unambiguous UTF-8 byte stream per the [s0 Canonical JSON v1 specification](certificate-spec.md). The spec deliberately deviates from RFC 8785/JCS on one point: float fields are forbidden at the schema level (all numeric values are integers), eliminating ES6 double-formatting ambiguity across languages without implementing it.
2. **Ed25519 Digital Signature (RFC 8032):**
   - The issuing authority signs the canonical byte digest with its private key:
     $$S = \text{Sign}_{K_{\text{priv}}}(\text{SHA256}(\text{Canonical}(P)))$$
3. **Client-Side Mathematical Check:**
   - The verifier loads the public key $K_{\text{pub}}$ from `keys.json` (or reads it from the certificate) and checks:
     $$\text{Verify}_{K_{\text{pub}}}(\text{SHA256}(\text{Canonical}(P)), S) \stackrel{?}{=} \text{TRUE}$$
   - If any actor modifies a single character (e.g., altering `bytes_processed` or changing `OVERWRITE_ZERO_1PASS` to `ATA_SECURE_ERASE`), the SHA-256 digest changes and verification **mathematically fails**.

---

## 3. How Offline Verification is Performed

An auditor or judge in an air-gapped court or SCIF has three offline options:

1. **Option A — Offline Web Browser (No Server Needed):**
   - Double-click `site/verify/index.html` (opens via `file:///` protocol in Chrome, Firefox, or Edge).
   - Drag and drop `certificate.json`.
   - `verify.js` executes purely in client memory and renders the green verification badge.
2. **Option B — Command-Line Offline Verifier:**
   - Run the included offline verification command:
     ```bash
     python -m s0.certcli verify --cert /path/to/certificate.json --key src/s0/data/keys/demo_issuer_public.pem
     ```
3. **Option C — Paper Certificate with Embedded QR Code:**
   - Scan the QR code printed on the official s0 PDF certificate.
   - The QR code contains the canonical certificate payload and signature directly, enabling mobile offline verification.

---

## 4. Trust Model: Pinned Keys (`keys.json`)

To prevent an adversary from generating their own key pair and signing a fraudulent certificate, the Verification Portal utilizes **Strict Public Key Pinning**:
- `keys.json` maintains the list of accredited issuing authorities (e.g., *Accredited Digital Forensics & Data Sanitization Lab*).
- When a certificate is evaluated, the portal compares the certificate's `public_key_fingerprint` against `keys.json`:
  - **Matched Pinned Key:** Display green `VALIDATED BY ACCREDITED AUTHORITY`.
  - **Unmatched Key with Valid Math:** Display amber `MATHEMATICALLY VALID BUT UNACCREDITED/UNKNOWN ISSUER KEY`.
  - **Tampered Content:** Display red `TAMPER DETECTED: SIGNATURE MISMATCH`.
