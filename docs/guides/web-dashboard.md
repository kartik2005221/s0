# Web Dashboard Operator Guide

> **Interface Type:** Local Forensics Operator Console  
> **Backend Architecture:** FastAPI (Python 3.10+) asynchronous server  
> **Frontend Stack:** Vanilla HTML5, CSS3 (Forensic Dark Theme `#222831`), JavaScript (Zero external framework dependencies)  
> **Default Bind Address:** `127.0.0.1:8669` (Strict loopback isolation)

---

## 1. Overview & Architecture

The **s0 Web Dashboard** provides a responsive, visual operating console for investigators and lab technicians who prefer a graphical interface over the command line.

Crucially, the Web Dashboard is **not a separate engine**. It runs the exact same cryptographic, sanitization, and carving routines as the `s0` CLI:
- Initiating a drive wipe from the web browser writes to the **same** local SQLite ledger (`~/.s0/s0_audit.db`).
- Carving from the web dashboard uses the **same** structure and entropy scoring engines.
- Certificates issued through the dashboard carry the identical Ed25519 digital signatures and Canonical JSON structure.

```mermaid
graph TD
    CLI[s0 Command-Line Interface] --> CORE[s0 Core & Methods Engine]
    WEB[FastAPI Web Console 127.0.0.1:8669] --> CORE
    
    CORE --> LEDGER[(Shared Blockchain Audit Ledger ~/.s0/s0_audit.db)]
    CORE --> CERTS[Signed Certificates .json / .pdf / .qr.png]
```

---

## 2. Launching the Dashboard

Launch directly using the native `sudo s0 web` command:

```bash
# Launch the web dashboard and automatically open in default browser
sudo s0 web
```

Or customize port and network binding:
```bash
# Launch on custom port without auto-opening browser
sudo s0 web --port 8669 --no-browser
```

{% tabs %}
{% tab title="Script Runner (Linux & macOS)" %}
```bash
# Start via standalone script runner
sudo bash web/run.sh
```
{% endtab %}
{% tab title="Script Runner (Windows)" %}
```powershell
# Launch via PowerShell script runner (Run as Administrator)
.\web\run.ps1
# Or in CMD: web\run.bat
```
{% endtab %}
{% endtabs %}

{% hint style="info" %}
**Privilege Requirements & Limited Mode**
Direct physical drive sanitization and bit-stream disk imaging require root privileges (`sudo s0 web`) to access raw storage block devices (`/dev/sd*`, `/dev/nvme*`). If launched without `sudo`, the web dashboard automatically operates in **Limited User Mode**: an alert banner appears, direct drive wiping is faded/restricted for safety, while file and directory wiping remains completely functional.
{% endhint %}

{% hint style="warning" %}
**Security & Network Exposure**
The dashboard is explicitly engineered for **local, single-operator forensic workstations**. By default, it binds strictly to `127.0.0.1` (localhost). Do not bind to `0.0.0.0` or expose the dashboard port to an untrusted local area network without authentication proxies, as it possesses the authority to perform irreversible storage erasure.
{% endhint %}

---

## 3. The Forensic Operating Modules

### Tab 1: Secure Drive Eraser

The Drive Eraser tab automates whole-media sanitization:

```
┌────────────────────────────────────────────────────────────────────────┐
│ [TAB 1: DRIVE ERASER]                                                  │
├────────────────────────────────────────────────────────────────────────┤
│ Target Device: [/dev/sdb - Samsung SSD 870 500GB (465.8 GiB)]       ▼  │
│ Recommended Profile: [NIST SP 800-88 Purge (ATA Secure Erase)]        │
│ Overwrite Passes: [1]   Pattern: [Zero Overwrite (0x00)]               │
│ Operator Identity: [analyst-07]  Organization: [Cyber Crime Cell]      │
│                                                                        │
│ Safety Confirmation: Type exact target path: [ /dev/sdb     ]          │
│                                                                        │
│ [ ■ START PERMANENT SANITIZATION ]                                     │
├────────────────────────────────────────────────────────────────────────┤
│ PROGRESS: [████████████████████████████░░░░] 78.4%                     │
│ Speed: 482 MB/s | Elapsed: 00:08:12 | ETA: 00:02:15 | Temp: 38°C       │
└────────────────────────────────────────────────────────────────────────┘
```

#### Step-by-Step Drive Sanitization Workflow:
1. **Select Target Device:** Choose from the auto-detected list of non-root block devices. Any mounted partitions are flagged with a prominent warning badge.
2. **Review Recommended Tier:** The system analyzes device geometry and controller bus (NVMe vs SATA vs USB) to recommend the highest applicable NIST SP 800-88 tier (`Purge` or `Clear`).
3. **Configure Operator Metadata:** Enter your forensic operator ID and organization name for inclusion in the tamper-evident certificate.
4. **Safety Confirmation Gate:** To prevent accidental destruction of secondary evidence drives, the `Start Sanitization` button remains locked until the operator explicitly types the exact target device path (e.g. `/dev/sdb`).
5. **Real-Time Telemetry Stream:** Monitor the live SVG progress bar, real-time read/write throughput, estimated time remaining, and real-time controller thermal telemetry (queried every 2 seconds via Linux `hwmon` or SMART).
6. **Certificate Receipt:** Upon completion, the dashboard renders direct download buttons for the signed `.json` certificate and the official printable `.pdf` report.

---

### Tab 2: Secure File & Folder Eraser

Designed for targeted evidence sanitization, GDPR/DPDPA data destruction requests, or sanitizing sensitive staging folders:

```
┌────────────────────────────────────────────────────────────────────────┐
│ [TAB 2: FILE & FOLDER ERASER]                                          │
├────────────────────────────────────────────────────────────────────────┤
│ Target Paths (one per line):                                           │
│ ┌────────────────────────────────────────────────────────────────────┐ │
│ │ /home/investigator/evidence/case_89/suspect_chat_export.pdf        │ │
│ │ /tmp/extracted_archive_dump/                                       │ │
│ └────────────────────────────────────────────────────────────────────┘ │
│ Overwrite Passes: [1]   Fill Pattern: [Crypto Random Overwrite (0x??)] │
│                                                                        │
│ [ EXECUTE TARGETED SANITIZATION ]                                    │
├────────────────────────────────────────────────────────────────────────┤
│ Status: Processed 48 files (1.2 GiB). All clusters overwritten.        │
│ Timestamps zeroed (1970-01-01). Directory entries randomized.         │
│ Issued Batch Certificate: certificate_8f21bc90.json                    │
└────────────────────────────────────────────────────────────────────────┘
```

#### Capabilities & Behavior:
- **In-Place Cluster Overwriting:** Allocations are overwritten in-place before unlinking to prevent residual sector carving.
- **Timestamp Zeroing:** Modification (`mtime`) and access (`atime`) timestamps are reset to epoch zero (`1970-01-01T00:00:00Z`).
- **Filename Scrambling:** Directory entry names are replaced with randomized alphanumeric strings prior to unlinking, scrubbing filename traces from directory nodes.
- **Copy-on-Write Warnings:** If paths reside on Btrfs, ZFS, or APFS volumes, the dashboard displays an inline advisory warning that snapshot or block redirect semantics may preserve historical extents.

---

### Tab 3: Forensic File Carver

The Carver tab recovers deleted artifacts from disk images (`.raw`, `.img`, `.dd`) or raw storage devices without mounting the volume:

```
┌────────────────────────────────────────────────────────────────────────┐
│ [TAB 3: FORENSIC FILE CARVER]                                          │
├────────────────────────────────────────────────────────────────────────┤
│ Image / Block Source: [/evidence/seized_usb_stick.raw]                 │
│ Target Extensions:  [x] JPG  [x] PNG  [x] PDF  [x] ZIP  [ ] ELF  ...    │
│ Minimum Confidence Threshold: [ 65% ] ────────────●───────             │
│ Destination Output Directory: [/home/investigator/recovered_cases]     │
│                                                                        │
│ [ START EVIDENCE CARVING ]                                           │
├────────────────────────────────────────────────────────────────────────┤
│ Carved Artifacts Table:                                                │
│ ID       Type   Size       Confidence  SHA-256 (Prefix)  Action        │
│ CRV_001  PDF    2.4 MiB    95%         4a8f910b2c1...    [ Download ]  │
│ CRV_002  JPG    480 KiB    88%         b1c900e478a...    [ Download ]  │
│ CRV_003  ZIP    14.1 MiB   70%         8e12ff98012...    [ Download ]  │
│                                                                        │
│ Total Artifacts Recovered: 38 | Manifest: carving_manifest_1092a.json  │
└────────────────────────────────────────────────────────────────────────┘
```

#### Key Capabilities:
- **Filesystem-Aware Acceleration:** Automatically detects ext4 (inode extents) or NTFS ($MFT) structures to index recovered files in seconds.
- **Custom Magic Byte File Signatures:** Define proprietary or uncataloged file signatures directly in the browser by expanding ** Custom File Signatures**. Enter custom header magic bytes (e.g. `53 45 43 55`), optional footer bytes (e.g. `00 00 45 4F 46`), format name, and target extension. The carver automatically injects these into the raw stream and filesystem parsers alongside built-in signatures.
- **Entropy & Confidence Filtering:** Use the interactive confidence slider to filter out fragmented noise or corrupted candidates before exporting.
- **Instant Triage:** Review extracted file sizes, SHA-256 hashes, and download recovered artifacts directly from the browser table.

---

### Tab 4: Forensic Imager & Cloner

Module 3 provides bit-stream forensic acquisition (raw `.dd` image creation) and physical disk-to-disk bit-stream cloning with real-time SHA-256 verification:

```
┌────────────────────────────────────────────────────────────────────────┐
│ [TAB 4: FORENSIC IMAGER & CLONER]                                      │
├────────────────────────────────────────────────────────────────────────┤
│ Operation Mode: (●) Bit-Stream Image (.dd)   ( ) Disk-to-Disk Clone    │
│ Source Block / Image: [/dev/sdb - Crucial CT500MX (465.8 GiB)]       ▼ │
│ Destination Target:   [/evidence/seized_drive_sdb.dd]                  │
│ Block Size: [1M]   Fault Policy: [Zero-Fill Bad Sectors (Forensic dd)] │
│                                                                        │
│ [ START FORENSIC ACQUISITION ]                                         │
├────────────────────────────────────────────────────────────────────────┤
│ PROGRESS: [████████████████████████████████] 100.0%                    │
│ Telemetry: Copied 500.1 GB | Speed: 320 MB/s | Bad Sectors: 0          │
│ Source SHA-256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca49... │
│ Destination SHA-256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b...  │
│ [ DOWNLOAD MANIFEST (JSON) ]  [ DOWNLOAD CERTIFICATE (JSON) ]          │
└────────────────────────────────────────────────────────────────────────┘
```

#### Imager & Cloner Capabilities:
- **Bit-Stream DD Imaging:** Byte-level read-only bit-stream extraction directly to raw forensic image files with real-time telemetry streaming.
- **Disk-to-Disk Physical Cloning:** Clones physical media directly to secondary target drives, guarded by an interactive confirmation safety gate requiring typing the destination drive path.
- **SHA-256 Integrity Verification:** Computes the streaming SHA-256 hash of both source and destination simultaneously, guaranteeing identical forensic images.
- **Resilient Bad Sector Handling:** Configurable fault tolerance allowing non-stop acquisition through failing hardware with automatic bad sector logging and zero-filling.
- **Tamper-Evident Manifests:** Generates structured JSON acquisition manifests and Ed25519-signed forensic certificates.

---

### Tab 5: Cryptographic Audit Ledger

The Audit Ledger tab provides visual verification of the forensic chain of custody:

```
┌────────────────────────────────────────────────────────────────────────┐
│ [TAB 5: CRYPTOGRAPHIC AUDIT LEDGER]                                    │
├────────────────────────────────────────────────────────────────────────┤
│ Ledger Status:  [ VALID & CONTINUOUS (42 Blocks Verified) ]            │
│ [ VERIFY CHAIN CONTINUITY ]  [ EXPORT AUDIT LOG (JSON) ]               │
│                                                                        │
│ Timeline:                                                              │
│ • Block #42 | DRIVE_ERASE  | 2026-09-09 14:22:15 UTC | analyst-07     │
│   Hash: 4b227777d4dd1fc6... | Prev: 88c019a2e41bf901... | Target: sdb │
│   Signature: 9a2f4c1e... [Ed25519 Valid]                              │
│                                                                        │
│ • Block #41 | FILE_CARVE   | 2026-09-09 11:05:40 UTC | investigator-4 │
│   Hash: 88c019a2e41bf901... | Prev: f100e49ab88190c3... | Target: raw │
│   Signature: 1c33b00e... [Ed25519 Valid]                              │
│                                                                        │
│ • Block #00 | GENESIS      | 2026-09-01 09:00:00 UTC | system-init    │
│   Hash: 0000000000000000... | Prev: 0000000000000000... | Initialized │
└────────────────────────────────────────────────────────────────────────┘
```

#### Auditor Functions:
- **One-Click Hash Chain Verification:** Computes the mathematical SHA-256 continuity and Ed25519 block signature verification from the genesis block to the tip in under 20 milliseconds.
- **Tamper Simulation & Detection:** If any actor manually edits or removes an entry in the SQLite database file, clicking `Verify Chain Continuity` immediately flags the exact block index where hash continuity or cryptographic signatures broke.
- **Inspect Block Payloads:** Click on any block to expand the raw signed canonical JSON payload, certificate UUID, and operator attribution.

---

### Tab 6: Forensic Certificate Portal

The Certificate Portal allows instant, offline, zero-trust verification of signed certificates issued by s0:
- **Air-Gapped Operation:** Pure client-side Web Crypto verification with zero network dependencies.
- **Multi-Format Ingestion:** Drop any `.json` certificate issued by s0, upload an official `.pdf` sanitization certificate for optical QR decoding, or paste/drop raw QR code images to instantly inspect cryptographic proofs.
- **Custom Key Verification:** Verify certificates issued by independent authorities by providing raw SPKI PEM or 64-character Ed25519 public keys.

---

## 4. Workstation Interface Features

### High-Contrast Light & Dark Theme Toggle
Both the primary Web Dashboard and the Verification Portal feature an instant theme toggle in the top navigation header:
- **Default Dark Mode:** High-contrast forensic aesthetic with deep blacks (`#000000`), subtle cards (`#070D18`), and signature orange accents (`#FF6500`).
- **Clean Light Mode:** Professional daytime workstation palette (`#F8FAFC` canvas, crisp `#FFFFFF` cards, navy terminal slate `#0F172A`).
- **Persistent State:** Theme preference is remembered via `localStorage` across all tabs and browser restarts, with zero page flicker on reload.

### Strict Offline Air-Gapped Typography
To ensure 100% air-gapped forensic operation without external telemetry leaks:
- Both web interfaces strictly load self-hosted **Rubik** (sans-serif UI) and **JetBrains Mono** (terminal, hexadecimal, hashes, and code metrics).
- All Google Fonts CDN links have been removed in favor of local `.woff2` font bundles served directly from `/static/fonts/` and `/fonts/`.

### Central Workspace Configuration (`s0_config.json`)
The Web Dashboard automatically reads `/home/kartik/s0/s0_config.json` via `/api/config` on startup:
- Default operator identifier, laboratory name, output directory, and verification URLs are automatically pre-populated into all dashboard forms.
- If customized in `s0_config.json`, the entire workstation reflects the updated organization details immediately upon page load.

