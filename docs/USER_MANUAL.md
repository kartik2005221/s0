# TrustWipe — User & Forensic Operator Manual (NTRO / SIH26149)

**Target Audience:** Digital Forensic Investigators, Cybersecurity Incident Responders, NTRO Field Technicians, and System Evaluators.  
**Version:** 2.0.0 (SIH26149 Release)

---

## 1. Quickstart & Installation

```bash
# Clone and enter directory
cd sih26149

# Run master build orchestrator (automatically sets up .venv and installs dependencies)
bash scripts/build_all.sh
```

---

## 2. Command-Line Interface (CLI) Manual

All functions are unified under `trustwipe-wipe` (or `python -m trustwipe_cli.main`).

### 2.1 Module 1: Secure Drive Eraser
- **Inventory Disks:**
  ```bash
  trustwipe-wipe list
  ```
- **Dry-Run Planning:**
  ```bash
  trustwipe-wipe plan --target /dev/sda
  ```
- **Execute Drive Sanitization:**
  ```bash
  trustwipe-wipe wipe --target /dev/sda --yes --operator "op-ntro-01" --organization "NTRO Forensic Lab"
  ```

### 2.2 Module 2: Secure File & Folder Eraser
- **Sanitize Specific Files / Folders:**
  ```bash
  trustwipe-wipe erase-files       --targets /path/to/classified_doc.pdf /path/to/sensitive_folder/       --passes 1       --pattern zero       --out-dir ./certificates
  ```

### 2.3 Module 3: Advanced File Carving & Recovery
- **Carve Evidence from Formatted Media / Disk Image:**
  ```bash
  trustwipe-wipe carve       --target /evidence/suspect_drive.raw       --out-dir ./recovered_evidence       --extensions jpg,png,pdf,zip       --min-confidence 50
  ```

### 2.4 Module 4: Blockchain Cryptographic Audit Ledger
- **List Audit Blocks:**
  ```bash
  trustwipe-wipe audit list --limit 20
  ```
- **Verify Blockchain Hash-Chain Continuity:**
  ```bash
  trustwipe-wipe audit verify
  ```

---

## 3. Local Web Dashboard

Launch the unified 4-module web console:
```bash
bash gui/run.sh
```
Open `http://127.0.0.1:8000` in your web browser.

**Dashboard Capabilities:**
1. **Drive Eraser Tab:** Visual device selector, NIST category recommendation, confirmation gate, and real-time progress bar.
2. **File Eraser Tab:** Batch file path input, pattern selection, and instant sanitization with metadata cleansing.
3. **Forensic Carver Tab:** Target image selection, file format filters, minimum confidence threshold, and interactive table of carved artifacts.
4. **Blockchain Audit Ledger Tab:** Live block timeline, block details inspector, and one-click cryptographic hash-chain verification.
