# Contributing to s0

> **License:** MIT License  
> **Engineering Discipline:** High-Assurance, Test-Driven, Absolute Engineering Honesty  
> **Repository:** [github.com/kartik2005221/s0](https://github.com/kartik2005221/s0)

---

## 1. Welcome & Code of Conduct

Thank you for your interest in contributing to **s0 (Sector Zero)**. s0 is an open-source digital forensic sanitization and evidence recovery suite engineered for incident responders, law enforcement cyber cells, defense contractors, and enterprise security auditors.

Because this tool is deployed in legal evidentiary contexts and compliance-critical data destruction scenarios, we maintain rigorous engineering standards:
- **No Floating-Point Numbers in Cryptography:** Canonical JSON must remain deterministic across all architectures and languages.
- **Mathematical Non-Repudiation:** Every action must be cryptographically auditable.
- **Absolute Engineering Honesty:** We never exaggerate capabilities. If a method does not work on a specific filesystem (such as CoW on Btrfs/ZFS) or hardware architecture (such as overprovisioned flash cells on SSDs), that boundary must be explicitly disclosed in the code, logs, certificates, and documentation.

---

## 2. Codebase Architecture & File Layout

```
s0/
├── core/                               # Cross-platform cryptographic foundation
│   ├── cert_schema.json                # Schema v1.0.0 for certificates & manifests
│   ├── CANONICAL_JSON.md               # Deterministic canonical serialization spec
│   ├── keys/                           # Demo public/private authority keys
│   └── python/s0_core/                 # Python reference implementation
│       ├── canonical.py                # s0 Canonical JSON v1 encoder
│       ├── crypto.py                   # Ed25519 key generation, sign & verify
│       ├── certificate.py              # Certificate builder & validation logic
│       └── pdfgen.py                   # ReportLab PDF generator with QR codes
├── linux/cli/s0_cli/                   # Linux & unified CLI suite
│   ├── main.py                         # Unified argument parser (all subcommands)
│   ├── devices.py                      # Block device & raw image inventory
│   ├── wipe.py                         # Module 1: Drive & media erasure orchestrator
│   ├── file_eraser.py                  # Module 1: File & folder cluster sanitizer
│   ├── temperature.py                  # Real-time thermal telemetry probe
│   ├── methods/                        # Sanitization method drivers
│   │   ├── base.py                     # Method abstract base class & Plan contract
│   │   ├── nvme.py                     # NVMe Sanitize & Format drivers
│   │   ├── ata.py                      # ATA Secure Erase & HPA/DCO detection
│   │   ├── blkdiscard.py               # BLKDISCARD ioctl wrapper
│   │   └── overwrite.py                # Multi-pass zero & CSPRNG random overwriter
│   ├── carver/                         # Module 2: Forensic file recovery
│   │   ├── engine.py                   # Raw stream & signature sliding window scanner
│   │   ├── signatures.py               # Magic byte definitions (JPEG, PNG, PDF, etc.)
│   │   ├── ext4_carver.py              # Superblock, block group & inode extent parser
│   │   ├── ntfs_carver.py              # Master File Table ($MFT) & runlist parser
│   │   ├── fat_carver.py               # FAT32 BPB & deleted directory entry carver
│   │   ├── exfat_carver.py             # exFAT VBR & directory entry set carver
│   │   ├── fragmentation.py            # Bifragment stream reassembly
│   │   └── scoring.py                  # Heuristic & Shannon entropy confidence scorer
│   ├── imager.py                       # Module 3: Bit-stream forensic imager & cloner
│   └── audit/                          # Supporting: Hash-chained audit ledger
│       ├── ledger.py                   # SQLite3 append-only ledger & hash-chaining
│       └── verify.py                   # Genesis-to-tip mathematical continuity auditor
├── windows/                            # Windows native file/folder sanitizer (Win32 FlushFileBuffers, ADS)
├── macos/                              # macOS native file/folder sanitizer (F_FULLFSYNC, xattr cleansing)
├── web/                                # FastAPI unified web dashboard (4 forensic tabs)
├── verification-portal/                # 100% client-side zero-backend static verifier
├── docs/                               # GitBook technical documentation suite
└── scripts/                            # Master build, test, and installer orchestrators
```

---

## 3. Development Setup

### Prerequisites
- Python 3.10+ (Python 3.12 or 3.14 recommended)
- Git
- OpenSSL / libsodium (standard on modern Linux/macOS)

### One-Command Automated Setup
The fastest way to initialize the development environment and verify your toolchain is running the master build orchestrator:

```bash
git clone https://github.com/kartik2005221/s0.git
cd s0
bash scripts/build_all.sh
```

`build_all.sh` will:
1. Automatically create and configure the `.venv` virtual environment.
2. Install all core and CLI packages in editable development mode (`pip install -e`).
3. Execute all 190+ unit and integration tests.
4. Validate verification portal cryptographic assets and documentation deliverables.

---

## 4. How to Add a New File Carving Signature

Adding support for a new file format to **Module 2 (File Carver)** requires adding an entry to `linux/cli/s0_cli/carver/signatures.py`:

```python
from .signatures import FileSignature, SIGNATURES

SIGNATURES.append(
    FileSignature(
        name="WebP Image",
        extension="webp",
        category="image",
        header=b"RIFF....WEBP",          # Header pattern (or exact magic bytes)
        footer=None,                     # Optional trailing boundary pattern
        min_size=64,                     # Minimum plausible byte length
        max_size=25 * 1024 * 1024,       # Maximum file size cap (25 MB)
    )
)
```

### Signature Guidelines:
- Keep `min_size` realistic to eliminate false-positive micro-fragments.
- For formats with variable footers, leave `footer=None` and ensure the size validator or entropy checker correctly scores the segment.
- Add an automated test case in `linux/cli/tests/test_carver.py` with a synthetic test image containing the planted header.

---

## 5. How to Add a New Sanitization Method

New wiping drivers inherit from `s0_cli.methods.base.Method`:

```python
from s0_cli.devices import Target
from s0_cli.methods.base import Candidate, Method, MethodResult, Plan

class CustomPurgeMethod(Method):
    method_id = "CUSTOM_HARDWARE_PURGE"
    nist_category = "Purge"

    def probe(self, target: Target) -> Candidate:
        if self._is_supported(target):
            return Candidate(method=self, available=True, reason="Hardware purge supported")
        return Candidate(method=None, available=False, reason="Hardware controller unsupported")

    def plan(self, target: Target) -> Plan:
        return Plan(
            method_id=self.method_id,
            nist_category=self.nist_category,
            summary="Custom controller-level purge sequence",
            commands=["ioctl(CUSTOM_PURGE_OP)"],
            warnings=[]
        )

    def run(self, target: Target, progress_cb) -> MethodResult:
        ...
        return MethodResult(status="success", bytes_processed=target.capacity_bytes)
```

Register your method in `s0_cli/methods/__init__.py` and add its identifier to `core/cert_schema.json` under `/properties/wipe/properties/method/enum`.

---

## 6. Running the Test Suite

Always ensure all test suites pass before submitting a pull request:

```bash
.venv/bin/pytest core/tests linux/cli/tests web/tests windows/cli/tests macos/cli/tests verification-portal/tests -v

.venv/bin/pytest --cov=s0_core --cov=s0_cli --cov-report=term-missing
```

### Critical Quality Invariants:
1. **Canonical JSON Golden Vectors:** `core/tests/test_canonical.py` validates byte-level serialization against `core/tests/data/canonical_vectors.json`. Never alter these vectors without formal RFC review.
2. **The Tamper Matrix:** `core/tests/test_tamper.py` systematically mutates every field, character, and delimiter in a valid certificate. Every single mutation must be caught and rejected by the verifier.
3. **End-to-End Forensic Demo:** `bash linux/cli/demo_e2e.sh` creates a sparse test image, plants secret markers, executes sanitization, samples blocks, verifies 0 hits, and confirms certificate verification.

---

## 7. Documentation Contributions

The documentation is published via **GitBook** and synced directly from Git via Git Sync. All documentation pages reside in standard GitHub Flavored Markdown with GitBook syntax extensions (hints, tabs, and card tables).

When contributing to documentation:
- Place new guides or reference documents in their relevant directory (`getting-started/`, `guides/`, `architecture/`, `compliance/`, or `project/`).
- Register every new page in `SUMMARY.md` to include it in the sidebar navigation tree.
- Use `{% hint style="info|success|warning|danger" %}` blocks for callouts and `{% tabs %}` for multi-platform commands.
- Ensure all internal cross-links use proper relative markdown paths.

---

## 8. Pull Request Checklist

Before submitting your PR:
- [ ] Code is formatted cleanly and includes type hints (`from __future__ import annotations`).
- [ ] All 190+ automated tests pass (`pytest` runs 100% green).
- [ ] Schema changes in `core/cert_schema.json` are mirrored in `verification-portal/verify.js` and `core/python/s0_core/`.
- [ ] Documentation has been updated to reflect any new CLI flags, methods, or limitations.
- [ ] Any added pages are linked in `SUMMARY.md`.
