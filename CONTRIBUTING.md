# Contributing to s0

Thank you for your interest in contributing to **s0 (Sector Zero)**! 

s0 is an open-source, forensic-grade drive sanitization, file recovery, and cryptographic audit suite. Because s0 operates on raw hardware block devices, filesystem allocation tables, and court-admissible cryptographic evidence, contributions are held to rigorous standards of **mathematical precision, data safety, and engineering transparency**.

---

## 1. Code of Conduct

All contributors, maintainers, and community participants are expected to adhere to our [Code of Conduct](CODE_OF_CONDUCT.md) (Contributor Covenant v2.1). Please review it before participating in discussions or submitting pull requests.

---

## 2. Reporting Issues & Security Vulnerabilities

### Reporting Bugs & Feature Requests
- Check the [issue tracker](https://github.com/kartik2005221/s0/issues) to ensure your issue or feature request has not already been reported.
- When filing a bug, include:
  - Operating system and kernel release (`uname -a` or Windows build)
  - Python version (`python3 --version`)
  - Target storage device model, bus interface (NVMe, SATA, USB), and capacity
  - Exact command line executed (with non-sensitive paths)
  - Full terminal output or traceback

### Reporting Security Vulnerabilities
If you discover a vulnerability affecting data destruction guarantees, signature verification bypasses, or elevation of privilege:
- **Do not open a public GitHub issue.**
- Submit a confidential report via GitHub Security Advisories or contact the project maintainers directly.
- We practice coordinated vulnerability disclosure and will respond promptly to review and remediate confirmed issues.

---

## 3. Development Setup

### Prerequisites
- Python 3.10+ (tested through Python 3.14)
- Git
- `gcc`, `make`, and standard POSIX utilities (Linux/macOS)
- Platform-specific build tools:
  - **Linux:** `hdparm`, `nvme-cli`, `util-linux` (`blkdiscard`, `lsblk`)
  - **macOS:** Xcode command-line tools (`xcode-select --install`)
  - **Windows:** PowerShell 5.1+ or PowerShell Core 7+

### One-Command Setup
Clone the repository and run the master bootstrap script, which creates the local virtual environment (`.venv`), installs all platform dependencies, and runs the entire test suite:

```bash
# Clone repository
git clone https://github.com/kartik2005221/s0.git
cd s0

# Run automated development bootstrap and test orchestrator
bash scripts/build_all.sh
```

*(On Windows, run `.\scripts\build_all.ps1` or `scripts\build_all.bat`).*

---

## 4. Codebase Architecture

```
s0/
├── core/                         # Cryptographic & canonicalization engine
│   ├── python/s0_core/           # Canonical JSON v1 serializer, Ed25519 signer
│   ├── cert_schema.json          # s0-cert-v1.0.0 JSON Schema
│   └── tests/                    # Cryptographic test vectors & tamper matrix
├── linux/cli/s0_cli/             # Master CLI binary and controller drivers
│   ├── wipe/                     # Hardware erasure waterfalls & cluster overwrite
│   ├── carver/                   # 5 recovery engines (signatures, ext4, NTFS, FAT)
│   ├── imager/                   # Bit-stream disk acquisition & cloning
│   └── audit/                    # SQLite SHA-256 hash-chained audit ledger
├── web/                          # Local web dashboard console (FastAPI)
├── windows/                      # Native Windows Win32 ctypes & ADS drivers
├── macos/                        # Native macOS Darwin APFS & F_FULLFSYNC drivers
├── docs/                 # GitBook documentation site (5 sections, 28 pages)
├── gitbook-docs.yaml             # GitBook site-wide Git Sync configuration
├── verification-portal/          # Standalone client-side zero-trust verifier
└── install-portal/               # Cross-platform installation scripts
```

---

## 5. Running Tests

Every pull request must pass all tests across the 5-layer QA pyramid:

```bash
# Run the complete automated test suite
.venv/bin/pytest core/tests linux/cli/tests web/tests windows/cli/tests macos/cli/tests verification-portal/tests -v

# Run with test coverage
.venv/bin/pytest --cov=s0_core --cov=s0_cli --cov-report=term-missing
```

### Critical Invariants to Preserve:
1. **Canonical JSON Golden Vectors:** `core/tests/test_canonical.py` validates byte-level serialization against `core/tests/data/canonical_vectors.json`. Never modify these golden vectors without formal architectural RFC.
2. **The Tamper Matrix:** `core/tests/test_tamper.py` mutates every field, character, and delimiter in a valid certificate. Every single mutation must be detected and rejected by the verifier.
3. **No Floating-Point Discipline:** Schema v1 strictly forbids floats to prevent cross-language stringification divergence. All sizes are integer bytes; all durations are integer seconds.
4. **End-to-End Forensic Demo:** Run `S0_DEMO_SIZE_MIB=32 bash linux/cli/demo_e2e.sh` to verify end-to-end wiping, 64-block sampling, and certificate issuance on synthetic images.

---

## 6. Extending s0

### Adding File Carving Signatures
To add support for recovering a new file type, register its magic bytes in `linux/cli/s0_cli/carver/signatures.py`:

```python
BUILTIN_SIGNATURES["webp"] = FileSignature(
    extension="webp",
    header=b"RIFF....WEBP",    # Use dots (.) for wildcard bytes
    footer=None,
    max_size=50 * 1024 * 1024,
    description="WebP Image"
)
```

### Adding Sanitization Drivers
Sanitization methods inherit from `Method` in `linux/cli/s0_cli/wipe/methods/base.py`:
- Implement `probe(target)` returning applicability, NIST classification (Clear or Purge), and risks.
- Implement `run(target, progress_cb)` returning `MethodResult`.
- Register the method identifier in `core/cert_schema.json`.

---

## 7. Documentation Contributions

All documentation is maintained in `docs/` and published to [https://s0-docs.gitbook.io](https://s0-docs.gitbook.io).

When contributing to documentation:
- Add or edit markdown files inside `docs/` under their logical section (`getting-started/`, `guides/`, `architecture/`, `compliance/`, or `project/`).
- Every new page must be registered in [`docs/SUMMARY.md`](docs/SUMMARY.md) to appear in sidebar navigation.
- Use `{% hint style="info|success|warning|danger" %}` for callouts and `{% tabs %}` for multi-platform command examples.
- Use relative markdown links between pages (e.g. `[Manual](../guides/user-manual.md)`).

---

## 8. Pull Request Checklist

Before submitting your pull request, please verify:

- [ ] Code follows PEP 8 conventions, includes strict type annotations (`from __future__ import annotations`), and docstrings.
- [ ] All 190+ automated unit and integration tests pass (`.venv/bin/pytest`).
- [ ] Any modifications to `core/cert_schema.json` are reflected in `verification-portal/verify.js` and `core/python/s0_core/`.
- [ ] New CLI flags, methods, or limitations are documented in `docs/guides/cli-reference.md` and related guides.
- [ ] Added documentation pages are registered in `docs/SUMMARY.md`.
- [ ] `bash scripts/build_all.sh` completes cleanly with zero errors.
