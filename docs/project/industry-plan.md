# S0 — Industry-Grade Development Plan

Status: **active** · Branch: `agent/harness` · Never touch `master`.

This document is the execution contract for turning s0 from a working prototype into an
industry-grade forensic sanitization, acquisition and recovery product.

---

## 0. Reproduced defects (verified by direct testing, 2026-09-29)

### D1 — "recovery always returns the same set of files" (CONFIRMED, root-caused)

Three *completely different* 20 MiB targets produced **exactly 33 "recovered files"** each
time, always the same file *types* in the same order:

| target | candidates | "recovered" | output bytes |
|---|---:|---:|---:|
| random blob A | 366 | **33** | ~60 MB |
| random blob B | 387 | **33** | ~60 MB |
| 64 MiB mixed image | 1206 | **111** | **194 MB** (3× input size) |

Root causes, all in `linux/cli/s0_cli/carver/`:

1. **`engine.py:508-519` — header-only formats carve to end-of-buffer.**
   For any signature without a `footer` (13 of 19: `bmp`, `elf`, `sqlite`, `flac`, `ogg`,
   `7z`, `pcap`, `pcapng`, `gz`, and 4 × `mp3` variants) the code does
   `end_pos = min(len(data) - idx, sig.max_size)`. `data` is only the current 2 MiB read
   window, so **every match emits a full ~2 MiB blob of garbage**.
2. **`scoring.py:104-107` — header-only formats get +15 free**, and there is **no structural
   validation at all** for `flac`/`ogg`/`7z`/`pcap`/`pcapng`/`bmp`/`elf` beyond the first few
   bytes. Score floors at 55, above the default `--min-confidence 50`.
3. **`signatures.py:102-107` — `\xff\xfb`/`\xff\xf3`/`\xff\xfa` (MPEG audio sync) and `BM`
   are 2-byte magics.** They occur by chance roughly every 64 KiB of *any* data. 20 MiB →
   ~330 bogus candidates. The one that is emitted per chunk is always the same type, always
   the same score → "the same set of files, every time".
4. **`engine.py:555` — `pos = idx + max(len(sig.header), len(carved_data))`** means one carve
   suppresses every later match of that signature inside the same 2 MiB window, which is
   what makes the count deterministic at `1 per signature per chunk` (= 33).
5. **No output budget.** 202,329,138 bytes were written from a 67,108,864-byte input.
6. **`engine.py:485-488` — footer search is confined to the current 2 MiB window**, so any
   file larger than `chunk_size + overlap` (2.06 MiB) can *never* have its footer found. It
   silently degrades to the bifragment heuristic.
7. **Entropy is used backwards as a false-positive filter** (`scoring.py:123-132`): random
   noise scores H≈8.0 and is rewarded with +20 "consistent with compressed media".
8. **Ranking is meaningless** — files are listed in discovery order, so the 5 real 100%
   files sit next to 97 fake 55% files with no category summary, no "notable" section and
   no report of bytes wasted.

Correct behaviour observed for contrast: on a real ext4 image with unlinked inodes, the
**filesystem-native path** recovered all 5 deleted files at 100% with correct inode numbers
(`carved_00001_ext4_inode13_100pct.pdf`, …). The gap is that this path is only a
last-resort fallback *after* signature carving floods the results, and it never reports
original paths, deletion timestamps or cluster runs.

### D2 — Verification portal rejects s0's own PDFs (CONFIRMED, browser-reproduced)

`Failed to parse PDF document: Cannot read properties of undefined (reading 'height')`

Three compounding root causes:

1. **`verification-portal/js/portal.js:241`** renders **only page 1**. `core/python/s0_core/pdfgen.py`
   emits a 2-page A4 certificate whenever the device/wipe/signature tables overflow — the QR
   lands on **page 2**. Verified in Chromium: page 1 QR decode → `null`; page 2 QR decode →
   the complete signed certificate JSON.
2. **`portal.js:199-203`** retries with `inversionAttempts: "onlyInvert"`. The vendored jsQR
   build throws `TypeError` inside `locate()` for that value, at **every** scale (1/2/3/4).
   Measured: `dontInvert → null`, `onlyInvert → THROW`, `attemptBoth → null`.
   The exception propagates out of `decodeQrFromCanvas`, so the text-layer fallback at
   `portal.js:264-275` (which would have found the UUID) is **unreachable**.
3. **The text-layer fallback only reads page 1** as well, and there is no `try/catch`
   isolation between decode attempts.

### D3 — Dashboard is broken when opened without the `?token=` URL (CONFIRMED)

`web/app.py:513` `index()` serves `static/index.html` verbatim. `dashboard.js:116` looks for
`<meta name="s0-auth-token">` or `window.appConfig.auth_token` — **neither exists**. Opening
`http://127.0.0.1:8669/` (bookmark, kiosk, restarted server, old tab) yields `401` on
`/api/config`, `/api/devices`, `/api/capabilities` with no user-visible error.

### D4 — Certificate data-quality defects (CONFIRMED on a real issued PDF)

* `Type / storage: internal_disk / UNKNOWN` — a **file** wipe reports `internal_disk`.
* `Post-wipe verification: 1 samples × 0 B` — `sample_bytes_each` is 0 for file wipes.
* `⚠️`/`⚖` render as tofu boxes (ReportLab Helvetica has no emoji glyphs).

---

## 1. Implementation phases

### Phase 0 — Defect repair (P0)
| ID | Work | File(s) |
|---|---|---|
| 0.1 | Rewrite boundary resolution: per-format `calculate_size`, structural validators, frame-sequence validation | `carver/signatures.py`, `carver/boundary.py` (new) |
| 0.2 | Output budget, per-category caps, ranked + categorised report, "bytes wasted" accounting | `carver/engine.py` |
| 0.3 | Streaming carve that can exceed one chunk (fix the 2 MiB footer ceiling) | `carver/engine.py` |
| 0.4 | Portal: multi-page PDF scan, safe jsQR wrapper, always-reachable text fallback | `verification-portal/js/portal.js` |
| 0.5 | Dashboard: server-side token injection into `index.html` | `web/app.py` |
| 0.6 | Certificate field correctness (`storage_type`, verification sample fields, no emoji in PDF) | `core/python/s0_core/pdfgen.py`, `file_eraser.py` |

### Phase 1 — Unified CLI contract (P1)
`sysexits`-based exit codes · `--format text|json|csv` on every subcommand · stdout=data /
stderr=chrome · `NO_COLOR`/`--color` · `--quiet`/`--verbose`/`--yes` · width-aware tables ·
non-TTY degradation · eight-section help everywhere · `tests/test_cli_contract.py`.

### Phase 2 — Portal consistency (P1)
One token source · identical header/nav/footer shell · self-hosted fonts · strict CSP
(hash-based, no `unsafe-inline`) · SRI on vendored JS · WCAG 2.2 AA pass · `prefers-color-scheme`
· reduced-motion · `THIRD_PARTY_NOTICES.md` + `vendor/manifest.json`.

### Phase 3 — Filesystem-native recovery (P2, highest product value)
Free-space-only search space (PhotoRec `remove_used_space` model) · NTFS deleted MFT run-lists
with **original names** · NTFS USN journal path reconstruction · ext4 deleted-inode extents ·
FAT32/exFAT 8.3 + LFN recovery · recovered **original paths** and deletion timestamps ·
resume-able sessions (`photorec.ses` model).

### Phase 4 — Carving engine v2 (P2)
Container-length-driven boundaries (PNG chunk walk, RIFF walk, MP4/EBML atoms, Ogg page walk,
CFB, tar, 7z, SQLite, PCAPNG) · MP3/AAC frame-sequence validation · streaming decompress to
boundary (gzip/xz/zstd) · Aho-Corasick single-pass multi-pattern search · first-byte bucketed
dispatch · hash-set suppression of known files · bodyfile output · two-phase (incremental +
deep) structural validation.

### Phase 5 — Industry-grade sanitization (P2)
Capability ladder (crypto/block-erase/sanitize → secure discard → overwrite → **refuse**) ·
ATA SANITIZE `0xB4` · **NVMe Sanitize `0x84`** (research corrected the widely-repeated wrong
opcode `0xF4`) · SCSI SANITIZE `0x48` · `nvme-cli`/`hdparm`/`sg_sanitize` drivers ·
NVMe log `0x81` GLOBAL DATA ERASED attestation · SMART before/after delta · HPA/DCO reset ·
state-machine (SD0–SD4) handling · **refuse silent downgrade** · statistical sampling proof
with recorded confidence bound · **NIST SP 800-88 Rev. 2 (2025-09-26) + IEEE 2883-2022**
terminology in certificates.

### Phase 6 — Professionalization (P3)
Single-source version · `importlib.resources` package data (fixes a latent install bug) ·
CI matrix + ruff/mypy/bandit/pip-audit/CodeQL/actionlint/shellcheck/hadolint/SBOM ·
`SECURITY.md`, `CODEOWNERS`, `.editorconfig`, `.gitattributes`, pre-commit, dependabot ·
Keep-a-Changelog `CHANGELOG.md`.

---

## 2. Non-negotiable invariants

1. Never claim a sanitization tier the evidence does not support.
2. Never silently downgrade a requested method.
3. Never emit a carved artifact the tool cannot structurally justify.
4. Every signed artifact must be reproducible and offline-verifiable.
5. `master` is never touched. All work lands on `agent/harness`.
6. Push between phases.
