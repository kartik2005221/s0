# Carving Benchmark: s0 vs PhotoRec

The board asked for two things: fix the NTFS carver, and *"see photorec and
take inspiration from it"*. This page records both halves — the study that
informed the fixes, and a reproducible measurement harness.

## Running the benchmark

```bash
# s0's column runs anywhere:
.venv/bin/python -I tools/benchmark_carving.py --out benchmark-out

# PhotoRec's column needs the tool:
sudo apt install testdisk
.venv/bin/python -I tools/benchmark_carving.py --out benchmark-out
```

The harness plants six known files (JPEG, PNG, GIF, PDF, ZIP, WAV) in empty
space on a raw 64 MiB image — no filesystem metadata, exactly the surface
both signature carvers operate on — runs each tool headlessly, and grades
recoveries **byte-exact by SHA-256** against the planted originals. "Found
something at that offset" is not credit; only the exact original bytes are.

## Measured results

| Tool | Planted | Recovered byte-exact | Notes |
|---|---|---|---|
| **s0 carve** | 6 | **6 / 6** | jpg, png, gif, pdf, zip, wav — all SHA-256 exact; signed recovery index emitted |
| photorec | 6 | *pending tool install* | run the harness after `sudo apt install testdisk` |

Raw JSON results are written to `benchmark-out/carving-benchmark-<timestamp>.json`
alongside each run.

## What the PhotoRec study changed in s0

PhotoRec (TestDisk 7.x) is the industry reference for signature carving. The
study — source-level, since no vendored copy ships — identified five
properties, and each one was acted on:

1. **Per-format validation of every candidate** (PhotoRec's `file_check`
   hooks). s0 already had `validate_structure` covering ~24 formats, but the
   statistical entropy gate ran *ahead of* most validators because the
   `_STRUCTURALLY_VALIDATED` frozenset was stale at 8 entries — fixed, and a
   drift-guard test now pins the set to the dispatch chain mechanically.
2. **Breadth of the signature database** (~480 families). s0's table was
   extended with the forensically relevant families the existing machinery can
   size honestly: **Windows Event Log (evtx)** with a chunk-walking boundary
   resolver, **ISO 9660** sized from its Primary Volume Descriptor, and **SVG**
   footer-anchored. Adding families without an honest end-rule is exactly what
   s0 refuses to do, so breadth grows only where a resolver or footer exists.
3. **`remove_used_space()`** — PhotoRec's single largest yield improvement.
   s0 already implements the equivalent (`FreeSpaceMap` + gate in the engine);
   verified, not changed.
4. **Filesystem-native recovery is where s0 is deliberately ahead.** PhotoRec
   discards names; s0 recovers deleted files with their original names,
   timestamps, and paths from the MFT, the USN change journal, and now the
   ext4 jbd2 journal (previously parsed but never wired in). The NTFS fixes
   shipped alongside this benchmark — multi-level path reconstruction,
   split-$DATA reassembly across satellite records, record-size geometries,
   and boot-sector validation with backup fallback — close correctness gaps
   PhotoRec shares (its deleted-file recovery is signature-only).
5. **Fragmented FAT32 files.** PhotoRec carves signatures, so fragmentation
   hurts it too; s0's FAT carver at least follows live chains now (deleted
   entries keep the contiguous-prefix convention, honestly labelled).

## Known limits (stated, not hidden)

- The harness measures signature-carving recall on planted files. It does not
  measure filesystem-native recovery (names/timestamps), where PhotoRec has no
  equivalent column to compare against.
- The PhotoRec column is populated only on a machine with testdisk installed;
  the CI environment does not carry it. The harness skips with a notice
  instead of pretending to a number.
