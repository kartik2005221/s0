# Carving Signatures, File Formats & Entropy Heuristics

This reference specifies the 10 magic-byte signatures, filesystem structure engines, and statistical scoring heuristics implemented in `s0 carve`.

---

## 1. Supported File Formats Matrix

| Extension | Category | Magic Header (Hex / ASCII) | Footer / EOF Marker | Max Carve Size | Default Min Entropy |
|---|---|---|---|---|---|
| `jpg` | Image | `FF D8 FF` | `FF D9` | 30 MB | 7.2 bits/byte |
| `png` | Image | `89 50 4E 47 0D 0A 1A 0A` | `49 45 4E 44 AE 42 60 82` | 30 MB | 7.4 bits/byte |
| `pdf` | Document | `%PDF-` (`25 50 44 46`) | `%%EOF` | 50 MB | 5.5 bits/byte |
| `zip` | Archive/OpenXML | `PK\x03\x04` (`50 4B 03 04`) | Central Directory Record | 100 MB | 7.5 bits/byte |
| `gif` | Image | `GIF87a` / `GIF89a` | `00 3B` | 20 MB | 6.8 bits/byte |
| `gz` | Archive | `1F 8B 08` | CRC-32 + ISIZE (8 bytes) | 50 MB | 7.5 bits/byte |
| `bmp` | Image | `BM` (`42 4D`) | Bi-level length field check | 30 MB | 4.0 bits/byte |
| `elf` | Executable | `7F 45 4C 46` (`\x7fELF`) | Section Header Table | 50 MB | 5.8 bits/byte |
| `sqlite` | Database | `SQLite format 3\0` | B-tree page size validation | 100 MB | 4.5 bits/byte |
| `mp3` | Audio | `49 44 33` (ID3v2) / `FF FB` | Frame header sync | 15 MB | 7.0 bits/byte |

!!! note "Office OpenXML & Compressed Archives"
    The `zip` signature also natively extracts Microsoft Office Open XML (`.docx`, `.xlsx`, `.pptx`), Java archives (`.jar`), and Android packages (`.apk`), which are packaged inside standard ZIP containers.

---

## 2. Confidence Scoring Algorithm

Every candidate file evaluated during carving is assigned an integer confidence score from `0` to `100` calculated across four independent forensic heuristics:

```text
Confidence Score = HeaderMatch (30 pts)
                 + FooterMatch (30 pts)
                 + SizePlausibility (20 pts)
                 + EntropyProfile (20 pts)
```

1. **Header Match (30 points)**:
   Exact match against the registered specification magic bytes at the initial boundary offset.
2. **Footer Match (30 points)**:
   Detection of an authentic closing EOF marker (e.g. `FF D9` for JPEG or `%%EOF` for PDF) within the maximum file size boundary.
3. **Size Plausibility (20 points)**:
   Carved stream length falls within realistic statistical bounds for the format (e.g. SQLite database $\ge$ 512 bytes; JPEG $\ge$ 100 bytes).
4. **Shannon Entropy (20 points)**:
   Shannon entropy is computed across 3 sampled 4096-byte blocks (start, middle, and end). Rejects zero-filled blocks (entropy $\approx 0$) or corrupt non-compressed random streams masquerading as compressed media.

---

## 3. Filesystem-Aware Structure Engines

Before falling back to raw sliding-window signature carving, `s0 carve` probes target images for file system metadata structures:

- **NTFS ($MFT Engine)**:
  Parses the Master File Table ($MFT). Reads 1024-byte MFT records, inspects `$FILE_NAME` and `$DATA` attributes, and reassembles non-resident multi-cluster runlists.
- **ext4 (Inode Engine)**:
  Parses block group descriptors, reads inode allocation bitmaps, and traverses extent trees (`i_block` structure) to recover deleted Linux files with exact names and timestamps.
- **FAT32 / exFAT (Directory Entry Engine)**:
  Scans directory sectors for deleted entry markers (`0xE5` in FAT32; `0x05`/`0x85` in exFAT). Extracts file size and starting cluster pointer directly from directory tables.
