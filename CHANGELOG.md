# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Everything below has landed on `agent/harness` and is verified by the suite
(1029 passed, 2 skipped at the time of writing). The changes are ordered by how
much they change what the tool *reports*, because that is the order in which
they matter to someone holding a report.

### Fixed

- **A failed NVMe sanitize was attested as successful.** SSTAT bits 3:0 are a
  status *code*, not a set of flags, but the decoder tested the field as a bit
  set. A completed sanitize read as *not* completed, and a **failed** sanitize
  read as *completed and not failed*. A drive that refused to erase attested as
  erased. The Global Data Erased bit -- the strongest evidence the specification
  offers -- was not decoded at all. The test suite had pinned the misreading: it
  asserted that "in progress" meant "completed".
- **Sanitize progress was off by a factor of 65536.** SPROG's denominator is
  65536, not 100, so a finished sanitize read as 0.15% complete.
- **The same bytes were reported twice under two names.** JPEG 2000 opens with a
  `ftyp` box naming the `jp2 ` brand, so the ISO-BMFF walker found a valid box
  tree inside a file that had already been recovered whole.
- **A resumed carve could report nothing while appearing to succeed.** A skip
  flag was threaded into the signature carver and not the filesystem one; the
  engine caught the resulting `NameError` and downgraded it to a warning.
- **An unknown-size Matroska Segment was rejected as absurdly oversized.** The
  all-ones VINT sentinel means "no size", not 2^56-1 bytes, and the sanity check
  ran before the unknown flag was tested.
- **Matroska padding was reported as video.** A run of `0x5a` parses as element
  `0x5A5A` with a size of 6746, which fits any carve window.
- **Frame extents ran past the end of the file.** The cluster offset was added
  to an already-absolute offset.
- **A freshly formatted volume lost every Matroska fragment.** A zero-size box
  means "to the end of the file" in ISO-BMFF, and the shared box walker
  normalises it that way.
- **TIFF resolved 6 bytes short, zstd 4 bytes short**, and every registry hive
  and every Java class file was refused outright. Details in the commit history.
- **An ISO download could be redirected to a local file.** The asset URL comes
  from a GitHub API response and was written straight to disk, so a `file://` or
  plain `http://` value would have turned a release download into a local file
  read. There is now a scheme check.

### Added

- **Fragment reassembly ordered by the key inside each fragment.** `mfhd`
  sequence numbers, `tfdt` decode times and Matroska cluster timestamps survive
  fragmentation, so the ordering is read rather than inferred. Byte-exact
  recovery under every permutation tried, including exact reverse order, with
  unrelated evidence between each piece. 46% of real fragmented recordings are
  laid out out of order, which is what defeats every forward-scanning carver.
- **Matroska and WebM carving**, including unknown-size Segments and clusters.
- **Hash-set suppression**, applied to both the signature and the
  filesystem-native paths, with every suppression attributed to an algorithm and
  counted rather than silently dropped.
- **Bodyfile output**, including the gaps -- the ranges searched and found
  nothing, which for fragmented work is the finding.
- **Resume-able sessions.** A session is evidence about a past run and never
  about the present: a file it names that is no longer there is reported, and a
  session taken against a different image is refused.
- **Name and path provenance.** exFAT, FAT32 and ext4 cannot recover a path
  from a deleted record; the report now says so in a sentence rather than
  printing a null or assembling a path from whatever directories still parse.
- **Structural boundaries for twelve container formats** that previously had a
  signature and no way to size the file, including exact decompression-derived
  lengths for bzip2, xz, lzma, zstd and lz4.
- **A sampling proof with its bound attached**, because a sample says nothing
  about the bytes it did not read.
- **CI on every branch** rather than `master` only, across Python 3.10-3.13,
  with ruff, mypy, bandit, pip-audit, CodeQL, actionlint, shellcheck, hadolint
  and an SBOM.
- `SECURITY.md`, `CODEOWNERS`, `.editorconfig`, `.gitattributes`, pre-commit,
  Dependabot and this changelog.

### Not done

- No sanitize was executed during development: there is no NVMe, ATA or SCSI
  sanitizer in the test environment, so command construction is verified against
  the specification and the decoders against synthesised log pages, but the
  drivers remain untested against hardware. This limitation is carried in the
  method docstrings and surfaced as certificate notes.
- ext4 jbd2 filename recovery is deferred to last. It is the one item whose
  central claim cannot be verified in this environment.
- Compressed TIFF is refused rather than sized. A compressed strip's length is
  not its byte count, so the strip geometry gives a confident wrong answer.
- Clusters whose header was overwritten are not reconstructed. With no in-band
  key left, any position is a guess, and a guessed position yields a file that
  plays the wrong footage rather than no footage.
- The ~1,286 pre-existing ruff findings are not cleared. The lint gate is a
  ratchet: it hard-fails on changed files and reports the backlog as a notice. A
  wall would be red from the first commit, and a gate that is always red is one
  people learn to ignore.
