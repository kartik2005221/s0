# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.0] - 2026-10-05

Sector Zero 3.0.0 unifies the data sanitization, cryptographic attestation, and deleted file carving engines into a single consolidated distribution with hardened safety verification.

### Breaking changes and migration from 2.x

**The distribution is now one package, not two.** `master` shipped `s0-core`
(`core/python/`) and `s0-cli` (`linux/cli/`) as separate distributions with separate
entry points. Both are now the single distribution `s0`, importable as `s0`, with one
console script. If you had both installed, uninstall both before installing v3:

```bash
pip uninstall -y s0-core s0-cli
pip install .  # or pip install git+https://github.com/kartik2005221/s0.git
```

The importable names moved with it. `s0_core.*` and `s0_cli.*` no longer exist:

| 2.x | 3.0 |
|---|---|
| `s0_core.canonical` | `s0.canonical` |
| `s0_core.crypto` | `s0.crypto` |
| `s0_core.certificate` | `s0.certificate` |
| `s0_core.audit` | `s0.audit` |
| `s0_core.carve` | `s0.carve` |
| `s0_core.wipe` | `s0.wipe` |
| `s0_cli.main` | `s0.cli.main` |
| `s0_cli.wipe` | `s0.wipe` |

The platform engines moved too: `macos.cli.s0_eraser` and `windows.cli.s0_eraser` are
now `s0.platform.macos.s0_eraser` and `s0.platform.windows.s0_eraser`, and they ship
inside the wheel. On 2.x they were top-level packages that `pyproject.toml` did not
package, so an installed (rather than cloned) copy had no wipe engine at all and
reported a drive as having "zero or unreadable capacity".

**The repository layout moved under `src/`.** `core/python/s0_core/` and
`linux/cli/s0_cli/` became `src/s0/`. The two sites `verification-portal/` and
`install-portal/` are now one `site/` directory, and `scripts/` is now `tools/`. If
you have tooling, CI jobs or `.gitignore` rules pointing at the old paths they need
updating; nothing at runtime depends on the checkout layout any more.

**The demo signing key moved, and the old lookup was CWD-dependent.**
`s0_config.json`'s `default_key_path` was `core/keys/demo_issuer_private.pem`, which
`default_issuer_key()` resolved relative to the repository root *or* relative to the
current working directory -- so running s0 from a directory that happened to contain a
`core/keys/` picked up a different key depending on where you were standing. It is now
`src/s0/data/keys/demo_issuer_private.pem`, resolved through package resources, so the
key is the same wherever you run the tool from.

**Exit codes changed.** 2.x returned bare `0`, `1` and `2` from the CLI -- 37 separate
`return 2` sites, and argparse's own usage error also being 2. 3.0 uses the
`sysexits.h` convention, defined once in `s0.terminal`:

| Meaning | 2.x | 3.0 |
|---|---|---|
| success | 0 | 0 |
| ran and failed | 1 | 1 |
| bad flags or arguments | 2 | **64** |
| supplied data malformed | 2 | **65** |
| input missing or unreadable | 2 | **66** |
| refused, or insufficient privileges | 2 | **77** |
| configuration error | 2 | **78** |
| interrupted (SIGINT) | 1 | **130** |

If you gate on exit codes, `s0 <cmd> && next_step` still works, but a script that
distinguished 1 from 2 no longer can, and one that treated 2 as "bad flags" now has to
test 64. Full table: `docs/guides/cli-reference.md`, "Exit Codes". Note that a non-zero
exit is never a success: `s0 live flash` declining and `s0 plan` refusing a mounted
target both return non-zero where 2.x returned 0.

**`--dry-run` is now a real guard, and it is fail-closed.** On 2.x the flag was
attached to every subcommand by the shared parent parser but read only by `wipe` on its
block-device path, so `s0 image --dry-run` wrote a full image, `s0 clone --dry-run`
cloned, `s0 carve --dry-run` wrote carved files and appended to the audit ledger,
`keygen` wrote a private key, `live download` pulled ~550 MB, `upgrade` ran a real
`git fetch` and three `pip install`s, and `uninstall` wrote a database backup -- each
while printing that nothing would be written. In 3.0 every state-changing command
stops at a single guard, and the allowlist is inverted so anything not known to be
read-only is refused. A new command is therefore safe by default.

**The installer and `s0 upgrade` pin an explicit ref.** 2.x `install.sh` ran
`git clone --depth 1` with no ref, so it followed whatever the remote's default branch
was at that moment, while `upgrade.sh` independently hard-coded `origin master` -- so
an upgrade could move an install to a different ref than the one it was installed
from, and neither honoured an override. 3.0 pins one ref in both, resolved from
`S0_INSTALL_REF` then `S0_BRANCH` then the declared default, and the default is set in
one place by `tools/set_install_ref.py`. **If you are upgrading across this boundary,
set it explicitly:**

```bash
S0_INSTALL_REF=v3.0.0 sh site/install/install.sh
```

**Old editable installs need reinstalling.** A `pip install -e` from a 2.x checkout
leaves `__editable__` finder shims pointing at `core/python` and `linux/cli`, which no
longer exist, and s0 fails to import. Remove and reinstall:

```bash
pip uninstall -y s0-core s0-cli
pip install -e .          # from a fresh checkout
```

**Not breaking, but worth knowing:** the global output flags now work on either side of
the subcommand (`s0 --json list` as well as `s0 list --json`; on 2.x only the latter did
anything). In text mode stdout stays empty and human output goes to stderr on every
command, so `s0 <cmd> > file` captures nothing -- use `--json` or `--format csv`.
Compatibility-only flags were removed rather than deprecated: `--output-format` and
`--keep-audit` are gone, because there was no prior userbase to migrate.

### Fixed

- `s0 live build` crashed with `NameError` before it could check anything. The
  script looked for `iso/build.sh` through a `_root` variable that was never
  defined, so the non-root path always raised instead of reporting where it
  looked. It now resolves the install tree with `s0.resources.repo_root()`, the
  same helper the rest of the package uses.
- `s0.wipe.methods.capabilities.__all__` advertised `PURGE_METHODS`, a name the
  module never defined, so `from s0.wipe.methods.capabilities import *` raised
  `AttributeError`. The entry now names `SCSI_SANITIZE_SERVICE_ACTIONS`, which
  does exist. Whether a purge-capable method is available is a property of the
  connected device, so it comes from `probe_capabilities` rather than a
  hardcoded list.
- `s0.cli.devices._get_root_mount_source` was annotated `Optional[str]` without
  importing `Optional`, so the annotation referenced an undefined name.
- Exception chaining (`raise ... from`) added where a handler deliberately
  replaces the original error with a more meaningful one. The path-traversal
  guard in the web app uses `from None` on purpose: chaining the
  `ValueError` from `relative_to()` would tell a caller which prefix it was
  probing.
- `test_global_flags_are_not_required` iterated every parser action and then did
  nothing, so it asserted nothing while looking like coverage. It now checks the
  property it claims to.

### Changed

- Ruff linting is now enforced across the entire codebase as a blocking CI gate.
- The lint exceptions are `per-file-ignores` in `pyproject.toml` with a stated
  reason each, not scattered `# noqa` comments: best-effort cleanup (`S110`),
  deliberately deferred imports (`E402`), and the platform erasers, release
  script, benchmark and skill checker calling tools found on `PATH`
  (`S603`, `S607`). 129 genuinely unused imports were removed.
- Bandit reports zero medium, high or undefined findings across `src/`. The 177
  low-severity hits are the same accepted-risk patterns above (`B404`, `B603`,
  `B607`, `B110`).


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

### Known Limitations

- Bare-metal hardware sanitize commands (NVMe, ATA, SCSI) are validated against
  specification models and synthetic log structures; hardware execution requires
  the target drive and environment.
- ext4 deleted filename recovery via journal is currently limited when directory
  entry blocks are overwritten.
- Compressed TIFF strips are skipped from automated sizing to avoid miscalculating
  uncompressed vs compressed byte lengths.
- Corrupted video clusters lacking keyframes or headers are not reconstructed.
- Platform-native erasers (`macos/cli/`, `windows/cli/`) are verified via CLI
  dispatch and dry-run tests in CI.
