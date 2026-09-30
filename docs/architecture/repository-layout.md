# Repository Layout

**Status:** current · **Applies to:** s0 2.4.4 and later

This document exists because a forensic tool that cannot be navigated is not
auditable. An examiner who cannot find where a claim is implemented cannot
verify it, and a maintainer who cannot find the code cannot fix it.

## The problem this layout fixes

Before this restructure the directory names actively lied about the code:

| What the name said | What was actually there |
|---|---|
| `linux/cli/` held the Linux CLI | `s0_cli`, the **cross-platform** CLI. Both `main.py` and `devices.py` branch on `sys.platform == "win32"` / `"darwin"`. |
| `windows/` held the Windows implementation | A single standalone eraser script. Not the s0 CLI. |
| `macos/` held the macOS implementation | A single standalone eraser script. Not the s0 CLI. |
| `core/python/` and `linux/cli/` were two packages | Two distributions, `s0-core` and `s0-cli`. |
| The Windows installer installed "core" and "linux" | `pip install -e core\python` and `pip install -e linux\cli`, so the Windows console script pointed into a directory named after a different operating system. |

The last row is the one that matters most. An operator reading `windows/` would
reasonably conclude it held the Windows implementation of s0. It did not, and the
installer said so in a way that only failed if you already knew the answer.

## Target layout

```
s0/
├── pyproject.toml               # The one distribution: name "s0", entry point s0
├── s0_config.json               # Release single source of truth for the version
├── requirements.txt             # For ISO/Docker/CI images that build before install
│
├── src/s0/                      # The single importable package
│   ├── __init__.py              #   __version__ from importlib.metadata
│   ├── resources.py             #   Every packaged asset, via importlib.resources
│   ├── config.py                #   Config loader (env > checkout > ~/.s0 > /etc)
│   ├── canonical.py  crypto.py  certificate.py  pdfgen.py
│   ├── terminal.py  progress.py  temperature.py  validation.py
│   ├── certcli.py               #   s0-keygen / -sign / -verify / -cert-pdf
│   ├── data/                    #   Packaged data: demo keypair, cert schema
│   ├── cli/                     #   Argument parsing + command implementations
│   ├── carve/                   #   File carving: engine, boundary, policy, FS carvers
│   ├── wipe/                    #   planner.py + methods/ (ata, nvme, blkdiscard, ...)
│   ├── image/                   #   Forensic acquisition and cloning
│   ├── audit/                   #   Hash-chained audit ledger
│   ├── live/                    #   Live-image download and device discovery
│   └── web/                     #   FastAPI dashboard + its static assets
│
├── tests/                       # Every pytest suite
│   ├── core/  cli/  web/  portal/
│   └── platform_windows/  platform_macos/
│
├── portals/install/             # Static installation portal
├── portals/verify/              # 100% static, offline Ed25519 verifier
├── iso/                         # Debian Live ISO build
├── tools/                       # build_all, build_iso, benchmark_perf, release, demo/
├── docs/  skills/  shared/  vendor/
├── windows/                     # Windows standalone eraser launcher
└── macos/                       # macOS standalone eraser launcher
```

## Old → new map

| Old path | New path |
|---|---|
| `core/python/s0_core/` | `src/s0/` |
| `core/python/pyproject.toml` | `pyproject.toml` (merged) |
| `core/keys/` | `src/s0/data/keys/` |
| `core/cert_schema.json` | `src/s0/data/cert_schema.json` |
| `core/CANONICAL_JSON.md` | `docs/architecture/canonical-json.md` |
| `core/standards/nist_800_88_mapping.md` | `docs/compliance/nist-800-88-mapping.md` |
| `core/tests/` | `tests/core/` |
| `linux/cli/s0_cli/main.py` | `src/s0/cli/main.py` |
| `linux/cli/s0_cli/devices.py` | `src/s0/cli/devices.py` |
| `linux/cli/s0_cli/ui.py` | `src/s0/cli/ui.py` |
| `linux/cli/s0_cli/file_eraser.py` | `src/s0/cli/file_eraser.py` |
| `linux/cli/s0_cli/carver/` | `src/s0/carve/` |
| `linux/cli/s0_cli/audit/` | `src/s0/audit/` |
| `linux/cli/s0_cli/methods/` | `src/s0/wipe/methods/` |
| `linux/cli/s0_cli/wipe.py` | `src/s0/wipe/planner.py` |
| `linux/cli/s0_cli/imager.py` | `src/s0/image/imager.py` |
| `linux/cli/s0_cli/live_manager.py` | `src/s0/live/live_manager.py` |
| `linux/cli/s0_cli/temperature.py` | `src/s0/temperature.py` (the shim was deleted) |
| `linux/cli/tests/` | `tests/cli/` |
| `linux/cli/demo_e2e*.sh` | `tools/demo/e2e*.sh` |
| `linux/iso/` | `iso/` |
| `web/` | `src/s0/web/` (now ships inside the package) |
| `web/tests/` | `tests/web/` |
| `verification-portal/` | `portals/verify/` |
| `verification-portal/tests/*.py` | `tests/portal/` |
| `verification-portal/tests/*.html|json` | `portals/verify/tests/` (browser assets, not pytest) |
| `install-portal/` | `portals/install/` |
| `scripts/` | `tools/` |
| `windows/cli/tests/` | `tests/platform_windows/` |
| `macos/cli/tests/` | `tests/platform_macos/` |

`import s0_core` became `import s0`. `import s0_cli.main` became
`import s0.cli.main`. `s0_cli.carver` became `s0.carve`, `s0_cli.methods`
became `s0.wipe.methods`, `s0_cli.wipe` became `s0.wipe.planner`.

## Rules the layout now enforces

1. **One installable distribution named `s0`.** Entry point `s0 = s0.cli.main:main`.
2. **No directory named `linux/` contains cross-platform code.**
3. **No directory named `windows/` or `macos/` that is not that platform's own code.**
   Both are standalone convenience launchers for the shared `s0 wipe` path, not
   parallel implementations.
4. **Installers reference package names, never directory names.** All four
   installers (`install`/`upgrade` × `sh`/`ps1`/`cmd`) run `pip install -e .`.
5. **`import s0` works from a clean pip install** with no `sys.path` help and no
   relative-path lookups. Every runtime asset resolves through
   `s0.resources` via `importlib.resources`. This is verified by building a
   wheel, installing it into an empty virtualenv, and running `s0 carve` on a
   synthetic image from a directory containing no source tree.
6. **`pyproject.toml`'s `testpaths` names every suite that exists.** CI runs a
   bare `pytest`, so a missing entry silently reduces coverage rather than
   failing. Treat that list as part of the release contract.
7. **`scripts/release.py`'s version-source table raises on a missing entry.**
   Its previous 25 hand-written blocks had already stopped matching after an
   earlier move and reported a failure against a file that no longer existed.

## Why `windows/` and `macos/` are still top-level

They are single-file launchers (`s0_eraser.py` plus a `.bat`/`.sh` wrapper) that
an operator can copy onto a USB stick and run without installing anything. They
are genuinely platform-specific, so top level is honest for them.

They are, however, a maintenance hazard: each contains its own copy of the
signing and certificate logic, and for a tool that issues signed claims about
device erasure, a second implementation of the signing path is a real custody
risk. Collapsing them to thin launchers over `s0.wipe.planner` is deliberately
**not** done here. It changes behaviour on two platforms that cannot be tested
from this environment, so it needs its own decision, its own test plan and its
own rollback — not to ride along in a layout commit. It is the first item of the
remaining work.

## `src/s0/platform/` is smaller than planned, on purpose

The plan proposed `platform/linux.py`, `platform/windows.py` and
`platform/macos.py` wrapping the ~60 `sys.platform` branches in `main.py`,
`file_eraser.py`, `imager.py`, `live_manager.py`, `temperature.py` and
`web/app.py`. That would be worse code. Those branches are small, local
conditionals — `if sys.platform == "darwin"` — and each is already the simplest
correct thing at its site. Behind a per-OS interface they gain a lookup and lose
their context.

What was genuinely duplicated was three rules, and they had already drifted:

| Rule | Was | Now |
|---|---|---|
| `is_block_device` | 7 copies; macOS missed entirely, because `/dev/disk2` is a *character* device | `platform.is_block_device` |
| Windows `physicaldrive` test | 3 copies, disagreeing on `//./` | `platform.is_windows_volume_path` |
| Platform name for certificate metadata | 2 copies; the imager's reported FreeBSD as macOS | `platform.current` |

So `s0/platform/` holds those three rules and nothing else. A new platform rule
belongs here only if it is currently written out more than once.

## Verifying the layout

```bash
pip install -e .                  # one distribution
python -c "import s0; print(s0.__version__)"
pytest                            # bare, driven by testpaths
s0 --version

# the packaging claim, from outside the source tree:
python -m build --wheel -o /tmp/w
python -m venv /tmp/clean && /tmp/clean/bin/pip install /tmp/w/s0-*.whl
cd /tmp && /tmp/clean/bin/s0 --version
```
