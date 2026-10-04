"""A global flag must work before *and* after the subcommand.

argparse parses the top-level flags, writes them into the namespace, and then lets
the subparser parse the same command line and overwrite those keys with the
subparser's own defaults. So `s0 --json list` used to resolve `json=True` and then
have it silently reset to `False`.

The failure mode is worse than a flag that does nothing: the command printed human
text to stderr, wrote nothing to stdout, and exited 0. A script doing
`s0 --json list | jq` got empty input and no error, and had no way to tell the
difference between "no devices" and "my flag was ignored".

Every global output flag is checked in both positions, against a real invocation.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
S0 = Path(sys.executable).parent / "s0"


#: A real small regular file, so `plan` has a target it will accept. Created
#: eagerly at import because the parametrised cases are built then.
_SCRATCH = REPO / ".git" / "s0-scratch-plan-target.img"
_SCRATCH.write_bytes(b"\0" * 4096)


def _s0(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([str(S0), *args], capture_output=True, text=True, cwd=str(REPO), timeout=120)


#: (leading global flags, trailing subcommand args, expected start of stdout)
MATRIX = [
    (["--json"], ["list"], "{"),
    (["--format", "json"], ["list"], "{"),
    (["--format", "csv"], ["list"], "path"),
    (["--json"], ["audit", "list"], "{"),
    (["--json"], ["carve", "--help"], "usage:"),
    (["--format", "json"], ["verify", "--help"], "usage:"),
]


@pytest.mark.parametrize(("leading", "trailing", "expected"), MATRIX)
def test_global_flags_work_before_the_subcommand(leading, trailing, expected):
    before = _s0(*leading, *trailing)
    after = _s0(*trailing, *leading)

    assert before.returncode == after.returncode, (
        f"`s0 {' '.join(leading + trailing)}` exited {before.returncode} but "
        f"`s0 {' '.join(trailing + leading)}` exited {after.returncode}"
    )
    assert before.stdout.startswith(expected), (
        f"`s0 {' '.join(leading + trailing)}` wrote "
        f"{len(before.stdout)} bytes to stdout starting {before.stdout[:40]!r}; "
        f"the flag was ignored. stderr began: {before.stderr[:200]!r}"
    )


def test_every_global_flag_survives_leading_placement():
    """Parser-level, so it covers flags whose effect no single command shows.

    `s0 list -vv` prints exactly what `s0 list` prints, so an end-to-end check of
    `--verbose` would pass even if the count were being thrown away.
    """
    sys.path.insert(0, str(REPO / "src"))
    from s0.cli.main import build_parser

    parser = build_parser()
    for argv, expected in [
        (["-v", "list"], {"verbose": 1, "quiet": False, "json": False, "color": None}),
        (["-vv", "list"], {"verbose": 2}),
        (["-vvv", "list"], {"verbose": 3}),
        (["list", "-vv"], {"verbose": 2}),
        (["--quiet", "list"], {"quiet": True, "verbose": 0}),
        (["list", "--quiet"], {"quiet": True, "verbose": 0}),
        (["--no-color", "list"], {"no_color": True, "color": None}),
        (["list", "--no-color"], {"no_color": True, "color": None}),
        (["--color", "never", "list"], {"color": "never"}),
        (["list", "--color", "never"], {"color": "never"}),
    ]:
        args = parser.parse_args(argv)
        for key, want in expected.items():
            assert getattr(args, key, None) == want, (
                f"`s0 {' '.join(argv)}` gave {key}={getattr(args, key, None)!r}, expected {want!r}"
            )


def test_the_json_flag_is_not_silently_dropped():
    """The specific regression: empty stdout, exit 0, no complaint."""
    result = _s0("--json", "list")
    assert result.stdout.strip(), "stdout was empty: the leading --json was discarded"
    payload = json.loads(result.stdout)
    assert "result" in payload, f"stdout was not an envelope: {sorted(payload)}"


def test_text_mode_still_writes_nothing_to_stdout_either_side():
    """The fix must not make text mode start writing to stdout."""
    for args in (["list"], ["--quiet", "list"], ["list", "--quiet"]):
        result = _s0(*args)
        assert result.stdout == "", (
            f"`s0 {' '.join(args)}` wrote {len(result.stdout)} bytes to stdout in "
            f"text mode, breaking the documented contract"
        )


def test_a_flag_the_subcommand_does_not_own_still_errors():
    """SUPPRESS must not turn unknown flags into silently-ignored ones."""
    result = _s0("--no-such-flag", "list")
    assert result.returncode != 0
    assert "unrecognized" in result.stderr.lower()
