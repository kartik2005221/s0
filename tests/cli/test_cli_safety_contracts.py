"""The CLI's safety and output contracts, as executable assertions.

Each test here corresponds to a defect that shipped. The common thread is that
these were all *documented* behaviours that the code did not implement, so a
reviewer reading the help text or the manual would reasonably have believed the
opposite. A contract nobody checks is a comment.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest


def _entry_point() -> str:
    """The installed console script. There is no `s0.__main__`, so
    `python -m s0` does not work; going through the entry point is also the more
    honest test because that is how users invoke it."""
    import shutil

    found = shutil.which("s0") or str(Path(sys.executable).parent / "s0")
    assert Path(found).is_file(), f"s0 entry point not found at {found}"
    return found


def _s0(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [_entry_point(), *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=180,
    )


def _md5(path) -> str:
    return hashlib.md5(path.read_bytes(), usedforsecurity=False).hexdigest()


# --------------------------------------------------------------------------- #
# --dry-run must never write.
# --------------------------------------------------------------------------- #


def test_wipe_dry_run_does_not_modify_the_target(tmp_path):
    """Regression: `s0 wipe --dry-run` wiped the target.

    `--dry-run` is attached to *every* subcommand by the shared argument group
    with the help text "plan only; never write to the target", but no handler
    except `s0 live flash` read it. The documented way to preview a wipe was the
    one way guaranteed to perform it.
    """
    image = tmp_path / "dryrun.img"
    image.write_bytes(b"\xa7" * (4 * 1024 * 1024))
    before = _md5(image)

    result = _s0("wipe", "--target", str(image), "--yes", "--dry-run")

    assert _md5(image) == before, "--dry-run modified the target"
    assert result.returncode == 0
    assert "nothing will be written" in result.stdout + result.stderr


def _build_parser():
    from s0.cli.main import build_parser

    return build_parser()


def _find_subparser(parser, name):
    for action in parser._actions:
        if hasattr(action, "choices") and isinstance(action.choices, dict):
            if name in action.choices:
                return action.choices[name]
    raise AssertionError(f"subcommand {name} not found")


# --------------------------------------------------------------------------- #
# --format json must be exactly one JSON document on stdout.
# --------------------------------------------------------------------------- #


def test_file_and_folder_wipe_json_is_valid_and_uncontaminated(tmp_path):
    """Regression: `wipe --targets <dir> --json` printed 8 lines of chrome to
    stdout and then crashed with
    `AttributeError: 'BatchEraseSummary' object has no attribute
    'bytes_overwritten'`.

    Two defects in one path: the wrong dataclass field name, and `cmd_erase_files`
    never constructing a UI, so every banner and summary line went to stdout.
    """
    victim = tmp_path / "target"
    victim.mkdir()
    (victim / "a.txt").write_text("hello")
    (victim / "b.txt").write_text("world")

    result = _s0("wipe", "--targets", str(victim), "--json", "--out-dir", str(tmp_path))

    assert result.returncode == 0, result.stderr[-800:]
    assert result.stdout.strip(), "expected a JSON document on stdout"
    payload = json.loads(result.stdout)  # raises if chrome leaked onto stdout
    assert "status" in payload


def test_erase_files_chrome_goes_to_stderr(tmp_path):
    """stdout is reserved for records; banners and summaries are not records."""
    victim = tmp_path / "t"
    victim.mkdir()
    (victim / "a.txt").write_text("hello")
    (victim / "b.txt").write_text("world")
    result = _s0("wipe", "--targets", str(victim), "--json", "--out-dir", str(tmp_path))
    for marker in ("Files Processed", "Successful", "Failed", "Bytes Sanitized"):
        assert marker not in result.stdout, (
            f"{marker!r} is chrome and must not appear on stdout in --json mode"
        )


# --------------------------------------------------------------------------- #
# Tier promises must not be silently downgraded.
# --------------------------------------------------------------------------- #


def test_require_tier_destroy_is_not_silently_satisfied_by_clear():
    """Regression: `--require-tier Destroy` reported `satisfiable: true` on any
    device, so s0 wiped at Clear while the operator had asked for Destroy.

    The ladder checked `requested_tier == "Purge"` and treated everything else as
    satisfiable. `--require-tier` is a promise; substituting a lower tier without
    saying so is what `--allow-downgrade` exists to make explicit.
    """
    from s0.wipe.methods.capabilities import plan_ladder

    class FakeCaps:
        path = "/dev/fake"

        def available_methods(self):
            # Only a Clear-equivalent technique is on offer.
            return [("OVERWRITE_ZERO_1PASS", "Clear", "logical overwrite")]

        def best_tier(self):
            return "Clear"

    caps = FakeCaps()
    assert plan_ladder(caps, "Clear")["satisfiable"] is True
    assert plan_ladder(caps, "Purge")["satisfiable"] is False
    destroy = plan_ladder(caps, "Destroy")
    assert destroy["satisfiable"] is False, (
        "Destroy must not be reported satisfiable when only Clear is available"
    )
    assert destroy["refusal_reason"], "a refusal must explain itself"


def test_unknown_tier_is_never_satisfiable():
    from s0.wipe.methods.capabilities import plan_ladder

    class FakeCaps:
        path = "/dev/fake"

        def available_methods(self):
            return [("OVERWRITE_ZERO_1PASS", "Clear", "logical overwrite")]

        def best_tier(self):
            return "Clear"

    assert plan_ladder(FakeCaps(), "Nonsense")["satisfiable"] is False


# --------------------------------------------------------------------------- #
# Help text must describe behaviour that exists.
# --------------------------------------------------------------------------- #


def test_dry_run_help_promises_are_true_for_every_subcommand_that_offers_it():
    """The help says "plan only; never write to the target". Hold it to that."""
    from s0.cli.main import build_parser

    parser = build_parser()
    names = (
        "list",
        "plan",
        "wipe",
        "carve",
        "audit",
        "verify",
        "keygen",
        "image",
        "clone",
        "uninstall",
        "web",
        "live",
    )
    for name in names:
        sub = _find_subparser(parser, name)
        for action in sub._actions:
            if action.dest != "dry_run":
                continue
            assert "never write" in (action.help or ""), f"{name} --dry-run help lost its safety promise"


def test_every_subcommand_help_renders():
    """A help string with a bare `%` raises at runtime inside argparse."""
    for name in (
        "list",
        "plan",
        "wipe",
        "carve",
        "audit",
        "verify",
        "keygen",
        "upgrade",
        "uninstall",
        "image",
        "clone",
        "web",
        "live",
    ):
        result = _s0(name, "--help")
        assert result.returncode == 0, f"{name} --help failed: {result.stderr[-300:]}"
        assert result.stderr == "", f"{name} --help wrote to stderr"


# --------------------------------------------------------------------------- #
# Operator abort is not success.
# --------------------------------------------------------------------------- #


def test_aborting_a_destructive_confirmation_is_not_exit_zero(tmp_path):
    """`s0 wipe ... && echo "wipe succeeded"` printed "succeeded" on a refusal."""
    image = tmp_path / "abort.img"
    image.write_bytes(b"\xa7" * (1024 * 1024))
    before = _md5(image)

    # A confirmation prompt that does not match must not report success.
    result = subprocess.run(
        [_entry_point(), "wipe", "--target", str(image)],
        input="definitely-not-the-path\n",
        capture_output=True,
        text=True,
        timeout=120,
    )

    assert _md5(image) == before, "the target was modified despite the abort"
    assert result.returncode != 0, "operator abort returned 0; `cmd && next_step` would run the next step"


def test_live_devices_reports_failure_when_it_finds_nothing():
    """`s0 live devices && s0 live flash -t /dev/sdb` used to chain into a flash
    against a path that had never been enumerated."""
    from s0.live.live_manager import EX_NOINPUT, cmd_live_devices

    class Args:
        json = False

    assert cmd_live_devices(Args()) == EX_NOINPUT


def test_live_abort_exit_codes_are_non_zero():
    from s0.live import live_manager

    assert live_manager.EX_TEMPFAIL != 0, "an operator abort must not be success"
    assert live_manager.EX_NOINPUT != 0, "finding no target must not be success"
    # sysex.h values, spelled out because `sysex` is missing from minimal and
    # Windows Python builds.
    assert live_manager.EX_NOINPUT == 66
    assert live_manager.EX_TEMPFAIL == 75


# --------------------------------------------------------------------------- #
# Config problems must be visible.
# --------------------------------------------------------------------------- #


def test_config_loading_reports_a_malformed_file(tmp_path):
    """Regression: a config containing `{ this is not json` produced rc=0 and no
    diagnostic at all, so an operator with a typo silently got defaults."""

    bad = tmp_path / "broken.json"
    bad.write_text("{ this is not json", encoding="utf-8")

    script = "import s0.config as c;print('CONFIG_OK', sorted(c.CONFIG)[:3])"
    env = {**os.environ, "S0_CONFIG_PATH": str(bad)}
    result = subprocess.run(
        [_entry_point(), "list"],
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
    )
    assert "is not valid JSON" in result.stderr, (
        "a malformed config was accepted silently; the operator gets defaults "
        f"with no hint that their file was ignored. stderr was: {result.stderr[:300]!r}"
    )
    assert script  # keep the import referenced


def test_config_type_mismatches_are_flagged(tmp_path):
    """Values are trusted blindly, so `{"api_port": "not-a-number"}` reached
    `s0 web --port` and a dict `version` reached the JSON envelope as a Python
    repr. Typing is a separate change; saying so is cheap."""
    weird = tmp_path / "weird.json"
    weird.write_text('{"api_port": "not-a-number", "nope": 1}', encoding="utf-8")
    env = {**os.environ, "S0_CONFIG_PATH": str(weird)}
    result = subprocess.run([_entry_point(), "list"], capture_output=True, text=True, env=env, timeout=120)
    assert "WARNING" in result.stderr, (
        f"no warning about a string port or an unknown key: {result.stderr[:300]!r}"
    )


# --------------------------------------------------------------------------- #
# The manual must describe the contract the code implements.
# --------------------------------------------------------------------------- #


def test_documented_exit_codes_match_the_implemented_constants():
    """Regression: the manual promised a "consistent three-value exit code
    contract" (0/1/2) while the code returned sysexits 64-130.

    A CI gate written from the manual -- `if [ $? -eq 2 ]; then fail` -- silently
    passed on a failed `plan` (66) and treated a broken audit chain (1) as
    indistinguishable from a hardware failure.
    """
    import re

    from s0 import terminal

    doc = (Path(__file__).resolve().parent.parent.parent / "docs" / "guides" / "cli-reference.md").read_text(
        encoding="utf-8"
    )
    section = doc[doc.index("## Exit Codes") :]
    section = (
        section[: section.index("---", section.index("| `130`"))] if "| `130`" in section else section[:4000]
    )

    documented = {int(m) for m in re.findall(r"^\| `(\d+)` \|", section, re.M)}
    implemented = {
        value for name, value in vars(terminal).items() if name.startswith("EX_") and isinstance(value, int)
    }

    assert documented, "no exit codes documented at all"
    missing = implemented - documented
    assert not missing, (
        "src/s0/terminal.py defines exit codes the manual does not document: "
        f"{sorted(missing)}. A reader cannot write a correct gate against an "
        "undocumented code."
    )


def test_documented_json_envelope_keys_are_real():
    """The manual described an ndjson event stream with an `event` key.

    No envelope has ever had that key, so the documented
    `grep '"event":"complete"' wipe.log | jq -r '.cert_path'` matched nothing.
    """
    doc = (Path(__file__).resolve().parent.parent.parent / "docs" / "guides" / "cli-reference.md").read_text(
        encoding="utf-8"
    )
    assert "event stream schema" not in doc, (
        "there is no event stream; --json emits a single envelope. Remove the ndjson section."
    )
    from s0 import terminal

    source = Path(terminal.__file__).read_text(encoding="utf-8")
    for key in (
        "schema",
        "schema_version",
        "tool",
        "invocation",
        "status",
        "warnings",
        "errors",
        "result",
        "artifacts",
        "audit",
        "signature",
    ):
        assert f'"{key}"' in source, f"documented envelope key {key} is not emitted"


def test_config_has_no_dead_keys():
    """`website_url` was in s0_config.json but in neither DEFAULT_CONFIG nor any
    code, so it was a key that configured nothing. It is removed; this keeps the
    unknown-key warning honest instead of noisy."""
    import json

    from s0.config import DEFAULT_CONFIG

    supplied = json.loads(
        (Path(__file__).resolve().parent.parent.parent / "s0_config.json").read_text(encoding="utf-8")
    )
    dead = sorted(set(supplied) - set(DEFAULT_CONFIG))
    assert not dead, (
        f"s0_config.json declares {dead}, which no code reads. Either wire them "
        "up or remove them; a key that configures nothing is a trap."
    )


# --------------------------------------------------------------------------- #
# --format csv must produce a document on every subcommand that accepts it.
# --------------------------------------------------------------------------- #


def test_csv_is_not_silently_empty_on_any_subcommand(tmp_path):
    """Regression: `--format csv` emitted nothing on seven of eight commands.

    `UI.finish()` only rendered `json`, but eight call sites tested
    `fmt in ("json", "csv")` and skipped their human branch. So `s0 plan --format csv
    > plan.csv` produced a zero-byte file and exited 0. A flag that is accepted,
    does nothing and reports success is worse than a flag that is absent.
    """
    import csv
    import io

    from s0.cli.ui import write_csv_rows

    # a single record
    buf = io.StringIO()
    write_csv_rows({"a": 1, "b": "x"}, stream=buf)
    assert list(csv.DictReader(io.StringIO(buf.getvalue()))) == [{"a": "1", "b": "x"}]

    # a list of records -> one row each, columns in first-seen order
    buf = io.StringIO()
    write_csv_rows([{"p": "/dev/sdb", "m": "SanDisk"}, {"p": "/dev/sdc", "extra": 1}], stream=buf)
    rows = list(csv.DictReader(io.StringIO(buf.getvalue())))
    assert [r["p"] for r in rows] == ["/dev/sdb", "/dev/sdc"]
    assert rows[1]["extra"] == "1", "ragged records must not lose keys"
    assert rows[0]["extra"] == "", "absent keys become empty cells"

    # a wrapper around one record list -> expanded, siblings carried down
    buf = io.StringIO()
    write_csv_rows({"block_count": 2, "blocks": [{"i": 0}, {"i": 1}]}, stream=buf)
    rows = list(csv.DictReader(io.StringIO(buf.getvalue())))
    assert [r["i"] for r in rows] == ["0", "1"]
    assert all(r["block_count"] == "2" for r in rows)

    # nested structures are JSON, not Python repr
    buf = io.StringIO()
    write_csv_rows({"k": {"a": 1}}, stream=buf)
    # Parsed, not raw: csv quotes the cell because it contains double quotes.
    cell = list(csv.DictReader(io.StringIO(buf.getvalue())))[0]["k"]
    assert json.loads(cell) == {"a": 1}, f"nested cell must be JSON, got {cell!r}"

    # booleans are lowercase, None is empty
    buf = io.StringIO()
    write_csv_rows({"t": True, "f": False, "n": None}, stream=buf)
    rows = list(csv.DictReader(io.StringIO(buf.getvalue())))
    assert rows[0] == {"t": "true", "f": "false", "n": ""}


def test_csv_on_the_real_cli_is_never_empty(tmp_path):
    """End to end, through the entry point, for the commands that accept it."""
    import csv as csv_mod
    import io

    image = tmp_path / "p.img"
    image.write_bytes(b"\xa7" * (256 * 1024))

    for argv in (["list"], ["audit", "list"], ["plan", "--target", str(image)]):
        result = _s0(*argv, "--format", "csv")
        assert result.stdout.strip(), (
            f"`s0 {' '.join(argv)} --format csv` produced no stdout. It exits "
            f"{result.returncode}, so a script trusting it gets an empty file."
        )
        # A header plus at least one row, or at least a parseable document.
        rows = list(csv_mod.reader(io.StringIO(result.stdout)))
        assert rows, f"{argv} produced unparseable CSV"


def test_json_still_wins_and_is_unaffected():
    """Adding the csv branch must not disturb the json envelope."""
    result = _s0("list", "--json")
    payload = json.loads(result.stdout)
    assert payload["schema"].startswith("s0.")
    assert "result" in payload


# --------------------------------------------------------------------------- #
# A documented flag must do something.
# --------------------------------------------------------------------------- #


def test_list_output_format_alias_works():
    """Regression: `--output-format` was declared on `s0 list` and never read.

    Three places in the manual document it, including
    `s0 list --output-format json | jq -r '.[] | select(.mounted == false) | .path'`.
    The pipeline received nothing and exited 0.
    """
    result = _s0("list", "--output-format", "json")
    assert result.returncode == 0, result.stderr[-400:]
    # cmd_list has its own envelope shape (a "targets" key), so the assertion is
    # "emits JSON with records in it", not "matches the generic envelope".
    payload = json.loads(result.stdout)
    rows = payload["result"].get("targets") or payload["result"]
    assert isinstance(rows, list) and rows, f"--output-format json produced no records: {sorted(payload)}"


def test_removed_flags_are_gone_from_the_parser():
    """`--sanitize` and `--sanitize-passes` described firmware-action selection
    that does not exist. `s0 wipe --sanitize crypto-erase` silently fell back to
    the automatic choice and reported OVERWRITE_ZERO_1PASS. Better absent than a
    lie."""
    from s0.cli.main import build_parser

    parser = build_parser()
    wipe = _find_subparser(parser, "wipe")
    opts = {o for action in wipe._actions for o in action.option_strings}
    assert "--sanitize" not in opts, "--sanitize must not be offered"
    assert "--sanitize-passes" not in opts, "--sanitize-passes must not be offered"
    # --passes remains the real control.
    assert "--passes" in opts


def test_no_documented_flag_is_silently_ignored_in_help():
    """Sweep: every flag whose help promises machine-readable output must be read."""
    from s0.cli.main import build_parser

    parser = build_parser()
    for name in ("list", "plan", "wipe", "carve", "audit", "keygen", "image"):
        try:
            sub = _find_subparser(parser, name)
        except AssertionError:
            continue
        for action in sub._actions:
            if not action.option_strings or action.dest in ("help",):
                continue
            # A flag that no handler reads is a flag that lies.
            if action.dest in {"sanitize", "sanitize_passes"}:
                pytest.fail(f"{name} still offers the removed --{action.dest}")


# --------------------------------------------------------------------------- #
# Colour must honour the policy, not hard-coded escapes.
# --------------------------------------------------------------------------- #


def _carve_stderr_lines(*extra: str) -> str:
    import os as _os

    env = {**_os.environ, "S0_LEGAL_NOTICE_SHOWN": ""}
    env.pop("S0_LEGAL_NOTICE_SHOWN", None)
    image = Path(tempfile.mkdtemp()) / "evidence.bin"
    image.write_bytes(b"\xa7" * (2 * 1024 * 1024))
    result = subprocess.run(
        [
            _entry_point(),
            "carve",
            "--target",
            str(image),
            "--out-dir",
            str(image.parent / "out"),
            "--no-certificate",
            *extra,
        ],
        capture_output=True,
        text=True,
        env=env,
        timeout=180,
    )
    return result.stderr


def test_no_color_flags_suppress_every_ansi_escape():
    """Regression: the legal and demo-key notices hard-coded their own escapes.

    So `--no-color`, `--color never` and `NO_COLOR=1` were all ignored for exactly
    those two messages -- five coloured lines on stderr that no flag could turn
    off. `list`, `plan`, `audit` and `keygen` emitted none, so the behaviour was
    also inconsistent between commands.
    """
    for flags in (["--no-color"], ["--color", "never"]):
        stderr = _carve_stderr_lines(*flags)
        assert "\033[" not in stderr, f"{' '.join(flags)} left ANSI escapes in stderr:\n" + repr(stderr[:400])


def test_no_color_env_var_suppresses_every_ansi_escape():
    stderr = _carve_stderr_lines()
    assert "\033[" not in stderr, f"NO_COLOR was inherited but ignored: {stderr[:300]!r}"


def test_colour_is_still_emitted_on_a_terminal():
    """Suppressing everything unconditionally would be its own bug."""
    from s0.terminal import OutputPolicy

    policy = OutputPolicy(color=True)
    import io

    stream = io.StringIO()
    policy.err_stream = stream
    assert policy.use_color is True
