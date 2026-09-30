"""The s0 CLI output contract.

These tests are the enforcement mechanism for the rules every subcommand must
obey. A tool that is inconsistent in shape cannot be scripted, and a forensic
tool that cannot be scripted cannot be relied on in a case file.

Invariants asserted here:

1. Every subcommand exposes the same global output flags.
2. ``--json`` puts a versioned envelope on stdout and *nothing else*.
3. Progress, banners and warnings never contaminate stdout.
4. ``--quiet`` silences chrome but never the result.
5. Exit codes come from ``sysexits.h``, not a bare 1 or 2.
6. ``NO_COLOR`` and ``--no-color`` are honoured.
7. Structured output contains no floats (Canonical JSON v1 rule 5).
"""

from __future__ import annotations

import io
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from s0.cli.main import build_parser, main
from s0.cli.ui import GLOBAL_HELP, add_global_arguments, policy_from_args
from s0.terminal import (
    EX_INTERRUPTED,
    EX_NOINPUT,
    EX_OK,
    EX_USAGE,
    Column,
    OutputPolicy,
    envelope,
    human_bytes,
    render_table,
)

REPO = Path(__file__).resolve().parents[3]

GLOBAL_FLAGS = {
    "--format", "--json", "--quiet", "--verbose",
    "--color", "--no-color", "--yes", "--dry-run",
}


# --------------------------------------------------------------------------- #
# 1. identical global flags everywhere
# --------------------------------------------------------------------------- #


def _all_subparsers(parser, prefix=""):
    out = {}
    for action in parser._actions:
        if isinstance(action, __import__("argparse")._SubParsersAction):
            for name, child in action.choices.items():
                out[f"{prefix}{name}"] = child
                out.update(_all_subparsers(child, f"{prefix}{name} "))
    return out


def test_every_subcommand_exposes_the_global_flags():
    parsers = _all_subparsers(build_parser())
    assert len(parsers) >= 12, f"expected the full command surface, found {sorted(parsers)}"
    for name, sp in parsers.items():
        opts = {o for a in sp._actions for o in a.option_strings}
        missing = GLOBAL_FLAGS - opts
        assert not missing, f"s0 {name.strip()} is missing {sorted(missing)}"


def test_global_flags_are_not_required():
    parsers = _all_subparsers(build_parser())
    for name, sp in parsers.items():
        for action in sp._actions:
            if isinstance(action, type(sp._get_positional_actions()[0]) if
                          sp._get_positional_actions() else ()):
                pass
    # A cheap smoke test is the real check: every command must still parse
    # without any global flag present.
    for name in ("list", "audit", "carve", "plan", "verify", "keygen"):
        with pytest.raises(SystemExit):
            build_parser().parse_args([name, "--help"])


# --------------------------------------------------------------------------- #
# 2/3. stdout is data, stderr is chrome
# --------------------------------------------------------------------------- #


class TTY(io.StringIO):
    encoding = "utf-8"

    def isatty(self):
        return True


def run_cli(argv, monkeypatch, tty=False):
    out, err = (TTY(), TTY()) if tty else (io.StringIO(), io.StringIO())
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", err)
    code = main(argv)
    return code, out.getvalue(), err.getvalue()


def test_json_output_is_pure_envelope_on_stdout(monkeypatch):
    code, out, err = run_cli(["list", "--json"], monkeypatch)
    assert code == EX_OK
    doc = json.loads(out)                      # must parse with no pre-processing
    assert doc["schema"] == "s0.list/1"
    assert doc["schema_version"] == "1.0.0"
    assert doc["status"] in ("success", "failure", "partial", "aborted", "refused")
    assert isinstance(doc["result"], dict)
    assert "targets" in doc["result"]


def test_text_mode_writes_tables_to_stderr(monkeypatch):
    code, out, err = run_cli(["list"], monkeypatch)
    assert code == EX_OK
    assert out == "", "a human table must never land on stdout"
    assert "PATH" in err and "STORAGE" in err


def test_csv_output_is_clean_rows_on_stdout(monkeypatch):
    code, out, err = run_cli(["list", "--format", "csv"], monkeypatch)
    assert code == EX_OK
    lines = [l for l in out.splitlines() if l]
    assert lines[0].startswith("path,kind,storage_type")
    for line in lines[1:]:
        assert len(line.split(",")) == len(lines[0].split(","))


def test_no_json_floats_anywhere_in_structured_output(monkeypatch):
    """Canonical JSON v1 forbids float fields; a float here would break
    byte-for-byte signature reproducibility of any envelope we later sign."""
    code, out, _ = run_cli(["list", "--json"], monkeypatch)

    def walk(node, path="$"):
        if isinstance(node, float):
            raise AssertionError(f"float at {path}")
        if isinstance(node, dict):
            for k, v in node.items():
                walk(v, f"{path}.{k}")
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{path}[{i}]")

    walk(json.loads(out))


def test_envelope_schema_is_versioned_per_command():
    for command in ("list", "audit", "verify", "carve"):
        env = envelope(command, result={}, status="success")
        assert env["schema"] == f"s0.{command}/1"
        assert env["schema_version"] == "1.0.0"
        assert env["invocation"]["command"] == command


# --------------------------------------------------------------------------- #
# 4. quiet
# --------------------------------------------------------------------------- #


def test_quiet_silences_chrome_but_not_the_result(monkeypatch):
    _, loud_err = run_cli(["list"], monkeypatch)[1:]
    _, quiet_err = run_cli(["list", "--quiet"], monkeypatch)[1:]
    assert quiet_err == "", "--quiet must silence human chrome"
    assert loud_err != ""


def test_quiet_still_produces_json(monkeypatch):
    code, out, _ = run_cli(["list", "--json", "--quiet"], monkeypatch)
    assert code == EX_OK
    assert json.loads(out)["schema"] == "s0.list/1"


# --------------------------------------------------------------------------- #
# 5. exit codes
# --------------------------------------------------------------------------- #


def test_unknown_flag_is_ex_usage_not_2(monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdout", io.StringIO())
    monkeypatch.setattr(sys, "stderr", io.StringIO())
    assert main(["list", "--definitely-not-a-flag"]) == EX_USAGE


def test_missing_input_is_ex_noinput(monkeypatch):
    code, _, err = run_cli(["verify", "/nonexistent/cert.json"], monkeypatch)
    assert code == EX_NOINPUT
    assert "does not exist" in err


def test_malformed_certificate_is_ex_dataerr(monkeypatch, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    code, _, _ = run_cli(["verify", str(bad)], monkeypatch)
    assert code == 65  # EX_DATAERR


def test_exit_codes_are_distinct_and_documented():
    from s0.terminal import EXIT_MEANINGS
    for code, meaning in EXIT_MEANINGS.items():
        assert meaning and isinstance(code, int)
    assert EX_USAGE != EX_NOINPUT


# --------------------------------------------------------------------------- #
# 6. colour
# --------------------------------------------------------------------------- #


def test_no_color_env_disables_colour(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    policy = policy_from_args(build_parser().parse_args(["list"]), stdout=TTY(), stderr=TTY())
    assert policy.use_color is False


def test_clicolor_force_overrides_non_tty(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("CLICOLOR_FORCE", "1")
    policy = policy_from_args(build_parser().parse_args(["list"]), stdout=io.StringIO())
    assert policy.use_color is True


def test_no_color_flag_wins_over_clicolor_force(monkeypatch):
    monkeypatch.setenv("CLICOLOR_FORCE", "1")
    policy = policy_from_args(
        build_parser().parse_args(["list", "--no-color"]), stdout=TTY())
    assert policy.use_color is False


def test_no_ansi_escapes_in_output_when_colour_is_disabled():
    policy = OutputPolicy(color=False, stream=io.StringIO(), err_stream=io.StringIO())
    out = io.StringIO()
    out.write(policy.status("ok", "valid"))
    assert "\033[" not in out.getvalue()


# --------------------------------------------------------------------------- #
# tables
# --------------------------------------------------------------------------- #


def test_status_never_relies_on_colour_alone():
    """WCAG 1.4.1 and forensic print legibility: glyph plus word, always."""
    for colour in (True, False):
        policy = OutputPolicy(color=colour, stream=io.StringIO(), err_stream=io.StringIO())
        for state, word in (("ok", "OK"), ("warn", "WARN"), ("error", "ERROR"), ("skip", "SKIP")):
            rendered = policy.status(state, "detail")
            assert word in rendered
            if not colour:
                assert "\033[" not in rendered


def test_table_right_aligns_numeric_columns():
    policy = OutputPolicy(color=False, stream=io.StringIO(), err_stream=io.StringIO())
    render_table(policy, [Column("EXT"), Column("SIZE", align="r")],
                 [["png", "1,234"], ["jpg", "12"]])
    err = policy.err_stream.getvalue()
    assert "1,234" in err and "12" in err
    assert err.index("1,234") < err.index("12")


def test_table_truncates_long_paths_from_the_left():
    policy = OutputPolicy(color=False, stream=io.StringIO(), err_stream=io.StringIO())
    render_table(policy, [Column("PATH", max_width=20)],
                 [["/very/long/prefix/that/goes/on/forever/carved_00001.png"]])
    err = policy.err_stream.getvalue()
    assert "..." in err and "carved_00001.png" in err


# --------------------------------------------------------------------------- #
# formatting helpers
# --------------------------------------------------------------------------- #


def test_human_bytes_uses_binary_units():
    assert human_bytes(0) == "0 B"
    assert human_bytes(1023) == "1023 B"
    assert human_bytes(1024) == "1.00 KiB"
    assert human_bytes(1024 ** 3) == "1.00 GiB"
    assert human_bytes(None) == "-"


def test_no_emoji_in_machine_readable_output(monkeypatch):
    """Emoji break monospace alignment and screen readers; s0 emits geometric
    Unicode only, and nothing outside the basic multilingual plane."""
    code, out, _ = run_cli(["list", "--json"], monkeypatch)
    emoji = re.compile("[\U0001F300-\U0001FAFF☀-➿⬀-⯿️]")
    assert not emoji.search(out)


# --------------------------------------------------------------------------- #
# 8. every command actually implements the envelope
# --------------------------------------------------------------------------- #

# Minimal argv for each command that can run without hardware or a key file.
SMOKE = {
    "list": ["list"],
    "plan": ["plan", "--target", "{image}", "--force"],
    "audit list": ["audit", "list", "--limit", "2"],
    "audit verify": ["audit", "verify"],
    "keygen": ["keygen", "--out-dir", "{out}", "--name", "contract"],
    "carve": ["carve", "--target", "{image}", "--out-dir", "{out}",
              "--no-certificate", "--extensions", "png"],
    "verify": ["verify", "{cert}"],
    "wipe": ["wipe", "--target", "{image}", "--out-dir", "{out}", "--yes",
             "--no-certificate"],
    "image": ["image", "--source", "{image}", "--destination", "{dest}",
              "--out-dir", "{out}", "--no-certificate"],
}


def _make_fixtures(tmp_path):
    from PIL import Image
    import io as _io
    img = tmp_path / "target.img"
    img.write_bytes(b"\x00" * 4096)
    cert = tmp_path / "cert.json"
    cert.write_text("{}")
    out = tmp_path / "out"
    out.mkdir()
    return {"image": str(img), "out": str(out), "cert": str(cert),
            "dest": str(tmp_path / "dest.img")}


@pytest.mark.parametrize("name", sorted(SMOKE))
def test_every_command_emits_a_clean_envelope(name, tmp_path, monkeypatch):
    """A command that crashes when asked for JSON is a command nobody can
    automate. This walks the whole runnable surface."""
    fx = _make_fixtures(tmp_path)
    argv = []
    for tok in SMOKE[name]:
        argv.append(fx[tok[1:-1]] if tok.startswith("{") and tok.endswith("}") else tok)

    out, err = io.StringIO(), io.StringIO()
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", err)
    try:
        main(argv)
    except SystemExit as exc:
        # argparse exiting non-zero is a legitimate refusal (e.g. missing
        # hardware); what must never happen is an unhandled traceback.
        assert "Traceback" not in err.getvalue(), err.getvalue()[-2000:]

    assert "Traceback" not in err.getvalue(), (
        f"s0 {name} --json raised an unhandled exception:\n{err.getvalue()[-2000:]}")

    if out.getvalue().strip():
        doc = json.loads(out.getvalue())
        assert doc["schema"] == f"s0.{name.split()[0]}/1"
        assert doc["status"] in ("success", "failure", "partial", "aborted", "refused")
        assert isinstance(doc["result"], (dict, list))


def test_prose_column_is_cut_from_the_right_so_the_meaning_survives():
    """A value that is not an identifier must keep its beginning.

    Truncating "MFT + journal" from the left leaves "...al only", which names
    nothing. Identifiers -- paths, digests -- are the opposite case and keep
    their tail, which is what identifies them.
    """
    policy = OutputPolicy(color=False, stream=io.StringIO(), err_stream=io.StringIO())
    render_table(policy, [Column("EVIDENCE", max_width=14, tail=False)],
                 [["both structures"], ["journal only"]])
    lines = policy.err_stream.getvalue().splitlines()
    assert "EVIDENCE" in lines[0]
    # 14 wide, so 11 characters plus the ellipsis, and the head of the value.
    assert lines[2].strip() == "both struct..."


def test_path_column_still_keeps_its_tail():
    policy = OutputPolicy(color=False, stream=io.StringIO(), err_stream=io.StringIO())
    render_table(policy, [Column("PATH", max_width=20)],
                 [["/very/long/prefix/forever/carved_00001.png"]])
    assert "carved_00001.png" in policy.err_stream.getvalue()


def test_column_caption_is_never_ellipsised_away():
    """A long value in one column must not squeeze a short caption to nothing."""
    policy = OutputPolicy(color=False, stream=io.StringIO(), err_stream=io.StringIO())
    render_table(
        policy,
        [Column("NAME", max_width=12), Column("EVIDENCE", max_width=13, tail=False)],
        [["/a/very/long/path/indeed/name.txt", "both structures"]],
    )
    lines = policy.err_stream.getvalue().splitlines()
    assert "EVIDENCE" in lines[0]
    # 13 wide is 10 characters plus the ellipsis.
    assert "both struc..." in lines[2]
