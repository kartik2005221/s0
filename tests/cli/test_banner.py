"""The ASCII banner must actually be reachable.

Regression (9c13675): ``_print_banner`` was called *after* ``parse_args``, but
bare ``s0`` (subparsers are required) and ``--help`` both exit inside
``parse_args`` -- so the banner could never display for either trigger. The
call now happens before parsing, with suppression flags scanned from raw argv
because the parsed output policy does not exist yet.
"""

from __future__ import annotations

import io
import sys

import pytest

import s0.cli.main as main_mod


@pytest.fixture
def banner_calls(monkeypatch):
    calls = []
    monkeypatch.setattr(main_mod, "_print_banner", lambda *a, **k: calls.append(k))
    return calls


def test_bare_s0_prints_the_banner_before_the_usage_error(banner_calls):
    """`s0` exits 64 with a required-subparser usage error -- but the banner
    must have printed first, not been skipped by the argparse exit."""
    rc = main_mod.main([])
    assert rc == main_mod.EX_USAGE
    assert banner_calls, "bare `s0` must show the banner"


def test_help_prints_the_banner(banner_calls):
    """`s0 --help` exits inside parse_args after printing help; the banner
    call must have happened before that exit. main() maps the argparse
    SystemExit(0) to a clean 0."""
    rc = main_mod.main(["--help"])
    assert rc == 0
    assert banner_calls, "`s0 --help` must show the banner"


def test_a_subcommand_shows_no_banner(banner_calls):
    """The banner is chrome for bare `s0`/`--help` only; real commands never
    print it, or every JSON envelope's stderr chatter grows a logo."""
    main_mod.main(["list", "--json"])
    assert banner_calls == []


def test_quiet_suppresses_the_pre_parse_banner(banner_calls):
    main_mod.main(["--quiet"])
    assert banner_calls == []


def test_structured_format_suppresses_the_pre_parse_banner(banner_calls):
    main_mod.main(["--format", "json"])
    assert banner_calls == []


def test_banner_suppressed_by_flags_helper():
    from s0.cli.main import _banner_suppressed_by_flags

    assert _banner_suppressed_by_flags([]) is False
    assert _banner_suppressed_by_flags(["--help"]) is False
    assert _banner_suppressed_by_flags(["--quiet"]) is True
    assert _banner_suppressed_by_flags(["-q"]) is True
    assert _banner_suppressed_by_flags(["--json"]) is True
    assert _banner_suppressed_by_flags(["--format", "json"]) is True
    assert _banner_suppressed_by_flags(["--format", "text"]) is False
    assert _banner_suppressed_by_flags(["--format=json"]) is True


def test_banner_content_when_stderr_is_a_tty(monkeypatch):
    """With no parsed policy yet, the TTY fallback governs; on a TTY the art
    and the version line are written to stderr (never stdout)."""
    stream = io.StringIO()
    stream.isatty = lambda: True  # type: ignore[method-assign]
    monkeypatch.setattr(sys, "stderr", stream)
    main_mod._print_banner()
    out = stream.getvalue()
    assert "/$$$$$$" in out, "the ASCII art itself is missing"
    assert "Sector Zero (s0)" in out
    assert "github.com/kartik2005221/s0" in out


def test_banner_stays_off_stderr_when_not_a_tty(monkeypatch):
    stream = io.StringIO()
    stream.isatty = lambda: False  # type: ignore[method-assign]
    monkeypatch.setattr(sys, "stderr", stream)
    main_mod._print_banner()
    assert stream.getvalue() == ""
