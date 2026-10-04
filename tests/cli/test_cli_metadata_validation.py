"""Tests for CLI metadata validation on wipe, carve, image subcommands."""

from types import SimpleNamespace

from s0.cli.main import _validate_cli_metadata, cmd_wipe
from s0.terminal import EX_USAGE


def test_validate_cli_metadata_valid():
    args = SimpleNamespace(
        operator="valid_op", operator_id="valid_op", organization="Digital Forensics & Data Sanitization Lab"
    )
    assert _validate_cli_metadata(args) is True
    assert args.operator == "valid_op"


def test_validate_cli_metadata_xss_rejected(capsys):
    bad_payloads = [
        "<script>alert(1)</script>",
        "op>redirect",
        "op|pipe",
        'op"quote',
        "op\x27quote",
    ]
    for bad in bad_payloads:
        args = SimpleNamespace(operator=bad, organization="Valid Org")
        assert _validate_cli_metadata(args) is False
        err = capsys.readouterr().err
        assert "error: invalid --operator" in err

        args = SimpleNamespace(operator="valid_op", organization=bad)
        assert _validate_cli_metadata(args) is False
        err = capsys.readouterr().err
        assert "error: invalid --organization" in err


def test_cmd_wipe_rejects_bad_operator(capsys):
    args = SimpleNamespace(
        operator="bad<script>",
        organization="Valid Org",
        targets=["/dev/null"],
        target="/dev/null",
        yes=True,
    )
    rc = cmd_wipe(args)
    assert rc == EX_USAGE
    err = capsys.readouterr().err
    assert "invalid --operator" in err
