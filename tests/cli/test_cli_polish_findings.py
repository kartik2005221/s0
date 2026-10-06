"""Tests verifying S0-13, S0-14, S0-18 CLI polish and ergonomics."""

from __future__ import annotations

import json

from s0.cli.main import main
from s0.terminal import EX_DATAERR, EX_NOINPUT, EX_USAGE


def test_plan_missing_target_prints_usage(capsys):
    rc = main(["plan"])
    assert rc == EX_USAGE
    captured = capsys.readouterr()
    assert "usage: s0 plan" in captured.err
    assert "the following arguments are required: --target" in captured.err


def test_carve_missing_target_exits_without_banners(tmp_path, capsys):
    out_dir = tmp_path / "out"
    rc = main(["carve", "--target", "/nonexistent/img.raw", "--out-dir", str(out_dir)])
    assert rc == EX_NOINPUT
    captured = capsys.readouterr()
    assert "target not found" in captured.err
    assert "LEGAL & RESPONSIBLE USE NOTICE" not in captured.err
    assert "S0 - Forensic File Carving & Recovery" not in captured.err
    assert not out_dir.exists()


def test_carve_custom_sig_list_of_ints_gives_clean_error(tmp_path, capsys):
    img = tmp_path / "test.img"
    img.write_bytes(b"\x00" * 1024)
    out_dir = tmp_path / "out"
    rc = main(["carve", "--target", str(img), "--out-dir", str(out_dir), "--custom-sig", "[1, 2]"])
    assert rc == EX_DATAERR
    captured = capsys.readouterr()
    assert "'int' object has no attribute 'get'" not in captured.err
    assert "expected custom signature object" in captured.err


def test_quiet_mode_suppresses_banners_in_carve(tmp_path, capsys):
    img = tmp_path / "test.img"
    img.write_bytes(b"\x00" * 1024)
    out_dir = tmp_path / "out"
    rc = main(
        [
            "carve",
            "--target",
            str(img),
            "--out-dir",
            str(out_dir),
            "--quiet",
            "--no-certificate",
            "--no-pdf",
        ]
    )
    assert rc == 0
    captured = capsys.readouterr()
    assert "LEGAL & RESPONSIBLE USE NOTICE" not in captured.err
    assert "S0 - Forensic File Carving & Recovery" not in captured.err


def test_verify_does_not_duplicate_reason(tmp_path, capsys):
    bad_cert = tmp_path / "bad_cert.json"
    bad_cert.write_text(json.dumps({"cert_uuid": "123", "notes": ["invalid"]}))
    rc = main(["verify", str(bad_cert)])
    assert rc != 0
    captured = capsys.readouterr()
    # "Reason" should only appear once as a field in output
    assert captured.err.count("Reason") <= 1
