"""END-TO-END: plant recoverable data -> wipe via CLI -> forensically verify ->
signed certificate -> independent verification -> tamper rejection.

This is the core demo loop of the whole project, automated. It runs on a
file-backed image (no root needed); the bytes are real and land on disk.
"""

import json
from pathlib import Path

import pytest

from s0 import certificate, crypto
from s0.cli import main as cli_main
from s0.wipe.methods.overwrite import count_pattern_hits, plant_patterns

MARKER = b"S0-CONFIDENTIAL-PAN-ABCD1234F"
IMAGE_SIZE = 24 * 1024 * 1024


@pytest.fixture(scope="module")
def e2e(tmp_path_factory):
    """Run the full wipe through the real CLI entry point; return artifacts."""
    tmp = tmp_path_factory.mktemp("e2e")
    img = tmp / "target_disk.img"

    # 1. Create a non-sparse target with junk + externally-planted markers.
    #    The CLI's own --plant-markers adds its own random marker set on top,
    #    so BOTH the external forensic grep and the CLI's internal check run.
    with open(img, "wb") as f:
        f.write(b"\x5a" * IMAGE_SIZE)
    n_markers = 12
    stride = IMAGE_SIZE // n_markers
    plant_patterns(str(img), [(i * stride, MARKER) for i in range(n_markers)])
    assert count_pattern_hits(str(img), MARKER) == n_markers

    out_dir = tmp / "out"
    key = tmp_path_factory.mktemp("k") / "issuer_private.pem"
    from s0.crypto import write_private_pem, write_public_pem
    priv = crypto.generate_private_key()
    write_private_pem(priv, key)
    pub = tmp_path_factory.mktemp("k") / "issuer_public.pem"
    write_public_pem(priv.public_key(), pub)

    # 2. Wipe through the actual CLI argv path.
    rc = cli_main.main([
        "wipe",
        "--target", str(img),
        "--yes",
        "--key", str(key),
        "--out-dir", str(out_dir),
        "--operator", "op-e2e-test",
        "--organization", "s0 Test Lab",
        "--pattern", "zero",
        "--plant-markers",
        "--json",
    ])
    assert rc == 0, "CLI wipe exited non-zero"

    cert_files = sorted(out_dir.glob("certificate_*.json"))
    pdf_files = sorted(out_dir.glob("certificate_*.pdf"))
    qr_files = sorted(out_dir.glob("certificate_*.qr.png"))
    assert len(cert_files) == 1 and len(pdf_files) == 1 and len(qr_files) == 1

    return {
        "image": img, "cert": json.loads(cert_files[0].read_text()),
        "cert_file": cert_files[0], "pdf": pdf_files[0],
        "pub_key": pub, "n_markers": n_markers,
    }


def test_forensic_grep_finds_nothing(e2e):
    """The planted marker must be unrecoverable by raw byte search."""
    assert count_pattern_hits(str(e2e["image"]), MARKER) == 0


def test_certificate_records_honest_clear_tier_and_verification(e2e):
    cert = e2e["cert"]
    assert cert["wipe"]["method"] == "OVERWRITE_ZERO_1PASS"
    assert cert["wipe"]["nist_category"] == "Clear"  # never Purge for overwrite
    assert cert["result"]["status"] == "success"
    v = cert["result"]["verification"]
    assert v["all_samples_match_wipe_pattern"] is True
    assert v["planted_pattern_hits_after"] == 0
    assert any("image target" in n.lower() for n in cert.get("notes", []))


def test_certificate_verifies_against_issuer_key(e2e):
    pub = crypto.load_public_pem(e2e["pub_key"])
    ok, reason = certificate.verify_certificate(e2e["cert"], [pub])
    assert ok, reason


def test_pdf_and_qr_were_produced(e2e):
    assert e2e["pdf"].stat().st_size > 2000


def test_plan_dry_run_does_not_modify_target(tmp_path, monkeypatch):
    img = tmp_path / "planme.img"
    img.write_bytes(b"\x77" * (1024 * 1024))
    before = img.read_bytes()

    rc = cli_main.main(["plan", "--target", str(img)])
    assert rc == 0
    assert img.read_bytes() == before, "plan must never write to the target"


def test_wipe_refuses_missing_target():
    assert cli_main.main(["wipe", "--yes", "--target", "/nonexistent/path.img"]) == 2


def test_uninstall_cli_subcommand(tmp_path, monkeypatch):
    dummy_install = tmp_path / ".s0"
    dummy_install.mkdir()
    (dummy_install / "dummy.txt").write_text("s0 content")
    audit_file = dummy_install / "s0_audit.db"
    audit_file.write_text("sqlite-mock-audit")

    monkeypatch.setenv("S0_INSTALL_DIR", str(dummy_install))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    # Test uninstall with --yes and --keep-audit
    rc = cli_main.main(["uninstall", "--yes", "--keep-audit"])
    assert rc == 0
    assert not dummy_install.exists()
    assert (tmp_path / "s0_audit.db.bak").exists()

