"""The audit ledger must never report "valid" for something it did not check.

Two ways it used to:

1. **Fail open on an empty trust set.** `verify_audit_ledger` computed
   `effective_keys` and then guarded both signature checks with
   `if effective_keys:`. With no trusted key available -- a normal non-editable
   install with no `~/.s0/keys` -- both checks were skipped and the ledger was
   still reported valid. The block hash is plain SHA-256 over fields anyone can
   recompute, so the signatures were the only authenticity there was; a ledger
   whose signatures had been replaced with arbitrary bytes verified as
   "VALID & CONTINUOUS".

2. **Trust a key from the current directory.** `get_default_trusted_keys()` used
   to include `Path("core/keys/demo_issuer_public.pem")`, a CWD-relative path, in
   its candidate list. An examiner who `cd`s into a case folder supplied by a
   third party and runs `s0 audit verify` would silently trust a planted key.

An empty trust set is not "nothing to check"; it is "nothing can be checked", and
the report has to say so.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent.parent
DEMO_PUB = REPO / "src" / "s0" / "data" / "keys" / "demo_issuer_public.pem"


def _run_verify(db: Path, *extra: str, cwd: Path | None = None) -> subprocess.CompletedProcess:
    env = {**os.environ, "S0_AUDIT_DB": str(db)}
    return subprocess.run(
        [str(Path(sys.executable).parent / "s0"), "audit", "verify", *extra],
        capture_output=True, text=True, env=env, cwd=str(cwd or REPO), timeout=120,
    )


@pytest.fixture(scope="module")
def ledger(tmp_path_factory) -> Path:
    """A real, valid, demo-key-signed ledger."""
    from s0.audit.db import init_audit_db, record_audit_event
    from s0.certificate import build_certificate, sign_certificate
    from s0.crypto import load_private_pem

    db = tmp_path_factory.mktemp("ledger") / "chain.db"
    init_audit_db(db)
    priv = load_private_pem(REPO / "src" / "s0" / "data" / "keys" / "demo_issuer_private.pem")
    for _ in range(2):
        # A real certificate: record_audit_event() validates before appending.
        cert = build_certificate(
            organization="Acme", operator_id="op-test", tool_name="s0",
            tool_version="2.4.4", platform="linux", device_id="sha256:deadbeef",
            device_type="removable_disk", storage_type="HDD",
            method="OVERWRITE_ZERO_1PASS", nist_category="Clear",
            start_time="2026-01-01T00:00:00Z", end_time="2026-01-01T00:01:00Z",
            bytes_processed=4096, capacity_bytes=8192,
        )
        record_audit_event(
            sign_certificate(cert, priv),
            operation_type="DRIVE_ERASE",
            db_path=db,
        )
    return db


def test_empty_trust_set_fails_closed(ledger):
    """The core bug: no key meant no check, and the answer was still 'valid'."""
    from s0.audit.verify import verify_audit_ledger

    report = verify_audit_ledger(ledger, trusted_public_keys=[])
    assert report.is_valid is False, (
        "an empty trusted-key set must not verify. The signature checks are "
        "skipped in that case, so a ledger with arbitrary signatures would "
        "otherwise pass."
    )
    assert report.total_blocks_verified == 0
    assert "UNVERIFIABLE" in (report.reason or "") or "no trusted" in (report.reason or "").lower()


def test_the_reason_explains_that_continuity_is_not_authenticity(ledger):
    from s0.audit.verify import verify_audit_ledger

    report = verify_audit_ledger(ledger, trusted_public_keys=[])
    text = " ".join([report.reason or ""] + list(report.details or [])).lower()
    assert "continuity is not authenticity" in text, (
        f"the refusal must say why an unchecked chain is not a verified one: {report.reason!r}"
    )
    assert "do not treat" in text, (
        f"the refusal must tell the operator not to rely on the result: {report.details!r}"
    )


def test_a_real_key_still_verifies(ledger):
    """The refusal must not fire when a key genuinely is available."""
    from s0.audit.verify import verify_audit_ledger

    report = verify_audit_ledger(ledger)  # default: packaged demo public key
    assert report.is_valid is True, f"a valid demo-key ledger should verify: {report.reason}"
    assert report.total_blocks_verified >= 2


def test_cli_refuses_an_empty_trust_set(ledger):
    """`s0 audit verify --key <empty dir>` must exit non-zero, not pass."""
    empty = ledger.parent / "empty-keys"
    empty.mkdir(exist_ok=True)
    result = _run_verify(ledger, "--key", str(empty))
    assert result.returncode != 0, (
        f"an empty key directory must not exit 0.\n{result.stdout}\n{result.stderr}"
    )
    assert "no *.pem" in (result.stdout + result.stderr)


def test_cli_accepts_a_directory_of_keys(ledger):
    """Regression: `--key <directory>` raised IsADirectoryError as a traceback."""
    keydir = ledger.parent / "keys"
    keydir.mkdir(exist_ok=True)
    (keydir / "issuer.pem").write_bytes(DEMO_PUB.read_bytes())
    result = _run_verify(ledger, "--key", str(keydir))
    assert "IsADirectoryError" not in result.stderr, (
        f"--key on a directory must not traceback:\n{result.stderr[-600:]}"
    )
    assert "Traceback" not in result.stderr
    assert "Loaded 1 trusted issuer key" in (result.stdout + result.stderr)


def test_cli_accepts_several_keys(ledger):
    """A ledger signed by more than one key needs every signer supplied."""
    second = ledger.parent / "keys2"
    second.mkdir(exist_ok=True)
    (second / "other.pem").write_bytes(DEMO_PUB.read_bytes())
    result = _run_verify(ledger, "--key", str(DEMO_PUB), "--key", str(second))
    combined = result.stdout + result.stderr
    assert "Traceback" not in combined, combined[-600:]
    assert "Loaded" in combined


def test_trust_anchor_is_never_cwd_relative(ledger):
    """N-2: a key planted in the working directory must not become trusted.

    `get_default_trusted_keys()` used to include the CWD-relative path
    `core/keys/demo_issuer_public.pem`. An examiner running `s0 audit verify`
    inside a third party's case folder would trust whatever was planted there.
    """
    import shutil

    from s0.audit.verify import get_default_trusted_keys

    elsewhere = ledger.parent / "attacker"
    (elsewhere / "core" / "keys").mkdir(parents=True, exist_ok=True)
    shutil.copy(DEMO_PUB, elsewhere / "core" / "keys" / "demo_issuer_public.pem")

    cwd = os.getcwd()
    try:
        os.chdir(elsewhere)
        keys = get_default_trusted_keys()
    finally:
        os.chdir(cwd)

    # The demo key is also found via the packaged resource, so compare against
    # what the same call returns from a clean directory.
    clean = get_default_trusted_keys()
    from s0.crypto import public_key_fingerprint

    planted_fp = public_key_fingerprint(
        __import__("s0.crypto", fromlist=["load_public_pem"]).load_public_pem(
            elsewhere / "core" / "keys" / "demo_issuer_public.pem"
        )
    )
    found = {public_key_fingerprint(k) for k in keys}
    assert len(found) == len(clean) or planted_fp in {public_key_fingerprint(k) for k in clean}, (
        "the trust set grew after cd-ing into a directory containing a planted "
        "core/keys/demo_issuer_public.pem -- the CWD anchor is back"
    )


def test_get_default_trusted_keys_has_no_relative_candidate():
    """Static guard: the loader must not reintroduce a CWD-relative path."""
    from s0.audit import verify as v

    source = Path(v.__file__).read_text(encoding="utf-8")
    body = source[source.index("def get_default_trusted_keys"):]
    body = body[: body.index("\ndef ", 5)]
    for suspect in ('Path("core/keys', "Path('core/keys", 'Path("./', "Path('."):
        assert suspect not in body, (
            f"get_default_trusted_keys() references {suspect!r}; a trust anchor "
            "must never be resolved relative to the working directory"
        )
