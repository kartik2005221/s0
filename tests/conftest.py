"""Test isolation. Read at collection time, before any s0 module is imported.

## Why this file exists at all

Running the test suite created `~/.s0/` on the developer's machine, containing
audit blocks signed by `op-forensic`, `op-e2e-test` and `op-cert-test`, plus
keypairs and a web auth token. `s0 audit verify` then failed with

    UNVERIFIABLE - SIGNING KEY NOT IN THE TRUST SET

On an examiner's workstation this is not untidy, it is damaging: the tool's
chain-of-custody ledger is the record of every operation already performed, and a
test run appends blocks to it signed by keys that are not in any trust set. The
ledger then no longer verifies, and there is no supported way to tell those blocks
apart from real evidence.

## Why it is module level and not a fixture

`s0.audit.db` evaluates `DEFAULT_AUDIT_DB = get_default_audit_db()` at *import*
time, and `s0.config` resolves `~/.s0/s0_config.json` the same way. A fixture
runs after collection, by which point those modules are already imported and the
real paths are baked in. Setting `HOME` here, at conftest import, happens before
pytest imports any test module, so the constants come out pointing at the
temporary tree.

`homedir` is redirected too, because `pathlib.Path.home()` consults it on POSIX
and a process that has already cached the real home would otherwise keep writing
there.
"""

from __future__ import annotations

import atexit
import os
import shutil
import tempfile

# A per-run temporary home. `prefix` keeps it out of $TMPDIR's immediate listing
# noise and makes it obvious in a `ls /tmp` what the directory is.
_SANDBOX_HOME = tempfile.mkdtemp(prefix="s0-test-home-")

os.environ["HOME"] = _SANDBOX_HOME
os.environ["USERPROFILE"] = _SANDBOX_HOME  # Windows
os.environ["homedir"] = _SANDBOX_HOME  # consulted by Path.home() on some builds

# Point the audit ledger at the sandbox explicitly as well, so isolation holds even
# if a future refactor reintroduces a direct path that does not consult HOME.
#
# S0_CONFIG_PATH is deliberately NOT set. Pointing it at a missing file makes every
# command emit a "no such config" warning (which is correct behaviour, and was
# briefly introduced here), and HOME redirection already excludes a developer's own
# ~/.s0/s0_config.json -- which is the only thing that variable would be used to
# defeat.
os.environ["S0_AUDIT_DB"] = os.path.join(_SANDBOX_HOME, ".s0", "s0_audit.db")

atexit.register(shutil.rmtree, _SANDBOX_HOME, True)


def pytest_report_header(config) -> list[str]:
    """Make the sandbox visible in the run header.

    A test suite that silently redirects HOME is the kind of thing that looks like
    a bug the next time somebody reads the output, so it is stated outright.
    """
    return [f"s0: HOME redirected to {_SANDBOX_HOME} for the duration of the run"]

def test_home_is_redirected_for_the_whole_run() -> None:
    """The isolation is load-bearing, so assert it rather than trust it.

    If a future refactor reintroduces a direct `Path.home()` write, this is the
    test that notices -- and it is a test in the suite rather than a comment,
    because the whole point of the finding was that a comment would not have
    helped.
    """
    from pathlib import Path

    real = Path(os.environ["HOME"])
    assert str(real).startswith(tempfile.gettempdir()), (
        f"HOME is {real}, not inside the temporary directory; the test suite is "
        "writing to the developer's real home directory"
    )
    assert real.name.startswith("s0-test-home-")

    # The ledger s0 itself resolved must also be inside the sandbox.
    from s0.config import CONFIG  # noqa: F401  (import proves load order)
    from s0.resources import get_default_audit_db

    db = get_default_audit_db()
    assert str(db).startswith(str(real)), f"audit ledger resolves to {db}, outside the sandbox"
