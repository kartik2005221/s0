"""Guard parity across the web API, and a dashboard that admits what it exposes.

**`/api/image` had no guard on `destination`.** `/api/carve` refused an `out_dir` inside
a system path; `/api/image` wrote the image wherever `destination` said, including
`/etc`. Two routes taking an output path applied different rules to the same class of
input, and the dashboard documents itself as wanting root -- so that is a write into
`/etc` by a component whose sibling route blocks the same thing.

An API that blocks one of two equivalent inputs is not a security control, it is a
coincidence. All five system-path checks now call one function, so parity is structural
rather than a fact someone has to remember.

**The banner claimed "Strict loopback isolation" whatever `--host` said.** With
`--host 0.0.0.0` the server listens on every interface. The only thing protecting a
non-loopback bind is the session token -- the Host allow-list checks the header the client
chose to send, so it stops nothing. The label is now truthful and a non-loopback bind
warns.

**The portal returned `ok: true` for a demo-key certificate.** The signature check *did*
pass and the page renders it correctly ("VALID SIGNATURE -- UNACCREDITED DEMO KEY", amber).
But `s0 verify` exits 75 for the same file specifically so a pipeline cannot read it as a
pass, and a script consuming the verifier's return value got the opposite. `attested` and
`cliExitCode` are now in the result, so a machine consumer has something to gate on.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
APP = REPO_ROOT / "src" / "s0" / "web" / "app.py"
VERIFY_JS = REPO_ROOT / "site" / "verify" / "verify.js"
KEYS_JSON = REPO_ROOT / "site" / "verify" / "keys.json"
MAIN = REPO_ROOT / "src" / "s0" / "cli" / "main.py"


class TestOutputPathGuardsAreParityByConstruction:
    def test_every_system_path_check_goes_through_one_function(self):
        """If someone adds a route, they get the rule by calling the shared helper."""
        source = APP.read_text(encoding="utf-8")
        inline = source.count('raise ValueError(f"out_dir cannot be in system path')
        assert inline == 0, (
            f"{inline} route(s) still inline the system-path check for out_dir instead of "
            f"calling _reject_system_path; parity is not structural any more"
        )
        inline_key = source.count('raise ValueError(f"key_path cannot be in system path')
        assert inline_key == 0, f"{inline_key} inline key_path check(s) remain"
        assert "def _reject_system_path(" in source

    def test_image_destination_is_guarded(self):
        """The field that names where the image is *written*, which was the gap."""
        source = APP.read_text(encoding="utf-8")
        img = source[source.index("class ImageRequest") :]
        img = img[: img.index("\nclass ", 5)] if "\nclass " in img[5:] else img
        assert "def validate_destination" in img, (
            "ImageRequest has no destination validator; /api/image writes wherever "
            "destination says while /api/carve guards the equivalent field"
        )
        assert '_reject_system_path("destination"' in img

    @pytest.mark.parametrize("field", ["out_dir", "key_path", "destination"])
    def test_the_helper_names_the_field_in_its_error(self, field):
        """An error saying "out_dir" for a destination field sends the operator hunting."""
        sys.path.insert(0, str(REPO_ROOT / "src"))
        from s0.web.app import _reject_system_path

        with pytest.raises(ValueError, match=field):
            _reject_system_path(field, "/etc/s0-probe")

    def test_a_legitimate_path_is_accepted(self):
        sys.path.insert(0, str(REPO_ROOT / "src"))
        from s0.web.app import _reject_system_path

        assert _reject_system_path("out_dir", "/home/user/evidence") == "/home/user/evidence"
        assert _reject_system_path("out_dir", None) is None
        assert _reject_system_path("out_dir", "  ") == "  "


class TestTheBindingLabelIsTrue:
    def test_the_banner_does_not_claim_loopback_unconditionally(self):
        source = MAIN.read_text(encoding="utf-8")
        assert 'f"[s0 web]  Binding  : {host} (Strict loopback isolation)"' not in source, (
            "the banner still claims 'Strict loopback isolation' whatever --host says"
        )
        assert "loopback only" in source, "the loopback case is no longer labelled"
        assert "is not a loopback address" in source, (
            "a non-loopback bind does not warn; that is the case the false label hid"
        )

    def test_it_reports_both_ways(self, tmp_path):
        entry = shutil.which("s0") or str(Path(sys.executable).parent / "s0")
        if not Path(entry).is_file():
            pytest.skip("s0 entry point not available")
        if not shutil.which("script"):
            pytest.skip("needs util-linux `script` to give the banner a TTY")

        def banner(*args: str) -> str:
            # `s0 web` runs until interrupted, so this starts it, lets the banner print,
            # then kills it -- reading the output either way. `subprocess.run(timeout=...)`
            # would raise TimeoutExpired and discard the very lines under test.
            proc = subprocess.Popen(
                ["script", "-qec", f"{entry} web --no-browser " + " ".join(args), "/dev/null"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                cwd=str(tmp_path),
                env={**os.environ, "HOME": str(tmp_path)},
                start_new_session=True,
            )
            try:
                out, _ = proc.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, 15)
                try:
                    out, _ = proc.communicate(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    out, _ = proc.communicate()
            return out or ""

        loop = banner()
        assert "loopback only" in loop, loop[-400:]
        assert "is not a loopback address" not in loop, (
            "the default loopback bind warned about network exposure: " + loop[-400:]
        )

        # S104: binding to all interfaces is the point of this test -- it is asserting
        # that s0 *warns* when asked to do it.
        wide = banner("--host", "0.0.0.0")  # noqa: S104
        assert "0.0.0.0 is not a loopback address" in wide, wide[-500:]
        assert "Strict loopback isolation" not in wide


class TestThePortalSaysWhatTheCliSays:
    """`s0 verify` exits 75 for a demo-key certificate. The portal must agree.

    Driven through the real `verify.js` under Node when Node is available, and by
    reading the source otherwise -- the UI already renders this case correctly, so the
    only thing at risk is the machine-readable result.
    """

    def test_the_demo_key_result_is_machine_readable_as_unaccredited(self):
        source = VERIFY_JS.read_text(encoding="utf-8")
        assert "attested: !isDemoKey" in source, (
            "verify.js does not report whether the document is attributable to an "
            "accredited issuer; a consumer reading ok:true cannot tell a demo key apart"
        )
        assert "cliExitCode: isDemoKey ? 75 : 0" in source, (
            "verify.js does not carry the exit code `s0 verify` would return"
        )

    def test_the_ui_still_renders_the_demo_key_case(self):
        """Adding the fields must not have broken the page's own handling."""
        portal = (REPO_ROOT / "site" / "verify" / "js" / "portal.js").read_text(encoding="utf-8")
        assert "isDemoKey" in portal, "portal.js stopped special-casing the demo key"
        assert "UNACCREDITED DEMO KEY" in portal.upper()

    @pytest.mark.skipif(shutil.which("node") is None, reason="needs node to load verify.js")
    def test_it_agrees_with_the_cli_on_a_real_certificate(self, tmp_path):
        target = tmp_path / "e.bin"
        target.write_bytes(b"evidence\n" * 200)
        entry = shutil.which("s0") or str(Path(sys.executable).parent / "s0")
        if not Path(entry).is_file():
            pytest.skip("s0 entry point not available")
        wipe = subprocess.run(
            [entry, "wipe", "--targets", str(target), "--yes", "--no-pdf", "--out-dir", str(tmp_path / "c")],
            capture_output=True,
            text=True,
            timeout=900,
            env={**os.environ, "HOME": str(tmp_path)},
        )
        assert wipe.returncode == 0, wipe.stderr[-400:]
        certs = list((tmp_path / "c").glob("*.json"))
        assert certs, "no certificate produced"
        cert = json.loads(certs[0].read_text(encoding="utf-8"))

        cli = subprocess.run(
            [entry, "verify", str(certs[0])],
            capture_output=True,
            text=True,
            timeout=600,
            env={**os.environ, "HOME": str(tmp_path)},
        )

        script = f"""
const v = require({json.dumps(str(VERIFY_JS))});
const keys = require({json.dumps(str(KEYS_JSON))}).trusted_keys;
const cert = {json.dumps(cert)};
const r = v.verifyCertificate(cert, keys);
console.log(JSON.stringify({{ok: r.ok, isDemoKey: r.isDemoKey,
  attested: r.attested, cliExitCode: r.cliExitCode}}));
"""
        node = subprocess.run(["node", "-e", script], capture_output=True, text=True, timeout=120)
        assert node.returncode == 0, node.stderr[-400:]
        got = json.loads(node.stdout.strip().splitlines()[-1])

        assert got["isDemoKey"] is True, "the demo key was not detected"
        assert got["attested"] is False, "the portal calls a demo-key certificate attested; it is not"
        assert got["cliExitCode"] == cli.returncode, (
            f"the portal says the CLI would exit {got['cliExitCode']}, and it exited {cli.returncode}"
        )


class TestThePinnedKeyListIsHonestAboutWhatItPins:
    def test_keys_json_says_the_pinned_key_is_not_accredited(self):
        keys = json.loads(KEYS_JSON.read_text(encoding="utf-8"))
        entry = keys["trusted_keys"][0]
        assert "unaccredited" in entry["issuer"].lower(), (
            "the pinned demo key's issuer does not say it is unaccredited; a verifier "
            "reading only this field cannot tell what it is trusting"
        )
