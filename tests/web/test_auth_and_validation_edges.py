"""The web dashboard's authentication and validation edges.

Everything here was reachable on a live server and none of it was covered.

**A world-readable live token.** ``os.open(path, ..., 0o600)`` applies its mode
only when the file is *created*. A ``~/.s0/web_auth_token`` left at 0644 by an
earlier version kept its mode while holding the live session credential, so the
mode argument looked like it was protecting the file and was not.

**Import rotated the token.** The token was generated and written at module
import, so merely importing the app rewrote the file. A second process -- a
reload, a test, a second worker -- silently invalidated the token a running
dashboard was already using, and the operator's cookie stopped working with
nothing having changed on their side.

**``?token=`` worked everywhere.** It is documented as a bootstrap for the kiosk,
which cannot set a header, and ``GET /`` converts it to a cookie and redirects to
a clean URL. But every API route honoured it too, which defeats the reason for
restricting it: a token in a URL leaks into browser history, Referer headers and
proxy logs.

**No server-side Origin check.** SameSite=Strict stops a browser sending the
cookie cross-site, and no CORS middleware means a cross-origin read is blocked.
That is real protection, but it rests entirely on the client honouring
SameSite. Nothing checked the request itself.

**``%00`` in a filename returned a 500.** ``Path.resolve()`` raises ValueError on
an embedded NUL and nothing caught it, so the deepest layer of the request threw.

**``min_confidence=999`` was accepted.** The CLI documents 0-100 and rejects
out-of-range values; the web tier did not.

**Host matching was case-sensitive.** RFC 9110 says host names are
case-insensitive, so ``Host: LOCALHOST`` got a 400 while ``Host: localhost`` was
accepted. Fails closed, so never a hole -- a robustness bug.

**An existing imaging destination returned an opaque code.** The operator got
``operation_failed`` and a correlation id they have no way to look up, instead of
"destination exists, pass force".
"""

from __future__ import annotations

import os
import stat

import pytest
from fastapi.testclient import TestClient

from s0.web import app as gui


@pytest.fixture
def client():
    return TestClient(gui.app)


def _token() -> str:
    return gui._SESSION_AUTH_TOKEN


def _auth() -> dict[str, str]:
    return {"X-S0-Auth-Token": _token()}


class TestTokenFilePermissions:
    @pytest.fixture(autouse=True)
    def _isolate_home(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("USERPROFILE", str(tmp_path))

    @pytest.mark.skipif(os.name == "nt", reason="POSIX file permission bits not supported on Windows")
    def test_a_preexisting_loose_token_file_is_narrowed(self, tmp_path, monkeypatch):
        """The reported defect: 0644 survives because the mode only applies on create."""
        token_file = tmp_path / ".s0" / "web_auth_token"
        token_file.parent.mkdir(parents=True)
        token_file.write_text("a" * 64)
        os.chmod(token_file, 0o644)
        assert stat.S_IMODE(token_file.stat().st_mode) == 0o644

        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.delenv("S0_WEB_AUTH_TOKEN", raising=False)
        gui._load_or_create_session_token()

        mode = stat.S_IMODE(token_file.stat().st_mode)
        assert mode == 0o600, (
            f"a pre-existing token file was left at {mode:04o} while holding the "
            f"live session token; os.open's mode argument is ignored for an "
            f"existing file, so it must be chmod'ed explicitly"
        )

    def test_the_adopted_token_is_the_one_on_disk(self, tmp_path, monkeypatch):
        token_file = tmp_path / ".s0" / "web_auth_token"
        token_file.parent.mkdir(parents=True)
        token_file.write_text("b" * 64)
        os.chmod(token_file, 0o600)
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.delenv("S0_WEB_AUTH_TOKEN", raising=False)
        assert gui._load_or_create_session_token() == "b" * 64

    def test_a_corrupt_token_file_is_replaced_not_adopted(self, tmp_path, monkeypatch):
        token_file = tmp_path / ".s0" / "web_auth_token"
        token_file.parent.mkdir(parents=True)
        token_file.write_text("truncated")
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.delenv("S0_WEB_AUTH_TOKEN", raising=False)
        issued = gui._load_or_create_session_token()
        assert issued != "truncated", "a malformed token file was adopted as the credential"
        assert len(issued) == 64

    @pytest.mark.skipif(os.name == "nt", reason="POSIX file permission bits not supported on Windows")
    def test_a_fresh_token_file_is_0600(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.delenv("S0_WEB_AUTH_TOKEN", raising=False)
        gui._load_or_create_session_token()
        token_file = tmp_path / ".s0" / "web_auth_token"
        assert stat.S_IMODE(token_file.stat().st_mode) == 0o600

    def test_the_environment_override_still_wins(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("S0_WEB_AUTH_TOKEN", "c" * 64)
        assert gui._load_or_create_session_token() == "c" * 64

    def test_repeated_calls_do_not_rotate_the_token(self, tmp_path, monkeypatch):
        """Importing must not invalidate a token another process is serving."""
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.delenv("S0_WEB_AUTH_TOKEN", raising=False)
        first = gui._load_or_create_session_token()
        assert gui._load_or_create_session_token() == first


class TestQueryTokenIsBootstrapOnly:
    API = "/api/devices"

    def test_an_api_route_refuses_the_query_token(self, client):
        r = client.get(f"{self.API}?token={_token()}")
        assert r.status_code == 401, (
            "?token= was accepted on an API route; it is a bootstrap for the kiosk "
            "and leaks into browser history, Referer headers and proxy logs"
        )

    def test_the_error_explains_what_to_use_instead(self, client):
        detail = client.get(f"{self.API}?token={_token()}").json()["detail"]
        assert "X-S0-Auth-Token" in detail, (
            "the rejection does not say how to authenticate, so an integrator is left guessing"
        )

    def test_the_header_still_works_on_an_api_route(self, client):
        assert client.get(self.API, headers=_auth()).status_code == 200

    def test_the_cookie_still_works_on_an_api_route(self, client):
        client.cookies.set(gui.AUTH_COOKIE, _token())
        try:
            assert client.get(self.API).status_code == 200
        finally:
            client.cookies.clear()

    def test_the_bootstrap_route_still_accepts_the_query_token(self, client):
        """The kiosk has nowhere to put a header, so '/' must keep working."""
        r = client.get(f"/?token={_token()}", follow_redirects=False)
        assert r.status_code in (302, 303, 307), f"the kiosk bootstrap stopped working: {r.status_code}"


class TestCrossOriginRequestsAreRefused:
    def test_a_cross_origin_post_is_refused(self, client):
        client.cookies.set(gui.AUTH_COOKIE, _token())
        try:
            r = client.post(
                "/api/erase-files",
                json={"targets": ["/tmp/whatever"], "confirm": True},
                headers={"Origin": "http://evil.example"},
            )
            assert r.status_code == 403, (
                "a cross-origin cookie-authenticated POST was accepted; the only "
                "thing that stopped it was the client honouring SameSite"
            )
        finally:
            client.cookies.clear()

    def test_a_cross_site_fetch_metadata_header_is_refused(self, client):
        client.cookies.set(gui.AUTH_COOKIE, _token())
        try:
            r = client.post(
                "/api/erase-files",
                json={"targets": ["/tmp/whatever"], "confirm": True},
                headers={"Sec-Fetch-Site": "cross-site"},
            )
            assert r.status_code == 403
        finally:
            client.cookies.clear()

    def test_a_same_origin_post_is_allowed(self, client):
        """The check must not break the dashboard's own fetches."""
        client.cookies.set(gui.AUTH_COOKIE, _token())
        try:
            r = client.post(
                "/api/erase-files",
                json={"targets": [], "confirm": True},
                headers={"Origin": "http://testserver", "Sec-Fetch-Site": "same-origin"},
            )
            assert r.status_code != 403, "a same-origin POST was refused"
        finally:
            client.cookies.clear()

    def test_a_request_without_an_origin_is_allowed(self, client):
        """curl and the kiosk send no Origin, and are not subject to ambient
        credential attachment, so refusing them would break legitimate clients."""
        client.cookies.set(gui.AUTH_COOKIE, _token())
        try:
            r = client.post("/api/erase-files", json={"targets": [], "confirm": True})
            assert r.status_code != 403
        finally:
            client.cookies.clear()

    def test_safe_methods_are_not_origin_checked(self, client):
        """A cross-origin GET cannot change anything, so refusing it is noise."""
        client.cookies.set(gui.AUTH_COOKIE, _token())
        try:
            r = client.get("/api/devices", headers={"Origin": "http://evil.example"})
            assert r.status_code == 200
        finally:
            client.cookies.clear()


class TestInputValidation:
    def test_a_nul_byte_in_a_download_filename_is_a_400(self, client):
        """It used to reach Path.resolve() and return an unhandled 500."""
        job_id = "nultest"
        with gui._lock:
            gui._jobs[job_id] = {"status": "done", "out_dir": "/tmp", "result": {"cert_filename": "c.json"}}
        try:
            r = client.get(f"/api/download/{job_id}/a%00b.json", headers=_auth())
            assert r.status_code == 400, f"a NUL byte in the filename returned {r.status_code}, not 400"
        finally:
            with gui._lock:
                gui._jobs.pop(job_id, None)

    def test_out_of_range_min_confidence_is_rejected(self, client):
        r = client.post("/api/carve", json={"target": "/tmp/x.img", "min_confidence": 999}, headers=_auth())
        assert r.status_code == 422, "min_confidence=999 was accepted; the CLI documents and enforces 0-100"

    def test_negative_min_confidence_is_rejected(self, client):
        r = client.post("/api/carve", json={"target": "/tmp/x.img", "min_confidence": -5}, headers=_auth())
        assert r.status_code == 422

    @pytest.mark.parametrize("value", [0, 50, 100])
    def test_the_documented_range_is_accepted(self, client, value):
        """The bound must not be so tight it rejects legitimate values."""
        r = client.post(
            "/api/carve", json={"target": "/nonexistent-target.img", "min_confidence": value}, headers=_auth()
        )
        assert r.status_code != 422, f"min_confidence={value} was rejected"

    @pytest.mark.parametrize("host", ["LOCALHOST", "LocalHost", "localhost"])
    def test_host_matching_is_case_insensitive(self, client, host):
        """RFC 9110: host names are case-insensitive."""
        r = client.get("/api/devices", headers={"Host": host, **_auth()})
        assert r.status_code != 400, f"Host: {host} was refused; host names are case-insensitive per RFC 9110"

    def test_a_genuinely_foreign_host_is_still_refused(self, client):
        """The case fix must not weaken DNS-rebinding protection."""
        r = client.get("/api/devices", headers={"Host": "evil.example", **_auth()})
        assert r.status_code == 400, "an arbitrary Host header was accepted"


class TestImagingPreFlight:
    def test_an_existing_destination_is_a_409_with_an_actionable_message(self, client, tmp_path):
        src = tmp_path / "src.raw"
        src.write_bytes(b"\x00" * 4096)
        dst = tmp_path / "dst.img"
        dst.write_bytes(b"already here")

        r = client.post("/api/image", json={"source": str(src), "destination": str(dst)}, headers=_auth())
        assert r.status_code == 409, (
            f"imaging onto an existing file returned {r.status_code}; the operator "
            f"got an opaque code instead of the one thing they could act on"
        )
        assert "force" in r.json()["detail"], "the rejection does not say how to proceed"

    def test_the_check_does_not_prevent_a_new_destination(self, client, tmp_path):
        src = tmp_path / "src.raw"
        src.write_bytes(b"\x00" * 4096)
        dst = tmp_path / "brand-new.img"
        r = client.post("/api/image", json={"source": str(src), "destination": str(dst)}, headers=_auth())
        assert r.status_code == 200, "the pre-flight check rejected a destination that does not exist"


class TestBrowseDoesNotLieAboutWhatItListed:
    """An out-of-root path used to be silently replaced with the repository root.

    The dashboard asked to list `/etc`, received HTTP 200 and a plausible listing of
    the repo, and had no way to tell. An operator choosing an output directory from
    that list would have been choosing from the wrong tree entirely.
    """

    def test_a_protected_path_is_a_403(self, client):
        client.cookies.set(gui.AUTH_COOKIE, _token())
        r = client.get("/api/browse?path=/etc")
        assert r.status_code == 403, f"expected an explicit refusal, got {r.status_code}: {r.json()}"
        assert "outside" in r.json()["error"]
        assert r.json()["items"] == [], "a refused path still returned a listing"

    def test_a_missing_path_is_a_404_not_a_redirect(self, client):
        client.cookies.set(gui.AUTH_COOKIE, _token())
        r = client.get("/api/browse?path=/definitely-not-here-s0")
        assert r.status_code == 404

    def test_a_refusal_never_names_the_repository_as_the_listing(self, client):
        client.cookies.set(gui.AUTH_COOKIE, _token())
        for path in ("/etc", "/usr", "/"):
            r = client.get(f"/api/browse?path={path}")
            body = r.json()
            assert str(body.get("current", "")).rstrip("/") != str(gui.REPO).rstrip("/"), (
                f"browsing {path} was answered with the repository root; the caller "
                f"cannot distinguish that from a real listing"
            )

    def test_an_allowed_path_still_works(self, client):
        """The refusal must not have broken the legitimate case."""
        client.cookies.set(gui.AUTH_COOKIE, _token())
        r = client.get(f"/api/browse?path={gui.REPO}")
        assert r.status_code == 200
        assert r.json()["items"], "the repository root should list its own contents"


class TestConfigReportsAUsableKeyPath:
    """`default_key_path` is declared relative to a source checkout."""

    def test_the_reported_key_path_resolves(self, client):
        from pathlib import Path as _Path

        client.cookies.set(gui.AUTH_COOKIE, _token())
        body = client.get("/api/config").json()
        reported = body.get("default_key_path")
        assert body.get("default_key_path_is_usable") is True, (
            f"the config claims a usable key path but got {reported!r}"
        )
        assert reported and _Path(reported).is_file(), (
            f"/api/config reported {reported!r}, which does not exist. A dashboard "
            f"showing a key location that resolves nowhere is worse than showing none."
        )

    def test_a_checkout_relative_path_is_not_handed_out(self, client):
        client.cookies.set(gui.AUTH_COOKIE, _token())
        body = client.get("/api/config").json()
        reported = body.get("default_key_path") or ""
        assert not reported.startswith("src/s0/"), (
            f"/api/config returned the source-relative {reported!r}, which resolves "
            f"nowhere for anyone who installed s0 from a wheel"
        )
