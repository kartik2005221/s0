"""Web Dashboard API tests — headless via FastAPI TestClient."""

import json
import os
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from s0.audit import init_audit_db
from s0.resources import repo_root
from s0.web import app as gui_app

REPO = repo_root()
assert REPO is not None, "web dashboard tests require a source checkout"

#: Static assets live beside the app module, inside the package.
STATIC_ROOT = Path(gui_app.__file__).resolve().parent


@pytest.fixture(autouse=True)
def isolate_test_audit_db(tmp_path, monkeypatch):
    test_db = tmp_path / "test_gui_audit.db"
    init_audit_db(test_db)
    monkeypatch.setenv("S0_AUDIT_DB", str(test_db))
    monkeypatch.setattr("s0.audit.db.DEFAULT_AUDIT_DB", test_db)
    monkeypatch.setattr("s0.audit.DEFAULT_AUDIT_DB", test_db)
    monkeypatch.setattr("s0.audit.verify.DEFAULT_AUDIT_DB", test_db)
    return test_db


@pytest.fixture()
def client():
    c = TestClient(gui_app.app)
    c.headers.update({"X-S0-Auth-Token": gui_app._SESSION_AUTH_TOKEN})
    return c


@pytest.fixture()
def small_image(tmp_path):
    img = tmp_path / "gui_test.img"
    with open(img, "wb") as f:
        f.write(b"\xa7" * (4 * 1024 * 1024))
    gui_app.IMAGE_DIRS.append(tmp_path)
    yield str(img)
    gui_app.IMAGE_DIRS.pop()


def test_index_serves(client):
    r = client.get("/")
    assert r.status_code == 200
    assert b"s0" in r.content.lower()
    # The session token is deliberately injected into <head> so the dashboard
    # works when reached without the ?token= query string (bookmark, reopened
    # tab, live-ISO kiosk, restarted server). It is a loopback-only, per-session
    # capability and must never be echoed by an API response or written to disk.
    assert '<meta name="s0-auth-token"' in r.text
    assert gui_app._SESSION_AUTH_TOKEN in r.text


def test_index_does_not_leak_token_to_sub_resources(client):
    """Static assets must not carry the token — only the document does."""
    for asset in ("/static/css/dashboard.css", "/static/js/dashboard.js"):
        r = client.get(asset)
        assert r.status_code == 200
        assert gui_app._SESSION_AUTH_TOKEN not in r.text


def test_api_config_does_not_leak_auth_token(client):
    r = client.get("/api/config")
    assert r.status_code == 200
    assert "auth_token" not in r.json()


def test_unauthenticated_destructive_endpoints_fail_401():
    unauth = TestClient(gui_app.app)
    r = unauth.post("/api/wipe", json={"target": "/dev/null"})
    assert r.status_code == 401
    assert "Unauthorized" in r.json().get("detail", "")

    r = unauth.post("/api/erase-files", json={"paths": ["/tmp/test.txt"]})
    assert r.status_code == 401

    r = unauth.post("/api/carve", json={"target": "/dev/null"})
    assert r.status_code == 401

    r = unauth.post("/api/image", json={"source": "/dev/null", "destination": "/tmp/out.dd"})
    assert r.status_code == 401



def test_devices_lists_images(client, small_image):
    r = client.get("/api/devices")
    assert r.status_code == 200
    paths = [i["path"] for i in r.json()["images"]]
    assert small_image in paths


def test_plan_on_image(client, small_image):
    r = client.post("/api/plan", json={"target": small_image})
    p = r.json()
    assert p["method_id"] == "OVERWRITE_ZERO_1PASS"
    assert p["nist_category"] == "Clear"
    assert p["refusal"] is None


def test_plan_refuses_missing(client):
    r = client.post("/api/plan", json={"target": "/nope/none.img"})
    assert r.status_code == 404


def test_wipe_requires_exact_confirmation(client, small_image):
    r = client.post("/api/wipe", json={"target": small_image, "confirm_text": "WIPE"})
    assert r.status_code == 400
    assert small_image in r.json()["detail"]


def test_full_wipe_job_produces_verifiable_certificate(client, small_image, tmp_path):
    r = client.post("/api/wipe", json={"target": small_image, "confirm_text": small_image})
    job_id = r.json()["job_id"]

    result = None
    for _ in range(120):
        j = client.get(f"/api/job/{job_id}").json()
        if j["status"] in ("done", "error"):
            result = j.get("result")
            break
        time.sleep(0.5)
    assert result is not None and result["returncode"] == 0, f"wipe job failed: {result}"

    from s0 import certificate, crypto

    cert = json.loads(Path(result["certificate"]).read_text())
    key = crypto.load_public_pem(REPO / "src" / "s0" / "data" / "keys" / "demo_issuer_public.pem")
    ok, reason = certificate.verify_certificate(cert, [key])
    assert ok, reason
    assert result.get("cert_filename") is not None
    assert result.get("pdf_filename") is not None


def test_erase_files_api(client, tmp_path):
    f1 = tmp_path / "secret_file.txt"
    f1.write_text("CLASSIFIED DATA")

    r = client.post("/api/erase-files", json={"targets": [str(f1)], "passes": 1, "pattern": "zero"})
    assert r.status_code == 200
    job_id = r.json()["job_id"]

    result = None
    for _ in range(60):
        j = client.get(f"/api/job/{job_id}").json()
        if j["status"] in ("done", "error"):
            result = j.get("result")
            break
        time.sleep(0.1)

    assert result is not None and result["returncode"] == 0
    assert result["successful_files"] == 1
    assert not f1.exists()


def test_carve_api(client, tmp_path):
    """The planted JPEG must be a real one: the carver resolves a JPEG by
    walking its marker segments, so a hand-built header would (correctly) be
    rejected."""
    import io as _io

    from PIL import Image as _Image
    buf = _io.BytesIO()
    _Image.new("RGB", (32, 32), (12, 34, 56)).save(buf, format="JPEG", quality=85)
    jpeg_payload = buf.getvalue()
    disk_img = tmp_path / "gui_carve_test.raw"
    disk_img.write_bytes(os.urandom(4096) + jpeg_payload + os.urandom(4096))

    r = client.post("/api/carve", json={"target": str(disk_img), "extensions": ["jpg"], "min_confidence": 50})
    assert r.status_code == 200
    job_id = r.json()["job_id"]

    result = None
    for _ in range(60):
        j = client.get(f"/api/job/{job_id}").json()
        if j["status"] in ("done", "error"):
            result = j.get("result")
            break
        time.sleep(0.1)

    assert result is not None and result["returncode"] == 0
    assert result["files_recovered"] >= 1
    assert result.get("pdf_filename") is not None


def test_audit_api(client):
    r_blocks = client.get("/api/audit/blocks")
    assert r_blocks.status_code == 200
    assert len(r_blocks.json()["blocks"]) >= 1

    r_verify = client.get("/api/audit/verify")
    assert r_verify.status_code == 200
    assert r_verify.json()["is_valid"] is True


def test_portal_serves(client):
    r = client.get("/portal/")
    assert r.status_code == 200
    assert b"s0" in r.content.lower()
    assert b"Verification" in r.content


def test_operator_id_xss_injection_rejected(client, tmp_path):
    target = tmp_path / "xss_test.txt"
    target.write_text("DUMMY")

    # XSS payloads must be rejected by Pydantic schema validation (HTTP 422)
    xss_payloads = [
        "<img src=x onerror=alert(1)>XSSPROBE",
        "<script>alert(1)</script>",
        "operator\"><svg onload=alert(1)>",
        "op' OR '1'='1",
    ]
    for p in xss_payloads:
        r_erase = client.post("/api/erase-files", json={"targets": [str(target)], "operator_id": p})
        assert r_erase.status_code == 422, f"Failed to reject payload in erase-files: {p}"

        r_carve = client.post("/api/carve", json={"target": str(target), "operator_id": p})
        assert r_carve.status_code == 422, f"Failed to reject payload in carve: {p}"

    # Valid operator IDs must be accepted
    r_valid = client.post("/api/erase-files", json={"targets": [str(target)], "operator_id": "op-forensic_01@lab"})
    assert r_valid.status_code == 200


def test_download_path_traversal_blocked(client, tmp_path):
    import uuid

    from s0.web.app import _jobs, _lock

    job_id = uuid.uuid4().hex[:12]
    out_dir = tmp_path / f"job-{job_id}"
    out_dir.mkdir()
    artifact = out_dir / "certificate.json"
    artifact.write_text('{"test": true}')

    with _lock:
        _jobs[job_id] = {"status": "done", "out_dir": str(out_dir)}

    # Valid download succeeds
    r_ok = client.get(f"/api/download/{job_id}/certificate.json")
    assert r_ok.status_code == 200

    # Path traversal attempts must return 404
    r_trav1 = client.get(f"/api/download/{job_id}/../../etc/passwd")
    assert r_trav1.status_code == 404

    r_trav2 = client.get(f"/api/download/{job_id}/..%2f..%2fetc%2fpasswd")
    assert r_trav2.status_code == 404


def test_index_html_safe_rendering():
    js_file = STATIC_ROOT / "static" / "js" / "dashboard.js"
    source = js_file.read_text(encoding="utf-8") if js_file.exists() else (STATIC_ROOT / "static" / "index.html").read_text(encoding="utf-8")
    assert "function escapeHtml" in source
    # Ensure unescaped injection into innerHTML is absent
    assert "${b.operator}" not in source
    assert "${b.target}" not in source
    assert "tdOpId.textContent = b.operator" in source
    assert "tdTarget.textContent = b.target" in source


def test_image_api(client, small_image, tmp_path):
    dst = tmp_path / "cloned.img"
    r = client.post("/api/image", json={
        "source": small_image,
        "destination": str(dst),
        "block_size": 65536,
        "no_recovery": False,
        "is_clone": False,
    })
    assert r.status_code == 200
    job_id = r.json()["job_id"]

    result = None
    for _ in range(60):
        j = client.get(f"/api/job/{job_id}").json()
        if j["status"] in ("done", "error"):
            result = j.get("result")
            break
        time.sleep(0.1)

    assert result is not None and result["returncode"] == 0, f"imager failed: {result}"
    assert result["bytes_copied"] == 4 * 1024 * 1024
    assert result["manifest_filename"] is not None
    assert result["cert_filename"] is not None
    assert result["pdf_filename"] is not None
    assert dst.exists()
    assert dst.stat().st_size == 4 * 1024 * 1024

    # Verify download of manifest and certificate works
    r_dl1 = client.get(f"/api/download/{job_id}/{result['manifest_filename']}")
    assert r_dl1.status_code == 200
    r_dl2 = client.get(f"/api/download/{job_id}/{result['cert_filename']}")
    assert r_dl2.status_code == 200


def test_config_endpoint(client):
    r = client.get("/api/config")
    assert r.status_code == 200
    cfg = r.json()
    assert cfg["version"] == gui_app.CONFIG.get("version")
    assert "documentation_url" in cfg
    assert "verification_portal_url" in cfg


def test_browse_endpoint(client):
    r = client.get("/api/browse")
    assert r.status_code == 200
    data = r.json()
    assert "current" in data
    assert "items" in data
    assert isinstance(data["items"], list)


def test_carve_with_custom_signatures(client, tmp_path):
    img = tmp_path / "custom_test.img"
    payload = b"SECVAULT" + b"X" * 64 + b"ENDVAULT"
    with open(img, "wb") as f:
        f.write(os.urandom(4096) + payload + os.urandom(4096))

    r = client.post("/api/carve", json={
        "target": str(img),
        "custom_signatures": [{
            "name": "Secure Vault Test",
            "extension": "svt",
            "category": "archive",
            "header_hex": "53 45 43 56 41 55 4C 54",
            "footer_hex": "45 4E 44 56 41 55 4C 54",
        }],
        "min_confidence": 40,
    })
    assert r.status_code == 200
    job_id = r.json()["job_id"]

    result = None
    for _ in range(60):
        j = client.get(f"/api/job/{job_id}").json()
        if j["status"] in ("done", "error"):
            result = j.get("result")
            break
        time.sleep(0.1)

    assert result is not None, "Job did not complete"
    assert result["files_recovered"] >= 1
    assert any(f["ext"] == "svt" for f in result["carved_files"])


def test_browse_endpoint_traversal_restricted(client):
    """Attempting to browse unauthorized directories falls back to REPO root."""
    r = client.get("/api/browse?path=/etc")
    assert r.status_code == 200
    data = r.json()
    assert data["current"] == str(gui_app.REPO.resolve())


def test_custom_key_isolated_from_out_dir(tmp_path):
    """Custom pasted key data is written to ~/.s0/keys/, NOT the evidence out_dir."""
    out_dir = tmp_path / "evidence_output"
    out_dir.mkdir()
    sample_pem = (
        "-----BEGIN PRIVATE KEY-----\n"
        "MC4CAQAwBQYDK2VwBCIEIPz5W2a/Jt5+3E8qg9v+8n8bQeZqR2m8/0j5c7X7n7xL\n"
        "-----END PRIVATE KEY-----\n"
    )
    resolved_key, is_demo = gui_app._resolve_key(None, sample_pem, out_dir)
    assert resolved_key is not None
    assert resolved_key.exists()
    assert not (out_dir / "custom_issuer_private.pem").exists()
    assert ".s0" in str(resolved_key)
    # Cleanup temp file
    try:
        resolved_key.unlink()
    except Exception:
        pass


def test_destructive_endpoints_require_auth():
    unauth = TestClient(gui_app.app)
    # Missing header
    r = unauth.post("/api/wipe", json={"target": "/dev/null", "confirm_text": "/dev/null"})
    assert r.status_code == 401
    assert "Unauthorized" in r.json()["detail"]

    r = unauth.post("/api/erase-files", json={"targets": ["/dev/null"]})
    assert r.status_code == 401

    r = unauth.post("/api/carve", json={"target": "/dev/null"})
    assert r.status_code == 401

    r = unauth.post("/api/image", json={"source": "/dev/null", "destination": "/dev/null"})
    assert r.status_code == 401

    # Invalid header
    r = unauth.post(
        "/api/wipe",
        json={"target": "/dev/null", "confirm_text": "/dev/null"},
        headers={"X-S0-Auth-Token": "bad_token_12345"},
    )
    assert r.status_code == 401


def test_metadata_pipe_rejected(client, tmp_path):
    target = tmp_path / "sanitize_test.txt"
    target.write_text("DUMMY")

    # Pipe and dangerous characters must be rejected by validation (422)
    bad_payloads = [
        "op|injection",
        "op<script>",
        "op>redirect",
        "op&param",
        "op\"quote",
        "op'quote",
        "op\\backslash",
    ]
    for bad in bad_payloads:
        r = client.post("/api/erase-files", json={"targets": [str(target)], "operator_id": bad})
        assert r.status_code == 422

        r = client.post("/api/erase-files", json={"targets": [str(target)], "organization": bad})
        assert r.status_code == 422


def test_portal_url_validation(client, tmp_path):
    target = tmp_path / "portal_test.txt"
    target.write_text("DUMMY")

    bad_urls = [
        "ftp://example.com",
        "http://attacker.com",
        "https://user:pass@attacker.com",
        "javascript:alert(1)",
    ]
    for url in bad_urls:
        r = client.post("/api/erase-files", json={"targets": [str(target)], "portal_url": url})
        assert r.status_code == 422


def test_capabilities_endpoint(client):
    r = client.get("/api/capabilities")
    assert r.status_code == 200
    data = r.json()
    assert "is_root" in data
    assert "platform" in data
    assert "restricted_operations" in data
    assert isinstance(data["restricted_operations"], list)


def test_temperature_endpoint(client, small_image):
    r = client.get(f"/api/temperature?path={small_image}")
    assert r.status_code == 200
    data = r.json()
    assert data["path"] == small_image
    assert "temperature_c" in data
    assert "status" in data


def test_image_windows_device_path_confirmation(client, small_image, monkeypatch):
    """Bug #4 / R2-4: Windows raw volume destinations (e.g. \\\\.\\C:) must require exact confirmation."""
    monkeypatch.setattr(gui_app, "_sys", type("FakeSys", (), {"platform": "win32"}))

    win_target = r"\\.\C:"
    # Missing confirmation text for Windows block device target -> 400
    payload = {
        "source": small_image,
        "destination": win_target,
        "confirm_text": "",
        "operator_id": "test-op"
    }
    r = client.post("/api/image", json=payload)
    assert r.status_code == 400
    assert "Cloning to target block device requires typing exact destination" in r.json()["detail"]


def test_api_plan_validation(client):
    """Bug #5: Missing target in /api/plan must return clean 422 HTTP validation error, not 500."""
    r = client.post("/api/plan", json={})
    assert r.status_code == 422


def test_wipe_accepts_operator_alias(client, small_image, monkeypatch):
    """Bug #6: /api/wipe must accept both 'operator' (alias) and 'operator_id' seamlessly."""
    # Test model parsing with 'operator'
    req1 = gui_app.WipeRequest(target=small_image, confirm_text=small_image, operator="alice")
    assert req1.operator_id == "alice"

    # Test model parsing with 'operator_id'
    req2 = gui_app.WipeRequest(target=small_image, confirm_text=small_image, operator_id="bob")
    assert req2.operator_id == "bob"


def test_endpoints_require_authentication():
    raw_client = TestClient(gui_app.app)
    # /api/browse
    assert raw_client.get("/api/browse").status_code == 401
    # /api/plan
    assert raw_client.post("/api/plan", json={"target": "/dev/null"}).status_code == 401
    # /api/wipe
    assert raw_client.post("/api/wipe", json={}).status_code == 401
    # /api/erase-files
    assert raw_client.post("/api/erase-files", json={}).status_code == 401
    # /api/carve
    assert raw_client.post("/api/carve", json={}).status_code == 401
    # /api/image
    assert raw_client.post("/api/image", json={}).status_code == 401
    # /api/download/{job_id}/{filename}
    assert raw_client.get("/api/download/fakejob/fakefile.json").status_code == 401


def test_download_via_query_token(tmp_path):
    fake_job_id = "job_test_token"
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    test_file = out_dir / "sample.json"
    test_file.write_text('{"test": true}')
    with gui_app._lock:
        gui_app._jobs[fake_job_id] = {
            "status": "done",
            "out_dir": str(out_dir),
            "result": {"cert_filename": "sample.json"},
        }
    raw_client = TestClient(gui_app.app)
    # Without token -> 401
    r_unauth = raw_client.get(f"/api/download/{fake_job_id}/sample.json")
    assert r_unauth.status_code == 401
    # With query parameter token -> 200
    r_auth = raw_client.get(f"/api/download/{fake_job_id}/sample.json?token={gui_app._SESSION_AUTH_TOKEN}")
    assert r_auth.status_code == 200
    assert r_auth.json() == {"test": True}


def test_pattern_validation():
    raw_client = TestClient(gui_app.app)
    raw_client.headers.update({"X-S0-Auth-Token": gui_app._SESSION_AUTH_TOKEN})
    r = raw_client.post("/api/erase-files", json={"targets": ["/tmp/test"], "pattern": "bogus"})
    assert r.status_code == 422
    r_wipe = raw_client.post("/api/wipe", json={"target": "/dev/null", "pattern": "invalid_pattern"})
    assert r_wipe.status_code == 422


def test_audit_verify_reports_demo_key_status(client):
    r = client.get("/api/audit/verify")
    assert r.status_code == 200
    data = r.json()
    assert "is_valid" in data
    assert "is_demo_signed" in data


def test_system_path_wipe_blocked(client):
    """Wiping /etc/passwd or system paths must be refused."""
    r = client.post("/api/wipe", json={"target": "/etc/passwd", "confirm_text": "/etc/passwd"})
    assert r.status_code in (403, 422)


def test_input_bounds_validation(client, small_image):
    """Passes <= 0 or verify_samples <= 0 must be rejected with 422."""
    r = client.post("/api/wipe", json={"target": small_image, "confirm_text": small_image, "passes": 0})
    assert r.status_code == 422

    r = client.post("/api/wipe", json={"target": small_image, "confirm_text": small_image, "verify_samples": 0})
    assert r.status_code == 422

    r = client.post("/api/wipe", json={"target": small_image, "confirm_text": small_image, "out_dir": "/etc/cron.d"})
    assert r.status_code == 422

    r = client.post("/api/wipe", json={"target": small_image, "confirm_text": small_image, "key_path": "/etc/shadow"})
    assert r.status_code in (403, 422)


def test_non_ascii_auth_token_returns_401():
    """Non-ASCII authentication token must return 401 without crashing with 500."""
    raw_client = TestClient(gui_app.app)
    r = raw_client.get("/api/devices?token=%C3%B6%C3%B1")
    assert r.status_code == 401





