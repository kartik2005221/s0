"""GUI API tests — headless via FastAPI TestClient."""

import json
import sys
import time
from pathlib import Path

import pytest

WEB_DIR = Path(__file__).resolve().parents[1]
REPO = WEB_DIR.parent
sys.path.insert(0, str(WEB_DIR))
sys.path.insert(0, str(REPO / "linux" / "cli"))

from fastapi.testclient import TestClient  # noqa: E402
import app as gui_app  # noqa: E402
from s0_cli.audit import init_audit_db  # noqa: E402


@pytest.fixture(autouse=True)
def isolate_test_audit_db(tmp_path, monkeypatch):
    test_db = tmp_path / "test_gui_audit.db"
    init_audit_db(test_db)
    monkeypatch.setenv("S0_AUDIT_DB", str(test_db))
    monkeypatch.setattr("s0_cli.audit.db.DEFAULT_AUDIT_DB", test_db)
    monkeypatch.setattr("s0_cli.audit.DEFAULT_AUDIT_DB", test_db)
    monkeypatch.setattr("s0_cli.audit.verify.DEFAULT_AUDIT_DB", test_db)
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
    assert "s0-auth-token" not in r.text
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
    last = None
    for _ in range(120):
        j = client.get(f"/api/job/{job_id}").json()
        last = j
        if j["status"] in ("done", "error"):
            result = j.get("result")
            break
        time.sleep(0.5)
    assert result is not None and result["returncode"] == 0, f"wipe job failed: {result}"

    from s0_core import certificate, crypto

    cert = json.loads(Path(result["certificate"]).read_text())
    key = crypto.load_public_pem(REPO / "core" / "keys" / "demo_issuer_public.pem")
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
    disk_img = tmp_path / "gui_carve_test.raw"
    jpeg_payload = b"\xff\xd8\xff\xe0\x00\x10JFIF" + (b"\x11" * 100) + b"\xff\xd9"
    disk_img.write_bytes(b"\x00" * 512 + jpeg_payload + b"\x00" * 512)

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
    from app import _jobs, _lock

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
    js_file = WEB_DIR / "static" / "js" / "dashboard.js"
    source = js_file.read_text(encoding="utf-8") if js_file.exists() else (WEB_DIR / "static" / "index.html").read_text(encoding="utf-8")
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
    assert cfg["version"] == "2.2.1"
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
        f.write(b"\x00" * 1024 + payload + b"\x00" * 1024)

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

