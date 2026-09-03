"""GUI API tests — headless via FastAPI TestClient."""

import json
import sys
import time
from pathlib import Path

import pytest

GUI_DIR = Path(__file__).resolve().parents[1]
REPO = GUI_DIR.parents[1]
sys.path.insert(0, str(GUI_DIR))
sys.path.insert(0, str(REPO / "linux" / "cli"))

from fastapi.testclient import TestClient  # noqa: E402
import app as gui_app  # noqa: E402


@pytest.fixture()
def client():
    return TestClient(gui_app.app)


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
    assert b"TrustWipe" in r.content or b"TRUSTWIPE" in r.content.upper()


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
    r = client.post("/api/wipe", json={"target": small_image, "confirm_text": "wipe"})
    assert r.status_code == 400
    assert "WIPE" in r.json()["detail"]


def test_full_wipe_job_produces_verifiable_certificate(client, small_image, tmp_path):
    r = client.post("/api/wipe", json={"target": small_image, "confirm_text": "WIPE"})
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

    from trustwipe_core import certificate, crypto

    cert = json.loads(Path(result["certificate"]).read_text())
    key = crypto.load_public_pem(REPO / "core" / "keys" / "demo_issuer_public.pem")
    ok, reason = certificate.verify_certificate(cert, [key])
    assert ok, reason


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
    assert b"TrustWipe" in r.content
    assert b"Verification" in r.content

