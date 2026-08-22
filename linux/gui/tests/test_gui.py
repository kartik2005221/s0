"""GUI API tests — headless via FastAPI TestClient.

The GUI must behave exactly like the CLI it wraps: same refusals, same
certificate artifacts. These tests drive a real (tiny) wipe through the API.
"""

import json
import sys
import time
from pathlib import Path

import pytest

GUI_DIR = Path(__file__).resolve().parents[1]
REPO = GUI_DIR.parents[1]
sys.path.insert(0, str(GUI_DIR))  # for `import app`
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
    # point the app's image discovery at our tmp dir too
    gui_app.IMAGE_DIRS.append(tmp_path)
    yield str(img)
    gui_app.IMAGE_DIRS.pop()


def test_index_serves(client):
    r = client.get("/")
    assert r.status_code == 200
    assert b"TRUSTWIPE" in r.content


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
    r = client.post("/api/wipe", json={"target": small_image,
                                       "confirm_text": "wipe"})
    assert r.status_code == 400
    assert "WIPE" in r.json()["detail"]


def test_full_wipe_job_produces_verifiable_certificate(client, small_image, tmp_path):
    r = client.post("/api/wipe", json={"target": small_image,
                                       "confirm_text": "WIPE"})
    job_id = r.json()["job_id"]

    result = None
    last = None
    for _ in range(120):  # up to ~60s; a 4 MiB wipe takes <2s in practice
        j = client.get(f"/api/job/{job_id}").json()
        last = j
        if j["status"] in ("done", "error"):
            result = j.get("result")
            break
        time.sleep(0.5)
    assert result is not None and result["returncode"] == 0, \
        f"wipe job failed: {json.dumps({'last': last, 'result': result}, indent=2)}"

    # The certificate the CLI produced must verify against the pinned issuer key.
    from trustwipe_core import certificate, crypto

    cert = json.loads(Path(result["certificate"]).read_text())
    key = crypto.load_public_pem(REPO / "core" / "keys" / "demo_issuer_public.pem")
    ok, reason = certificate.verify_certificate(cert, [key])
    assert ok, reason

    # And the artifact download endpoint serves it back byte-identical.
    dl = client.get(
        f"/api/download/{job_id}/{Path(result['certificate']).name}")
    assert dl.status_code == 200
    assert json.loads(dl.content)["cert_uuid"] == cert["cert_uuid"]


def test_download_traversal_blocked(client, small_image):
    r = client.get("/api/download/nonexistent/../etc/passwd")
    assert r.status_code in (404, 400)
