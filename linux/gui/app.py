"""TrustWipe local GUI — a thin web wrapper around the real CLI.

Design rules:
  * the CLI does the wiping; the GUI only orchestrates it (single wipe code
    path — the GUI can never drift from what the CLI actually does)
  * runs on localhost only by default; a wipe tool must not expose a network
    API that lets a remote peer erase your disks
  * destructive actions require typing WIPE in the UI, mirroring the CLI gate

Run:  .venv/bin/uvicorn app:app --port 8080   (from linux/gui/)
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

REPO = Path(__file__).resolve().parents[2]
VENV_BIN = REPO / ".venv" / "bin"
CLI = VENV_BIN / "trustwipe-wipe"
if not CLI.exists():  # fallback for non-venv dev setups
    CLI = shutil.which("trustwipe-wipe") or "trustwipe-wipe"

IMAGE_DIRS = [
    Path(os.environ.get("TRUSTWIPE_IMAGE_DIR", "")) if os.environ.get("TRUSTWIPE_IMAGE_DIR") else None,
    REPO / "demo-out",
]

app = FastAPI(title="TrustWipe GUI", docs_url=None, redoc_url=None)
_jobs: dict[str, dict] = {}
_lock = threading.Lock()

import sys as _sys  # noqa: E402
_sys.path.insert(0, str(REPO / "linux" / "cli"))
from trustwipe_cli.devices import SafetyError, check_safety, image_target, list_block_targets  # noqa: E402
from trustwipe_cli.methods.ata import hpa_dco_report  # noqa: E402
from trustwipe_cli.wipe import select_method  # noqa: E402


class WipeRequest(BaseModel):
    target: str
    confirm_text: str
    pattern: str = "zero"
    passes: int = 1


def _find_target(path: str):
    p = Path(path)
    if p.is_block_device():
        for t in list_block_targets():
            if Path(t.path) == p.resolve():
                return t
        raise HTTPException(400, f"unrecognised block device {path}")
    try:
        return image_target(path)
    except FileNotFoundError:
        raise HTTPException(404, f"no such image file: {path}")


@app.get("/")
def index() -> FileResponse:
    return FileResponse(Path(__file__).parent / "static" / "index.html")


@app.get("/api/devices")
def devices() -> JSONResponse:
    block = []
    for t in list_block_targets():
        block.append({
            "path": t.path, "storage_type": t.storage_type,
            "capacity_bytes": t.capacity_bytes, "model": t.model,
            "serial": t.serial,
            "mounted_hint": None,  # refined by /api/plan safety check
        })
    images = []
    for d in IMAGE_DIRS:
        if d and d.is_dir():
            for img in sorted(d.glob("*.img")):
                images.append({"path": str(img),
                               "capacity_bytes": img.stat().st_size})
    return JSONResponse({"block": block, "images": images})


def plan_payload(target_path: str) -> dict:
    target = _find_target(target_path)
    warnings: list[str] = []
    refusal = None
    try:
        warnings = check_safety(target)
    except SafetyError as exc:
        refusal = str(exc)
    candidate, alternatives = select_method(target)
    hpa_dco = None
    if target.kind == "block" and not target.path.startswith("/dev/nvme") \
            and shutil.which("hdparm"):
        hpa_dco = hpa_dco_report(target)
    method = candidate.method
    plan = {
        "target": {"path": target.path, "kind": target.kind,
                   "storage_type": target.storage_type,
                   "capacity_bytes": target.capacity_bytes},
        "method_id": method.id if method else None,
        "nist_category": method.nist_category if method else None,
        "summary": method.plan(target).summary if method else None,
        "warnings": warnings + (method.plan(target).warnings if method else []),
        "alternatives": [{"reason": a.reason, "available": a.available}
                         for a in alternatives],
        "hpa_dco": hpa_dco,
        "refusal": refusal,
    }
    return plan


@app.post("/api/plan")
def api_plan(req: dict) -> JSONResponse:
    return JSONResponse(plan_payload(req["target"]))


@app.post("/api/wipe")
def start_wipe(req: WipeRequest) -> JSONResponse:
    if req.confirm_text != "WIPE":
        raise HTTPException(400, 'confirmation must be exactly "WIPE"')
    plan = plan_payload(req.target)
    if plan["refusal"]:
        raise HTTPException(409, plan["refusal"])
    if not plan["method_id"]:
        raise HTTPException(422, "no applicable wipe method")

    job_id = uuid.uuid4().hex[:12]
    out_dir = REPO / "demo-out" / f"gui-{job_id}"
    cmd = [str(CLI), "wipe", "--target", req.target, "--yes",
           "--pattern", req.pattern, "--passes", str(req.passes),
           "--out-dir", str(out_dir), "--json"]
    key = REPO / "core" / "keys" / "demo_issuer_private.pem"
    if key.exists():
        cmd += ["--key", str(key)]

    with _lock:
        _jobs[job_id] = {"status": "running", "log": [], "cmd": cmd[1:],
                         "out_dir": str(out_dir)}

    def run() -> None:
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    text=True, bufsize=1)
            # Concurrent readers: a pump thread streams stderr into the job log
            # while communicate() drains stdout. Manually consuming one pipe
            # before communicate() races the internal reader and can lose data.
            assert proc.stderr is not None

            def pump_stderr() -> None:
                for line in proc.stderr:  # type: ignore[union-attr]
                    with _lock:
                        _jobs[job_id]["log"].append(line.rstrip())

            pumper = threading.Thread(target=pump_stderr, daemon=True)
            pumper.start()
            out, _ = proc.communicate()
            pumper.join(timeout=5)

            result: dict = {"returncode": proc.returncode}
            if proc.returncode == 0:
                if out.strip():
                    result.update(json.loads(out.strip()))
                else:
                    result["error"] = f"CLI produced no JSON summary; raw={out[:400]!r}"
                    result["returncode"] = -1
            else:
                result["stdout_tail"] = out.strip()[-2000:]
            with _lock:
                _jobs[job_id].update(status="done", result=result)
        except Exception as exc:  # never leave a job stuck "running"
            import traceback

            with _lock:
                _jobs[job_id].update(
                    status="error",
                    result={"returncode": -1,
                            "error": f"{exc}\n{traceback.format_exc()}"},
                )

    threading.Thread(target=run, daemon=True).start()
    return JSONResponse({"job_id": job_id})


@app.get("/api/job/{job_id}")
def job_status(job_id: str) -> JSONResponse:
    with _lock:
        job = _jobs.get(job_id)
        if not job:
            raise HTTPException(404, "unknown job")
        return JSONResponse({k: job[k] for k in ("status", "log", "result")
                             if k in job} | {"cmd": job.get("cmd")})


@app.get("/api/download/{job_id}/{filename}")
def download(job_id: str, filename: str) -> FileResponse:
    with _lock:
        job = _jobs.get(job_id)
    if not job:
        raise HTTPException(404, "unknown job")
    path = (Path(job["out_dir"]) / filename).resolve()
    if not str(path).startswith(str(Path(job["out_dir"]).resolve())) or not path.is_file():
        raise HTTPException(404, "no such artifact")
    return FileResponse(path, filename=filename)
