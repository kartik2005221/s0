"""TrustWipe Unified Forensic & Sanitization Web Dashboard (NTRO / SIH26149).

Endpoints:
  - GET  /                           -> Multi-tab Forensic GUI
  - GET  /api/devices                -> List block devices & test images
  - POST /api/plan                   -> Drive wipe planning preview
  - POST /api/wipe                   -> Execute Drive Sanitization (Module 1)
  - POST /api/erase-files            -> Execute Secure File & Folder Erasure (Module 2)
  - POST /api/carve                  -> Execute Advanced File Carving & Recovery (Module 3)
  - GET  /api/audit/blocks           -> Retrieve Blockchain Audit Ledger (Module 4)
  - GET  /api/audit/verify           -> Verify Hash Chain Integrity (Module 4)
  - GET  /api/job/{job_id}           -> Real-time Job Progress & Output
  - GET  /api/download/{job_id}/{fn} -> Download Sanitization & Forensic Artifacts
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
import uuid
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from starlette.staticfiles import StaticFiles

REPO = Path(__file__).resolve().parents[2]
VENV_BIN = REPO / ".venv" / "bin"
CLI = VENV_BIN / "trustwipe-wipe"
if not CLI.exists():
    CLI = shutil.which("trustwipe-wipe") or "trustwipe-wipe"

IMAGE_DIRS = [
    Path(os.environ.get("TRUSTWIPE_IMAGE_DIR", "")) if os.environ.get("TRUSTWIPE_IMAGE_DIR") else None,
    REPO / "demo-out",
]

app = FastAPI(title="TrustWipe Forensic & Sanitization Dashboard (NTRO)", docs_url=None, redoc_url=None)

PORTAL_DIR = REPO / "verification-portal"
if PORTAL_DIR.is_dir():
    app.mount("/portal", StaticFiles(directory=str(PORTAL_DIR), html=True), name="portal")
_jobs: dict[str, dict] = {}
_lock = threading.Lock()

import sys as _sys
_sys.path.insert(0, str(REPO / "linux" / "cli"))
from trustwipe_cli.audit import list_audit_blocks, verify_audit_ledger, record_audit_event  # noqa: E402
from trustwipe_cli.carver import carve_image  # noqa: E402
from trustwipe_cli.devices import SafetyError, Target, check_safety, get_block_device_size, image_target, list_block_targets  # noqa: E402
from trustwipe_cli.file_eraser import erase_batch  # noqa: E402
from trustwipe_cli.methods.ata import hpa_dco_report  # noqa: E402
from trustwipe_cli.wipe import select_method  # noqa: E402


class WipeRequest(BaseModel):
    target: str
    confirm_text: str
    pattern: str = "zero"
    passes: int = 1


class FileEraseRequest(BaseModel):
    targets: List[str]
    passes: int = 1
    pattern: str = "zero"
    operator_id: str = "op-ntro-forensic"


class CarveRequest(BaseModel):
    target: str
    extensions: Optional[List[str]] = None
    min_confidence: int = 50
    operator_id: str = "op-ntro-forensic"


def _find_target(path: str):
    p = Path(path)
    if p.is_block_device():
        for t in list_block_targets():
            if Path(t.path).resolve() == p.resolve():
                return t
        size = get_block_device_size(p)
        if size > 0:
            return Target(path=str(p), kind="block", capacity_bytes=size, sector_size=512, storage_type="UNKNOWN")
        raise HTTPException(400, f"unrecognised or 0-byte block device {path}")
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
            "mounted_hint": None,
        })
    images = []
    seen = set()
    for d in IMAGE_DIRS:
        if d and d.is_dir():
            candidates = list(d.glob("*.img")) + list(d.glob("*.raw")) + list(d.glob("*/*.img")) + list(d.glob("*/*.raw"))
            for img in sorted(candidates):
                resolved = str(img.resolve())
                if resolved not in seen and img.is_file():
                    seen.add(resolved)
                    images.append({"path": str(img), "capacity_bytes": img.stat().st_size})
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
    if target.kind == "block" and not target.path.startswith("/dev/nvme") and shutil.which("hdparm"):
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
        "alternatives": [{"reason": a.reason, "available": a.available} for a in alternatives],
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
    out_dir = REPO / "demo-out" / f"gui-wipe-{job_id}"
    cmd = [str(CLI), "wipe", "--target", req.target, "--yes",
           "--pattern", req.pattern, "--passes", str(req.passes),
           "--out-dir", str(out_dir), "--json"]
    key = REPO / "core" / "keys" / "demo_issuer_private.pem"
    if key.exists():
        cmd += ["--key", str(key)]

    with _lock:
        _jobs[job_id] = {"status": "running", "log": [], "cmd": cmd[1:], "out_dir": str(out_dir)}

    def run() -> None:
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
            assert proc.stderr is not None

            def pump_stderr() -> None:
                for line in proc.stderr:
                    with _lock:
                        _jobs[job_id]["log"].append(line.rstrip())

            pumper = threading.Thread(target=pump_stderr, daemon=True)
            pumper.start()
            out, _ = proc.communicate()
            pumper.join(timeout=5)

            result: dict = {"returncode": proc.returncode}
            if proc.returncode == 0:
                if out.strip():
                    parsed = json.loads(out.strip())
                    result.update(parsed)
                    if "certificate_path" in parsed and parsed["certificate_path"]:
                        result["cert_filename"] = Path(parsed["certificate_path"]).name
                    if "pdf_path" in parsed and parsed["pdf_path"]:
                        result["pdf_filename"] = Path(parsed["pdf_path"]).name
            else:
                result["stdout_tail"] = out.strip()[-2000:]
            with _lock:
                _jobs[job_id].update(status="done", result=result)
        except Exception as exc:
            with _lock:
                _jobs[job_id].update(status="error", result={"returncode": -1, "error": str(exc)})

    threading.Thread(target=run, daemon=True).start()
    return JSONResponse({"job_id": job_id})


@app.post("/api/erase-files")
def start_erase_files(req: FileEraseRequest) -> JSONResponse:
    if not req.targets:
        raise HTTPException(400, "no file targets provided")

    job_id = uuid.uuid4().hex[:12]
    out_dir = REPO / "demo-out" / f"gui-filewipe-{job_id}"
    out_dir.mkdir(parents=True, exist_ok=True)

    with _lock:
        _jobs[job_id] = {"status": "running", "log": [f"Sanitizing {len(req.targets)} file/folder targets..."],
                         "out_dir": str(out_dir)}

    def run() -> None:
        try:
            def file_progress(fpath: str, cur_pass: int, total_p: int) -> None:
                with _lock:
                    _jobs[job_id]["log"].append(f"Overwriting {Path(fpath).name}: pass {cur_pass}/{total_p}")

            summary = erase_batch(
                req.targets,
                passes=req.passes,
                pattern=req.pattern,
                operator_id=req.operator_id,
                organization="NTRO Digital Forensics & Data Sanitization Lab",
                progress_callback=file_progress,
            )
            cert_filename = None
            if summary.certificate:
                try:
                    record_audit_event(summary.certificate, operation_type="FILE_ERASE")
                except Exception:
                    pass
                cert_file = out_dir / f"file_wipe_certificate_{summary.certificate['cert_uuid'][:8]}.json"
                cert_file.write_text(json.dumps(summary.certificate, indent=2))
                cert_filename = cert_file.name

            with _lock:
                _jobs[job_id].update(
                    status="done",
                    result={
                        "returncode": 0 if summary.failed_files == 0 else 1,
                        "total_files": summary.total_files,
                        "successful_files": summary.successful_files,
                        "failed_files": summary.failed_files,
                        "total_bytes": summary.total_bytes_processed,
                        "cert_filename": cert_filename,
                        "warnings": summary.warnings,
                    },
                )
        except Exception as exc:
            with _lock:
                _jobs[job_id].update(status="error", result={"returncode": -1, "error": str(exc)})

    threading.Thread(target=run, daemon=True).start()
    return JSONResponse({"job_id": job_id})


@app.post("/api/carve")
def start_carve(req: CarveRequest) -> JSONResponse:
    target_p = Path(req.target)
    if not target_p.exists():
        raise HTTPException(404, "target media does not exist")

    job_id = uuid.uuid4().hex[:12]
    out_dir = REPO / "demo-out" / f"gui-carve-{job_id}"
    out_dir.mkdir(parents=True, exist_ok=True)

    with _lock:
        _jobs[job_id] = {"status": "running", "log": [f"Scanning {req.target} for carved artifacts..."],
                         "out_dir": str(out_dir)}

    def run() -> None:
        try:
            def carve_progress(scanned: int, total: int, found: int) -> None:
                with _lock:
                    pct = (scanned * 100 // total) if total else 0
                    msg = f"Carving: {scanned // (1024*1024)} MB / {total // (1024*1024)} MB ({pct}%) - {found} candidates"
                    if not _jobs[job_id]["log"] or _jobs[job_id]["log"][-1] != msg:
                        _jobs[job_id]["log"].append(msg)

            summary = carve_image(
                req.target,
                out_dir,
                extensions=req.extensions,
                min_confidence=req.min_confidence,
                operator_id=req.operator_id,
                progress_callback=carve_progress,
            )
            manifest_filename = None
            if summary.manifest_certificate:
                try:
                    record_audit_event(summary.manifest_certificate, operation_type="FILE_CARVE")
                except Exception:
                    pass
                m_file = out_dir / f"carving_manifest_{summary.manifest_certificate['cert_uuid'][:8]}.json"
                m_file.write_text(json.dumps(summary.manifest_certificate, indent=2))
                manifest_filename = m_file.name

            with _lock:
                _jobs[job_id].update(
                    status="done",
                    result={
                        "returncode": 0,
                        "bytes_scanned": summary.total_bytes_scanned,
                        "candidates_found": summary.total_candidates_found,
                        "files_recovered": summary.files_recovered,
                        "manifest_filename": manifest_filename,
                        "carved_files": [
                            {
                                "id": c.file_id,
                                "filename": c.filename,
                                "ext": c.extension,
                                "category": c.category,
                                "size": c.size_bytes,
                                "conf": c.confidence_score,
                                "sha256": c.sha256,
                                "heuristics": c.heuristics,
                                "recovery_method": c.recovery_method,
                            }
                            for c in summary.carved_files
                        ],
                    },
                )
        except Exception as exc:
            with _lock:
                _jobs[job_id].update(status="error", result={"returncode": -1, "error": str(exc)})

    threading.Thread(target=run, daemon=True).start()
    return JSONResponse({"job_id": job_id})


@app.get("/api/audit/blocks")
def get_audit_blocks(limit: int = 100, offset: int = 0) -> JSONResponse:
    blocks = list_audit_blocks(limit=limit, offset=offset)
    return JSONResponse({
        "blocks": [
            {
                "index": b.block_index,
                "timestamp": b.timestamp,
                "operation": b.operation_type,
                "target": b.target_id,
                "operator": b.operator_id,
                "organization": b.organization,
                "cert_uuid": b.cert_uuid,
                "prev_hash": b.prev_hash,
                "block_hash": b.block_hash,
                "payload_hash": b.payload_hash,
                "signature": b.signature,
                "certificate_json": b.certificate_json,
            }
            for b in blocks
        ]
    })


@app.get("/api/audit/verify")
def get_audit_verify() -> JSONResponse:
    report = verify_audit_ledger()
    return JSONResponse({
        "is_valid": report.is_valid,
        "total_blocks": report.total_blocks_verified,
        "reason": report.reason,
    })


@app.get("/api/job/{job_id}")
def job_status(job_id: str) -> JSONResponse:
    with _lock:
        job = _jobs.get(job_id)
        if not job:
            raise HTTPException(404, "unknown job")
        return JSONResponse({
            "status": job.get("status", "unknown"),
            "log": job.get("log", []),
            "result": job.get("result", None),
            "cmd": job.get("cmd", None),
        })


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
