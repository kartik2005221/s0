"""s0 Unified Forensic & Sanitization Web Dashboard.

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
import sys as _sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

REPO = Path(__file__).resolve().parents[1]
_sys.path.insert(0, str(REPO / "linux" / "cli"))
_sys.path.insert(0, str(REPO / "core" / "python"))

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field, field_validator
from starlette.staticfiles import StaticFiles

from s0_core.config import CONFIG  # noqa: E402
from s0_core import pdfgen  # noqa: E402
from s0_core.temperature import read_temperature  # noqa: E402
from s0_cli.audit import list_audit_blocks, verify_audit_ledger, record_audit_event  # noqa: E402
from s0_cli.carver import carve_image  # noqa: E402
from s0_cli.devices import SafetyError, Target, check_safety, get_block_device_size, image_target, list_block_targets  # noqa: E402
from s0_cli.file_eraser import erase_batch  # noqa: E402
from s0_cli.imager import ImagingOptions, acquire_image  # noqa: E402
from s0_cli.methods.ata import hpa_dco_report  # noqa: E402
from s0_cli.wipe import select_method  # noqa: E402

VENV_BIN = REPO / ".venv" / "bin"


def _get_s0_cmd() -> list[str]:
    v_s0 = VENV_BIN / "s0"
    if v_s0.is_file() and os.access(v_s0, os.X_OK):
        return [str(v_s0)]
    which_s0 = shutil.which("s0")
    if which_s0:
        return [which_s0]
    return [_sys.executable, "-m", "s0_cli.main"]


IMAGE_DIRS = [
    Path(os.environ.get("S0_IMAGE_DIR", "")) if os.environ.get("S0_IMAGE_DIR") else None,
    REPO / "demo-out",
]

app = FastAPI(title="s0 Forensic & Sanitization Dashboard", docs_url=None, redoc_url=None)

PORTAL_DIR = REPO / "verification-portal"
if PORTAL_DIR.is_dir():
    app.mount("/portal", StaticFiles(directory=str(PORTAL_DIR), html=True), name="portal")

STATIC_DIR = REPO / "gui" / "static"
if STATIC_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
_jobs: dict[str, dict] = {}
_lock = threading.Lock()


def _get_secure_keys_dir() -> Path:
    try:
        keys_dir = Path.home() / ".s0" / "keys"
        keys_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(keys_dir, 0o700)
        except Exception:
            pass
        return keys_dir
    except Exception:
        fallback = Path(tempfile.gettempdir()) / ".s0_keys"
        fallback.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(fallback, 0o700)
        except Exception:
            pass
        return fallback


def _resolve_key(key_path: Optional[str], key_data: Optional[str], out_dir: Optional[Path] = None) -> tuple[Optional[Path], bool]:
    """Resolve custom signing key from raw PEM content or local file path.

    Returns (key_path, is_demo_key). Custom pasted keys are securely saved into
    ~/.s0/keys/ (isolated from deliverables/evidence out_dir).
    """
    from s0_core.crypto import is_demo_key

    if key_data and key_data.strip():
        keys_dir = _get_secure_keys_dir()
        key_id = uuid.uuid4().hex[:12]
        custom_key_file = keys_dir / f"custom_issuer_{key_id}.pem"
        custom_key_file.write_text(key_data.strip() + "\n", encoding="utf-8")
        try:
            os.chmod(custom_key_file, 0o600)
        except Exception:
            pass
        return custom_key_file, is_demo_key(custom_key_file)

    if key_path and key_path.strip():
        kp = Path(key_path.strip())
        if not kp.is_file():
            kp = (REPO / key_path.strip()).resolve()
        if not kp.is_file():
            raise HTTPException(400, f"Specified signing key not found: {key_path}")
        return kp, is_demo_key(kp)

    default_key_rel = CONFIG.get("default_key_path", "core/keys/demo_issuer_private.pem")
    default_key = (REPO / default_key_rel).resolve()
    if default_key.exists():
        return default_key, True
    return None, True


class WipeRequest(BaseModel):
    target: str
    confirm_text: str
    pattern: str = "zero"
    passes: int = 1
    operator: str = CONFIG.get("default_operator", "op-forensic")
    organization: str = CONFIG.get("default_organization", "Digital Forensics & Data Sanitization Lab")
    key_path: Optional[str] = None
    key_data: Optional[str] = None
    out_dir: Optional[str] = None
    no_pdf: bool = False
    verify_samples: int = 64
    portal_url: Optional[str] = None


class FileEraseRequest(BaseModel):
    targets: List[str]
    passes: int = 1
    pattern: str = "zero"
    operator_id: str = Field(default_factory=lambda: CONFIG.get("default_operator", "op-forensic"))
    organization: str = CONFIG.get("default_organization", "Digital Forensics & Data Sanitization Lab")
    key_path: Optional[str] = None
    key_data: Optional[str] = None
    out_dir: Optional[str] = None
    no_pdf: bool = False
    verify_samples: int = 64
    portal_url: Optional[str] = None

    @field_validator("operator_id")
    @classmethod
    def validate_operator_id(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("operator_id cannot be empty")
        if any(c in v for c in "<>&\"'\\"):
            raise ValueError("operator_id contains forbidden characters")
        if len(v) > 64:
            raise ValueError("operator_id exceeds maximum length of 64 characters")
        return v


class CarveRequest(BaseModel):
    target: str
    extensions: Optional[List[str]] = None
    min_confidence: int = 50
    operator_id: str = Field(default_factory=lambda: CONFIG.get("default_operator", "op-forensic"))
    organization: str = CONFIG.get("default_organization", "Digital Forensics & Data Sanitization Lab")
    out_dir: Optional[str] = None
    key_path: Optional[str] = None
    key_data: Optional[str] = None
    custom_signatures: Optional[List[Dict[str, Any]]] = None

    @field_validator("operator_id")
    @classmethod
    def validate_operator_id(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("operator_id cannot be empty")
        if any(c in v for c in "<>&\"'\\"):
            raise ValueError("operator_id contains forbidden characters")
        if len(v) > 64:
            raise ValueError("operator_id exceeds maximum length of 64 characters")
        return v


class ImageRequest(BaseModel):
    source: str
    destination: str
    block_size: int = 1024 * 1024
    no_recovery: bool = False
    is_clone: bool = False
    confirm_text: str = ""
    operator_id: str = Field(default_factory=lambda: CONFIG.get("default_operator", "op-forensic"))
    organization: str = CONFIG.get("default_organization", "Digital Forensics & Data Sanitization Lab")
    out_dir: Optional[str] = None
    key_path: Optional[str] = None
    key_data: Optional[str] = None

    @field_validator("operator_id")
    @classmethod
    def validate_operator_id(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("operator_id cannot be empty")
        if any(c in v for c in "<>&\"'\\"):
            raise ValueError("operator_id contains forbidden characters")
        if len(v) > 64:
            raise ValueError("operator_id exceeds maximum length of 64 characters")
        return v


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


@app.get("/api/config")
def api_config() -> JSONResponse:
    return JSONResponse(CONFIG)


ALLOWED_BROWSE_ROOTS = [
    REPO.resolve(),
    Path.home().resolve(),
    Path("/media").resolve(),
    Path("/mnt").resolve(),
]


def _is_safe_browse_path(target: Path) -> bool:
    try:
        resolved = target.resolve()
        for root in ALLOWED_BROWSE_ROOTS:
            if root.exists():
                try:
                    resolved.relative_to(root)
                    return True
                except ValueError:
                    continue
        return False
    except Exception:
        return False


@app.get("/api/browse")
def api_browse(path: str = ".") -> JSONResponse:
    target = Path(path).expanduser().resolve()
    if not target.exists() or not target.is_dir() or not _is_safe_browse_path(target):
        target = REPO
    items = []
    try:
        for entry in sorted(target.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
            items.append({
                "name": entry.name,
                "path": str(entry.resolve()),
                "is_dir": entry.is_dir(),
                "size": entry.stat().st_size if entry.is_file() else 0,
            })
    except Exception as exc:
        return JSONResponse({"error": str(exc), "current": str(target), "items": []})
    return JSONResponse({
        "current": str(target),
        "parent": str(target.parent) if target.parent != target and _is_safe_browse_path(target.parent) else None,
        "items": items,
    })


@app.post("/api/plan")
def api_plan(req: dict) -> JSONResponse:
    return JSONResponse(plan_payload(req["target"]))


@app.post("/api/wipe")
def start_wipe(req: WipeRequest) -> JSONResponse:
    if req.confirm_text.strip() != req.target.strip():
        raise HTTPException(400, f'confirmation must be exact target path: "{req.target}"')
    plan = plan_payload(req.target)
    if plan["refusal"]:
        raise HTTPException(409, plan["refusal"])
    if not plan["method_id"]:
        raise HTTPException(422, "no applicable wipe method")

    job_id = uuid.uuid4().hex[:12]
    if req.out_dir and req.out_dir.strip():
        out_dir = Path(req.out_dir.strip()).resolve()
    else:
        out_dir = REPO / "demo-out" / f"gui-wipe-{job_id}"
    out_dir.mkdir(parents=True, exist_ok=True)

    key, is_demo = _resolve_key(req.key_path, req.key_data, out_dir)

    cmd = _get_s0_cmd() + [
        "wipe", "--target", req.target, "--yes",
        "--pattern", req.pattern, "--passes", str(req.passes),
        "--operator", req.operator,
        "--organization", req.organization,
        "--verify-samples", str(req.verify_samples),
        "--out-dir", str(out_dir), "--json"
    ]
    if key and key.exists():
        cmd += ["--key", str(key)]
    if req.no_pdf:
        cmd += ["--no-pdf"]
    if req.portal_url and req.portal_url.strip():
        cmd += ["--portal-url", req.portal_url.strip()]

    with _lock:
        _jobs[job_id] = {
            "status": "running",
            "log": [],
            "cmd": cmd[1:],
            "out_dir": str(out_dir),
            "demo_key_warning": is_demo,
        }

    def run() -> None:
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
            assert proc.stderr is not None

            def pump_stderr() -> None:
                for line in proc.stderr:
                    clean = line.rstrip()
                    if not clean:
                        continue
                    with _lock:
                        if clean.startswith("[s0 wipe]") and _jobs[job_id]["log"] and _jobs[job_id]["log"][-1].startswith("[s0 wipe]"):
                            _jobs[job_id]["log"][-1] = clean
                        else:
                            _jobs[job_id]["log"].append(clean)

            pumper = threading.Thread(target=pump_stderr, daemon=True)
            pumper.start()
            out, _ = proc.communicate()
            pumper.join(timeout=5)

            result: dict = {"returncode": proc.returncode}
            if proc.returncode == 0:
                if out.strip():
                    parsed = json.loads(out.strip())
                    result.update(parsed)
                    cert_p = parsed.get("certificate") or parsed.get("certificate_path")
                    pdf_p = parsed.get("pdf") or parsed.get("pdf_path")
                    if cert_p:
                        result["cert_filename"] = Path(cert_p).name
                        result["certificate_path"] = str(cert_p)
                    if pdf_p:
                        result["pdf_filename"] = Path(pdf_p).name
                        result["pdf_path"] = str(pdf_p)
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
    if req.out_dir and req.out_dir.strip():
        out_dir = Path(req.out_dir.strip()).resolve()
    else:
        out_dir = REPO / "demo-out" / f"gui-filewipe-{job_id}"
    out_dir.mkdir(parents=True, exist_ok=True)

    key, is_demo = _resolve_key(req.key_path, req.key_data, out_dir)

    with _lock:
        _jobs[job_id] = {
            "status": "running",
            "log": [f"Sanitizing {len(req.targets)} file/folder targets..."],
            "out_dir": str(out_dir),
            "demo_key_warning": is_demo,
        }

    def run() -> None:
        try:
            t_start = time.monotonic()
            last_log_time = 0.0
            last_temp_time = 0.0
            last_temp_val = [None]

            def file_progress(fpath: str, written_bytes: int, total_bytes: int) -> None:
                nonlocal last_log_time, last_temp_time
                now = time.monotonic()
                if now - last_log_time < 0.2 and written_bytes < total_bytes:
                    return
                last_log_time = now

                elapsed = max(0.001, now - t_start)
                speed = written_bytes / elapsed
                speed_str = f"{speed / (1024 * 1024):.1f} MiB/s" if speed >= 1024 * 1024 else f"{speed / 1024:.1f} KiB/s"
                pct = (written_bytes * 100 // total_bytes) if total_bytes > 0 else 0
                rem_bytes = max(0, total_bytes - written_bytes)
                eta_sec = int(rem_bytes / speed) if speed > 0 else 0
                eta_str = f"{eta_sec // 60:02d}:{eta_sec % 60:02d}"

                if now - last_temp_time >= 2.0:
                    last_temp_time = now
                    last_temp_val[0] = read_temperature(fpath)
                temp_str = f" | Temp: {last_temp_val[0]}°C" if last_temp_val[0] is not None else ""

                w_mb = written_bytes / (1024 * 1024)
                tot_mb = total_bytes / (1024 * 1024)
                msg = f"[s0 erase] | {pct:3d}% | {w_mb:.1f} MiB / {tot_mb:.1f} MiB | {speed_str} | ETA: {eta_str}{temp_str} ({Path(fpath).name[:20]})"
                with _lock:
                    if not _jobs[job_id]["log"] or not _jobs[job_id]["log"][-1].startswith("[s0 erase]"):
                        _jobs[job_id]["log"].append(msg)
                    else:
                        _jobs[job_id]["log"][-1] = msg

            summary = erase_batch(
                req.targets,
                passes=req.passes,
                pattern=req.pattern,
                operator_id=req.operator_id,
                organization=req.organization,
                signing_key_path=key,
                progress_callback=file_progress,
            )
            cert_filename = None
            pdf_filename = None
            if summary.certificate:
                try:
                    record_audit_event(summary.certificate, operation_type="FILE_ERASE", private_key=key)
                except Exception:
                    pass
                cert_file = out_dir / f"file_wipe_certificate_{summary.certificate['cert_uuid'][:8]}.json"
                cert_file.write_text(json.dumps(summary.certificate, indent=2))
                cert_filename = cert_file.name

                if not req.no_pdf:
                    try:
                        qr_url_tpl = CONFIG.get("qr_url_template", "https://s0-vp.vercel.app/?cert={cert_uuid}")
                        if req.portal_url and req.portal_url.strip():
                            p_url = req.portal_url.strip()
                            qr_url_tpl = f"{p_url.rstrip('/')}/?cert={{cert_uuid}}" if "{cert_uuid}" not in p_url else p_url
                        pdf_file = out_dir / f"file_wipe_certificate_{summary.certificate['cert_uuid'][:8]}.pdf"
                        qr_file = out_dir / f"file_wipe_certificate_{summary.certificate['cert_uuid'][:8]}.qr.png"
                        pdfgen.generate_pdf(summary.certificate, pdf_file, qr_url_template=qr_url_tpl)
                        pdfgen.write_qr_file(summary.certificate, qr_file)
                        pdf_filename = pdf_file.name
                    except Exception:
                        pass

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
                        "pdf_filename": pdf_filename,
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
    if req.out_dir and req.out_dir.strip():
        out_dir = Path(req.out_dir.strip()).resolve()
    else:
        out_dir = REPO / "demo-out" / f"gui-carve-{job_id}"
    out_dir.mkdir(parents=True, exist_ok=True)

    key, is_demo = _resolve_key(req.key_path, req.key_data, out_dir)

    with _lock:
        _jobs[job_id] = {
            "status": "running",
            "log": [f"Scanning {req.target} for carved artifacts..."],
            "out_dir": str(out_dir),
            "demo_key_warning": is_demo,
        }

    def run() -> None:
        try:
            t_start = time.monotonic()
            last_log_time = 0.0
            last_carve_temp_time = 0.0
            last_carve_temp_val = [None]

            def carve_progress(scanned: int, total: int, found: int) -> None:
                nonlocal last_log_time, last_carve_temp_time
                now = time.monotonic()
                if now - last_log_time < 0.2 and scanned < total:
                    return
                last_log_time = now

                elapsed = max(0.001, now - t_start)
                speed = scanned / elapsed
                speed_str = f"{speed / (1024 * 1024):.1f} MiB/s" if speed >= 1024 * 1024 else f"{speed / 1024:.1f} KiB/s"
                pct = (scanned * 100 // total) if total > 0 else 0
                rem_bytes = max(0, total - scanned)
                eta_sec = int(rem_bytes / speed) if speed > 0 else 0
                eta_str = f"{eta_sec // 60:02d}:{eta_sec % 60:02d}"

                if now - last_carve_temp_time >= 2.0:
                    last_carve_temp_time = now
                    last_carve_temp_val[0] = read_temperature(req.target)
                temp_str = f" | Temp: {last_carve_temp_val[0]}°C" if last_carve_temp_val[0] is not None else ""

                scanned_mb = scanned / (1024 * 1024)
                total_mb = total / (1024 * 1024)
                msg = f"[s0 carve] | {pct:3d}% | {scanned_mb:.1f} MiB / {total_mb:.1f} MiB | {speed_str} | {found} candidates | ETA: {eta_str}{temp_str}"
                with _lock:
                    if not _jobs[job_id]["log"] or not _jobs[job_id]["log"][-1].startswith("[s0 carve]"):
                        _jobs[job_id]["log"].append(msg)
                    else:
                        _jobs[job_id]["log"][-1] = msg

            custom_sigs = None
            if req.custom_signatures:
                from s0_cli.carver.signatures import signature_from_dict
                custom_sigs = []
                for cs in req.custom_signatures:
                    try:
                        custom_sigs.append(signature_from_dict(cs))
                    except Exception as sig_err:
                        with _lock:
                            _jobs[job_id]["log"].append(f"Warning: skipped invalid custom signature: {sig_err}")

            summary = carve_image(
                req.target,
                out_dir,
                extensions=req.extensions,
                custom_signatures=custom_sigs,
                min_confidence=req.min_confidence,
                operator_id=req.operator_id,
                organization=req.organization,
                signing_key_path=key,
                progress_callback=carve_progress,
            )
            manifest_filename = None
            if summary.manifest_certificate:
                try:
                    record_audit_event(summary.manifest_certificate, operation_type="FILE_CARVE", private_key=key)
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


@app.post("/api/image")
def start_image(req: ImageRequest) -> JSONResponse:
    if not req.source:
        raise HTTPException(400, "source path required")
    if not req.destination:
        raise HTTPException(400, "destination path required")
    if req.source == req.destination:
        raise HTTPException(400, "source and destination cannot be the same path")

    src_p = Path(req.source)
    if not src_p.exists():
        raise HTTPException(404, f"source does not exist: {req.source}")

    dst_p = Path(req.destination)
    is_blk = False
    try:
        is_blk = dst_p.is_block_device() or (_sys.platform == "darwin" and dst_p.is_char_device())
    except Exception:
        pass
    if _sys.platform == "win32" and ("physicaldrive" in req.destination.lower() or req.destination.startswith(r"\\.\\")):
        is_blk = True

    if (is_blk or req.is_clone) and req.confirm_text.strip() != req.destination.strip():
        raise HTTPException(400, f"Cloning to target block device requires typing exact destination: '{req.destination}'")

    job_id = uuid.uuid4().hex[:12]
    if req.out_dir and req.out_dir.strip():
        out_dir = Path(req.out_dir.strip()).resolve()
    else:
        out_dir = REPO / "demo-out" / f"gui-image-{job_id}"
    out_dir.mkdir(parents=True, exist_ok=True)

    key, is_demo = _resolve_key(req.key_path, req.key_data, out_dir)

    with _lock:
        _jobs[job_id] = {
            "status": "running",
            "log": [f"Acquiring forensic bit-stream from {req.source} to {req.destination}..."],
            "out_dir": str(out_dir),
            "demo_key_warning": is_demo,
        }

    def run() -> None:
        try:
            def _progress(bytes_copied, total_bytes, speed, bad_sectors):
                pct = int((bytes_copied / total_bytes) * 100) if total_bytes > 0 else 0
                msg = f"[s0 image] | {pct:3d}% | {bytes_copied / (1024 * 1024):.1f} MiB / {total_bytes / (1024 * 1024):.1f} MiB | {speed:.1f} MB/s | Bad Sectors: {bad_sectors}"
                with _lock:
                    if not _jobs[job_id]["log"] or not _jobs[job_id]["log"][-1].startswith("[s0 image]"):
                        _jobs[job_id]["log"].append(msg)
                    else:
                        _jobs[job_id]["log"][-1] = msg

            options = ImagingOptions(
                source=req.source,
                destination=req.destination,
                block_size=req.block_size,
                error_recovery=not req.no_recovery,
                operator=req.operator_id,
                organization=req.organization,
                key_path=key if key and key.exists() else None,
                no_certificate=False,
                out_dir=str(out_dir),
            )
            img_result = acquire_image(options, progress_callback=_progress)

            manifest_fn = Path(img_result.manifest_path).name if img_result.manifest_path else None
            cert_fn = None
            if img_result.manifest_certificate and "cert_uuid" in img_result.manifest_certificate:
                cert_fn = f"certificate_{img_result.manifest_certificate['cert_uuid']}.json"

            with _lock:
                _jobs[job_id].update(
                    status="done" if img_result.success else "error",
                    result={
                        "returncode": 0 if img_result.success else 1,
                        "success": img_result.success,
                        "source": img_result.source,
                        "destination": img_result.destination,
                        "is_clone": img_result.is_clone,
                        "bytes_copied": img_result.bytes_copied,
                        "duration_seconds": img_result.duration_seconds,
                        "speed_mbps": img_result.speed_mbps,
                        "bad_sectors_count": img_result.bad_sectors_count,
                        "bad_bytes_count": img_result.bad_bytes_count,
                        "source_sha256": img_result.source_sha256,
                        "source_md5": img_result.source_md5,
                        "manifest_filename": manifest_fn,
                        "cert_filename": cert_fn,
                        "error": img_result.error,
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
            "demo_key_warning": job.get("demo_key_warning", False),
        })


@app.get("/api/download/{job_id}/{filename}")
def download(job_id: str, filename: str) -> FileResponse:
    with _lock:
        job = _jobs.get(job_id)
    if not job:
        raise HTTPException(404, "unknown job")
    out_dir_path = Path(job["out_dir"]).resolve()
    path = (out_dir_path / filename).resolve()
    try:
        path.relative_to(out_dir_path)
    except ValueError:
        raise HTTPException(404, "no such artifact")
    if not path.is_file():
        raise HTTPException(404, "no such artifact")
    return FileResponse(path, filename=path.name)
