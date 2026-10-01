"""s0 Unified Forensic & Sanitization Web Dashboard.

Endpoints:
  - GET  /                           -> Multi-tab Forensic Web Dashboard
  - GET  /api/devices                -> List block devices & test images
  - POST /api/plan                   -> Drive wipe planning preview
  - POST /api/wipe                   -> Execute Drive Sanitization (Module 1)
  - POST /api/erase-files            -> Execute Secure File & Folder Erasure (Module 1)
  - POST /api/carve                  -> Execute Advanced File Carving & Recovery (Module 2)
  - POST /api/image                  -> Execute Forensic Bit-Stream Imaging (Module 3)
  - GET  /api/audit/blocks           -> Retrieve Hash-Chained Audit Ledger
  - GET  /api/audit/verify           -> Verify Hash Chain Integrity
  - GET  /api/job/{job_id}           -> Real-time Job Progress & Output
  - GET  /api/download/{job_id}/{fn} -> Download Sanitization & Forensic Artifacts
"""

from __future__ import annotations

import html
import json
import os
import secrets
import shutil
import subprocess
import sys as _sys
import tempfile
import threading
import time
import urllib.parse
import uuid
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from starlette.staticfiles import StaticFiles

from s0 import pdfgen, platform, resources
from s0.audit import list_audit_blocks, record_audit_event, verify_audit_ledger
from s0.audit.verify import get_default_trusted_keys
from s0.carve import carve_image
from s0.cli.devices import (
    SafetyError,
    Target,
    check_safety,
    get_block_device_size,
    image_target,
    list_block_targets,
)
from s0.cli.file_eraser import erase_batch
from s0.config import CONFIG
from s0.image.imager import ImagingOptions, acquire_image
from s0.temperature import read_temperature
from s0.validation import validate_metadata_str
from s0.wipe.methods.ata import hpa_dco_report
from s0.wipe.planner import select_method

#: Root the dashboard treats as its working directory: the source checkout when
#: running from one, otherwise the operator's ~/.s0 home. Resolved through
#: s0.resources so an installed wheel needs no sys.path help.
REPO = resources.repo_root() or (Path.home() / ".s0")

#: Static assets ship inside the package, next to this module.
STATIC_ROOT = Path(__file__).resolve().parent

VENV_BIN = REPO / ".venv" / "bin"


def _get_s0_cmd() -> list[str]:
    v_s0 = VENV_BIN / "s0"
    if v_s0.is_file() and os.access(v_s0, os.X_OK):
        return [str(v_s0)]
    which_s0 = shutil.which("s0")
    if which_s0:
        return [which_s0]
    return [_sys.executable, "-m", "s0.cli.main"]


IMAGE_DIRS = [
    Path(os.environ.get("S0_IMAGE_DIR", "")) if os.environ.get("S0_IMAGE_DIR") else None,
    REPO / "demo-out",
]

_SYSTEM_PATHS = (
    "/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64",
    "/boot", "/proc", "/sys", "/run", "/var", "/root", "/opt",
)


def _is_safe_wipe_path(target_path: str) -> tuple[bool, str]:
    """Ensure target path does not target protected system files/directories."""
    try:
        p = Path(target_path).resolve()
        if p.is_block_device():
            return True, ""
        target_str = str(p)
        for sp in _SYSTEM_PATHS:
            if target_str == sp or target_str.startswith(sp + "/"):
                return False, f"Refusing to target system path: {target_str}"
        return True, ""
    except Exception:
        return False, f"Invalid target path: {target_path}"


app = FastAPI(title="s0 Forensic & Sanitization Dashboard", docs_url=None, redoc_url=None)

from starlette.middleware.trustedhost import TrustedHostMiddleware

app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1", "*.local", "testserver"])

PORTAL_DIR = REPO / "portals/verify"
if PORTAL_DIR.is_dir():
    app.mount("/portal", StaticFiles(directory=str(PORTAL_DIR), html=True), name="portal")

STATIC_DIR = STATIC_ROOT / "static"
if STATIC_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
_jobs: dict[str, dict] = {}
_lock = threading.Lock()

_SESSION_AUTH_TOKEN = os.environ.get("S0_WEB_AUTH_TOKEN") or secrets.token_hex(32)


def _init_session_auth_token() -> None:
    try:
        token_path = Path.home() / ".s0" / "web_auth_token"
        token_path.parent.mkdir(parents=True, exist_ok=True)
        # Write atomically with 0600 permissions
        fd = os.open(str(token_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with open(fd, "w", encoding="utf-8") as f:
            f.write(_SESSION_AUTH_TOKEN)

        # When running as root (e.g. s0-web daemon on live ISO), make token available to kiosk user via s0-kiosk group
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            try:
                run_dir = Path("/run/s0")
                run_dir.mkdir(parents=True, exist_ok=True)
                run_token = run_dir / "web_auth_token"
                rfd = os.open(str(run_token), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with open(rfd, "w", encoding="utf-8") as f:
                    f.write(_SESSION_AUTH_TOKEN)
                # Restrict permissions: 0640 (owner root rw, group s0-kiosk r, others none)
                try:
                    import grp
                    kiosk_gid = grp.getgrnam("s0-kiosk").gr_gid
                    os.chown(run_token, 0, kiosk_gid)
                    os.chmod(run_token, 0o640)
                except Exception:
                    # Fallback if s0-kiosk group does not exist
                    os.chmod(run_token, 0o600)
            except Exception:
                pass
    except Exception:
        pass



_init_session_auth_token()


def verify_auth_token(
    x_s0_auth_token: str | None = Header(None, alias="X-S0-Auth-Token"),
    token: str | None = Query(None),
) -> None:
    """Verify per-session authentication token on protected endpoints."""
    tok = x_s0_auth_token or token
    if not tok:
        raise HTTPException(
            status_code=401,
            detail="Unauthorized: missing or invalid session authentication token (X-S0-Auth-Token)",
        )
    try:
        if not secrets.compare_digest(tok, _SESSION_AUTH_TOKEN):
            raise HTTPException(
                status_code=401,
                detail="Unauthorized: missing or invalid session authentication token (X-S0-Auth-Token)",
            )
    except (TypeError, ValueError):
        raise HTTPException(
            status_code=401,
            detail="Unauthorized: invalid session authentication token encoding",
        ) from None


def _validate_metadata_str(field_name: str, v: str, max_len: int = 128) -> str:
    res = validate_metadata_str(field_name, v, max_len)
    if res is None:
        raise ValueError(f"{field_name} cannot be empty")
    return res


def _validate_portal_url(v: str | None) -> str | None:
    if not v:
        return None
    v = v.strip()
    try:
        parsed = urllib.parse.urlparse(v)
        if parsed.scheme not in ("https", "http"):
            raise ValueError("portal_url must use https (or http for localhost)")
        if parsed.scheme == "http" and parsed.hostname not in ("localhost", "127.0.0.1"):
            raise ValueError("portal_url http scheme only permitted on localhost")
        if parsed.username or parsed.password:
            raise ValueError("portal_url cannot contain credentials")
        if not parsed.hostname:
            raise ValueError("portal_url missing hostname")
        return v
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError(f"Invalid portal_url: {exc}") from exc


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


def _resolve_key(key_path: str | None, key_data: str | None, out_dir: Path | None = None) -> tuple[Path | None, bool]:
    """Resolve custom signing key from raw PEM content or local file path.

    Returns (key_path, is_demo_key). Custom pasted keys are securely saved into
    ~/.s0/keys/ (isolated from deliverables/evidence out_dir).
    """
    from s0.crypto import is_demo_key

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
        kp = Path(key_path.strip()).resolve()
        for sp in _SYSTEM_PATHS:
            if str(kp) == sp or str(kp).startswith(sp + "/"):
                raise HTTPException(403, f"Access to system key path is forbidden: {key_path}")
        if not kp.is_file():
            kp = (REPO / key_path.strip()).resolve()
        if not kp.is_file():
            raise HTTPException(400, f"Specified signing key not found: {key_path}")
        return kp, is_demo_key(kp)

    default_key_rel = CONFIG.get("default_key_path", "src/s0/data/keys/demo_issuer_private.pem")
    default_key = (REPO / default_key_rel).resolve()
    if default_key.exists():
        return default_key, True
    return None, True


class PlanRequest(BaseModel):
    target: str


class WipeRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    target: str
    confirm_text: str
    pattern: str = "zero"
    passes: int = Field(default=1, ge=1, le=100)
    operator_id: str = Field(
        default_factory=lambda: CONFIG.get("default_operator", "op-forensic"),
        alias="operator"
    )
    organization: str = Field(default_factory=lambda: CONFIG.get("default_organization", "Digital Forensics & Data Sanitization Lab"))
    key_path: str | None = None
    key_data: str | None = None
    out_dir: str | None = None
    no_pdf: bool = False
    verify_samples: int = Field(default=64, ge=1, le=10000)
    portal_url: str | None = None

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        safe, reason = _is_safe_wipe_path(v)
        if not safe:
            raise ValueError(reason)
        return v

    @field_validator("pattern")
    @classmethod
    def validate_pattern(cls, v: str) -> str:
        if v not in ("zero", "random"):
            raise ValueError("pattern must be either 'zero' or 'random'")
        return v

    @field_validator("out_dir")
    @classmethod
    def validate_out_dir(cls, v: str | None) -> str | None:
        if v and v.strip():
            p = Path(v.strip()).resolve()
            for sp in _SYSTEM_PATHS:
                if str(p) == sp or str(p).startswith(sp + "/"):
                    raise ValueError(f"out_dir cannot be in system path: {sp}")
        return v

    @field_validator("key_path")
    @classmethod
    def validate_key_path(cls, v: str | None) -> str | None:
        if v and v.strip():
            p = Path(v.strip()).resolve()
            for sp in _SYSTEM_PATHS:
                if str(p) == sp or str(p).startswith(sp + "/"):
                    raise ValueError(f"key_path cannot be in system path: {sp}")
        return v

    @field_validator("operator_id")
    @classmethod
    def validate_operator_id(cls, v: str) -> str:
        return _validate_metadata_str("operator_id", v, 64)

    @field_validator("organization")
    @classmethod
    def validate_organization(cls, v: str) -> str:
        return _validate_metadata_str("organization", v, 128)

    @field_validator("portal_url")
    @classmethod
    def validate_portal_url(cls, v: str | None) -> str | None:
        return _validate_portal_url(v)


class FileEraseRequest(BaseModel):
    targets: list[str]
    passes: int = Field(default=1, ge=1, le=100)
    pattern: str = "zero"
    operator_id: str = Field(default_factory=lambda: CONFIG.get("default_operator", "op-forensic"))
    organization: str = Field(default_factory=lambda: CONFIG.get("default_organization", "Digital Forensics & Data Sanitization Lab"))
    key_path: str | None = None
    key_data: str | None = None
    out_dir: str | None = None
    no_pdf: bool = False
    verify_samples: int = Field(default=64, ge=1, le=10000)
    portal_url: str | None = None

    @field_validator("targets")
    @classmethod
    def validate_targets(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("targets list cannot be empty")
        for t in v:
            safe, reason = _is_safe_wipe_path(t)
            if not safe:
                raise ValueError(reason)
        return v

    @field_validator("pattern")
    @classmethod
    def validate_pattern(cls, v: str) -> str:
        if v not in ("zero", "random"):
            raise ValueError("pattern must be either 'zero' or 'random'")
        return v

    @field_validator("out_dir")
    @classmethod
    def validate_out_dir(cls, v: str | None) -> str | None:
        if v and v.strip():
            p = Path(v.strip()).resolve()
            for sp in _SYSTEM_PATHS:
                if str(p) == sp or str(p).startswith(sp + "/"):
                    raise ValueError(f"out_dir cannot be in system path: {sp}")
        return v

    @field_validator("key_path")
    @classmethod
    def validate_key_path(cls, v: str | None) -> str | None:
        if v and v.strip():
            p = Path(v.strip()).resolve()
            for sp in _SYSTEM_PATHS:
                if str(p) == sp or str(p).startswith(sp + "/"):
                    raise ValueError(f"key_path cannot be in system path: {sp}")
        return v

    @field_validator("operator_id")
    @classmethod
    def validate_operator_id(cls, v: str) -> str:
        return _validate_metadata_str("operator_id", v, 64)

    @field_validator("organization")
    @classmethod
    def validate_organization(cls, v: str) -> str:
        return _validate_metadata_str("organization", v, 128)

    @field_validator("portal_url")
    @classmethod
    def validate_portal_url(cls, v: str | None) -> str | None:
        return _validate_portal_url(v)


class CarveRequest(BaseModel):
    target: str
    extensions: list[str] | None = None
    min_confidence: int = 50
    operator_id: str = Field(default_factory=lambda: CONFIG.get("default_operator", "op-forensic"))
    organization: str = Field(default_factory=lambda: CONFIG.get("default_organization", "Digital Forensics & Data Sanitization Lab"))
    out_dir: str | None = None
    key_path: str | None = None
    key_data: str | None = None
    no_pdf: bool = False
    custom_signatures: list[dict[str, Any]] | None = None

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        safe, reason = _is_safe_wipe_path(v)
        if not safe:
            raise ValueError(reason)
        return v

    @field_validator("out_dir")
    @classmethod
    def validate_out_dir(cls, v: str | None) -> str | None:
        if v and v.strip():
            p = Path(v.strip()).resolve()
            for sp in _SYSTEM_PATHS:
                if str(p) == sp or str(p).startswith(sp + "/"):
                    raise ValueError(f"out_dir cannot be in system path: {sp}")
        return v

    @field_validator("key_path")
    @classmethod
    def validate_key_path(cls, v: str | None) -> str | None:
        if v and v.strip():
            p = Path(v.strip()).resolve()
            for sp in _SYSTEM_PATHS:
                if str(p) == sp or str(p).startswith(sp + "/"):
                    raise ValueError(f"key_path cannot be in system path: {sp}")
        return v

    @field_validator("operator_id")
    @classmethod
    def validate_operator_id(cls, v: str) -> str:
        return _validate_metadata_str("operator_id", v, 64)

    @field_validator("organization")
    @classmethod
    def validate_organization(cls, v: str) -> str:
        return _validate_metadata_str("organization", v, 128)


class ImageRequest(BaseModel):
    source: str
    destination: str
    block_size: int = 1024 * 1024
    no_recovery: bool = False
    is_clone: bool = False
    confirm_text: str = ""
    operator_id: str = Field(default_factory=lambda: CONFIG.get("default_operator", "op-forensic"))
    organization: str = Field(default_factory=lambda: CONFIG.get("default_organization", "Digital Forensics & Data Sanitization Lab"))
    out_dir: str | None = None
    key_path: str | None = None
    key_data: str | None = None
    no_pdf: bool = False

    @field_validator("out_dir")
    @classmethod
    def validate_out_dir(cls, v: str | None) -> str | None:
        if v and v.strip():
            p = Path(v.strip()).resolve()
            for sp in _SYSTEM_PATHS:
                if str(p) == sp or str(p).startswith(sp + "/"):
                    raise ValueError(f"out_dir cannot be in system path: {sp}")
        return v

    @field_validator("key_path")
    @classmethod
    def validate_key_path(cls, v: str | None) -> str | None:
        if v and v.strip():
            p = Path(v.strip()).resolve()
            for sp in _SYSTEM_PATHS:
                if str(p) == sp or str(p).startswith(sp + "/"):
                    raise ValueError(f"key_path cannot be in system path: {sp}")
        return v

    @field_validator("operator_id")
    @classmethod
    def validate_operator_id(cls, v: str) -> str:
        return _validate_metadata_str("operator_id", v, 64)

    @field_validator("organization")
    @classmethod
    def validate_organization(cls, v: str) -> str:
        return _validate_metadata_str("organization", v, 128)


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
    safe, reason = _is_safe_wipe_path(path)
    if not safe:
        raise HTTPException(403, reason)
    try:
        return image_target(path)
    except FileNotFoundError:
        raise HTTPException(404, f"no such image file: {path}") from None


@app.get("/")
def index() -> HTMLResponse:
    """Serve the dashboard, injecting the per-session auth token.

    The dashboard JS reads the token from, in order: the ``?token=`` query string,
    sessionStorage, ``<meta name="s0-auth-token">``, then ``window.appConfig``.
    Only the first is populated by ``s0 web`` when it opens a browser, so any
    other way of reaching the dashboard — a bookmark, a reopened tab, the live-ISO
    kiosk, or a server restarted under a new token — left every API call
    returning 401 with no visible error. Injecting the meta tag server-side makes
    ``http://127.0.0.1:8669/`` self-sufficient.
    """
    index_path = Path(__file__).parent / "static" / "index.html"
    content = index_path.read_text(encoding="utf-8")
    meta = (
        '<meta name="s0-auth-token" content="'
        + html.escape(_SESSION_AUTH_TOKEN, quote=True)
        + '">'
    )
    if "<head>" in content:
        content = content.replace("<head>", "<head>\n  " + meta, 1)
    else:  # pragma: no cover - index.html always has a head
        content = meta + content
    return HTMLResponse(content)


@app.get("/api/devices", dependencies=[Depends(verify_auth_token)])
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


@app.get("/api/config", dependencies=[Depends(verify_auth_token)])
def api_config() -> JSONResponse:
    cfg = dict(CONFIG)
    return JSONResponse(cfg)


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


@app.get("/api/browse", dependencies=[Depends(verify_auth_token)])
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


@app.get("/api/capabilities", dependencies=[Depends(verify_auth_token)])
def get_capabilities() -> JSONResponse:
    """Return runtime system capabilities and root/administrator privilege status."""
    is_root = False
    if hasattr(os, "geteuid"):
        is_root = (os.geteuid() == 0)
    elif _sys.platform == "win32":
        try:
            import ctypes
            is_root = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            is_root = False

    return JSONResponse({
        "is_root": is_root,
        "platform": _sys.platform,
        "restricted_operations": [] if is_root else ["block_wipe", "disk_image_acquisition"],
        "message": (
            "Full root / administrative access granted."
            if is_root
            else "Running without root privileges. Direct drive wiping and physical disk acquisition are disabled. For full functionality, launch with: sudo s0 web"
        ),
    })


@app.get("/api/temperature", dependencies=[Depends(verify_auth_token)])
def get_temperature(path: str = Query(..., description="Target device or file path")) -> JSONResponse:
    """Read hardware thermal sensor telemetry for a block device or target."""
    temp = read_temperature(path)
    status = "unavailable"
    if temp is not None:
        if temp < 55:
            status = "normal"
        elif temp < 70:
            status = "warm"
        else:
            status = "critical"

    return JSONResponse({
        "path": path,
        "temperature_c": temp,
        "status": status,
    })


@app.post("/api/plan", dependencies=[Depends(verify_auth_token)])
def api_plan(req: PlanRequest) -> JSONResponse:
    return JSONResponse(plan_payload(req.target))


@app.post("/api/wipe", dependencies=[Depends(verify_auth_token)])
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
        out_dir = REPO / "demo-out" / f"web-wipe-{job_id}"
    out_dir.mkdir(parents=True, exist_ok=True)

    key, is_demo = _resolve_key(req.key_path, req.key_data, out_dir)

    cmd = _get_s0_cmd() + [
        "wipe", "--target", req.target, "--yes",
        "--pattern", req.pattern, "--passes", str(req.passes),
        "--operator", req.operator_id,
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
                    # s0 CLI --json emits a versioned envelope
                    # (s0.<command>/1) with the payload under "result" and
                    # artifacts under "artifacts". Older builds emitted a flat
                    # object; both shapes are accepted so a mixed-version host
                    # still drives the dashboard.
                    body = parsed.get("result", parsed) if isinstance(parsed, dict) else parsed
                    result.update(body)
                    artifacts = parsed.get("artifacts", []) if isinstance(parsed, dict) else []
                    by_kind = {a.get("kind"): a.get("path") for a in artifacts
                               if isinstance(a, dict)}
                    cert_p = (by_kind.get("certificate")
                              or body.get("certificate")
                              or body.get("certificate_path"))
                    pdf_p = (by_kind.get("pdf_certificate")
                             or body.get("pdf")
                             or body.get("pdf_path"))
                    qr_p = by_kind.get("qr_code")
                    if cert_p:
                        result["cert_filename"] = Path(cert_p).name
                        result["certificate_path"] = str(cert_p)
                        result["certificate"] = str(cert_p)   # legacy alias
                    if pdf_p:
                        result["pdf_filename"] = Path(pdf_p).name
                        result["pdf_path"] = str(pdf_p)
                        result["pdf"] = str(pdf_p)           # legacy alias
                    if qr_p:
                        result["qr_filename"] = Path(qr_p).name
                    if isinstance(parsed, dict) and parsed.get("status") == "failure":
                        result["returncode"] = 1
                        result["error"] = "wipe completed with a failure status"
            else:
                result["stdout_tail"] = out.strip()[-2000:]
                result["error"] = f"Wipe command exited with code {proc.returncode}"
            status = "done" if proc.returncode == 0 else "error"
            with _lock:
                _jobs[job_id].update(status=status, result=result)
        except Exception as exc:
            with _lock:
                _jobs[job_id].update(status="error", result={"returncode": -1, "error": str(exc)})

    threading.Thread(target=run, daemon=True).start()
    return JSONResponse({"job_id": job_id})


@app.post("/api/erase-files", dependencies=[Depends(verify_auth_token)])
def start_erase_files(req: FileEraseRequest) -> JSONResponse:
    if not req.targets:
        raise HTTPException(400, "no file targets provided")

    job_id = uuid.uuid4().hex[:12]
    if req.out_dir and req.out_dir.strip():
        out_dir = Path(req.out_dir.strip()).resolve()
    else:
        out_dir = REPO / "demo-out" / f"web-filewipe-{job_id}"
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
                msg = f"[s0 wipe] | {pct:3d}% | {w_mb:.1f} MiB / {tot_mb:.1f} MiB | {speed_str} | ETA: {eta_str}{temp_str} ({Path(fpath).name[:20]})"
                with _lock:
                    if not _jobs[job_id]["log"] or not _jobs[job_id]["log"][-1].startswith("[s0 wipe]"):
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
            audit_ledger_recorded = False
            audit_ledger_error = None
            if summary.certificate:
                try:
                    record_audit_event(summary.certificate, operation_type="FILE_ERASE", private_key=key)
                    audit_ledger_recorded = True
                except Exception as exc:
                    audit_ledger_error = str(exc)
                    print(f"Warning: Failed to append to audit ledger: {exc}", file=_sys.stderr)
                    with _lock:
                        _jobs[job_id]["log"].append(f"Warning: Failed to append to audit ledger: {exc}")
                cert_file = out_dir / f"file_wipe_certificate_{summary.certificate['cert_uuid'][:8]}.json"
                cert_file.write_text(json.dumps(summary.certificate, indent=2))
                cert_filename = cert_file.name

                if not req.no_pdf:
                    try:
                        qr_url_tpl = CONFIG.get("qr_url_template", "https://s0-verify.pages.dev/?cert={cert_uuid}")
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
                    status="done" if summary.failed_files == 0 else "error",
                    result={
                        "returncode": 0 if summary.failed_files == 0 else 1,
                        "total_files": summary.total_files,
                        "successful_files": summary.successful_files,
                        "failed_files": summary.failed_files,
                        "total_bytes": summary.total_bytes_processed,
                        "cert_filename": cert_filename,
                        "pdf_filename": pdf_filename,
                        "warnings": summary.warnings,
                        "audit_ledger_recorded": audit_ledger_recorded,
                        "audit_ledger_error": audit_ledger_error,
                    },
                )
        except Exception as exc:
            with _lock:
                _jobs[job_id].update(status="error", result={"returncode": -1, "error": str(exc)})

    threading.Thread(target=run, daemon=True).start()
    return JSONResponse({"job_id": job_id})


@app.post("/api/carve", dependencies=[Depends(verify_auth_token)])
def start_carve(req: CarveRequest) -> JSONResponse:
    target_p = Path(req.target)
    if not target_p.exists():
        raise HTTPException(404, "target media does not exist")

    job_id = uuid.uuid4().hex[:12]
    if req.out_dir and req.out_dir.strip():
        out_dir = Path(req.out_dir.strip()).resolve()
    else:
        out_dir = REPO / "demo-out" / f"web-carve-{job_id}"
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
                from s0.carve.signatures import signature_from_dict
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
            pdf_filename = None
            audit_ledger_recorded = False
            audit_ledger_error = None
            if summary.manifest_certificate:
                try:
                    record_audit_event(summary.manifest_certificate, operation_type="FILE_CARVE", private_key=key)
                    audit_ledger_recorded = True
                except Exception as exc:
                    audit_ledger_error = str(exc)
                    print(f"Warning: Failed to append to audit ledger: {exc}", file=_sys.stderr)
                    with _lock:
                        _jobs[job_id]["log"].append(f"Warning: Failed to append to audit ledger: {exc}")
                m_file = out_dir / f"carving_manifest_{summary.manifest_certificate['cert_uuid'][:8]}.json"
                m_file.write_text(json.dumps(summary.manifest_certificate, indent=2))
                manifest_filename = m_file.name

                if not req.no_pdf:
                    try:
                        pdf_path = out_dir / f"carving_manifest_{summary.manifest_certificate['cert_uuid'][:8]}.pdf"
                        pdfgen.generate_pdf(summary.manifest_certificate, pdf_path)
                        pdfgen.write_qr_file(summary.manifest_certificate, out_dir / f"carving_manifest_{summary.manifest_certificate['cert_uuid'][:8]}.qr.png")
                        pdf_filename = pdf_path.name
                    except Exception:
                        pass

            with _lock:
                _jobs[job_id].update(
                    status="done",
                    result={
                        "returncode": 0,
                        "bytes_scanned": summary.total_bytes_scanned,
                        "candidates_found": summary.total_candidates_found,
                        "files_recovered": summary.files_recovered,
                        "manifest_filename": manifest_filename,
                        "pdf_filename": pdf_filename,
                        "audit_ledger_recorded": audit_ledger_recorded,
                        "audit_ledger_error": audit_ledger_error,
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


@app.post("/api/image", dependencies=[Depends(verify_auth_token)])
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
        is_blk = platform.is_block_device(dst_p)
    except Exception:
        pass
    if _sys.platform == "win32" and platform.is_windows_volume_path(req.destination):
        is_blk = True

    if (is_blk or req.is_clone) and req.confirm_text.strip() != req.destination.strip():
        raise HTTPException(400, f"Cloning to target block device requires typing exact destination: '{req.destination}'")

    job_id = uuid.uuid4().hex[:12]
    if req.out_dir and req.out_dir.strip():
        out_dir = Path(req.out_dir.strip()).resolve()
    else:
        out_dir = REPO / "demo-out" / f"web-image-{job_id}"
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
            pdf_fn = None
            if img_result.manifest_certificate and "cert_uuid" in img_result.manifest_certificate:
                cert_fn = f"certificate_{img_result.manifest_certificate['cert_uuid']}.json"
                if not req.no_pdf:
                    try:
                        pdf_path = out_dir / f"certificate_{img_result.manifest_certificate['cert_uuid'][:8]}.pdf"
                        pdfgen.generate_pdf(img_result.manifest_certificate, pdf_path)
                        pdfgen.write_qr_file(img_result.manifest_certificate, out_dir / f"certificate_{img_result.manifest_certificate['cert_uuid'][:8]}.qr.png")
                        pdf_fn = pdf_path.name
                    except Exception:
                        pass

            if not img_result.audit_ledger_recorded and img_result.audit_ledger_error:
                with _lock:
                    _jobs[job_id]["log"].append(f"Warning: Failed to append to audit ledger: {img_result.audit_ledger_error}")

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
                        "pdf_filename": pdf_fn,
                        "audit_ledger_recorded": img_result.audit_ledger_recorded,
                        "audit_ledger_error": img_result.audit_ledger_error,
                        "error": img_result.error,
                    },
                )
        except Exception as exc:
            with _lock:
                _jobs[job_id].update(status="error", result={"returncode": -1, "error": str(exc)})

    threading.Thread(target=run, daemon=True).start()
    return JSONResponse({"job_id": job_id})


@app.get("/api/audit/blocks", dependencies=[Depends(verify_auth_token)])
def get_audit_blocks(limit: int = 100, offset: int = 0) -> JSONResponse:
    blocks = list_audit_blocks(limit=limit, offset=offset)
    return JSONResponse({
        "total": len(blocks),
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


@app.get("/api/audit/verify", dependencies=[Depends(verify_auth_token)])
def get_audit_verify() -> JSONResponse:
    report = verify_audit_ledger(trusted_public_keys=get_default_trusted_keys())
    return JSONResponse({
        "is_valid": report.is_valid,
        "total_blocks": report.total_blocks_verified,
        "reason": report.reason,
        "is_demo_signed": report.is_demo_signed,
        "demo_key_warning": report.demo_key_warning,
    })


@app.get("/api/job/{job_id}", dependencies=[Depends(verify_auth_token)])
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


@app.get("/api/download/{job_id}/{filename}", dependencies=[Depends(verify_auth_token)])
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
        raise HTTPException(404, "no such artifact") from None
    if not path.is_file():
        raise HTTPException(404, "no such artifact")
    return FileResponse(path, filename=path.name)
