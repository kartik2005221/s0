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

import json
import logging
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
from collections import OrderedDict
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
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
from s0.safety import SYSTEM_PREFIXES, ProtectedPathError, check_path_is_destructive
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

_LOG = logging.getLogger("s0.web")

#: Auth cookie. HttpOnly because no script needs to read it -- the browser
#: attaches it to same-origin requests by itself. SameSite=Strict is what stops
#: cookie auth from reintroducing CSRF: a cross-site request never carries it.
#: Secure is deliberately NOT set: the dashboard is plain HTTP on loopback, and
#: a Secure cookie would be dropped there, breaking the only real deployment.
AUTH_COOKIE = "s0_session"

# Derived from s0.safety, which owns the rules. This used to be a hand-typed
# copy of the same list, and it had already drifted: /dev and /srv were missing
# here while s0.safety protected both. A second copy of a safety list is a second
# list that will drift again, and the direction it drifts is toward permitting
# something the CLI refuses.
_SYSTEM_PATHS = SYSTEM_PREFIXES


def _is_safe_wipe_path(target_path: str) -> tuple[bool, str]:
    """Refuse protected paths, using the same rules as the CLI.

    This used to keep its own `_SYSTEM_PATHS` copy, which is how the two
    interfaces came to disagree: the web tier refused `/etc/passwd` while the CLI
    refused nothing, and `~/.s0` was not on either list. One module owns the rules
    now (`s0.safety`), so a change applies to both.
    """
    try:
        if Path(target_path).resolve().is_block_device():
            return True, ""
        check_path_is_destructive(target_path, force=False)
        return True, ""
    except ProtectedPathError as exc:
        return False, str(exc)
    except Exception:
        return False, f"Invalid target path: {target_path}"


# openapi_url is disabled as well: /docs and /redoc were already off, but leaving
# the schema live handed an unauthenticated caller the full route and field list.
from starlette.middleware.trustedhost import TrustedHostMiddleware

app = FastAPI(
    title="s0 Forensic & Sanitization Dashboard",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


# `*.local` matches any mDNS name, so `http://attacker.local` was an accepted Host
# header -- a DNS-rebinding foothold. Only literal loopback names are needed;
# `testserver` remains for TestClient.
# NOTE: middleware added last runs first (Starlette prepends), so this has to be
# registered *after* TrustedHostMiddleware below in order to wrap it. Registered
# the other way round it would be inner, and TrustedHost would already have
# rejected `Host: LOCALHOST` before this ever saw the request.
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["localhost", "127.0.0.1", "[::1]", "testserver"],
)


@app.middleware("http")
async def normalize_host_header(request: Request, call_next):
    """Lowercase the Host header before TrustedHostMiddleware sees it.

    Host names are case-insensitive (RFC 9110 §4.2.3), but Starlette compares the
    raw header value against the allowlist, so `Host: LOCALHOST` was refused with
    a 400 while `Host: localhost` was accepted. That fails closed, so it was never
    a security hole -- it was a robustness bug that turned a valid request into an
    error only visible on a differently-cased client.
    """
    headers = request.scope.get("headers")
    if headers is not None:
        for i, (name, value) in enumerate(headers):
            if name == b"host":
                headers[i] = (name, value.lower())
                break
    return await call_next(request)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    """Apply the response headers the Cloudflare portals get from their _headers.

    That file is a Cloudflare Pages directive and does nothing for the FastAPI
    server, so the dashboard -- which serves evidence from the host -- was running
    with no nosniff, no frame protection, and no referrer policy.

    `script-src` still allows 'unsafe-inline'. The dashboard carries 45 inline
    `onclick`/`onchange` attributes (index.html), which a hash-based policy cannot
    cover without `'unsafe-hashes'` and a hash per handler. The dangerous vectors
    are closed regardless: `object-src 'none'`, `base-uri 'none'`, no plugins, no
    framing, forms same-origin only. Migrating the handlers to `addEventListener`
    is tracked in docs/compliance/limitations.md; until then this is the honest
    strictness, not a claim of full strictness.
    """
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    # HSTS is deliberately absent: the dashboard is plain HTTP on loopback, where
    # browsers ignore it anyway.
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "object-src 'none'; "
        "base-uri 'none'; "
        "form-action 'self'; "
        "frame-ancestors 'none'",
    )
    return response


PORTAL_DIR = REPO / "site/verify"
if PORTAL_DIR.is_dir():
    app.mount("/portal", StaticFiles(directory=str(PORTAL_DIR), html=True), name="portal")

STATIC_DIR = STATIC_ROOT / "static"
if STATIC_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
#: Job records are held for the process lifetime. Unbounded growth matters most
#: on the live-ISO kiosk, which runs for the whole session, so the store is a
#: capped LRU: oldest job is evicted once the cap is reached. Capped at a size
#: that comfortably covers a UI polling several concurrent operations.
#: Hard cap on a single job's captured log lines. `[s0 ...]` progress lines are
#: collapsed in place already; this bounds the diagnostic lines that are not.
_MAX_LOG_LINES = 500

#: Wall-clock budget for a CLI subprocess started by the web tier. `communicate()`
#: had no timeout, so a child wedged on a bad block device kept its thread and its
#: job record alive forever. Wiping a multi-TB device legitimately takes hours, so
#: this is generous: the point is to stop a *hung* job, not a slow one.
_JOB_TIMEOUT_SECONDS = 6 * 60 * 60

#: Job records live for the process lifetime. Unbounded growth matters most on the
#: live-ISO kiosk, which runs a whole session, so the store is a capped LRU.
_MAX_JOBS = 200
_jobs: OrderedDict[str, dict] = OrderedDict()


def _record_job(job_id: str, record: dict) -> None:
    """Store a job record, evicting the oldest once the cap is reached."""
    with _lock:
        _jobs[job_id] = record
        _jobs.move_to_end(job_id)
        while len(_jobs) > _MAX_JOBS:
            _jobs.popitem(last=False)


_lock = threading.Lock()


def _load_or_create_session_token() -> str:
    """Return the session token, writing it to disk only when it is created.

    Two problems with generating a token here and writing it unconditionally.

    The mode passed to ``os.open`` applies only when the file is *created*. A
    ``~/.s0/web_auth_token`` left at 0644 by an earlier version, or widened by a
    user, stayed 0644 while holding the live credential -- the mode argument
    looked like it was protecting the file and was not.

    And doing this at import time meant merely importing the module rotated the
    token on disk. A second server process -- a reload, a test, a second worker --
    silently invalidated the token a running dashboard was already using, so the
    operator's cookie stopped working with nothing changed on their side.

    So: adopt a usable token from disk if one is there, generate only if not, and
    enforce the mode on every path.
    """
    override = os.environ.get("S0_WEB_AUTH_TOKEN")
    if override:
        return override

    token_path = Path.home() / ".s0" / "web_auth_token"
    try:
        existing = token_path.read_text(encoding="utf-8").strip()
        # 64 hex chars is what token_hex(32) produces. Reuse only that shape, so a
        # truncated or corrupted file is replaced rather than adopted.
        if len(existing) == 64 and all(c in "0123456789abcdef" for c in existing):
            os.chmod(token_path, 0o600)
            return existing
    except (OSError, ValueError):
        pass

    token = secrets.token_hex(32)
    try:
        token_path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(token_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with open(fd, "w", encoding="utf-8") as f:
            f.write(token)
        # The mode above is ignored for a file that already existed, so narrow it
        # explicitly rather than trusting the argument.
        os.chmod(token_path, 0o600)
    except OSError:
        pass
    return token


_SESSION_AUTH_TOKEN = _load_or_create_session_token()


def _init_session_auth_token() -> None:
    """Publish the decided token where the operator and kiosk can read it.

    The token itself is chosen by _load_or_create_session_token, which adopts an
    existing one rather than rotating it. This only mirrors that decision to disk
    and to the kiosk group.
    """
    try:
        token_path = Path.home() / ".s0" / "web_auth_token"
        token_path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(token_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with open(fd, "w", encoding="utf-8") as f:
            f.write(_SESSION_AUTH_TOKEN)
        # os.open's mode applies only on creation; enforce it on every write so a
        # pre-existing world-readable token file cannot survive.
        os.chmod(token_path, 0o600)

        # When running as root (e.g. s0-web daemon on live ISO), make token available to kiosk user via s0-kiosk group
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            try:
                run_dir = Path("/run/s0")
                run_dir.mkdir(parents=True, exist_ok=True)
                run_token = run_dir / "web_auth_token"
                rfd = os.open(str(run_token), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with open(rfd, "w", encoding="utf-8") as f:
                    f.write(_SESSION_AUTH_TOKEN)
                os.chmod(run_token, 0o600)
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


# No longer rotates anything: _load_or_create_session_token already decided the
# token, and this only mirrors it to the kiosk-visible location. Kept at import
# because the kiosk reads the file at session start, and wrapped so a failure here
# cannot stop the app from importing.
try:
    _init_session_auth_token()
except Exception:  # pragma: no cover - best effort
    pass


#: Routes where ``?token=`` is accepted. The kiosk opens the dashboard by
#: navigating to a URL that carries the token, because it has nowhere to put a
#: header. Everywhere else the header or cookie is required.
_BOOTSTRAP_PATHS = ("/",)

#: Methods that change state. A cookie is attached to these automatically by the
#: browser, so they are the ones where a cross-site request needs checking.
_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _require_same_origin(request: Request) -> None:
    """Reject a state-changing request that did not come from this origin.

    SameSite=Strict already stops a browser sending the cookie cross-site, and no
    CORS middleware means a cross-origin *read* is blocked too. This is defence in
    depth for the case those do not cover: a client that echoes cookies regardless
    of SameSite, or a browser that does not enforce it.

    A missing Origin is allowed, because a non-browser client (curl, the kiosk
    script, the test suite) legitimately sends none, and such a client is not
    subject to ambient-credential attachment in the first place. Sec-Fetch-Site is
    checked too when present, since it is set by the browser even when Origin is
    suppressed.
    """
    if request.method.upper() not in _UNSAFE_METHODS:
        return

    fetch_site = request.headers.get("sec-fetch-site")
    if fetch_site and fetch_site.lower() not in ("same-origin", "none"):
        raise HTTPException(
            status_code=403,
            detail=f"Forbidden: cross-site request refused (Sec-Fetch-Site: {fetch_site})",
        )

    origin = request.headers.get("origin")
    if not origin:
        return
    host = request.headers.get("host", "")
    expected = {f"{scheme}://{host}" for scheme in ("http", "https")}
    if origin.rstrip("/") not in {e.rstrip("/") for e in expected}:
        raise HTTPException(
            status_code=403,
            detail="Forbidden: cross-origin request refused",
        )


def _token_matches(candidate: str | None) -> bool:
    """Constant-time comparison of a candidate token against the session token."""
    if not candidate:
        return False
    try:
        return secrets.compare_digest(candidate, _SESSION_AUTH_TOKEN)
    except (TypeError, ValueError):
        return False


def _set_auth_cookie(response: Response) -> Response:
    response.set_cookie(AUTH_COOKIE, _SESSION_AUTH_TOKEN, httponly=True, samesite="strict", path="/")
    # The bootstrap response carries the credential in a Set-Cookie header; a
    # shared cache must not keep it.
    response.headers["Cache-Control"] = "no-store"
    return response


def verify_auth_token(
    request: Request,
    x_s0_auth_token: str | None = Header(None, alias="X-S0-Auth-Token"),
    token: str | None = Query(None),
) -> None:
    """Verify per-session authentication token on protected endpoints.

    Accepted from, in order: the ``X-S0-Auth-Token`` header (what the dashboard JS
    sends), the auth cookie (what the browser attaches on its own), then ``?token=``
    (the one-shot bootstrap ``s0 web`` and the ISO kiosk use to open a browser).
    The query form is a bootstrap only -- a token in a URL leaks into browser
    history, ``Referer`` and proxy logs -- so ``GET /`` converts it to a cookie and
    redirects to a clean URL.
    """
    tok = x_s0_auth_token
    cookie = request.cookies.get(AUTH_COOKIE)
    if not tok and cookie:
        _require_same_origin(request)
        tok = cookie
    if not tok and token:
        # The query form is a bootstrap, so it is accepted on the bootstrap route
        # and nowhere else. Everywhere else it kept working, which defeated the
        # reason for restricting it: a token in a URL leaks into browser history,
        # Referer headers and proxy logs, and a caller who pasted it once had it
        # silently honoured on every later request.
        if request.url.path not in _BOOTSTRAP_PATHS:
            raise HTTPException(
                status_code=401,
                detail=(
                    "Unauthorized: the ?token= bootstrap form is only accepted "
                    f"on {'/'.join(_BOOTSTRAP_PATHS)}. Use the X-S0-Auth-Token "
                    "header or the session cookie."
                ),
            )
        tok = token

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

    # The Origin check already ran when the credential came from the cookie. A
    # request authenticated by header or by the bootstrap query form is not
    # carrying an ambient credential, so it has nothing to check.


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


def _resolve_key(
    key_path: str | None, key_data: str | None, out_dir: Path | None = None
) -> tuple[Path | None, bool]:
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
        raw = key_path.strip()
        # Resolve to ONE final candidate *before* any policy check. This used to
        # check `_SYSTEM_PATHS` against the CWD-relative resolve and only then fall
        # back to a REPO-relative resolve *without rechecking*. uvicorn runs with
        # cwd=src/s0/web, so `../../../../etc/hostname` resolved to
        # `<repo>/etc/hostname` (harmless, not a file) and the fallback then
        # resolved it to `/etc/hostname` -- a real file, accepted, and passed to the
        # CLI as `--key`. Checking after resolution makes the base irrelevant.
        kp = Path(raw)
        if not kp.is_absolute():
            kp = REPO / kp
        kp = kp.resolve()
        for sp in _SYSTEM_PATHS:
            if str(kp) == sp or str(kp).startswith(sp + "/"):
                raise HTTPException(403, f"Access to system key path is forbidden: {raw}")
        if not kp.is_file():
            raise HTTPException(400, f"Specified signing key not found: {raw}")
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
        default_factory=lambda: CONFIG.get("default_operator", "op-forensic"), alias="operator"
    )
    organization: str = Field(
        default_factory=lambda: CONFIG.get(
            "default_organization", "Digital Forensics & Data Sanitization Lab"
        )
    )
    key_path: str | None = None
    key_data: str | None = Field(
        default=None,
        max_length=16_384,
        description=(
            "PEM signing key pasted into the UI. Bounded because it is written "
            "to disk verbatim; a PEM is under 4 KiB."
        ),
    )
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
    organization: str = Field(
        default_factory=lambda: CONFIG.get(
            "default_organization", "Digital Forensics & Data Sanitization Lab"
        )
    )
    key_path: str | None = None
    key_data: str | None = Field(
        default=None,
        max_length=16_384,
        description=(
            "PEM signing key pasted into the UI. Bounded because it is written "
            "to disk verbatim; a PEM is under 4 KiB."
        ),
    )
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
    # The CLI documents 0-100 and its own parser rejects out-of-range values, so the
    # web tier did too. It accepted min_confidence=999, which is a confidence
    # nobody can express: the request succeeded and carved nothing, and the only
    # way to tell that from "nothing was recoverable" was to read the report.
    min_confidence: int = Field(default=50, ge=0, le=100)
    operator_id: str = Field(default_factory=lambda: CONFIG.get("default_operator", "op-forensic"))
    organization: str = Field(
        default_factory=lambda: CONFIG.get(
            "default_organization", "Digital Forensics & Data Sanitization Lab"
        )
    )
    out_dir: str | None = None
    key_path: str | None = None
    key_data: str | None = Field(
        default=None,
        max_length=16_384,
        description=(
            "PEM signing key pasted into the UI. Bounded because it is written "
            "to disk verbatim; a PEM is under 4 KiB."
        ),
    )
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
    force: bool = False
    confirm_text: str = ""
    operator_id: str = Field(default_factory=lambda: CONFIG.get("default_operator", "op-forensic"))
    organization: str = Field(
        default_factory=lambda: CONFIG.get(
            "default_organization", "Digital Forensics & Data Sanitization Lab"
        )
    )
    out_dir: str | None = None
    key_path: str | None = None
    key_data: str | None = Field(
        default=None,
        max_length=16_384,
        description=(
            "PEM signing key pasted into the UI. Bounded because it is written "
            "to disk verbatim; a PEM is under 4 KiB."
        ),
    )
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
            return Target(
                path=str(p), kind="block", capacity_bytes=size, sector_size=512, storage_type="UNKNOWN"
            )
        raise HTTPException(400, f"unrecognised or 0-byte block device {path}")
    safe, reason = _is_safe_wipe_path(path)
    if not safe:
        raise HTTPException(403, reason)
    try:
        return image_target(path)
    except FileNotFoundError:
        raise HTTPException(404, f"no such image file: {path}") from None


@app.get("/healthz")
def healthz() -> JSONResponse:
    """Unauthenticated readiness probe.

    Deliberately the only unauthenticated data route, and deliberately returns
    nothing about the host: no paths, no device list, no version-dependent detail
    beyond a literal. Readiness checks are conventionally unauthenticated, and the
    ISO kiosk needs one -- `s0-wait-web` used to poll `/api/devices` with no token,
    which returns 401, so its `if` test was always false and the kiosk always
    waited the full 30 s and then failed. Coupling a wait script to the auth
    token file's permissions is the wrong fix; a probe that exposes nothing does
    not need one.
    """
    return JSONResponse({"status": "ok"})


@app.get("/")
def index(
    request: Request,
    x_s0_auth_token: str | None = Header(None, alias="X-S0-Auth-Token"),
    token: str | None = Query(None),
) -> Response:
    """Serve the dashboard shell.

    This route used to inject the live session token into a ``<meta>`` tag in
    unauthenticated HTML. That handed the token to anything able to reach the
    loopback port -- a top-level navigation from any page in the operator's
    browser, another local account, a container sharing the network namespace --
    and the token unlocks every protected endpoint. The reason given was that a
    bookmark or reopened tab would otherwise 401 with no visible error. That is a
    real problem, but serving the credential to whoever asks is the wrong fix.

    So the token is never embedded:

    * ``/?token=X`` validates X, returns it as an ``HttpOnly`` cookie, and
      redirects to a clean ``/``. That is the path ``s0 web`` and the ISO kiosk use,
      and the redirect is what keeps the token out of history and ``Referer``.
    * A request already holding a valid cookie or header gets the plain shell.
    * Anything else gets 401 plus instructions, rather than a dashboard that
      silently 401s on every click.
    """
    index_path = Path(__file__).parent / "static" / "index.html"

    if token is not None:
        if not _token_matches(token):
            return HTMLResponse(_auth_required_page(), status_code=401)
        return _set_auth_cookie(RedirectResponse(url="/", status_code=303))

    if not _token_matches(x_s0_auth_token) and not _token_matches(request.cookies.get(AUTH_COOKIE)):
        return HTMLResponse(_auth_required_page(), status_code=401)

    return HTMLResponse(
        index_path.read_text(encoding="utf-8"),
        headers={"Cache-Control": "no-store"},
    )


def _auth_required_page() -> str:
    """A 401 that says what to do, instead of a dead dashboard."""
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        "<title>s0 - authentication required</title><style>body{font:16px/1.6 "
        "system-ui,sans-serif;max-width:44rem;margin:4rem auto;padding:0 1.5rem;"
        "color:#0f172a}code{background:#f1f5f9;padding:.15em .4em;border-radius:3px}"
        "pre{background:#f1f5f9;padding:1rem;border-radius:6px;overflow:auto}</style>"
        "</head><body><h1>Authentication required</h1><p>This dashboard serves "
        "evidence from your machine, so it requires the per-session token that "
        "<code>s0 web</code> prints at startup.</p><p>Open the authenticated URL, "
        "which looks like:</p><pre>http://127.0.0.1:8669/?token=&lt;token&gt;</pre>"
        "<p>The token is also written to <code>~/.s0/web_auth_token</code> (mode "
        "0600) and printed on the terminal running <code>s0 web</code>. It is "
        "regenerated every time the server starts.</p><p>If you arrived from a "
        "bookmark, the server has probably restarted and the token has changed."
        "</p></body></html>"
    )


@app.get("/api/devices", dependencies=[Depends(verify_auth_token)])
def devices() -> JSONResponse:
    block = []
    for t in list_block_targets():
        block.append(
            {
                "path": t.path,
                "storage_type": t.storage_type,
                "capacity_bytes": t.capacity_bytes,
                "model": t.model,
                "serial": t.serial,
                "mounted_hint": None,
            }
        )
    images = []
    seen = set()
    for d in IMAGE_DIRS:
        if d and d.is_dir():
            candidates = (
                list(d.glob("*.img"))
                + list(d.glob("*.raw"))
                + list(d.glob("*/*.img"))
                + list(d.glob("*/*.raw"))
            )
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
        "target": {
            "path": target.path,
            "kind": target.kind,
            "storage_type": target.storage_type,
            "capacity_bytes": target.capacity_bytes,
        },
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
    # `default_key_path` is declared relative to a source checkout
    # ("src/s0/data/keys/..."). For anyone who installed s0 from a wheel there is no
    # checkout above site-packages, so the path resolves nowhere -- the dashboard then
    # displays a key location that does not exist, which is worse than not naming one.
    #
    # Replaced with the packaged key's real location when we can find it, and with
    # null when there is none. A consumer must be able to tell "no key configured"
    # from "here is where the key is".
    relative = str(cfg.get("default_key_path", ""))
    resolved_default = None
    try:
        from s0 import resources

        candidate = resources.demo_private_key()
        if candidate is not None:
            resolved_default = str(candidate)
    except Exception:
        resolved_default = None
    cfg["default_key_path"] = resolved_default or relative or None
    cfg["default_key_path_is_usable"] = resolved_default is not None
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
    requested = Path(path).expanduser().resolve()

    # A rejected path used to be silently replaced with REPO. That is a lie the
    # caller cannot detect: the dashboard asked to list /tmp and received the
    # repository, with HTTP 200 and a plausible-looking listing. Silence here reads
    # as "this directory is empty" or "that is what was there", and an operator
    # picking an output directory would be choosing from the wrong tree entirely.
    #
    # So the refusal is explicit, and it says which condition failed.
    if not requested.exists():
        return JSONResponse(
            {"error": "no such directory", "path": str(requested), "items": []}, status_code=404
        )
    if not requested.is_dir():
        return JSONResponse(
            {"error": "not a directory", "path": str(requested), "items": []}, status_code=400
        )
    if not _is_safe_browse_path(requested):
        return JSONResponse(
            {"error": "path is outside the permitted roots", "path": str(requested), "items": []},
            status_code=403,
        )

    target = requested
    items = []
    try:
        for entry in sorted(target.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
            items.append(
                {
                    "name": entry.name,
                    "path": str(entry.resolve()),
                    "is_dir": entry.is_dir(),
                    "size": entry.stat().st_size if entry.is_file() else 0,
                }
            )
    except Exception:
        # The OSError text names server-side directories ("[Errno 13] Permission
        # denied: '/home/operator/...'"). `current` is already constrained by
        # _is_safe_browse_path, so the exception string adds leakage, not context.
        _LOG.exception("browse failed for an already-vetted path")
        return JSONResponse({"error": "directory not readable", "current": str(target), "items": []})
    return JSONResponse(
        {
            "current": str(target),
            "parent": str(target.parent)
            if target.parent != target and _is_safe_browse_path(target.parent)
            else None,
            "items": items,
        }
    )


@app.get("/api/capabilities", dependencies=[Depends(verify_auth_token)])
def get_capabilities() -> JSONResponse:
    """Return runtime system capabilities and root/administrator privilege status."""
    is_root = False
    if hasattr(os, "geteuid"):
        is_root = os.geteuid() == 0
    elif _sys.platform == "win32":
        try:
            import ctypes

            # ctypes.windll exists only on Windows; this branch is guarded by
            # sys.platform, and mypy analyses the module against Linux stdlib.
            is_root = bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:
            is_root = False

    return JSONResponse(
        {
            "is_root": is_root,
            "platform": _sys.platform,
            "restricted_operations": [] if is_root else ["block_wipe", "disk_image_acquisition"],
            "message": (
                "Full root / administrative access granted."
                if is_root
                else "Running without root privileges. Direct drive wiping and physical disk acquisition are disabled. For full functionality, launch with: sudo s0 web"
            ),
        }
    )


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

    return JSONResponse(
        {
            "path": path,
            "temperature_c": temp,
            "status": status,
        }
    )


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
        "wipe",
        "--target",
        req.target,
        "--yes",
        "--pattern",
        req.pattern,
        "--passes",
        str(req.passes),
        "--operator",
        req.operator_id,
        "--organization",
        req.organization,
        "--verify-samples",
        str(req.verify_samples),
        "--out-dir",
        str(out_dir),
        "--json",
    ]
    if key and key.exists():
        cmd += ["--key", str(key)]
    if req.no_pdf:
        cmd += ["--no-pdf"]
    if req.portal_url and req.portal_url.strip():
        cmd += ["--portal-url", req.portal_url.strip()]

    _record_job(
        job_id,
        {
            "status": "running",
            "log": [],
            "cmd": cmd[1:],
            "out_dir": str(out_dir),
            "demo_key_warning": is_demo,
        },
    )

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
                        log = _jobs[job_id]["log"]
                        if clean.startswith("[s0 wipe]") and log and log[-1].startswith("[s0 wipe]"):
                            log[-1] = clean
                        elif len(log) < _MAX_LOG_LINES:
                            log.append(clean)
                        elif log[-1] != "... log truncated":
                            log.append("... log truncated")

            pumper = threading.Thread(target=pump_stderr, daemon=True)
            pumper.start()
            try:
                out, _ = proc.communicate(timeout=_JOB_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                proc.kill()
                out, _ = proc.communicate()
                _LOG.error("job %s exceeded %ss; killed", job_id, _JOB_TIMEOUT_SECONDS)
                with _lock:
                    _jobs[job_id]["status"] = "error"
                    _jobs[job_id]["result"] = {
                        "returncode": -1,
                        "error": "timeout",
                        "error_id": uuid.uuid4().hex[:12],
                    }
                return
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
                    by_kind = {a.get("kind"): a.get("path") for a in artifacts if isinstance(a, dict)}
                    cert_p = (
                        by_kind.get("certificate") or body.get("certificate") or body.get("certificate_path")
                    )
                    pdf_p = by_kind.get("pdf_certificate") or body.get("pdf") or body.get("pdf_path")
                    qr_p = by_kind.get("qr_code")
                    if cert_p:
                        result["cert_filename"] = Path(cert_p).name
                        result["certificate_path"] = str(cert_p)
                        result["certificate"] = str(cert_p)  # legacy alias
                    if pdf_p:
                        result["pdf_filename"] = Path(pdf_p).name
                        result["pdf_path"] = str(pdf_p)
                        result["pdf"] = str(pdf_p)  # legacy alias
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
        except Exception:
            # The client gets a stable code plus a correlation id; the detail
            # (routinely absolute server paths from OSError and subprocess failures)
            # goes to the log, where it stays useful.
            error_id = uuid.uuid4().hex[:12]
            _LOG.exception("job %s failed", job_id)
            with _lock:
                _jobs[job_id].update(
                    status="error",
                    result={"returncode": -1, "error": "operation_failed", "error_id": error_id},
                )

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

    _record_job(
        job_id,
        {
            "status": "running",
            "log": [f"Sanitizing {len(req.targets)} file/folder targets..."],
            "out_dir": str(out_dir),
            "demo_key_warning": is_demo,
        },
    )

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
                speed_str = (
                    f"{speed / (1024 * 1024):.1f} MiB/s"
                    if speed >= 1024 * 1024
                    else f"{speed / 1024:.1f} KiB/s"
                )
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
                except Exception:
                    # The operator must know the ledger append failed -- it is the
                    # tamper-evident record -- but the exception text is not shown:
                    # it routinely carries absolute paths. Detail goes to the log.
                    _LOG.exception("audit ledger append failed for job %s", job_id)
                    audit_ledger_error = "audit_ledger_append_failed"
                    print(
                        "Warning: Failed to append to the audit ledger "
                        "(see the s0 web server log for detail)",
                        file=_sys.stderr,
                    )
                    with _lock:
                        _jobs[job_id]["log"].append("Warning: Failed to append to the audit ledger")
                cert_file = out_dir / f"file_wipe_certificate_{summary.certificate['cert_uuid'][:8]}.json"
                cert_file.write_text(json.dumps(summary.certificate, indent=2))
                cert_filename = cert_file.name

                if not req.no_pdf:
                    try:
                        qr_url_tpl = CONFIG.get(
                            "qr_url_template", "https://sector-zero.pages.dev/verify/?cert={cert_uuid}"
                        )
                        if req.portal_url and req.portal_url.strip():
                            p_url = req.portal_url.strip()
                            qr_url_tpl = (
                                f"{p_url.rstrip('/')}/?cert={{cert_uuid}}"
                                if "{cert_uuid}" not in p_url
                                else p_url
                            )
                        pdf_file = (
                            out_dir / f"file_wipe_certificate_{summary.certificate['cert_uuid'][:8]}.pdf"
                        )
                        qr_file = (
                            out_dir / f"file_wipe_certificate_{summary.certificate['cert_uuid'][:8]}.qr.png"
                        )
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
        except Exception:
            # The client gets a stable code plus a correlation id; the detail
            # (routinely absolute server paths from OSError and subprocess failures)
            # goes to the log, where it stays useful.
            error_id = uuid.uuid4().hex[:12]
            _LOG.exception("job %s failed", job_id)
            with _lock:
                _jobs[job_id].update(
                    status="error",
                    result={"returncode": -1, "error": "operation_failed", "error_id": error_id},
                )

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

    _record_job(
        job_id,
        {
            "status": "running",
            "log": [f"Scanning {req.target} for carved artifacts..."],
            "out_dir": str(out_dir),
            "demo_key_warning": is_demo,
        },
    )

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
                speed_str = (
                    f"{speed / (1024 * 1024):.1f} MiB/s"
                    if speed >= 1024 * 1024
                    else f"{speed / 1024:.1f} KiB/s"
                )
                pct = (scanned * 100 // total) if total > 0 else 0
                rem_bytes = max(0, total - scanned)
                eta_sec = int(rem_bytes / speed) if speed > 0 else 0
                eta_str = f"{eta_sec // 60:02d}:{eta_sec % 60:02d}"

                if now - last_carve_temp_time >= 2.0:
                    last_carve_temp_time = now
                    last_carve_temp_val[0] = read_temperature(req.target)
                temp_str = (
                    f" | Temp: {last_carve_temp_val[0]}°C" if last_carve_temp_val[0] is not None else ""
                )

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
                            _jobs[job_id]["log"].append(
                                f"Warning: skipped invalid custom signature: {sig_err}"
                            )

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
                    record_audit_event(
                        summary.manifest_certificate, operation_type="FILE_CARVE", private_key=key
                    )
                    audit_ledger_recorded = True
                except Exception:
                    # The operator must know the ledger append failed -- it is the
                    # tamper-evident record -- but the exception text is not shown:
                    # it routinely carries absolute paths. Detail goes to the log.
                    _LOG.exception("audit ledger append failed for job %s", job_id)
                    audit_ledger_error = "audit_ledger_append_failed"
                    print(
                        "Warning: Failed to append to the audit ledger "
                        "(see the s0 web server log for detail)",
                        file=_sys.stderr,
                    )
                    with _lock:
                        _jobs[job_id]["log"].append("Warning: Failed to append to the audit ledger")
                m_file = out_dir / f"carving_manifest_{summary.manifest_certificate['cert_uuid'][:8]}.json"
                m_file.write_text(json.dumps(summary.manifest_certificate, indent=2))
                manifest_filename = m_file.name

                if not req.no_pdf:
                    try:
                        pdf_path = (
                            out_dir / f"carving_manifest_{summary.manifest_certificate['cert_uuid'][:8]}.pdf"
                        )
                        pdfgen.generate_pdf(summary.manifest_certificate, pdf_path)
                        pdfgen.write_qr_file(
                            summary.manifest_certificate,
                            out_dir
                            / f"carving_manifest_{summary.manifest_certificate['cert_uuid'][:8]}.qr.png",
                        )
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
        except Exception:
            # The client gets a stable code plus a correlation id; the detail
            # (routinely absolute server paths from OSError and subprocess failures)
            # goes to the log, where it stays useful.
            error_id = uuid.uuid4().hex[:12]
            _LOG.exception("job %s failed", job_id)
            with _lock:
                _jobs[job_id].update(
                    status="error",
                    result={"returncode": -1, "error": "operation_failed", "error_id": error_id},
                )

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
    # Refuse an existing destination here, with an actionable message, rather than
    # letting the imager fail and surface as `operation_failed` with a correlation
    # id. The operator can act on "destination exists, pass force to overwrite";
    # they cannot act on a correlation id they have no way to look up.
    if dst_p.exists() and not req.force:
        raise HTTPException(
            409, f"destination already exists: {req.destination}. Set force=true to overwrite it."
        )

    is_blk = False
    try:
        is_blk = platform.is_block_device(dst_p)
    except Exception:
        pass
    if _sys.platform == "win32" and platform.is_windows_volume_path(req.destination):
        is_blk = True

    if (is_blk or req.is_clone) and req.confirm_text.strip() != req.destination.strip():
        raise HTTPException(
            400, f"Cloning to target block device requires typing exact destination: '{req.destination}'"
        )

    job_id = uuid.uuid4().hex[:12]
    if req.out_dir and req.out_dir.strip():
        out_dir = Path(req.out_dir.strip()).resolve()
    else:
        out_dir = REPO / "demo-out" / f"web-image-{job_id}"
    out_dir.mkdir(parents=True, exist_ok=True)

    key, is_demo = _resolve_key(req.key_path, req.key_data, out_dir)

    _record_job(
        job_id,
        {
            "status": "running",
            "log": [f"Acquiring forensic bit-stream from {req.source} to {req.destination}..."],
            "out_dir": str(out_dir),
            "demo_key_warning": is_demo,
        },
    )

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
                force=req.force,
            )
            img_result = acquire_image(options, progress_callback=_progress)

            manifest_fn = Path(img_result.manifest_path).name if img_result.manifest_path else None
            cert_fn = None
            pdf_fn = None
            if img_result.manifest_certificate and "cert_uuid" in img_result.manifest_certificate:
                cert_fn = f"certificate_{img_result.manifest_certificate['cert_uuid']}.json"
                if not req.no_pdf:
                    try:
                        pdf_path = (
                            out_dir / f"certificate_{img_result.manifest_certificate['cert_uuid'][:8]}.pdf"
                        )
                        pdfgen.generate_pdf(img_result.manifest_certificate, pdf_path)
                        pdfgen.write_qr_file(
                            img_result.manifest_certificate,
                            out_dir
                            / f"certificate_{img_result.manifest_certificate['cert_uuid'][:8]}.qr.png",
                        )
                        pdf_fn = pdf_path.name
                    except Exception:
                        pass

            if not img_result.audit_ledger_recorded and img_result.audit_ledger_error:
                with _lock:
                    _jobs[job_id]["log"].append(
                        f"Warning: Failed to append to audit ledger: {img_result.audit_ledger_error}"
                    )

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
        except Exception:
            # The client gets a stable code plus a correlation id; the detail
            # (routinely absolute server paths from OSError and subprocess failures)
            # goes to the log, where it stays useful.
            error_id = uuid.uuid4().hex[:12]
            _LOG.exception("job %s failed", job_id)
            with _lock:
                _jobs[job_id].update(
                    status="error",
                    result={"returncode": -1, "error": "operation_failed", "error_id": error_id},
                )

    threading.Thread(target=run, daemon=True).start()
    return JSONResponse({"job_id": job_id})


@app.get("/api/audit/blocks", dependencies=[Depends(verify_auth_token)])
def get_audit_blocks(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)) -> JSONResponse:
    blocks = list_audit_blocks(limit=limit, offset=offset)
    return JSONResponse(
        {
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
            ],
        }
    )


@app.get("/api/audit/verify", dependencies=[Depends(verify_auth_token)])
def get_audit_verify() -> JSONResponse:
    report = verify_audit_ledger(trusted_public_keys=get_default_trusted_keys())
    return JSONResponse(
        {
            "is_valid": report.is_valid,
            "total_blocks": report.total_blocks_verified,
            "reason": report.reason,
            "is_demo_signed": report.is_demo_signed,
            "demo_key_warning": report.demo_key_warning,
        }
    )


@app.get("/api/job/{job_id}", dependencies=[Depends(verify_auth_token)])
def job_status(job_id: str) -> JSONResponse:
    with _lock:
        job = _jobs.get(job_id)
        if not job:
            raise HTTPException(404, "unknown job")
        return JSONResponse(
            {
                "status": job.get("status", "unknown"),
                "log": job.get("log", []),
                "result": job.get("result", None),
                "cmd": job.get("cmd", None),
                "demo_key_warning": job.get("demo_key_warning", False),
            }
        )


@app.get("/api/download/{job_id}/{filename}", dependencies=[Depends(verify_auth_token)])
def download(job_id: str, filename: str) -> FileResponse:
    with _lock:
        job = _jobs.get(job_id)
    if not job:
        raise HTTPException(404, "unknown job")
    # A NUL byte makes Path.resolve() raise ValueError, which nothing above caught,
    # so `?filename=%00` returned an unhandled 500 from the deepest layer of the
    # request. Reject it as the bad input it is, before touching the filesystem.
    if "\x00" in filename or any(ord(c) < 32 for c in filename):
        raise HTTPException(400, "invalid artifact name")
    out_dir_path = Path(job["out_dir"]).resolve()
    path = (out_dir_path / filename).resolve()
    try:
        path.relative_to(out_dir_path)
    except ValueError:
        raise HTTPException(404, "no such artifact") from None
    if not path.is_file():
        raise HTTPException(404, "no such artifact")
    return FileResponse(path, filename=path.name)
