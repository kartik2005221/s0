# Web Dashboard HTTP API

<p style="font-size: 1.1rem; color: #00adb5; font-weight: 600; margin-top: -0.4rem;">
  Reference for the local FastAPI server behind <code>s0 web</code>.
</p>

`s0 web` starts a FastAPI application bound to loopback that the browser dashboard
drives. That server is not a private implementation detail — it listens on a TCP
port, any process on the host can reach it, and it can issue irreversible
sanitization commands. This page documents every route, what it requires, and
what it returns, so the API can be scripted deliberately rather than reverse
engineered out of the dashboard's JavaScript.

Every route below was read out of `src/s0/web/app.py`. Where the implementation and
the dashboard disagree, that is called out rather than smoothed over.

Start the server with:

```bash
sudo s0 web
```

---

## 1. Authentication

### The `X-S0-Auth-Token` header

At startup the server generates a per-session token: 32 random bytes, hex encoded,
taken from the `S0_WEB_AUTH_TOKEN` environment variable if set, otherwise
`secrets.token_hex(32)`. **A fresh token is minted on every server start**, so a
token from a previous run is dead.

Send it as a request header:

```bash
curl -H "X-S0-Auth-Token: $TOKEN" http://127.0.0.1:8669/api/capabilities
```

The token is written to `~/.s0/web_auth_token` with mode `0600` and printed on the
terminal that ran `s0 web`. When the server runs as root (the Live ISO kiosk case)
it is also written to `/run/s0/web_auth_token`, owned `root:s0-kiosk` at mode
`0640` when that group exists and `0600` otherwise, so the unprivileged kiosk user
can read it. Comparison is constant-time (`secrets.compare_digest`).

### `?token=` is a one-shot bootstrap, not a normal credential

Protected routes accept the token from three places, tried in this order:

| Order | Source | Use |
|-------|--------|-----|
| 1 | `X-S0-Auth-Token:` header | What the dashboard's JavaScript sends. The right choice for scripts. |
| 2 | `s0_session` cookie | What the browser attaches on its own for same-origin requests. |
| 3 | `?token=` query parameter | **Bootstrap only.** |

A token in a URL leaks: into browser history, into the `Referer` header of any
outbound request, and into proxy and web-server logs. So `GET /` treats `?token=`
as a one-shot bootstrap: it validates the value, sets it as an `HttpOnly` cookie,
and **redirects (303) to a clean `/`**. The redirect is what keeps the credential
out of history and `Referer`. After that, use the cookie or the header.

Use `?token=` only where a browser has to be launched and nothing else will do —
which is exactly the case `s0 web` and the ISO kiosk use.

```bash
# bootstrap: sets the cookie, then lands on a clean URL
curl -i "http://127.0.0.1:8669/?token=$TOKEN"
```

The cookie is `HttpOnly` (no script needs to read it — the browser attaches it on
its own) and `SameSite=Strict`, which is what stops cookie auth from reintroducing
CSRF: a cross-site request never carries it. `Secure` is deliberately **not** set,
because the dashboard is plain HTTP on loopback and a `Secure` cookie would be
dropped in the only real deployment.

### Failure modes

| Situation | Status | Body |
|-----------|--------|------|
| No token, or wrong token | `401` | `{"detail": "Unauthorized: missing or invalid session authentication token (X-S0-Auth-Token)"}` |
| Token with an encoding `compare_digest` rejects | `401` | `{"detail": "Unauthorized: invalid session authentication token encoding"}` |

### Hardening applied to every response

| Control | Value |
|---------|-------|
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Referrer-Policy` | `no-referrer` |
| `Content-Security-Policy` | `default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'` |
| `Host` header allowlist (`TrustedHostMiddleware`) | `localhost`, `127.0.0.1`, `[::1]`, `testserver` |
| HSTS | **absent by design** — the dashboard is plain HTTP on loopback, where browsers ignore it |

`script-src` still permits `'unsafe-inline'` because `index.html` carries inline
`onclick`/`onchange` handlers. The dangerous vectors are closed regardless: no
`object-src`, no `base-uri`, no framing, forms same-origin only. Migrating the
handlers off inline attributes is tracked in
[Technical Limitations](../compliance/limitations.md).

### The interactive OpenAPI schema is disabled

`docs_url`, `redoc_url`, and `openapi_url` are all `None`. Leaving the schema live
would hand an unauthenticated caller the full route and field list. This page is
the substitute.

---

## 2. Endpoint index

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| `GET` | `/` | yes | Dashboard shell; also the `?token=` bootstrap target |
| `GET` | `/healthz` | **no** | Readiness probe. The only unauthenticated data route. |
| `GET` | `/api/devices` | yes | Block devices and known image files |
| `GET` | `/api/config` | yes | Workspace configuration |
| `GET` | `/api/browse` | yes | Directory listing for the file picker |
| `GET` | `/api/capabilities` | yes | Privilege level and restricted operations |
| `GET` | `/api/temperature` | yes | Thermal sensor telemetry for a target |
| `POST` | `/api/plan` | yes | Dry-run plan, same payload as `s0 plan` |
| `POST` | `/api/wipe` | yes | Start a whole-media wipe (async job) |
| `POST` | `/api/erase-files` | yes | Start a file/folder wipe (async job) |
| `POST` | `/api/carve` | yes | Start a carving run (async job) |
| `POST` | `/api/image` | yes | Start an image or clone acquisition (async job) |
| `GET` | `/api/audit/blocks` | yes | Paginated audit ledger blocks |
| `GET` | `/api/audit/verify` | yes | Hash-chain verification result |
| `GET` | `/api/job/{job_id}` | yes | Poll a job's status, log, and result |
| `GET` | `/api/download/{job_id}/{filename}` | yes | Fetch an artifact a job produced |

Also mounted, both static and unauthenticated:

| Path | Contents |
|------|----------|
| `/static` | Dashboard assets (`src/s0/web/static/`) |
| `/portal` | The Verification Portal, if `site/verify/` exists |

---

## 3. The asynchronous job model

`/api/wipe`, `/api/erase-files`, `/api/carve`, and `/api/image` do not block. Each
one spawns the work in a background thread and returns immediately:

```json
{ "job_id": "3f9a2c1e4b7d" }
```

`job_id` is the first 12 hex characters of a UUID4. Poll `GET /api/job/{job_id}`
for progress, then collect artifacts with `GET /api/download/{job_id}/{filename}`.

Job records live for the process lifetime in a capped LRU:

| Limit | Value | Effect when exceeded |
|-------|-------|----------------------|
| Retained jobs | 200 | Oldest evicted; its `job_id` then returns `404` |
| Captured log lines per job | 500 | Truncated with a `... log truncated` marker |
| Wall-clock budget per job | 6 hours | Subprocess killed, job marked `error` with `{"error": "timeout"}` |

Poll until `status` is `done` or `error`. `status` is one of `running`, `done`,
`error`, or `unknown`.

{% hint style="warning" %}
**A job that vanishes was evicted, not cancelled**
`404 {"detail": "unknown job"}` after a long-running operation means the LRU rolled the record off, not that the subprocess stopped. Download artifacts before they age out, or keep them on disk.
{% endhint %}

---

## 4. Endpoints in detail

### `GET /` — dashboard shell

Unauthenticated only in the sense that it does not use the `verify_auth_token`
dependency; it does its own check so it can return an actionable 401 page instead
of a dashboard that 401s on every click.

| Request form | Behaviour |
|--------------|-----------|
| `/?token=<valid>` | Validates, sets the `s0_session` cookie, responds `303` redirect to `/` |
| `/?token=<invalid>` | `401` with the instructions page below |
| `X-S0-Auth-Token` header or valid cookie | `200`, the dashboard HTML, `Cache-Control: no-store` |
| Nothing valid | `401` with the instructions page below |

The `401` body is HTML explaining where the token comes from, not JSON. The token
is **never** embedded in the served HTML — this route used to inject it into a
`<meta>` tag, which handed a credential that unlocks every protected endpoint to
anything able to reach the loopback port (a top-level navigation from any page in
the operator's browser, another local account, a container sharing the network
namespace).

### `GET /healthz` — the only unauthenticated data route

No auth. Returns a literal:

```json
{ "status": "ok" }
```

Nothing else: no paths, no device list, no version detail. That is deliberate.
Readiness checks are conventionally unauthenticated, and the ISO kiosk's
`s0-wait-web` used to poll `/api/devices` without a token, get a `401`, and so
always waited the full 30 s and then failed. A probe that exposes nothing does not
need a token.

### `GET /api/devices`

No request fields. Returns selectable wipe targets in two groups:

```json
{
  "block": [
    {
      "path": "/dev/sdb",
      "storage_type": "SSD",
      "capacity_bytes": 512105932800,
      "model": "Samsung SSD 980 PRO 512GB",
      "serial": "S5GXNX0T123456",
      "mounted_hint": null
    }
  ],
  "images": [
    { "path": "/evidence/case_42/seized.raw", "capacity_bytes": 8589934592 }
  ]
}
```

`block` comes from the same discovery routine the CLI's `s0 list` uses. `images`
is a glob of `*.img` and `*.raw` (plus one subdirectory level) across the
configured image directories, de-duplicated by resolved path.

### `GET /api/config`

No request fields. Returns the parsed `s0_config.json` verbatim — `version`,
`tool_name`, `default_operator`, `default_organization`, `default_key_path`,
`default_public_key_path`, `default_out_dir`, `qr_url_template`, `api_port`, and
the portal/documentation URLs.

The dashboard calls this on load to prefill every form, so editing
`s0_config.json` changes the UI's defaults without a code change.

### `GET /api/browse`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `path` | query string | `.` | Directory to list |

```json
{
  "current": "/evidence/case_42",
  "parent": "/evidence",
  "items": [
    { "name": "recovered", "path": "/evidence/case_42/recovered", "is_dir": true, "size": 0 },
    { "name": "seized.raw", "path": "/evidence/case_42/seized.raw", "is_dir": false, "size": 8589934592 }
  ]
}
```

Directories sort first, then case-insensitive by name. `parent` is `null` at a root.

{% hint style="info" %}
**Browsing is confined to four roots**
`path` is resolved and must sit under the repository root, the user's home, `/media`, or `/mnt`. Anything else — nonexistent, not a directory, or outside those roots — is **silently substituted with the repository root** rather than rejected, so a crafted path cannot probe the filesystem. An unreadable directory that already passed the root check returns `{"error": "directory not readable", "current": ..., "items": []}`; the OS error text is withheld because it names server-side paths.
{% endhint %}

### `GET /api/capabilities`

No request fields. Reports privilege level so the UI can disable what it cannot do:

```json
{
  "is_root": false,
  "platform": "linux",
  "restricted_operations": ["block_wipe", "disk_image_acquisition"],
  "message": "Running without root privileges. Direct drive wiping and physical disk acquisition are disabled. For full functionality, launch with: sudo s0 web"
}
```

`is_root` uses `geteuid() == 0` on POSIX and `IsUserAnAdmin()` on Windows.
`restricted_operations` is empty when privileged.

### `GET /api/temperature`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `path` | query string | **yes** | Target device or file path |

```json
{ "path": "/dev/sdb", "temperature_c": 41.5, "status": "normal" }
```

`temperature_c` is `null` when no sensor can be read. `status` is derived:
`normal` below 55 °C, `warm` from 55 to under 70, `critical` at 70 and above, and
`unavailable` when the reading is `null`.

### `POST /api/plan`

Request body — one field:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `target` | string | **yes** | Block device or image file path |

Response body is the same structure the CLI's `s0 plan` prints:

| Field | Type | Description |
|-------|------|-------------|
| `target` | object | `path`, `kind` (`block`/`image`), `storage_type`, `capacity_bytes` |
| `method_id` | string \| null | Selected method identifier, or `null` if none applies |
| `nist_category` | string \| null | `Clear` or `Purge` |
| `summary` | string \| null | One-line description of the chosen method |
| `warnings` | array of string | Safety and method caveats |
| `alternatives` | array of object | `reason` and `available` per method considered |
| `hpa_dco` | object \| null | HPA/DCO report for non-NVMe block devices |
| `refusal` | string \| null | Set when a safety check refused the target; **not** an HTTP error |

This route is read-only. It writes nothing and appends no audit block.

### `POST /api/wipe`

Starts `s0 wipe` as a subprocess with `--yes` and `--json`.

| Field | Type | Default | Required | Description |
|-------|------|---------|----------|-------------|
| `target` | string | — | **yes** | Block device or image file |
| `confirm_text` | string | — | **yes** | Must equal `target` exactly, trimmed |
| `pattern` | `zero` \| `random` | `zero` | no | Overwrite pattern |
| `passes` | integer `1..100` | `1` | no | Overwrite passes |
| `operator_id` | string | `s0_config.json` | no | Operator identity. **Also accepted as `operator`** — see the note below |
| `organization` | string | `s0_config.json` | no | Organization name |
| `key_path` | string \| null | `null` | no | Issuer private key PEM on disk |
| `key_data` | string \| null | `null` | no | PEM pasted inline. Max 16 384 chars, because it is written to disk verbatim |
| `out_dir` | string \| null | `<repo>/demo-out/web-wipe-<job_id>` | no | Where artifacts are written |
| `no_pdf` | boolean | `false` | no | Skip the PDF certificate |
| `verify_samples` | integer `1..10000` | `64` | no | Blocks sampled for readback verification |
| `portal_url` | string \| null | `null` | no | Verification portal base URL for the QR code |

| Status | Condition |
|--------|-----------|
| `200` | Job accepted — `{"job_id": "..."}` |
| `400` | `confirm_text` does not match `target` |
| `409` | The target was refused by a safety check (`plan.refusal`) |
| `422` | No applicable wipe method for the medium |
| `422` | Field failed validation (bad `pattern`, `target` inside a protected path, `out_dir`/`key_path` under a system path) |

Validation reuses the CLI's own rules, so the web tier and `s0 wipe` refuse the
same paths. `out_dir` and `key_path` are additionally refused under `/etc`,
`/usr`, `/bin`, `/sbin`, `/lib`, `/lib64`, `/boot`, `/proc`, `/sys`, `/run`,
`/var`, `/root`, `/opt`. `operator_id` is capped at 64 characters and
`organization` at 128.

The job's `result` object carries the parsed `--json` envelope plus resolved
artifact paths: `cert_filename`, `certificate_path`, `certificate` (legacy alias),
`pdf_filename`, `pdf_path`, `pdf` (legacy alias), `qr_filename`, `returncode`, and
on failure `error` with `stdout_tail`.

### `POST /api/erase-files`

Sanitizes files and folders. Field set matches `/api/wipe` except:

| Field | Type | Default | Required | Description |
|-------|------|---------|----------|-------------|
| `targets` | array of string | — | **yes** | Files or directories. Must be non-empty |

…and except `target` and `confirm_text`, which do not exist here.

`result`: `total_files`, `successful_files`, `failed_files`, `total_bytes`,
`cert_filename`, `pdf_filename`, `warnings`, `audit_ledger_recorded`,
`audit_ledger_error`, `returncode`. Job status is `error` when
`failed_files > 0`.

### `POST /api/carve`

| Field | Type | Default | Required | Description |
|-------|------|---------|----------|-------------|
| `target` | string | — | **yes** | Raw image or block device |
| `extensions` | array of string \| null | `null` (all) | no | Restrict carving to these extensions |
| `min_confidence` | integer | `50` | no | Minimum confidence score, 0–100 |
| `operator_id` | string | `s0_config.json` | no | Operator identity |
| `organization` | string | `s0_config.json` | no | Organization name |
| `out_dir` | string \| null | `<repo>/demo-out/web-carve-<job_id>` | no | Output directory |
| `key_path` | string \| null | `null` | no | Signing key PEM |
| `key_data` | string \| null | `null` | no | Inline PEM, max 16 384 chars |
| `no_pdf` | boolean | `false` | no | Skip the PDF certificate |
| `custom_signatures` | array of object \| null | `null` | no | Signature definitions: `name`, `extension`, `category`, `header_hex`, `footer_hex`, `min_size`, `max_size` |

`404` when `target` does not exist. An invalid entry in `custom_signatures` is not
fatal: it is logged as a warning and skipped, and the run continues.

`result`: `bytes_scanned`, `candidates_found`, `files_recovered`,
`manifest_filename`, `pdf_filename`, `audit_ledger_recorded`,
`audit_ledger_error`, `returncode`, and `carved_files` — an array whose entries
carry `id`, `filename`, `ext`, `category`, `size`, `conf`, `sha256`,
`heuristics`, and `recovery_method`.

Note the body field is `custom_signatures`, whereas the CLI flag is `--custom-sig`.

### `POST /api/image`

Handles both imaging and cloning; `is_clone` selects which.

| Field | Type | Default | Required | Description |
|-------|------|---------|----------|-------------|
| `source` | string | — | **yes** | Source block device or raw image |
| `destination` | string | — | **yes** | Destination image file or block device |
| `block_size` | integer | `1048576` | no | Buffer size in bytes |
| `no_recovery` | boolean | `false` | no | Abort on I/O error instead of zero-filling bad sectors |
| `is_clone` | boolean | `false` | no | `true` clones to a physical disk, `false` images to a file |
| `confirm_text` | string | `""` | no | Required to equal `destination` when cloning to a block device |
| `operator_id` | string | `s0_config.json` | no | Operator identity |
| `organization` | string | `s0_config.json` | no | Organization name |
| `out_dir` | string \| null | `<repo>/demo-out/web-image-<job_id>` | no | Where the manifest and certificate go |
| `key_path` | string \| null | `null` | no | Signing key PEM |
| `key_data` | string \| null | `null` | no | Inline PEM, max 16 384 chars |
| `no_pdf` | boolean | `false` | no | Skip the PDF certificate |

| Status | Condition |
|--------|-----------|
| `400` | `source` empty, `destination` empty, `source == destination`, or a clone whose `confirm_text` does not equal `destination` |
| `404` | `source` does not exist |

`result`: `success`, `source`, `destination`, `is_clone`, `bytes_copied`,
`duration_seconds`, `speed_mbps`, `bad_sectors_count`, `bad_bytes_count`,
`source_sha256`, `source_md5`, `manifest_filename`, `cert_filename`,
`pdf_filename`, `audit_ledger_recorded`, `audit_ledger_error`, `error`,
`returncode`. Job status is `error` when `success` is `false`.

### `GET /api/audit/blocks`

| Field | Type | Default | Range | Description |
|-------|------|---------|-------|-------------|
| `limit` | integer | `100` | `1..500` | Maximum blocks returned |
| `offset` | integer | `0` | `>= 0` | Blocks to skip |

```json
{
  "total": 42,
  "blocks": [
    {
      "index": 42,
      "timestamp": "2026-09-09T14:22:15Z",
      "operation": "DRIVE_ERASE",
      "target": "/dev/sdb",
      "operator": "analyst-07",
      "organization": "Forensic Lab",
      "cert_uuid": "a8f3b201-...",
      "prev_hash": "88c019a2...",
      "block_hash": "4b227777...",
      "payload_hash": "1d9a0c33...",
      "signature": "9a2f4c1e...",
      "certificate_json": "{...}"
    }
  ]
}
```

`total` is the number of blocks **in this response**, not the size of the ledger.
There is no total-count route; use `offset` paging to walk further.

### `GET /api/audit/verify`

No request fields. Runs the same verification the CLI's `s0 audit verify` runs,
with the default trusted key set.

```json
{
  "is_valid": true,
  "total_blocks": 42,
  "reason": null,
  "is_demo_signed": true,
  "demo_key_warning": "Ledger is signed with the unaccredited demo issuer key"
}
```

This route has no `status_label` field, unlike `s0 audit verify`, which prints
`CHAIN INTEGRITY FAILURE` on the terminal. The two interfaces report the same
condition through different shapes: match on `is_valid` here, not on a string.

### `GET /api/job/{job_id}`

```json
{
  "status": "running",
  "log": ["[s0 wipe] 12.5% ...", "[s0 wipe] 37.0% ..."],
  "result": null,
  "cmd": ["wipe", "--target", "/dev/sdb", "--yes", "..."],
  "demo_key_warning": true
}
```

`cmd` is the argv the server ran, minus argv[0] — which is the fastest way to see
exactly what a dashboard click mapped to on the CLI. `demo_key_warning` is `true`
when the signing key fell back to the bundled demo issuer, meaning the resulting
certificate is not attributable to an accredited authority.

`404 {"detail": "unknown job"}` for an unknown or evicted `job_id`.

On failure, `result.error` is a stable code (`timeout`, `operation_failed`,
`wipe completed with a failure status`) and `result.error_id` correlates it with
the server-side log entry. The human-readable detail stays server-side on
purpose, because it routinely contains absolute paths.

### `GET /api/download/{job_id}/{filename}`

Returns the artifact as a file download with `Content-Disposition`.

| Status | Condition |
|--------|-----------|
| `404` | Unknown or evicted `job_id` |
| `404` | `filename` escapes the job's `out_dir` |
| `404` | File does not exist |

`filename` is joined to the job's recorded output directory and the resolved path
is checked to still be inside it, so `..` traversal out of `out_dir` is refused.

---

## 5. Known inconsistencies

### `operator` vs `operator_id`

**`/api/wipe` accepts `operator`; every other operation expects `operator_id`.**

| Route | Accepted field | Behaviour if you send the other one |
|-------|----------------|-------------------------------------|
| `POST /api/wipe` | `operator_id`, **and** `operator` as an alias | — |
| `POST /api/erase-files` | `operator_id` | `operator` is **silently ignored**; the config default is used |
| `POST /api/carve` | `operator_id` | `operator` is **silently ignored**; the config default is used |
| `POST /api/image` | `operator_id` | `operator` is **silently ignored**; the config default is used |

The reason is that `WipeRequest.operator_id` carries `alias="operator"` and sets
`populate_by_name=True`, so pydantic accepts both spellings. The other three
models declare `operator_id` with no alias, and the models' default `extra`
behaviour is `ignore` — an unrecognised key is dropped without complaint. Sending
`operator` to `/api/erase-files` does not error; it just records the certificate
against `op-forensic`, or whatever `default_operator` says. On a case where the
operator attribution is the point, that is a silent evidence-integrity defect.

The dashboard's own JavaScript mirrors the inconsistency: `dashboard.js` sends
`operator` in the `/api/wipe` body and `operator_id` in the other three.

**Send `operator_id` to every route.** It works on all four, including `/api/wipe`.

### Other rough edges

| Observation | Consequence |
|-------------|-------------|
| `/api/wipe` is the only route whose operator field has two spellings | Any client written against one interface can misattribute the other three |
| `/api/audit/verify` returns `is_valid`, while the CLI prints `CHAIN INTEGRITY FAILURE` | The same condition, two different shapes; do not string-match across interfaces |
| `/api/audit/blocks.total` counts the page, not the ledger | There is no ledger-size figure to page against |
| `GET /api/browse` substitutes the repository root for a disallowed path instead of erroring | Deliberate anti-probing, but it means a typo silently lists the wrong directory |
| Job records are in-process only | A server restart loses every `job_id`; nothing is persisted |

---

## 6. Scripting the API

```bash
# 1. Start the server in its own terminal, then capture the token
sudo s0 web --no-browser
TOKEN=$(cat ~/.s0/web_auth_token)

# 2. Check readiness (no token needed)
curl -s http://127.0.0.1:8669/healthz

# 3. See whether raw block devices are usable
curl -s -H "X-S0-Auth-Token: $TOKEN" http://127.0.0.1:8669/api/capabilities

# 4. List candidate targets
curl -s -H "X-S0-Auth-Token: $TOKEN" http://127.0.0.1:8669/api/devices

# 5. Dry-run the plan for one of them
curl -s -X POST -H "X-S0-Auth-Token: $TOKEN" -H 'Content-Type: application/json' \
  -d '{"target": "/dev/sdb"}' \
  http://127.0.0.1:8669/api/plan

# 6. Wipe it (note operator_id, not operator)
JOB=$(curl -s -X POST -H "X-S0-Auth-Token: $TOKEN" -H 'Content-Type: application/json' \
  -d '{"target":"/dev/sdb","confirm_text":"/dev/sdb","operator_id":"analyst-07","passes":1}' \
  http://127.0.0.1:8669/api/wipe | python3 -c 'import json,sys; print(json.load(sys.stdin)["job_id"])')

# 7. Poll, then download the certificate
curl -s -H "X-S0-Auth-Token: $TOKEN" "http://127.0.0.1:8669/api/job/$JOB"
curl -s -H "X-S0-Auth-Token: $TOKEN" -OJ \
  "http://127.0.0.1:8669/api/download/$JOB/certificate_$(date +%F).json"
```

{% hint style="danger" %}
**`/api/wipe` requires no interactive confirmation from the client**
The server passes `--yes` to the CLI subprocess on your behalf, and the only guard is that `confirm_text` must equal `target` exactly. Treat possession of a valid token as equivalent to physical access to the machine, and do not bind `s0 web` to anything but loopback.
{% endhint %}

---

*Web API Reference · s0 (Sector Zero) · routes enumerated from `src/s0/web/app.py`*