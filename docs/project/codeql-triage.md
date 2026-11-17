# CodeQL Alert Triage — 2026-11-17

The security tab carried 29 open CodeQL code-scanning alerts on `master`
(27 `py/path-injection`, 1 `py/url-redirection`, 1 `py/overly-permissive-file`).
Each alert was independently verified against the code at HEAD by a read-only
audit before disposition. The result: **one real (trivial) finding fixed in
code, one latent hardening gap fixed in code, and 28 alerts dismissed as
validated/by-design flows**, each with an auditable justification recorded in
the alert itself and summarized here.

## Fixed in code (not dismissed)

| Alert | Rule | Finding | Fix |
|---|---|---|---|
| #98 | `py/overly-permissive-file` | `tests/core/test_crypto.py` built its "loose mode" fixture with `os.chmod(p, 0o640)` — a group-readable private-key-looking file. | `86f4627` — the fixture now relies on default-umask creation; the property under test (final mode 0600) is unchanged. |

| Latent gap | Finding | Fix |
|---|---|---|
| Browse allowlist vacuous | `ALLOWED_BROWSE_ROOTS` contained `Path("/")` on POSIX (and the drive anchors on Windows), so its `commonpath` allowlist matched **every** path. The only real guards were the `..` rejection and the `SYSTEM_PREFIXES` denylist — an authenticated user could list e.g. another user's home directory, and the flow's containment claim (cited in three alerts: #89, #72, #73) did not hold. | `a4580cb` — the catch-all entries are removed; browse is now pinned to `REPO`, `home`, `/media`, `/mnt`, and temp directories, mirroring `ALLOWED_TARGET_ROOTS`/`ALLOWED_OUT_DIR_ROOTS`. Pinning tests in `73064b6`. |

## Dismissed as validated / by-design (28)

Reason recorded on every alert: `false positive`. Authentication on every
flagged endpoint was verified (`Depends(verify_auth_token)`); the only
unauthenticated routes are `/healthz` (returns nothing about the host) and the
same-origin `/portal` redirect.

| Group | Alerts | Flow | Guard chain verified at HEAD |
|---|---|---|---|
| out-dir | 85, 54 | `_prepare_job_out_dir` | strip/NUL → normpath + `..` reject → realpath → `SYSTEM_PREFIXES` → `ALLOWED_OUT_DIR_ROOTS` allowlist → relpath rebuild |
| key | 86, 79 | `_resolve_key` | same chain against `ALLOWED_KEY_ROOTS`; key is re-loaded and validated before use |
| wipe/target | 87, 88 | dashboard target picker | chain vs `ALLOWED_TARGET_ROOTS`, plus `_is_safe_wipe_path` (the CLI's `check_path_is_destructive` rules) |
| browse | 89, 72, 73 | `/api/browse` | chain vs `ALLOWED_BROWSE_ROOTS` — accurate only after `a4580cb` (above) |
| erase-files | 90, 91 | `POST /api/erase-files` | chain vs `ALLOWED_TARGET_ROOTS`; directory targets require exact `confirm_text` |
| carve | 92, 15 | `POST /api/carve` | chain vs `ALLOWED_TARGET_ROOTS`; block devices bypass the file allowlist by design and are matched against the enumerated block target list |
| image/clone | 93, 74, 94, 56 | `POST /api/image`, `/api/clone` | chain vs `ALLOWED_TARGET_ROOTS` for src and dst; `_reject_system_path` field validators; exact `confirm_text` for block/clone destinations |
| download | 95, 96, 97 | `/api/download/{job_id}/{filename}` | basename equality → directory from server-side job record (validated at creation) → final `commonpath` containment recheck before `FileResponse` |
| redirect | 99 | `/portal/{path}` | `Location` is the literal prefix `/verify/` + route segment; can never be protocol-relative or scheme-absolute |
| CLI image_target | 81, 82, 83, 33 | `image_target()` | operator argv is s0's product surface; NUL/`..`/root rejection before any access; web call site pre-validates |
| crypto loaders | 62, 64 | `load_private_pem` / `load_public_pem` | operator-supplied key paths; NUL/`..`/root rejection; no meaningful fixed allowlist exists for an offline signing authority |
| demo key | 75 | `is_demo_key` | same guard chain before `exists()`; demo determination compares the key fingerprint, not the name |

`CodeQL does not model os.path.commonpath as a sanitizer`, which is why these
flows report despite the containment checks. Dismissals are per-alert and
auditable in the security tab; nothing is suppressed wholesale, so any future
alert on a genuinely unguarded flow still surfaces.

## Re-open criteria

Any of these dispositions should be revisited if: the guard chain is refactored
away, a flagged endpoint loses authentication, or the dashboard is ever exposed
beyond loopback with a different trust model.
