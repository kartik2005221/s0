# Driving the s0 Web Dashboard over HTTP

Extracted from `SKILL.md`. Read this when the task actually involves the dashboard;
skip it for CLI-only work.

Two rules govern everything here:

1. **Never launch the dashboard with `sudo` yourself.**
2. **Authenticate with the `X-S0-Auth-Token` header, not the cookie.**

**Root is the operator's decision, never yours.** The documented command for a human
is `sudo s0 web`, because raw device access needs it and the dashboard disables drive
wiping without it. Do not run it that way yourself. Root on a loopback dashboard is
root over the machine and over the evidence stored on it, and the session token is
written under root's `~/.s0` — so any caller holding that token holds root. If the
operator wants privileged drive access, ask them to start the dashboard and give you
the token; then drive it over HTTP. If the operator has not started it, work through
the CLI, which needs no escalation for file and folder work.


`s0 web` serves the same operations as a loopback JSON API. An agent may use it, but
the dashboard is the most destructive surface s0 has: it can erase files on the host
without a prompt once authenticated.

**Authentication.** One token per run, written to `~/.s0/web_auth_token` (mode 0600).

```bash
s0 web --no-browser &            # or open the printed URL in a browser
TOKEN=$(cat ~/.s0/web_auth_token)
```

The token is accepted two ways, and only two:

* `X-S0-Auth-Token: $TOKEN` — **use this for anything scripted.**
* `?token=...` — bootstrap only, accepted on `/` alone. It exists because the kiosk
  cannot set a header. It is then moved into an HttpOnly cookie and the URL
  redirected, because a token in a URL leaks into history, `Referer` and proxy logs.

Passing `?token=` to an `/api/*` route returns 401. Do not work around this.

**Routes.** Read-only `GET`: `/healthz` (the only unauthenticated one),
`/api/devices`, `/api/config`, `/api/capabilities`, `/api/browse`,
`/api/temperature`, `/api/audit/blocks`, `/api/audit/verify`,
`/api/job/{job_id}`, `/api/download/{job_id}/{filename}`.

State-changing, all `POST`: `/api/plan` (read-only despite the verb), `/api/wipe`,
`/api/erase-files`, `/api/image`, `/api/carve`.

There is **no `/api/list` and no `/api/clone`**. Both were listed here and both
return 404. Device enumeration is `/api/devices`, and cloning goes through
`/api/image` with `mode: "clone"`.

`/api/wipe`, `/api/erase-files`, `/api/carve` and `/api/image` return a job id
immediately; **poll `GET /api/job/{job_id}`** for the result and then fetch
artifacts from `/api/download/{job_id}/{filename}`. `/api/plan` returns its plan
inline and does not create a job.

**Rules when driving it:**

* `/api/wipe` requires the **exact destination path** in `confirm_text`. It is not a
  boolean and not an acknowledgement.
* `/api/erase-files` runs **in-process**, not through the CLI. It applies the same
  shared path guard, so `/etc` and s0's own state directory are refused — but the
  guard is the only thing standing between a request and the filesystem. Confirm the
  target list with the operator before sending it.
* State-changing requests authenticated by **cookie** are rejected (403) when they
  carry a foreign `Origin` or a `Sec-Fetch-Site` other than `same-origin`/`none`.
  Authenticated by the **`X-S0-Auth-Token` header** they are *not* — that check
  runs only on the cookie path. This is deliberate: a header token is not attached
  ambiently by a browser, so it carries no cross-site request forgery risk. You are
  told to authenticate with the header, so do not rely on this rule to stop you.
* `/api/download` refuses any filename that resolves outside the job's output
  directory. Do not attempt traversal; it is refused, and trying is the wrong signal
  to send.
