# Third-Party Notices

s0 vendors a small number of third-party components so that the verification
portal and the live ISO keep working **air-gapped**, with no third-party request
at runtime. Vendoring is the reason the verification portal needs no network,
no CDN and no telemetry.

Every component below is redistributed under its own licence. Nothing here is
covered by s0's MIT licence.

---

## pdf.js

| Field | Value |
|---|---|
| Files | `site/verify/vendor/pdf.min.js`, `site/verify/vendor/pdf.worker.min.js` |
| Version | 3.11.174 |
| Upstream | https://github.com/mozilla/pdf.js |
| Licence | **Apache License 2.0** |
| Licence text | https://github.com/mozilla/pdf.js/blob/develop/LICENSE-2.0.txt |
| Modified | No. Redistributed as the upstream release build. |

The Apache-2.0 licence requires (§4a) that a copy of the licence accompany
redistribution and (§4c) that attribution notices be retained. Both are
satisfied by this file and by the licence text at the URL above. If upstream
ships a `NOTICE` file, its contents must be reproduced here verbatim.

## jsQR

| Field | Value |
|---|---|
| Files | `site/verify/vendor/jsqr.min.js` |
| Version | 1.4.0 |
| Upstream | https://github.com/cozmo/jsQR |
| Licence | **Apache License 2.0** |
| Licence text | https://raw.githubusercontent.com/cozmo/jsQR/master/LICENSE |
| Modified | No. |

**Known upstream defect.** This build throws a `TypeError` from inside
`locate()` when invoked with `inversionAttempts: "onlyInvert"`. s0 therefore
never requests that mode and isolates every decode attempt in
`site/verify/js/portal.js` (`jsQRSafe`), so a decoder fault degrades to
"no QR found" instead of failing verification. This is a caller-side
mitigation, not a modification of the vendored file.

## crypto-bundle.js

| Field | Value |
|---|---|
| Files | `site/verify/vendor/crypto-bundle.js` |
| Version | s0-internal |
| Origin | Authored for s0. No upstream project identified. |
| Licence | MIT, as part of s0 |

This is a WebCrypto-compatible SHA-512 / Ed25519 helper bundled so the
verification portal performs no network I/O. It is s0's own code.

## Rubik

| Field | Value |
|---|---|
| Files | `site/verify/fonts/rubik-*.woff2`, `site/install/fonts/rubik-*.woff2` |
| Upstream | https://fonts.google.com/specimen/Rubik |
| Licence | **SIL Open Font License 1.1** (SIL OFL) |
| Licence text | https://openfontlicense.org/ |
| Modified | No. WOFF2 conversions only. |

The OFL permits bundling and redistribution. The Reserved Font Name provisions
do not permit using the font in a modified form under the reserved names; the
fonts here are unmodified.

## JetBrains Mono

| Field | Value |
|---|---|
| Files | `site/verify/fonts/jetbrains-mono-*.woff2`, `site/install/fonts/jetbrains-mono-*.woff2` |
| Upstream | https://www.jetbrains.com/lp/mono/ |
| Licence | **SIL Open Font License 1.1** (SIL OFL) |
| Licence text | https://openfontlicense.org/ |
| Modified | No. WOFF2 conversions only. |

---

## Verifying the vendored tree

`site/verify/vendor/manifest.json` records the SHA-256, version, upstream
URL, licence and modification state of every vendored file.
`tests/portal/test_portal_consistency.py` fails if a file is added,
removed or modified without updating the manifest, and if any `<script
src="vendor/...">` in the portal lacks a matching Subresource Integrity hash.

To re-vendor, update the manifest and the `integrity=` attributes together:

```bash
python - <<'PY'
import base64, hashlib, pathlib
p = pathlib.Path("site/verify/vendor/jsqr.min.js")
print("sha384-" + base64.b64encode(hashlib.sha384(p.read_bytes()).digest()).decode())
PY
```

## Runtime dependencies

The Python dependencies (`cryptography`, `reportlab`, `qrcode`, `Pillow`,
`FastAPI`, `uvicorn`, `starlette`) are installed from PyPI under their own
licences and are not redistributed in this repository. Their licence
information is available from each project and is recorded by
`pip-licenses` / `pip-audit` in CI.
