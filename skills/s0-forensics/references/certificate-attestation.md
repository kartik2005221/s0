# Reading a Certificate Attestation

The certificate is the evidence; the exit code is not. For any wipe:

```bash
# Device wipes emit certificate_<uuid8>.json; file/folder erases emit
# file_wipe_certificate_<uuid8>.json. The leading * is required: a glob of
# `certificate_*.json` alone matches nothing for a file erase, and the shell
# then passes the literal pattern to python.
python3 - /evidence/certs/*certificate_*.json <<'PY'
import json, sys

for path in sys.argv[1:]:
    with open(path, encoding="utf-8") as fh:
        cert = json.load(fh)
    result = cert.get("result") or {}
    v = result.get("verification") or {}
    print(f"== {path}")
    print(f"  result.status    : {result.get('status')}")
    print(f"  method           : {cert.get('wipe', {}).get('method')}"
          f" (NIST {cert.get('wipe', {}).get('nist_category')})")
    checked = v.get("samples_checked")
    population = v.get("population_blocks")
    print(f"  readbacks checked: {checked}"
          + (f" of {population}" if population is not None else ""))
    print(f"  sample strategy  : {v.get('sample_strategy') or '(not recorded)'}")
    if "residual_fraction_upper_bound_ppm" in v:
        ppm = v["residual_fraction_upper_bound_ppm"]
        print(f"  residual bound   : {ppm / 10000:.4f}% of the medium at"
              f" {v.get('confidence_percent')}% confidence")
    else:
        print("  residual bound   : NONE RECORDED -- this was not a statistical"
              " sample, so there is no bound. Read the attestation below.")
    print(f"  attestation      : {v.get('attestation') or '(not recorded)'}")
PY
```

Two things that snippet deliberately does not do, because doing them is how a
reader ends up reporting a number the certificate never produced:

- **It never prints `0` for an absent bound.** `residual_fraction_upper_bound_ppm`
  is optional in the schema and is genuinely *absent* on a file/folder erase,
  where the operation was exhaustive rather than sampled. A missing bound means
  "no bound applies", which is not the same claim as "the residue is zero", and
  an exhaustive re-stat of a file list is not a measurement of a medium.
- **It never calls a file list a "sample".** `samples_checked` on a file erase
  counts the paths that were re-stat()ed; `sample_strategy` says
  `exhaustive_over_supplied_paths` so you can tell.

Three cases, and they are not interchangeable:

- **Sampled readback** (device wipe, `method: sampled_readback`). Carries a
  statistical bound in `residual_fraction_upper_bound_ppm`. The default 64
  samples bound the residue at ~4.5% at 95% confidence — weak. Raise
  `--verify-samples` when the bound is load-bearing.
- **Exhaustive over supplied paths** (file/folder erase, `method:
  post_erase_absence_and_overwrite_readback`). Not a sample, so no
  residual bound applies. It attests absence *for the paths you supplied* — s0
  cannot verify that your list was complete.
- **NVMe sanitize** (`s0.wipe.attest`). The strongest available: the
  controller's own Global Data Erased bit, plus the action it reports having run.
  Note that the bit means nothing has been written *since the last successful
  sanitize*; it does not mean this operation was that sanitize. Always read it
  together with the status code, which is `result.status` in the sanitize log.

---
