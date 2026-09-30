#!/usr/bin/env bash
# s0 end-to-end demo — the core sanitization demonstration loop.
#
#   1. create a 256 MiB disk image and fill it with junk
#   2. plant "confidential" markers a forensics tool could find
#   3. show the device inventory (s0 list)
#   4. dry-run the plan (nothing written)
#   5. wipe it via the real CLI (zero pass, verified)
#   6. grep the raw image for every planted marker -> must be ZERO hits
#   7. verify the signed certificate independently (and reject a tampered copy)
#
# Runs entirely without root on a file-backed image: the bytes are real,
# they land on your actual disk through the normal filesystem path.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
PY="$REPO/.venv/bin/python"
CLI=("$PY" -m s0.cli.main)
WORK="${S0_DEMO_DIR:-$REPO/demo-out/e2e-$(date +%H%M%S)}"
IMG="$WORK/target_disk.img"
SIZE_MiB="${S0_DEMO_SIZE_MIB:-256}"

mkdir -p "$WORK"
cd "$REPO"

echo "═══════════════════════════════════════════════════════════════════"
echo " s0 end-to-end demo — target: $IMG (${SIZE_MiB} MiB)"
echo "═══════════════════════════════════════════════════════════════════"

echo
echo "── [1/7] creating image filled with non-zero junk ──────────────────"
"$PY" - "$IMG" "$SIZE_MiB" <<'EOF'
import sys
path, mib = sys.argv[1], int(sys.argv[2])
block = b"\x5a" * (1024 * 1024)
with open(path, "wb") as f:
    for _ in range(mib):
        f.write(block)
EOF
ls -lh "$IMG"

echo
echo "── [2/7] planting confidential markers at known offsets ────────────"
"$PY" - "$IMG" <<'EOF'
import sys
sys.path.insert(0, "src")
from s0.wipe.methods.overwrite import plant_patterns, count_pattern_hits
path = sys.argv[1]
marker = b"S0-CONFIDENTIAL-PAN-ABCD1234F|AADHAAR-1234-5678-9012"
import os
size = os.path.getsize(path)
n = max(16, size // (4 * 1024 * 1024))
plant_patterns(path, [(i * (size // n), marker) for i in range(n)])
print(f"planted {n} markers; pre-wipe raw-grep hits = "
      f"{count_pattern_hits(path, marker)}")
EOF

echo
echo "── [3/7] device inventory (s0 list) ─────────────────────────────────"
"${CLI[@]}" list || true

echo
echo "── [4/7] DRY RUN plan (nothing is written) ──────────────────────────"
"${CLI[@]}" plan --target "$IMG"

echo
echo "── [5/7] wiping (real overwrite + sampled verification) ─────────────"
"${CLI[@]}" wipe \
    --target "$IMG" \
    --yes \
    --plant-markers \
    --operator "demo-operator" \
    --organization "s0 Demo Lab (unaccredited)" \
    --out-dir "$WORK"

echo
echo "── [6/7] forensic check: raw byte-search of the wiped image ─────────"
"$PY" - "$IMG" <<'EOF'
import sys
sys.path.insert(0, "src")
from s0.wipe.methods.overwrite import count_pattern_hits
hits = count_pattern_hits(sys.argv[1], b"S0-CONFIDENTIAL")
junk = count_pattern_hits(sys.argv[1], b"\x5a" * 4096)
print(f"confidential-marker hits : {hits}")
print(f"original junk-pattern hits: {junk}")
assert hits == 0 and junk == 0, "RECOVERY STILL POSSIBLE — demo FAILED"
print("=> nothing recoverable by raw search")
EOF

CERT_JSON=$(ls "$WORK"/certificate_*.json | head -1)

echo
echo "── [7/7] certificate verification (independent of the wiper) ────────"
"$PY" - "$CERT_JSON" <<'EOF'
import json, sys
cert = json.load(open(sys.argv[1]))
tampered = json.loads(json.dumps(cert))
tampered["device"]["capacity_bytes"] += 1   # forge one byte
json.dump(tampered, open(sys.argv[1].replace(".json", ".tampered.json"), "w"))
EOF
.venv/bin/s0 verify "$CERT_JSON" --key src/s0/data/keys/demo_issuer_public.pem
echo "→ tampered copy:"
.venv/bin/s0 verify "${CERT_JSON%.json}.tampered.json" \
    --key src/s0/data/keys/demo_issuer_public.pem && {
    echo "TAMPER CHECK FAILED — tampered cert verified!"; exit 1
} || echo "→ tampered certificate correctly REJECTED"

echo
echo "═══════════════════════════════════════════════════════════════════"
echo " DEMO COMPLETE"
echo "   artifacts in: $WORK"
echo "     - certificate JSON/PDF/QR   (signed by demo issuer key)"
echo "     - target_disk.img           (wiped; keep or delete)"
echo "═══════════════════════════════════════════════════════════════════"
