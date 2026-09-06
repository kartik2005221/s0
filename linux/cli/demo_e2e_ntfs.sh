#!/usr/bin/env bash
# s0 NTFS Forensic Carving End-to-End Demo (NTRO)
#
#   1. Construct an NTFS image containing planted deleted evidence files (PDF, JPEG)
#   2. Detect NTFS volume and parse $MFT structure
#   3. Run structure & signature carver via CLI (s0 carve)
#   4. Validate recovered file SHA-256 hashes against original planted evidence
#   5. Validate Ed25519 signed forensic recovery manifest certificate
#   6. Verify blockchain audit ledger continuity
#
# Runs entirely without root on a file-backed image.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
PY="$REPO/.venv/bin/python"
CLI=("$PY" -m s0_cli.main)
WORK="${S0_NTFS_DEMO_DIR:-$REPO/demo-out/ntfs-e2e-$(date +%H%M%S)}"
IMG="$WORK/ntfs_evidence_target.raw"
REC_DIR="$WORK/recovered_evidence"

mkdir -p "$WORK" "$REC_DIR"
cd "$REPO"

echo "═══════════════════════════════════════════════════════════════════"
echo " s0 NTFS Forensic Carving Demo — Target: $IMG"
echo " National Technical Research Organisation (NTRO) • Theme: Blockchain & Forensics"
echo "═══════════════════════════════════════════════════════════════════"

echo
echo "── [1/6] Creating NTFS Image with Planted Deleted Evidence ────────"
"$PY" - "$IMG" << 'PYEOF'
import hashlib, struct, sys
from pathlib import Path

img_path = Path(sys.argv[1])
cluster_size = 4096
mft_cluster = 4
mft_offset = mft_cluster * cluster_size

data = bytearray(4 * 1024 * 1024) # 4 MiB image

# 1. Boot Sector (NTFS)
data[0:3] = bytes([0xEB, 0x52, 0x90])
data[3:11] = b"NTFS    "
struct.pack_into("<H", data, 0x0B, 512)
data[0x0D] = 8 # 8 sectors/cluster = 4096 bytes
struct.pack_into("<Q", data, 0x28, 8192)
struct.pack_into("<q", data, 0x30, mft_cluster)
data[0x40] = 0xF6 # -10 -> 1024 B MFT record
data[510:512] = bytes([0x55, 0xAA])

# 2. System Records 0..15
for i in range(16):
    sys_rec = bytearray(1024)
    sys_rec[0:4] = b"FILE"
    struct.pack_into("<H", sys_rec, 0x16, 1) # allocated
    struct.pack_into("<I", sys_rec, 0x2C, i)
    data[mft_offset + i * 1024 : mft_offset + (i + 1) * 1024] = sys_rec

def build_mft(rec_num, fn, payload, is_res=True, clus_off=10):
    rec = bytearray(1024)
    rec[0:4] = b"FILE"
    struct.pack_into("<H", rec, 0x14, 56)
    struct.pack_into("<H", rec, 0x16, 0) # UNALLOCATED / DELETED
    struct.pack_into("<I", rec, 0x2C, rec_num)

    attr_off = 56
    # $FILE_NAME
    fn_b = fn.encode("utf-16le")
    fn_vlen = 0x42 + len(fn_b)
    fn_alen = (24 + fn_vlen + 7) & ~7
    struct.pack_into("<I", rec, attr_off, 0x30)
    struct.pack_into("<I", rec, attr_off + 4, fn_alen)
    struct.pack_into("<I", rec, attr_off + 16, fn_vlen)
    struct.pack_into("<H", rec, attr_off + 20, 24)
    rec[attr_off + 24 + 0x40] = len(fn)
    rec[attr_off + 24 + 0x41] = 3
    rec[attr_off + 24 + 0x42 : attr_off + 24 + 0x42 + len(fn_b)] = fn_b
    attr_off += fn_alen

    # $DATA
    if is_res:
        d_vlen = len(payload)
        d_alen = (24 + d_vlen + 7) & ~7
        struct.pack_into("<I", rec, attr_off, 0x80)
        struct.pack_into("<I", rec, attr_off + 4, d_alen)
        struct.pack_into("<I", rec, attr_off + 16, d_vlen)
        struct.pack_into("<H", rec, attr_off + 20, 24)
        rec[attr_off + 24 : attr_off + 24 + d_vlen] = payload
        attr_off += d_alen
    else:
        runlist = bytes([0x11, 0x01, clus_off, 0x00])
        d_alen = (64 + len(runlist) + 7) & ~7
        struct.pack_into("<I", rec, attr_off, 0x80)
        struct.pack_into("<I", rec, attr_off + 4, d_alen)
        rec[attr_off + 8] = 1 # Non-resident
        struct.pack_into("<H", rec, attr_off + 32, 64)
        struct.pack_into("<Q", rec, attr_off + 40, cluster_size)
        struct.pack_into("<Q", rec, attr_off + 48, len(payload))
        rec[attr_off + 64 : attr_off + 64 + len(runlist)] = runlist
        attr_off += d_alen

    struct.pack_into("<I", rec, attr_off, 0xFFFFFFFF)
    return bytes(rec)

# Evidence Payloads
pdf_data = b"%PDF-1.5\n1 0 obj\n<< /Title (TOP_SECRET_NTRO_OPERATION) >>\nendobj\nstream\nCLASSIFIED RECONNAISSANCE INTELLIGENCE\nendstream\n%%EOF"
jpg_data = bytes([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10]) + b"JFIF" + bytes([0x00, 0x01]) + (b"SATELLITE_INTERCEPT_PIXELS" * 50) + bytes([0xFF, 0xD9])

# Plant Resident PDF at Record 16
r16 = build_mft(16, "classified_mission_brief.pdf", pdf_data, is_res=True)
data[mft_offset + 16 * 1024 : mft_offset + 17 * 1024] = r16

# Plant Non-Resident JPEG at Record 17 (Cluster 30)
r17 = build_mft(17, "satellite_intercept.jpg", jpg_data, is_res=False, clus_off=30)
data[mft_offset + 17 * 1024 : mft_offset + 18 * 1024] = r17
data[30 * cluster_size : 30 * cluster_size + len(jpg_data)] = jpg_data

img_path.write_bytes(data)

# Save expected hashes
(img_path.parent / "expected_pdf.sha256").write_text(hashlib.sha256(pdf_data).hexdigest())
(img_path.parent / "expected_jpg.sha256").write_text(hashlib.sha256(jpg_data).hexdigest())

print(f"=> Formatted 4 MiB NTFS image at {img_path}")
print(f"=> Planted deleted resident: 'classified_mission_brief.pdf' (SHA256: {hashlib.sha256(pdf_data).hexdigest()[:16]}...)")
print(f"=> Planted deleted non-resident: 'satellite_intercept.jpg' (SHA256: {hashlib.sha256(jpg_data).hexdigest()[:16]}...)")
PYEOF

echo
echo "── [2/6] Detecting Filesystem & Volume Structure ──────────────────"
"$PY" - "$IMG" << 'PYEOF'
import sys
sys.path.insert(0, "linux/cli")
from s0_cli.carver import detect_filesystem, parse_ntfs_boot_sector
path = sys.argv[1]
fs = detect_filesystem(path)
boot = parse_ntfs_boot_sector(path)
print(f"Filesystem Detected : {fs.upper()}")
print(f"Cluster Size        : {boot.cluster_size} bytes ({boot.sectors_per_cluster} sectors)")
print(f"MFT Start Cluster   : #{boot.mft_start_cluster} (Offset {boot.mft_start_cluster * boot.cluster_size})")
print(f"MFT Record Size     : {boot.mft_record_size} bytes")
PYEOF

echo
echo "── [3/6] Executing Structure & Signature Carving ──────────────────"
"${CLI[@]}" carve \
    --target "$IMG" \
    --out-dir "$REC_DIR" \
    --min-confidence 60 \
    --operator "op-ntro-forensics" \
    --organization "NTRO Digital Forensics & Data Sanitization Lab"

echo
echo "── [4/6] Cryptographic Hash Verification of Carved Files ─────────"
"$PY" - "$WORK" "$REC_DIR" << 'PYEOF'
import hashlib, os, sys
from pathlib import Path

work = Path(sys.argv[1])
rec_dir = Path(sys.argv[2])

exp_pdf = (work / "expected_pdf.sha256").read_text().strip()
exp_jpg = (work / "expected_jpg.sha256").read_text().strip()

recovered_files = list(rec_dir.glob("*.*"))
pdf_found = False
jpg_found = False

for f in recovered_files:
    data = f.read_bytes()
    h = hashlib.sha256(data).hexdigest()
    if h == exp_pdf:
        print(f"  ✓ PDF Recovered & Verified: {f.name} (SHA-256 match)")
        pdf_found = True
    elif h == exp_jpg:
        print(f"  ✓ JPEG Recovered & Verified: {f.name} (SHA-256 match)")
        jpg_found = True

assert pdf_found, "FAILED: Planted PDF was not accurately recovered!"
assert jpg_found, "FAILED: Planted JPEG was not accurately recovered!"
print("=> 100% Bit-for-bit cryptographic integrity verified on all carved evidence.")
PYEOF

echo
echo "── [5/6] Verifying Signed Forensic Recovery Manifest ──────────────"
MANIFEST_JSON=$(ls "$REC_DIR"/carving_manifest_*.json | head -1)
"$PY" - "$MANIFEST_JSON" << 'PYEOF'
import json, sys
from pathlib import Path
sys.path.insert(0, "core/python")
from s0_core.certificate import verify_certificate
from s0_core.crypto import load_public_pem

cert = json.load(open(sys.argv[1]))
pub = load_public_pem("core/keys/demo_issuer_public.pem")
ok, reason = verify_certificate(cert, [pub])
assert ok, f"Manifest verification failed: {reason}"
print(f"PASS: Valid Ed25519 signature on forensic manifest.")
print(f"  Certificate UUID: {cert['cert_uuid']}")
print(f"  Filesystem      : {cert['notes'][1]}")
PYEOF

echo
echo "── [6/6] Auditing Blockchain Ledger Integrity ─────────────────────"
"${CLI[@]}" audit verify

echo
echo "═══════════════════════════════════════════════════════════════════"
echo " NTFS FORENSIC DEMO COMPLETE: ALL OBJECTIVES VERIFIED"
echo "   Artifacts stored in: $WORK"
echo "═══════════════════════════════════════════════════════════════════"
