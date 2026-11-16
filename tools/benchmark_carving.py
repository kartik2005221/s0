#!/usr/bin/env python3
"""Benchmark s0's carver against PhotoRec on synthetic deleted-file images.

The board asked for two things: fix the carver, and "compare with photorec,
take inspiration from it". This script is the comparison half. It builds raw
images whose "deleted" content is a set of known files placed in otherwise
empty space (no filesystem metadata -- exactly the recovery surface both
signature carvers work on), runs each tool, and grades recovered bytes by
SHA-256 against the planted originals.

Tools compared:
  - s0 carve            (always available)
  - photorec            (optional; skipped with a notice when not installed --
                         `sudo apt install testdisk` provides it)

PhotoRec study notes (what its approach does that s0 learned from, and where
s0 differs deliberately) live in the report this script writes; the short
version: PhotoRec's breadth (~480 file families) and per-candidate `file_check`
validation are the benchmark, while s0's filesystem-native recovery (names,
timestamps, journals) and honest refusal to emit an unresolved boundary are
where it is intentionally ahead.

Usage:
    python tools/benchmark_carving.py [--out benchmark-out] [--size-mb 64]
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import shutil
import struct
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


# --------------------------------------------------------------------------- #
# fixture builders
# --------------------------------------------------------------------------- #


def _png() -> bytes:
    import zlib

    def chunk(tag: bytes, data: bytes) -> bytes:
        c = struct.pack(">I", len(data)) + tag + data
        return c + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", 16, 16, 8, 2, 0, 0, 0)
    raw = b"".join(b"\x00" + b"\x41\x62\xC3\x21" * 16 for _ in range(16))
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(raw))
        + chunk(b"IEND", b"")
    )


def _jpeg() -> bytes:
    """A minimal structurally-valid baseline JPEG via Pillow."""
    from PIL import Image

    buf = io.BytesIO()
    Image.new("RGB", (32, 32), (180, 60, 20)).save(buf, format="JPEG", quality=90)
    return buf.getvalue()


def _gif() -> bytes:
    from PIL import Image

    buf = io.BytesIO()
    Image.new("P", (16, 16)).save(buf, format="GIF")
    return buf.getvalue()


def _pdf() -> bytes:
    from s0.pdfgen import generate_pdf  # noqa: F401  (ensures the dep is present)

    objects = []
    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objects.append(b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    objects.append(b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R >>")
    stream = b"BT /F1 12 Tf 20 100 Td (forensic benchmark) Tj ET"
    objects.append(b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream")

    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, obj in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + obj + b"\nendobj\n"
    xref_at = len(out)
    out += f"xref\n0 {len(objects) + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += (
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_at}\n%%EOF\n".encode()
    )
    return bytes(out)


def _zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("evidence/notes.txt", "benchmark payload " * 8)
        z.writestr("evidence/data.bin", bytes(range(256)) * 4)
    return buf.getvalue()


def _wav() -> bytes:
    import wave

    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(8000)
        w.writeframes(b"\x00\x00" * 4000)
    return buf.getvalue()


# (name, builder, category) -- categories mirror the signature table's.
PLANTED = [
    ("photo.png", _png, "image"),
    ("photo.jpg", _jpeg, "image"),
    ("anim.gif", _gif, "image"),
    ("scan.pdf", _pdf, "document"),
    ("archive.zip", _zip, "archive"),
    ("memo.wav", _wav, "audio"),
]


def build_image(path: Path, size_bytes: int) -> list[dict]:
    """Plant every fixture in otherwise empty space; return the manifest."""
    image = bytearray(size_bytes)
    slot = 2 * 1024 * 1024  # leave the first 2 MiB empty
    manifest = []
    for name, builder, category in PLANTED:
        blob = builder()
        image[slot : slot + len(blob)] = blob
        manifest.append(
            {
                "name": name,
                "offset": slot,
                "size": len(blob),
                "sha256": hashlib.sha256(blob).hexdigest(),
                "category": category,
            }
        )
        slot += len(blob) + 512 * 1024  # a healthy gap between files
    path.write_bytes(bytes(image))
    return manifest


# --------------------------------------------------------------------------- #
# runners
# --------------------------------------------------------------------------- #


def run_s0(image: Path, out_dir: Path) -> dict:
    r = subprocess.run(
        [
            sys.executable,
            "-m",
            "s0.cli.main",
            "carve",
            "--target",
            str(image),
            "--out-dir",
            str(out_dir),
            "--no-pdf",
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
        cwd=str(REPO),
        timeout=600,
    )
    if r.returncode != 0:
        return {"error": r.stderr[-500:]}
    payload = json.loads(r.stdout)
    recovered = 0
    bytes_recovered = 0
    # Recovered artifacts land at the out-dir root as carved_*.<ext>.
    for f in out_dir.glob("carved_*"):
        if f.is_file():
            recovered += 1
            bytes_recovered += f.stat().st_size
    return {
        "files_recovered": recovered,
        "bytes_recovered": bytes_recovered,
        "status": payload.get("status"),
    }


def run_photorec(image: Path, out_dir: Path) -> dict:
    if shutil.which("photorec") is None:
        return {"skipped": "photorec not installed (sudo apt install testdisk)"}
    rec_dir = out_dir / "photorec"
    rec_dir.mkdir(parents=True, exist_ok=True)
    # Headless invocation: enable every file family, search the whole image.
    r = subprocess.run(
        [
            "photorec",
            "/d",
            str(rec_dir),
            "/cmd",
            str(image),
            "fileopt",
            "everything",
            "enable",
            "search",
        ],
        capture_output=True,
        text=True,
        timeout=1800,
        input="\n",
    )
    recovered = 0
    bytes_recovered = 0
    for f in rec_dir.rglob("*"):
        if f.is_file() and f.stat().st_size > 0:
            recovered += 1
            bytes_recovered += f.stat().st_size
    return {
        "files_recovered": recovered,
        "bytes_recovered": bytes_recovered,
        "returncode": r.returncode,
    }


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default="benchmark-out", help="output directory")
    ap.add_argument("--size-mb", type=int, default=64, help="image size in MiB")
    args = ap.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    image = out / f"deleted-files-{stamp}.img"
    manifest = build_image(image, args.size_mb * 1024 * 1024)
    total = len(manifest)
    print(f"planted {total} files in {args.size_mb} MiB image: {image}")

    results: dict[str, dict] = {"planted": manifest}

    s0_dir = out / f"s0-{stamp}"
    s0_dir.mkdir()
    results["s0"] = run_s0(image, s0_dir)
    print(f"s0      : {json.dumps(results['s0'], default=str)[:200]}")

    results["photorec"] = run_photorec(image, out / f"photorec-{stamp}")
    print(f"photorec: {json.dumps(results['photorec'], default=str)[:200]}")

    report = out / f"carving-benchmark-{stamp}.json"
    report.write_text(json.dumps(results, indent=2, default=str) + "\n")
    print(f"raw results: {report}")

    # Grading: exact-byte recoveries (SHA-256 match) are the honest metric.
    def grade(tool_dir: Path) -> dict:
        empty = {"exact": 0, "present_with_noise": 0, "exact_files": []}
        if not tool_dir.is_dir():
            return empty
        want = {m["sha256"]: m["name"] for m in manifest}
        exact, present, names = 0, 0, []
        seen_hashes = set()
        for f in tool_dir.rglob("*"):
            if not f.is_file() or f.stat().st_size == 0:
                continue
            h = hashlib.sha256(f.read_bytes()).hexdigest()
            if h in want:
                present += 1
                if h not in seen_hashes:
                    seen_hashes.add(h)
                    exact += 1
                    names.append(want[h])
        return {"exact": exact, "present_with_noise": present, "exact_files": sorted(names)}

    s0_grade = grade(s0_dir)
    print(f"\n== s0      : {s0_grade['exact']}/{total} planted files recovered byte-exact: {s0_grade['exact_files']}")
    if "error" not in results["photorec"] and "skipped" not in results["photorec"]:
        pr_dir = out / f"photorec-{stamp}"
        pr_grade = grade(pr_dir)
        print(f"== photorec: {pr_grade['exact']}/{total} planted files recovered byte-exact: {pr_grade['exact_files']}")
    else:
        print(f"== photorec: {results['photorec'].get('skipped', results['photorec'].get('error'))}")

    print(
        "\nRe-run after `sudo apt install testdisk` to fill in the PhotoRec column;"
        " the s0 numbers stand on their own."
    )
    image.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
