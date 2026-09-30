"""Unit tests for s0 Module 2: file carving, boundary resolution and scoring.

These fixtures are built with real encoders (Pillow, zipfile, sqlite3, gzip,
tarfile, wave) rather than hand-assembled magic bytes. That matters: the
previous version of this suite concatenated plausible-looking headers by hand
and then asserted that the carver "recovered" them, which is precisely the
behaviour that made s0 return the same junk for every target. A carver that
correctly rejects a malformed object must have tests that feed it malformed
objects and say so.
"""

import gzip
import hashlib
import io
import os
import sqlite3
import struct
import tarfile
import wave
import zipfile
import zlib
from pathlib import Path

import pytest

from s0_cli.carver import calculate_shannon_entropy, carve_image, score_carved_candidate
from s0_cli.carver import boundary, signatures
from s0_cli.carver.policy import CarveBudget, CarvePolicy
from s0_cli.carver.signatures import get_signature_by_ext, sniff
from s0_core.certificate import verify_certificate
from s0_core.crypto import load_public_pem

pil = pytest.importorskip("PIL.Image", reason="Pillow required to build image fixtures")


# --------------------------------------------------------------------------- #
# real-encoder fixtures
# --------------------------------------------------------------------------- #


def _png_bytes(w=64, h=64, colour=(200, 30, 60)):
    from PIL import Image
    buf = io.BytesIO()
    Image.new("RGB", (w, h), colour).save(buf, format="PNG")
    return buf.getvalue()


def _jpeg_bytes(w=64, h=64):
    from PIL import Image
    buf = io.BytesIO()
    Image.new("RGB", (w, h), (10, 120, 200)).save(buf, format="JPEG", quality=85)
    return buf.getvalue()


def _gif_bytes():
    from PIL import Image
    buf = io.BytesIO()
    Image.new("P", (32, 24)).save(buf, format="GIF")
    return buf.getvalue()


def _bmp_bytes():
    from PIL import Image
    buf = io.BytesIO()
    Image.new("RGB", (32, 24), (7, 7, 7)).save(buf, format="BMP")
    return buf.getvalue()


def _zip_bytes():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("notes.txt", "forensic evidence " * 100)
        z.writestr("data.csv", "a,b,c\n" * 200)
    return buf.getvalue()


def _wav_bytes():
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(2)
        w.setsampwidth(2)
        w.setframerate(44100)
        w.writeframes(b"\x00\x01" * 8000)
    return buf.getvalue()


def _sqlite_bytes(tmp_path):
    p = tmp_path / "fixture.sqlite"
    con = sqlite3.connect(p)
    con.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, blob BLOB)")
    for i in range(300):
        con.execute("INSERT INTO t VALUES (?, ?)", (i, os.urandom(48)))
    con.commit()
    con.close()
    return p.read_bytes()


def _tar_bytes():
    buf = io.BytesIO()
    body = os.urandom(20_000)
    with tarfile.open(fileobj=buf, mode="w") as t:
        info = tarfile.TarInfo("evidence.bin")
        info.size = len(body)
        t.addfile(info, io.BytesIO(body))
    return buf.getvalue()


def _pdf_bytes(title="Case 42"):
    return (f"%PDF-1.7\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
            f"trailer<</Root 1 0 R/Info<</Title({title})>>>>\n%%EOF\n").encode()


def _write_image_with_payloads(tmp_path, payloads, total=48 * 1024 * 1024, fill=None):
    """Scatter payloads through a noisy image and return (path, {name: offset})."""
    fill = fill if fill is not None else os.urandom(1 << 20)
    span = total // (len(payloads) + 2)
    buf = bytearray()
    placements = {}
    for i, (name, data) in enumerate(payloads.items()):
        pad = (fill * ((span * 2) // len(fill) + 2))[: span]
        buf += pad
        placements[name] = len(buf)
        buf += data
    pad = (fill * ((span * 2) // len(fill) + 2))[: span]
    buf += pad
    p = tmp_path / "evidence.raw"
    p.write_bytes(bytes(buf))
    return p, placements


# --------------------------------------------------------------------------- #
# entropy
# --------------------------------------------------------------------------- #


def test_shannon_entropy():
    assert calculate_shannon_entropy(b"\x00" * 1024) == 0.0
    import secrets
    assert 7.5 <= calculate_shannon_entropy(secrets.token_bytes(4096)) <= 8.0


# --------------------------------------------------------------------------- #
# boundary resolution -- the mechanism that replaces "carve to max_size"
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("name,data,expected_size", [
    ("png", _png_bytes, 0),
    ("jpg", _jpeg_bytes, 0),
    ("gif", _gif_bytes, 0),
    ("bmp", _bmp_bytes, 0),
    ("zip", _zip_bytes, 0),
    ("wav", _wav_bytes, 0),
])
def test_boundary_resolves_exact_size(tmp_path, name, data, expected_size):
    blob = data()
    path = tmp_path / "blob.bin"
    path.write_bytes(blob)
    with open(path, "rb") as fh:
        src = boundary.ByteSource(fh, len(blob))
        sig = get_signature_by_ext(name)
        b = boundary.resolve_boundary(src, 0, sig, sig.max_size)
    assert b.resolved, b.notes
    assert b.end == len(blob), f"{name}: resolved {b.end} for a {len(blob)}-byte object"


def test_gzip_boundary_is_the_end_of_the_stream(tmp_path):
    blob = gzip.compress(b"PAYLOAD-" * 5000, 9)
    path = tmp_path / "blob.gz"
    path.write_bytes(blob)
    with open(path, "rb") as fh:
        src = boundary.ByteSource(fh, len(blob))
        sig = get_signature_by_ext("gz")
        b = boundary.resolve_boundary(src, 0, sig, sig.max_size)
    assert b.resolved and b.end == len(blob)
    assert any("CRC32" in n for n in b.notes)


def test_sqlite_boundary_uses_the_page_count(tmp_path):
    blob = _sqlite_bytes(tmp_path)
    path = tmp_path / "blob.sqlite"
    path.write_bytes(blob)
    with open(path, "rb") as fh:
        src = boundary.ByteSource(fh, len(blob))
        sig = get_signature_by_ext("sqlite")
        b = boundary.resolve_boundary(src, 0, sig, sig.max_size)
    assert b.resolved and b.end == len(blob)


def test_tar_boundary_accounts_for_the_257_byte_magic_offset(tmp_path):
    blob = _tar_bytes()
    path = tmp_path / "blob.tar"
    path.write_bytes(blob)
    ustar = blob.index(b"ustar")           # the signature is 257 bytes in
    with open(path, "rb") as fh:
        src = boundary.ByteSource(fh, len(blob))
        sig = get_signature_by_ext("tar")
        b = boundary.resolve_boundary(src, ustar, sig, sig.max_size)
    assert b.resolved
    # The returned end is expressed in the candidate's own frame, so the carved
    # length still equals the whole archive.
    assert b.end - ustar == len(blob)


def test_no_boundary_rule_means_reject_not_guess(tmp_path):
    blob = b"BM" + os.urandom(4096)
    path = tmp_path / "junk.bin"
    path.write_bytes(blob)
    with open(path, "rb") as fh:
        src = boundary.ByteSource(fh, len(blob))
        sig = get_signature_by_ext("bmp")
        b = boundary.resolve_boundary(src, 0, sig, sig.max_size)
    assert not b.resolved
    assert b.method == boundary.UNDETERMINED


# --------------------------------------------------------------------------- #
# structural validation -- the gate
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("name,data", [
    ("png", _png_bytes), ("jpg", _jpeg_bytes), ("gif", _gif_bytes),
    ("bmp", _bmp_bytes), ("zip", _zip_bytes), ("wav", _wav_bytes),
])
def test_structural_validation_accepts_real_files(name, data):
    ok, reason = boundary.validate_structure(data(), name)
    assert ok, reason


@pytest.mark.parametrize("name,blob", [
    ("png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 200),
    ("jpg", b"\xff\xd8\xff" + b"\x00" * 200),
    ("zip", b"PK\x03\x04" + b"\x00" * 200),
    ("gif", b"GIF8" + b"\x00" * 200),
    ("bmp", b"BM" + os.urandom(400)),
    ("sqlite", b"SQLite format 3\x00" + b"\x00" * 900),
])
def test_structural_validation_rejects_truncated_or_random_data(name, blob):
    ok, reason = boundary.validate_structure(blob, name)
    assert not ok
    assert reason


def test_mp3_frame_chain_rejects_a_lone_sync_word():
    """Two bytes of sync magic are not an MP3. This is the bug that made s0
    return 30-odd 2 MiB junk files for every target."""
    ok, reason = boundary.validate_structure(b"\xff\xfb" + os.urandom(200_000), "mp3")
    assert not ok
    assert "consecutive" in reason


def test_mp3_frame_chain_accepts_a_real_frame_sequence(tmp_path):
    ffmpeg = None
    payload = _synth_mp3_frames(40)
    if payload is None:
        pytest.skip("no MPEG frame sequence generator available")
    path = tmp_path / "frames.bin"
    path.write_bytes(payload)
    with open(path, "rb") as fh:
        src = boundary.ByteSource(fh, len(payload))
        sig = get_signature_by_ext("mp3")
        b = boundary.resolve_boundary(src, 0, sig, sig.max_size)
    assert b.resolved
    assert b.method == boundary.FRAME_VALIDATED
    ok, reason = boundary.validate_structure(src.read(0, b.end), "mp3")
    assert ok, reason


def _synth_mp3_frames(n=40):
    """Build a valid MPEG-1 Layer III frame chain: 128 kbps, 44.1 kHz, mono."""
    header = bytes([0xFF, 0xFB, 0x90, 0x00])       # MPEG1 L3 128kbps 44.1k no-CRC
    frame_len = 144 * 128_000 // 44100              # 417
    hdr = boundary.parse_mpeg_frame_header(header, 0)
    if hdr is None or hdr["frame_len"] != frame_len:
        return None
    return header + b"\x5a" * (frame_len - 4) * n


# --------------------------------------------------------------------------- #
# scoring
# --------------------------------------------------------------------------- #


def test_valid_bmp_scores_high_despite_low_entropy():
    """A solid-colour BMP is genuinely low entropy. It must not be discarded."""
    blob = _bmp_bytes()
    sig = get_signature_by_ext("bmp")
    with open.__call__ and _tmpfile(blob) as fh:
        src = boundary.ByteSource(fh, len(blob))
        b = boundary.resolve_boundary(src, 0, sig, sig.max_size)
    assert b.resolved
    score, heuristics = score_carved_candidate(
        sig, blob, boundary_method=b.method, boundary_notes=tuple(b.notes))
    assert score >= 90, heuristics


def test_entropy_alone_can_never_reject_a_valid_file():
    """Entropy is capped at a small share of the score and may not go negative
    except for effectively constant data."""
    blob = _png_bytes(8, 8, (0, 0, 0))          # near-constant image
    sig = get_signature_by_ext("png")
    score, heuristics = score_carved_candidate(sig, blob, boundary_method=boundary.CONTAINER_WALK)
    assert score >= 85, heuristics


def test_header_only_signature_without_a_resolvable_boundary_is_not_scored():
    sig = get_signature_by_ext("bmp")
    score, heuristics = score_carved_candidate(sig, b"BM" + os.urandom(4096))
    assert score < 60
    assert any("not independently resolvable" in h for h in heuristics)


def _tmpfile(blob):
    import tempfile
    fd, path = tempfile.mkstemp()
    os.write(fd, blob)
    os.close(fd)
    fh = open(path, "rb")
    fh._s0_tmp = path
    return fh


# --------------------------------------------------------------------------- #
# end-to-end carving
# --------------------------------------------------------------------------- #


def test_carve_recovers_every_planted_file_and_no_others(tmp_path):
    payloads = {
        "a.png": _png_bytes(),
        "b.jpg": _jpeg_bytes(),
        "c.gif": _gif_bytes(),
        "d.bmp": _bmp_bytes(),
        "e.zip": _zip_bytes(),
        "f.pdf": _pdf_bytes(),
        "g.gz": gzip.compress(b"PAYLOAD-" * 5000, 9),
        "h.wav": _wav_bytes(),
    }
    path, placements = _write_image_with_payloads(tmp_path, payloads)
    out = tmp_path / "out"
    summary = carve_image(path, out, generate_certificate=False)

    recovered = {c.filename.split(".")[-1] for c in summary.carved_files}
    offsets = {c.offset for c in summary.carved_files}
    for name, off in placements.items():
        assert off in offsets, f"{name} was not recovered (offsets: {sorted(offsets)})"
        ext = name.split(".")[-1]
        assert ext in recovered, f"{name} missing from {sorted(recovered)}"

    expected_sizes = {n: len(v) for n, v in payloads.items()}
    for c in summary.carved_files:
        truth = next(n for n, o in placements.items() if o == c.offset)
        assert c.size_bytes == expected_sizes[truth], (
            f"{truth}: carved {c.size_bytes} but planted {expected_sizes[truth]}")

    assert summary.files_recovered == len(payloads)
    assert all(c.confidence_score >= 60 for c in summary.carved_files)


def test_carve_emits_nothing_for_pure_noise(tmp_path):
    """The regression that matters: unrelated data must yield nothing, and the
    output must never exceed the input."""
    path = tmp_path / "noise.raw"
    path.write_bytes(os.urandom(8 * 1024 * 1024))
    out = tmp_path / "out"
    summary = carve_image(path, out, generate_certificate=False)
    assert summary.files_recovered == 0
    written = sum(p.stat().st_size for p in out.iterdir() if p.is_file())
    assert written < path.stat().st_size
    assert summary.total_candidates_found > 0, "noise should still generate candidates"


def test_carve_output_never_exceeds_its_budget(tmp_path):
    payloads = {f"p{i}.png": _png_bytes(256, 256, (i * 7 % 255, 3, 9)) for i in range(40)}
    path, _ = _write_image_with_payloads(tmp_path, payloads, total=32 * 1024 * 1024)
    out = tmp_path / "out"
    policy = CarvePolicy.for_target(path.stat().st_size, max_files_total=10)
    summary = carve_image(path, out, generate_certificate=False, policy=policy)
    assert summary.files_recovered <= 10
    written = sum(p.stat().st_size for p in out.iterdir()
                  if p.is_file() and p.suffix != ".json")
    assert written <= policy.max_output_bytes


def test_carve_extension_filter_is_honoured(tmp_path):
    payloads = {"a.png": _png_bytes(), "b.pdf": _pdf_bytes()}
    path, _ = _write_image_with_payloads(tmp_path, payloads, total=8 * 1024 * 1024)
    out = tmp_path / "out"
    summary = carve_image(path, out, extensions=["pdf"], generate_certificate=False)
    assert {c.extension for c in summary.carved_files} == {"pdf"}


def test_carve_records_why_candidates_were_rejected(tmp_path):
    path = tmp_path / "mixed.raw"
    blob = os.urandom(4 * 1024 * 1024) + b"BM" + os.urandom(100_000)
    path.write_bytes(blob)
    out = tmp_path / "out"
    summary = carve_image(path, out, generate_certificate=False)
    assert summary.rejected_candidates > 0
    assert summary.rejected_samples
    assert summary.rejection_summary
    assert summary.rejection_summary[0][1] >= 1
    stages = {r.stage for r in summary.rejected_samples}
    assert stages <= {"boundary", "structure", "score", "budget"}
    assert all(r.reason for r in summary.rejected_samples)


def test_recovery_index_is_written_and_machine_readable(tmp_path):
    import json
    payloads = {"a.png": _png_bytes(), "b.zip": _zip_bytes()}
    path, _ = _write_image_with_payloads(tmp_path, payloads, total=8 * 1024 * 1024)
    out = tmp_path / "out"
    carve_image(path, out, generate_certificate=False)
    idx = json.loads((out / "recovery_index.json").read_text())
    assert idx["schema"] == "s0.recovery-index/1"
    assert idx["files_recovered"] == 2
    assert idx["candidates_rejected"] >= 0
    assert all("sha256" in f for f in idx["recovered_files"])
    assert all("boundary_method" in f for f in idx["recovered_files"])


def test_carve_issues_a_verifiable_manifest_certificate(tmp_path):
    from s0_core.crypto import DEMO_KEY_FINGERPRINT
    payloads = {"a.png": _png_bytes(), "b.zip": _zip_bytes()}
    path, _ = _write_image_with_payloads(tmp_path, payloads, total=8 * 1024 * 1024)
    out = tmp_path / "out"
    summary = carve_image(path, out, generate_certificate=True)
    cert = summary.manifest_certificate
    assert cert is not None
    assert cert["signature"]["public_key_fingerprint"] == DEMO_KEY_FINGERPRINT
    pub = Path(__file__).resolve().parents[3] / "core" / "keys" / "demo_issuer_public.pem"
    ok, reason = verify_certificate(cert, [load_public_pem(pub)])
    assert ok, reason
    assert cert["wipe"]["method"] == "FORENSIC_CARVING"


def test_custom_signature_is_honoured(tmp_path):
    blob = b"\x93S0MARKER\x00" + b"payload-" * 500
    payload = blob + os.urandom(4096)
    path = tmp_path / "custom.raw"
    path.write_bytes(os.urandom(1 << 20) + payload + os.urandom(1 << 20))
    sigs = [signatures.signature_from_dict({
        "name": "S0 Marker", "extension": "s0m", "category": "custom",
        "header": "9353304d41524b4552", "min_size": 64, "max_size": 65536,
    })]
    out = tmp_path / "out"
    summary = carve_image(path, out, custom_signatures=sigs, generate_certificate=False)
    assert summary.files_recovered == 1
    c = summary.carved_files[0]
    assert c.extension == "s0m"
    # No boundary rule exists for an operator-defined format, so s0 carves the
    # declared max_size and says so rather than pretending the end was resolved.
    assert c.boundary_method == boundary.MAX_SIZE_FALLBACK
    assert c.size_bytes == 65536
    written = Path(c.recovered_path).read_bytes()
    assert written.startswith(blob)
    assert any("no boundary rule exists" in h for h in c.heuristics)


def test_sniff_identifies_content():
    assert sniff(_png_bytes()).extension == "png"
    assert sniff(_jpeg_bytes()).extension == "jpg"
    assert sniff(_zip_bytes()).extension == "zip"
    assert sniff(os.urandom(4096)) is None


# --------------------------------------------------------------------------- #
# budget policy
# --------------------------------------------------------------------------- #


def test_budget_scales_with_target_size():
    small = CarvePolicy.for_target(64 * 1024 * 1024)
    large = CarvePolicy.for_target(512 * 1024 * 1024 * 1024)
    assert small.max_output_bytes < large.max_output_bytes
    assert small.max_output_bytes <= small.max_output_bytes * 8


def test_budget_admission_is_ordered_and_explained():
    b = CarveBudget(policy=CarvePolicy(max_files_total=2, max_file_bytes=1024,
                                       max_output_bytes=4096,
                                       max_files_per_category=5,
                                       max_files_per_extension=5))
    assert b.admit("image", "png", 500)[0]
    b.commit("image", "png", 500)
    ok, reason = b.admit("image", "png", 999_999)
    assert not ok and "per-file cap" in reason
    b.commit("image", "png", 500)
    ok, reason = b.admit("image", "png", 100)
    assert not ok and "session cap" in reason


# --------------------------------------------------------------------------- #
# allocation-aware carving
# --------------------------------------------------------------------------- #


def _jpg_bytes(seed: int = 0, size: tuple = (48, 48)) -> bytes:
    """A genuinely valid JPEG, so the structural validator accepts it."""
    import random
    from PIL import Image
    rnd = random.Random(seed)
    im = Image.new("RGB", size)
    im.putdata([(rnd.randrange(256), rnd.randrange(256), rnd.randrange(256))
                for _ in range(size[0] * size[1])])
    buf = io.BytesIO()
    im.save(buf, "JPEG", quality=90)
    return buf.getvalue()


def _ext4_with_two_jpegs(tmp_path: Path, allocated: bool):
    """Build an ext4 image where one JPEG is live and the other is deleted.

    Without mount privileges a deleted file's blocks cannot be released through
    the filesystem, so the payload is written into the image and its bitmap bits
    are then cleared by hand. Blocks 16.. are marked in use by the fixture and
    carry no real structure, so they are safe to park a payload in.

    `allocated=True` leaves the second JPEG's blocks marked in use, making it a
    live file; `allocated=False` clears them, making it a deleted file whose
    content is still sitting in free space.
    """
    import sys as _sys
    _sys.path.insert(0, str(Path(__file__).parent))
    from test_allocation import _ext4_image

    BLOCK = 1024
    img = _ext4_image(tmp_path / "vol.img", block_size=BLOCK, blocks=64,
                      blocks_per_group=32, free_per_group=8)

    live = _jpg_bytes(seed=1, size=(48, 48))
    deleted = _jpg_bytes(seed=2, size=(56, 56))
    live_block, deleted_block = 16, 20

    with open(img, "r+b") as f:
        f.seek(live_block * BLOCK)
        f.write(live)
        f.seek(deleted_block * BLOCK)
        f.write(deleted)

    if not allocated:
        # Group 0's bitmap is the block right after the descriptor table. Bit b
        # of group 0 describes block 1 + b.
        bitmap_off = 3 * BLOCK
        first_bit = deleted_block - 1
        last_bit = first_bit + -(-len(deleted) // BLOCK)
        with open(img, "r+b") as f:
            for bit in range(first_bit, last_bit):
                off = bitmap_off + (bit // 8)
                f.seek(off)
                byte = f.read(1)[0]
                f.seek(off)
                f.write(bytes([byte & ~(1 << (bit & 7))]))
    return img, live, deleted, deleted_block


def test_carve_restricted_to_free_space_does_not_report_live_files(tmp_path):
    """A live file must not be reported as a recovery.

    This is the behaviour that made s0 "recover the same set of files" every
    time: signature carving swept the entire volume, so every still-allocated
    file on the disk came back as if it had been deleted.
    """
    from s0_cli.carver.allocation import build_free_space

    img, live, _deleted, live_block = _ext4_with_two_jpegs(tmp_path, allocated=True)
    fsm = build_free_space(str(img), "ext4", 0, img.stat().st_size)
    assert fsm.reliable
    # The live JPEG sits in a block the bitmap still marks as in use.
    assert not fsm.contains(live_block * 1024, 1)

    results = {}
    for free_only in (True, False):
        out = tmp_path / f"out_{int(free_only)}"
        policy = CarvePolicy.for_target(img.stat().st_size)
        policy.use_free_space_only = free_only
        policy.structure_recovery_enabled = False
        s = carve_image(str(img), str(out), extensions=[".jpg"], policy=policy,
                        generate_certificate=False)
        results[free_only] = {
            hashlib.sha256(Path(f.recovered_path).read_bytes()).hexdigest()
            for f in s.carved_files if f.recovered_path
        }
        if free_only:
            assert s.free_space is not None
        else:
            assert s.free_space is None

    live_hash = hashlib.sha256(live).hexdigest()
    # Searching everything finds the live file and reports it as a recovery.
    assert live_hash in results[False], "fixture did not place a live file in allocated space"
    # Restricting to unallocated space does not.
    assert live_hash not in results[True]


def test_carve_in_unallocated_space_still_finds_a_deleted_file(tmp_path):
    from s0_cli.carver.allocation import build_free_space

    img, _live, deleted, deleted_block = _ext4_with_two_jpegs(tmp_path, allocated=False)
    fsm = build_free_space(str(img), "ext4", 0, img.stat().st_size)
    assert fsm.contains(deleted_block * 1024, 1), "fixture did not free the deleted file"

    out = tmp_path / "out"
    policy = CarvePolicy.for_target(img.stat().st_size)
    policy.structure_recovery_enabled = False
    s = carve_image(str(img), str(out), extensions=[".jpg"], policy=policy,
                    generate_certificate=False)
    hashes = {hashlib.sha256(Path(f.recovered_path).read_bytes()).hexdigest()
              for f in s.carved_files if f.recovered_path}
    assert hashlib.sha256(deleted).hexdigest() in hashes


def test_unknown_filesystem_searches_everything_and_says_so(tmp_path):
    """A carve that silently searched less than it claimed would be worse."""
    blob = tmp_path / "raw.img"
    blob.write_bytes(_jpg_bytes(seed=3) + b"\x00" * 4096)
    out = tmp_path / "out"
    s = carve_image(str(blob), str(out), extensions=[".jpg"],
                    policy=CarvePolicy.for_target(blob.stat().st_size),
                    generate_certificate=False)
    assert s.free_space is None
    assert any("whole volume" in w or "not a recognised filesystem" in w
               for w in s.warnings), s.warnings
