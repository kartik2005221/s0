"""Unit tests for s0 Module 2: file carving, boundary resolution and scoring.

These fixtures are built with real encoders (Pillow, zipfile, sqlite3, gzip,
tarfile, wave) rather than hand-assembled magic bytes. That matters: the
previous version of this suite concatenated plausible-looking headers by hand
and then asserted that the carver "recovered" them, which is precisely the
behaviour that made s0 return the same junk for every target. A carver that
correctly rejects a malformed object must have tests that feed it malformed
objects and say so.
"""

import contextlib
import gzip
import hashlib
import io
import os
import random
import shutil
import sqlite3
import subprocess
import tarfile
import tempfile
import wave
import zipfile
from pathlib import Path

import pytest

from s0 import resources
from s0.carve import boundary, calculate_shannon_entropy, carve_image, score_carved_candidate, signatures
from s0.carve.policy import CarveBudget, CarvePolicy
from s0.carve.signatures import get_signature_by_ext, sniff
from s0.certificate import verify_certificate
from s0.crypto import load_public_pem

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
    for _i, (name, data) in enumerate(payloads.items()):
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
    assert reason
    # Two independent gates reject this: the MPEG frame chain, and the
    # uniform-random entropy profile. Either is a correct answer, so accept
    # both and let the next test pin the frame chain specifically.
    assert ("consecutive" in reason
            or "maximum entropy" in reason), reason


def test_mp3_frame_chain_rejects_a_non_random_lone_sync_word():
    """The frame chain must still do its job when the entropy gate cannot.

    A low-entropy tail has no uniform block profile, so the entropy gate stays
    quiet and the frame chain is the only thing that can reject this. If the
    frame-chain check ever regressed, this test would catch it.
    """
    ok, reason = boundary.validate_structure(b"\xff\xfb" + b"\x11\x22\x33\x44" * 50_000, "mp3")
    assert not ok
    assert "consecutive" in reason, reason


def test_mp3_frame_chain_accepts_a_real_frame_sequence(tmp_path):
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


@contextlib.contextmanager
def _tmp_bytes(data: bytes):
    """Write bytes to a temp file and yield its path."""
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "blob.bin"
        p.write_bytes(data)
        yield p


def _resolve_boundary(fn, path: Path):
    """Run a boundary function against a file, the way the engine does."""
    size = path.stat().st_size
    with open(path, "rb") as fh:
        return fn(boundary.ByteSource(fh, size), 0, size)


#: Fixed seed for the noise fixture. The test asserts that a carver emits
#: nothing from unrelated data, so the input must be reproducible: with
#: ``os.urandom`` the test was a coin flip, and it lost roughly one run in forty
#: before the MPEG-TS and JPEG structural gates were tightened.
_NOISE_SEED = 0x5EED_C0DE


def _pseudo_noise(nbytes: int, seed: int = _NOISE_SEED) -> bytes:
    """Deterministic high-entropy filler, indistinguishable from /dev/urandom."""
    rng = random.Random(seed)
    return rng.randbytes(nbytes)


def _mpegts_packets(count: int, pid: int = 0x0100, payload: bytes = b"\x00" * 184) -> bytes:
    """A well-formed MPEG-TS run: 188-byte packets, one PID, AFC=1, CC counting."""
    out = bytearray()
    for i in range(count):
        hdr = bytes([
            0x47,
            ((pid >> 8) & 0x1F),          # TEI=0, PUSI, priority=0
            pid & 0xFF,
            (0x01 << 4) | (i & 0x0F),     # scrambling=0, AFC=1 (payload only), CC
        ])
        out += hdr + payload
    return bytes(out)


def test_mpegts_transport_header_rules():
    """The reserved/invalid header values the standard forbids must be rejected.

    A transport header that merely starts with 0x47 is worthless as evidence: in
    8 MiB of noise the 0x47 sync byte alone occurs every 256 bytes. These are the
    rules that make a 0x47 run distinguishable from coincidence.
    """
    def hdr(tei=0, pusi=0, scrambling=0, afc=1, cc=0):
        return bytes([0x47, (tei << 7) | (pusi << 6) | 0x00, 0x00,
                      (scrambling << 6) | (afc << 4) | cc])

    assert boundary._ts_packet_header(hdr()) is not None
    assert boundary._ts_packet_header(hdr(tei=1)) is None, "transport_error_indicator"
    assert boundary._ts_packet_header(hdr(afc=0)) is None, "adaptation_field_control 0 is forbidden"
    assert boundary._ts_packet_header(hdr(scrambling=1)) is None, "scrambling_control 1 is reserved"
    assert boundary._ts_packet_header(b"\x48" + hdr()[1:]) is None, "sync byte must be 0x47"


def test_mpegts_rejects_a_short_sync_run_and_random_payloads():
    """Four 0x47 bytes at 188-byte spacing is not a stream; noise headers are not either."""
    # A run of 0x47s with no valid transport headers anywhere.
    junk = bytearray(b"\x47" * (188 * 16))
    for i in range(0, len(junk), 188):
        junk[i + 3] = 0x00          # AFC = 0, which the standard forbids
    ok, why = boundary._validate_mpegts(bytes(junk))
    assert not ok
    assert "transport header" in why or "PID" in why

    # Fewer than the minimum packet count must not validate.
    short = _mpegts_packets(boundary._TS_MIN_PACKETS - 1)
    ok, why = boundary._validate_mpegts(short)
    assert not ok and "too short" in why

    # A genuine run must still validate, and report a sync run rather than
    # claiming a validated frame sequence: ISO/IEC 13818-1 has no end marker.
    good = _mpegts_packets(boundary._TS_MIN_PACKETS + 20)
    ok, why = boundary._validate_mpegts(good)
    assert ok, why
    assert "PID(s)" in why


def _mpegts_multiplexed(packets: int) -> bytes:
    """A realistic multiplex: PAT, PMT, video and audio in one run.

    A ``.ts`` file is not one elementary stream. Requiring a single PID
    throughout rejected every real ``.ts`` file, because the PID changes within
    the first few packets -- the original version of this test encoded that
    wrong assumption and passed only because it used a single-PID fixture.
    """
    pids = (0x0000, 0x1000, 0x0100, 0x0200)
    out = bytearray()
    for i in range(packets):
        pid = pids[i % len(pids)]
        out += bytes([0x47, ((pid >> 8) & 0x1F), pid & 0xFF, (0x01 << 4) | (i & 0x0F)])
        out += b"\x00" * 184
    return bytes(out)


def test_mpegts_multiplexed_streams_are_accepted():
    data = _mpegts_multiplexed(boundary._TS_MIN_PACKETS + 40)
    ok, why = boundary._validate_mpegts(data)
    assert ok, why
    assert "PID(s)" in why


def test_mpegts_unbounded_pid_count_is_rejected():
    """Random headers put a different PID in every packet; real ones do not."""
    n = boundary._TS_MAX_PIDS + 20
    out = bytearray()
    for i in range(n):
        pid = 0x0001 + i * 7
        out += bytes([0x47, ((pid >> 8) & 0x1F), pid & 0xFF, (0x01 << 4) | (i & 0x0F)])
        out += b"\x00" * 184
    ok, why = boundary._validate_mpegts(bytes(out))
    assert not ok and "PID" in why


def test_mpegts_adaptation_fields_do_not_move_the_stride(tmp_path):
    """A transport packet is always 188 bytes, adaptation field or not.

    Walking by ``188 + 1 + adaptation_field_length`` lands in the middle of every
    stream that carries PCRs, which is most of them.
    """
    out = bytearray()
    for i in range(64):
        af_len = 7 if i % 2 else 0
        afc = 3 if af_len else 1
        pid = 0x0100
        out += bytes([0x47, ((pid >> 8) & 0x1F), pid & 0xFF, (afc << 4) | (i & 0x0F)])
        if af_len:
            # adaptation_field_length counts itself, so the field is af_len
            # bytes in total and the payload is whatever is left of the 188.
            out += bytes([af_len]) + b"\x00" * (af_len - 1)
        out += b"\x00" * (184 - af_len)
    data = bytes(out)
    assert len(data) == 64 * 188
    path = tmp_path / "af.ts"
    path.write_bytes(data)
    with open(path, "rb") as fh:
        b = boundary._mpegts_end(boundary.ByteSource(fh, len(data)), 0, 1 << 20)
    assert b.end == len(data), "adaptation fields must not shift the packet stride"
    ok, why = boundary._validate_mpegts(data)
    assert ok, why


@pytest.mark.skipif(shutil.which("ffmpeg") is None, reason="ffmpeg not available")
def test_a_real_ffmpeg_transport_stream_is_recovered(tmp_path):
    """End to end: a real multiplexed stream must carve byte-exact."""
    from s0.carve import carve_image
    ffmpeg = shutil.which("ffmpeg")
    src = tmp_path / "real.ts"
    proc = subprocess.run(
        [ffmpeg, "-hide_banner", "-loglevel", "error", "-y", "-f", "lavfi",
         "-i", "testsrc=size=160x120:rate=15:duration=2",
         "-c:v", "mpeg2video", "-f", "mpegts", str(src)],
        capture_output=True, text=True)
    if proc.returncode != 0:
        pytest.skip(proc.stderr[:200])
    original = src.read_bytes()
    image = tmp_path / "img.raw"
    image.write_bytes(b"\x5a" * 4096 + original + b"\x5a" * 4096)
    out = tmp_path / "out"
    carve_image(image, out, generate_certificate=False)
    files = [f for f in out.iterdir() if f.suffix == ".ts"]
    assert len(files) == 1, sorted(f.name for f in out.iterdir())
    assert files[0].read_bytes() == original


def test_jpeg_sof_length_must_match_component_count():
    """A SOF whose declared length contradicts its component count is not a JPEG.

    This is the check that removed a 1.2 MB false positive: 8 MiB of noise
    contains plenty of plausible FF-marker runs, but it satisfies
    ``length == 8 + 3 * components`` about once in 32,768.
    """
    from PIL import Image
    buf = io.BytesIO()
    Image.new("RGB", (64, 64), (10, 120, 200)).save(buf, format="JPEG", quality=85)
    jpg = bytearray(buf.getvalue())

    # Find SOF0 and lie about the component count.
    i = jpg.index(b"\xff\xc0")
    original = jpg[i + 9]
    jpg[i + 9] = 1                      # claims 1 component but length says 17
    with _tmp_bytes(bytes(jpg)) as path:
        bnd = _resolve_boundary(boundary._jpeg_end, path)
    assert bnd.method == boundary.UNDETERMINED
    assert "component" in bnd.notes[0]

    jpg[i + 9] = original
    with _tmp_bytes(bytes(jpg)) as path:
        bnd = _resolve_boundary(boundary._jpeg_end, path)
    assert bnd.method == boundary.FOOTER_ANCHORED, bnd.notes


def test_jpeg_without_dqt_and_dht_is_rejected():
    """A scan with no quantisation or Huffman table is undecodable, so not a file."""
    from PIL import Image
    buf = io.BytesIO()
    Image.new("L", (64, 64), 128).save(buf, format="JPEG", quality=85)
    jpg = buf.getvalue()
    dqt = jpg.index(b"\xff\xdb")
    ln = int.from_bytes(jpg[dqt + 2:dqt + 4], "big")
    stripped = jpg[:dqt] + jpg[dqt + 2 + ln:]      # delete the DQT segment
    with _tmp_bytes(stripped) as path:
        bnd = _resolve_boundary(boundary._jpeg_end, path)
    assert bnd.method == boundary.UNDETERMINED
    assert "undecodable" in bnd.notes[0]


def test_dqt_and_dht_length_helpers():
    assert boundary._dqt_length_is_exact(bytes([0x00]) + bytes(64))       # 8-bit table
    assert boundary._dqt_length_is_exact(bytes([0x10]) + bytes(128))      # 16-bit table
    assert boundary._dqt_length_is_exact((bytes([0x00]) + bytes(64)) * 2)   # two tables
    assert not boundary._dqt_length_is_exact(bytes([0x00]) + bytes(63))   # short table
    assert not boundary._dqt_length_is_exact(bytes([0x20]) + bytes(64))   # Pq=2 invalid
    counts = bytes([0] * 15 + [1])
    assert boundary._dht_length_is_plausible(bytes([0x00]) + counts + b"\x00")
    assert not boundary._dht_length_is_plausible(bytes([0x00]) + counts)   # truncated
    assert not boundary._dht_length_is_plausible(bytes([0x00]) + bytes(16))  # zero symbols


def test_carve_emits_nothing_for_pure_noise(tmp_path):
    """The regression that matters: unrelated data must yield nothing, and the
    output must never exceed the input."""
    path = tmp_path / "noise.raw"
    path.write_bytes(_pseudo_noise(8 * 1024 * 1024))
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
    from s0.crypto import DEMO_KEY_FINGERPRINT
    payloads = {"a.png": _png_bytes(), "b.zip": _zip_bytes()}
    path, _ = _write_image_with_payloads(tmp_path, payloads, total=8 * 1024 * 1024)
    out = tmp_path / "out"
    summary = carve_image(path, out, generate_certificate=True)
    cert = summary.manifest_certificate
    assert cert is not None
    assert cert["signature"]["public_key_fingerprint"] == DEMO_KEY_FINGERPRINT
    pub = resources.demo_public_key()
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
    from s0.carve.allocation import build_free_space

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
    from s0.carve.allocation import build_free_space

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


class TestUniformRandomGate:
    """The universal pre-gate: no file format is uniformly random throughout.

    Thresholds are not guesses. Over 60 samples of random data at 8 KiB, 32 KiB
    and 256 KiB the block-entropy standard deviation never exceeded 0.027; over
    real output from nine encoder/format combinations the lowest was 0.137. The
    gate sits at 0.08, between the two.
    """

    def test_uniform_noise_is_rejected(self):
        from s0.carve import scoring
        for size in (8 * 1024, 64 * 1024, 512 * 1024):
            data = os.urandom(size)
            complaint = scoring.uniform_random_complaint(data)
            assert complaint is not None, f"{size} bytes of noise was not rejected"
            assert "maximum entropy" in complaint

    def test_the_pattern_that_caused_the_original_false_positives_is_caught(self):
        """752 bytes of noise scored 100% as an MPEG-TS before this gate.

        A magic byte plus uniform random data is the exact shape this rejects,
        and it is worth keeping as a named regression because the boundary
        walker will never catch it on its own.
        """
        payload = b"G" + os.urandom(64 * 1024)
        from s0.carve import scoring
        assert scoring.uniform_random_complaint(payload) is not None

    def test_a_repetitive_real_file_is_not_caught(self):
        """Low spread alone is not evidence of noise.

        A solid-colour image or a file of zeroes also has a flat entropy
        profile. Rejecting those would be a catastrophic false positive, which
        is why the gate also requires the mean to be near-maximal.
        """
        from s0.carve import scoring
        for data in (b"\x00" * 64 * 1024,
                     b"\xff" * 64 * 1024,
                     b"A" * 200_000,
                     b"the quick brown fox jumps over the lazy dog. " * 3000):
            assert scoring.uniform_random_complaint(data) is None, \
                "a low-entropy payload is not noise"

    def test_a_deterministic_maximally_uniform_pattern_is_also_rejected(self):
        """The gate does not care that the noise is predictable.

        ``bytes(range(256))`` repeated is not a file either, and it has a
        perfectly flat entropy profile, so the same rule must catch it. Whether
        the bytes are unpredictable is irrelevant; whether they are uniformly
        distributed is not.
        """
        from s0.carve import scoring
        complaint = scoring.uniform_random_complaint(bytes(range(256)) * 256)
        assert complaint is not None
        assert "maximum entropy" in complaint

    def test_a_real_encoded_file_is_not_caught(self, tmp_path):
        from s0.carve import scoring
        ffmpeg = shutil.which("ffmpeg")
        if ffmpeg is None:
            pytest.skip("ffmpeg not available")
        for codec, fmt, ext in (("mpeg4", "avi", "avi"), ("libx264", "mp4", "mp4"),
                                ("libx264", "matroska", "mkv"), ("ffv1", "avi", "avi")):
            out = tmp_path / f"r{len(list(tmp_path.iterdir()))}.{ext}"
            proc = subprocess.run(
                [ffmpeg, "-hide_banner", "-loglevel", "error", "-y", "-f", "lavfi",
                 "-i", "testsrc=size=320x240:rate=25:duration=4",
                 "-c:v", codec, "-f", fmt, str(out)],
                capture_output=True, text=True)
            if proc.returncode != 0 or not out.is_file():
                continue
            data = out.read_bytes()
            assert scoring.uniform_random_complaint(data) is None, \
                f"{codec}/{fmt} was wrongly called noise"

    def test_payloads_too_small_to_judge_are_not_complained_about(self):
        from s0.carve import scoring
        for size in (16, 512, 4096, 8191):
            assert scoring.uniform_random_complaint(os.urandom(size)) is None

    def test_the_gate_is_applied_before_the_format_specific_check(self):
        """A bare magic byte plus noise must not reach the format validator."""
        from s0.carve import boundary
        ok, reason = boundary.validate_structure(b"RIFF" + os.urandom(32 * 1024), "avi")
        assert not ok
        assert "maximum entropy" in reason

    def test_solid_containers_still_validate(self):
        """A deliberately tiny but real PNG must not be caught by the gate."""
        from s0.carve import boundary
        data = _png_bytes(16, 16)
        ok, reason = boundary.validate_structure(data, "png")
        assert ok, reason


class TestCandidatePrefilter:
    """The in-memory prefilter, and the measurements that justify its thresholds.

    Profiling 32 MiB of noise found 265,811 calls into the boundary resolver for
    978 real candidates. Eight of the 59 signatures have a one- or two-byte
    magic and so match almost everywhere; the resolver was doing file seeks to
    reject candidates whose header bytes already disproved them.
    """

    def _sig(self, ext):
        from s0.carve.signatures import SIGNATURES
        return next(s for s in SIGNATURES if s.extension == ext)

    def test_noise_matching_a_one_byte_magic_is_rejected_in_memory(self):
        from s0.carve.engine import _plausible_header
        sig = self._sig("ts")
        window = bytes([0x47]) + os.urandom(64 * 1024)
        # Force an invalid adaptation_field_control at +3 on the first packets.
        window = bytearray(window)
        for i in range(0, 8 * 188, 188):
            window[i + 3] = 0x00            # AFC 0 is forbidden
        window = bytes(window)
        assert _plausible_header(sig, window, 0) is not None
        assert "consecutive valid" in _plausible_header(sig, window, 0)

    def test_a_real_transport_stream_passes_the_prefilter(self, tmp_path):
        from s0.carve.engine import _plausible_header
        ffmpeg = shutil.which("ffmpeg")
        if ffmpeg is None:
            pytest.skip("ffmpeg not available")
        src = tmp_path / "r.ts"
        proc = subprocess.run(
            [ffmpeg, "-hide_banner", "-loglevel", "error", "-y", "-f", "lavfi",
             "-i", "testsrc=size=160x120:rate=15:duration=2",
             "-c:v", "mpeg2video", "-f", "mpegts", str(src)],
            capture_output=True, text=True)
        if proc.returncode != 0:
            pytest.skip(proc.stderr[:200])
        data = src.read_bytes()
        sig = self._sig("ts")
        assert _plausible_header(sig, data, 0) is None, \
            "a real multiplexed stream must not be prefiltered away"

    @pytest.mark.parametrize("ext", ["avi", "mp4"])
    def test_real_container_starts_pass(self, tmp_path, ext):
        from s0.carve.engine import _plausible_header
        sig = self._sig(ext)
        if ext == "avi":
            ffmpeg = shutil.which("ffmpeg")
            if ffmpeg is None:
                pytest.skip("ffmpeg not available")
            src = tmp_path / "a.avi"
            proc = subprocess.run(
                [ffmpeg, "-hide_banner", "-loglevel", "error", "-y", "-f", "lavfi",
                 "-i", "testsrc=size=160x120:rate=15:duration=2", "-c:v", "mpeg4",
                 "-f", "avi", str(src)], capture_output=True, text=True)
            if proc.returncode != 0:
                pytest.skip(proc.stderr[:200])
        else:
            src = _png_bytes()          # placeholder, replaced below
            src = tmp_path / "a.mp4"
            ffmpeg = shutil.which("ffmpeg")
            if ffmpeg is None:
                pytest.skip("ffmpeg not available")
            proc = subprocess.run(
                [ffmpeg, "-hide_banner", "-loglevel", "error", "-y", "-f", "lavfi",
                 "-i", "testsrc=size=160x120:rate=15:duration=2", "-c:v", "libx264",
                 "-f", "mp4", str(src)], capture_output=True, text=True)
            if proc.returncode != 0:
                pytest.skip(proc.stderr[:200])
        data = src.read_bytes()
        i = data.find(sig.header, sig.header_offset)
        assert i >= 0
        assert _plausible_header(sig, data, i - sig.header_offset) is None

    def test_bmp_with_a_plausible_size_but_nonsense_reserved_words_is_rejected(self):
        import struct as _struct

        from s0.carve.engine import _plausible_header
        sig = self._sig("bmp")
        window = bytearray(64)
        window[0:2] = b"BM"
        _struct.pack_into("<I", window, 2, 1000)      # declared size
        _struct.pack_into("<HHI", window, 6, 0, 0, 54)   # data offset
        window = bytes(window)
        assert _plausible_header(sig, window, 0) is None
        bad = bytearray(window)
        _struct.pack_into("<H", bad, 6, 0x1234)       # non-zero reserved word
        assert "reserved" in (_plausible_header(sig, bytes(bad), 0) or "")

    def test_prefilter_near_the_window_edge_defers_to_the_boundary_walker(self):
        """Incomplete evidence must not be treated as disproof."""
        from s0.carve.engine import _plausible_header
        sig = self._sig("ts")
        assert _plausible_header(sig, b"G", 0) is None


class TestScanThroughput:
    """Throughput, recorded so a future change cannot silently undo it."""

    def test_noise_scan_does_not_drown_in_candidates(self, tmp_path):
        from s0.carve import carve_image
        img = tmp_path / "noise.raw"
        img.write_bytes(os.urandom(8 * 1024 * 1024))
        out = tmp_path / "out"
        summary = carve_image(img, out, generate_certificate=False)
        # Before the prefilter this was ~66,000 candidates per 8 MiB.
        assert summary.total_candidates_found < 500, \
            f"{summary.total_candidates_found} candidates from 8 MiB of noise"

    def test_a_sparse_window_skips_magics_that_cannot_match(self, tmp_path):
        from s0.carve import carve_image
        img = tmp_path / "sparse.raw"
        with open(img, "wb") as f:
            for _ in range(8):
                f.write(b"\x00" * (1 << 20))
            f.write(os.urandom(1024))
        out = tmp_path / "out"
        carve_image(img, out, generate_certificate=False)
        assert [f for f in out.iterdir() if f.suffix != ".json"] == []

    def test_a_real_file_is_still_found_in_a_sparse_image(self, tmp_path):
        from s0.carve import carve_image
        payload = _png_bytes(64, 64)
        img = tmp_path / "sparse.raw"
        img.write_bytes(b"\x00" * 4096 + payload + b"\x00" * 4096)
        out = tmp_path / "out"
        carve_image(img, out, generate_certificate=False)
        pngs = [f for f in out.iterdir() if f.suffix == ".png"]
        assert len(pngs) == 1
        assert pngs[0].read_bytes() == payload


# --------------------------------------------------------------------------- #
# Findings 2.1 and 2.2 from the adversarial pass on this branch.
# --------------------------------------------------------------------------- #

def test_valid_compressed_and_encrypted_containers_are_not_entropy_rejected():
    """Regression: the entropy gate vetoed files whose container had validated.

    It ran *before* the per-format validator, so a perfectly valid PNG was
    rejected for having uniform 1 KiB blocks. Measured on a 480 KB noisy PNG:

        mean 7.808  stdev 0.017   -> old gate rejected it
        validate_structure(png, "png") -> True, 0 CRC mismatch

    `--min-confidence 0` did not help, because the gate is a hard reject rather
    than a score component. The docstring's premise -- that no format is uniformly
    random throughout -- holds for uncompressed formats and is false for every
    compressed or encrypted one, which is exactly what an examiner wants flagged.
    """
    import struct
    import zlib

    from s0.carve import scoring
    from s0.carve.boundary import validate_structure

    w = h = 400
    raw = b"".join(b"\x00" + os.urandom(w * 3) for _ in range(h))

    def chunk(tag: bytes, payload: bytes) -> bytes:
        body = tag + payload
        return struct.pack(">I", len(payload)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)

    png = (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw, 1))
        + chunk(b"IEND", b"")
    )

    mean, stdev = scoring.entropy_block_profile(png)
    # The fixture must actually exercise the bug, or it proves nothing.
    assert stdev < scoring._UNIFORM_STDEV_MAX and mean > scoring._UNIFORM_MEAN_MIN, (
        f"fixture no longer reproduces the reported profile (mean={mean}, stdev={stdev})"
    )

    ok, reason = validate_structure(png, "png")
    assert ok, f"a valid PNG with uniform block entropy was rejected: {reason}"


def test_mp4_atom_walk_stops_at_zero_padding():
    """Regression: a size-0 atom of any type was read as 'to end of window'.

    Zero padding after a moov-last MP4 therefore parsed as one enormous box, so
    the carver ran to the end of the search window, swallowed whatever file
    followed, and reported "100%, declared size".

    Size 0 now means end-of-file only for `mdat`, and every atom's fourcc must be
    printable ASCII -- which zero padding is not.
    """
    from s0.carve.boundary import _is_media_payload_box, _is_printable_fourcc

    assert _is_media_payload_box(b"mdat") is True
    assert _is_media_payload_box(b"moov") is False
    assert _is_media_payload_box(b"free") is False
    assert _is_media_payload_box(b"\x00\x00\x00\x00") is False

    assert _is_printable_fourcc(b"moov") is True
    assert _is_printable_fourcc(b"\x00\x00\x00\x00") is False
    assert _is_printable_fourcc(b"\x01\x02\x03\x04") is False


def test_gif_with_extension_blocks_reaches_its_trailer():
    """Regression: the byte after the 0x21 introducer is a *label*, not a length.

    The walker read it as a length and skipped 249 bytes for a Graphic Control
    Extension (label 0xF9), landing in the middle of the stream. Every animated,
    ffmpeg-made and transparent GIF was rejected with "unexpected GIF block
    introducer"; only the extension-free single-image case survived, which is why
    1 of 6 test GIFs recovered.

    Verified against the pre-fix behaviour: the animated fixture below ends at 43
    and the walker reported "GIF sub-blocks overrun the window".
    """
    import struct

    from s0.carve.boundary import _gif_end

    class Src:
        def __init__(self, data: bytes):
            self.d = data
            self.size = len(data)

        def read(self, offset: int, count: int) -> bytes:
            return self.d[offset:offset + count] if 0 <= offset < len(self.d) else b""

    def build(animated: bool) -> bytes:
        # logical screen descriptor, 2-entry global colour table (flag 0x80, size 0)
        out = b"GIF89a" + struct.pack("<HH", 2, 2) + bytes([0x80, 0, 0]) + b"\x00" * 6
        gce = b"\x21\xF9\x04\x00\x00\x00\x00\x00"      # graphic control extension
        img = b"\x2C" + struct.pack("<HHHH", 0, 0, 2, 2) + b"\x00\x02\x02ab\x00"
        return out + (gce + img if animated else img) + b"\x3B"

    # An application extension as ffmpeg writes it: 0x21 0xFF, a 12-byte block
    # (size byte + "NETSCAPE2.0" + auth code), then the sub-blocks. Getting that
    # 12 wrong by one desynchronises the walk and the rest of the file reads as
    # garbage, so it is pinned here explicitly.
    with_app = b"\x21\xFF\x0BNETSCAPE2.0\x03\x01\x00\x00\x00"

    def build_app(animated: bool) -> bytes:
        out = b"GIF89a" + struct.pack("<HH", 2, 2) + bytes([0x80, 0, 0]) + b"\x00" * 6
        out += with_app
        gce = b"\x21\xF9\x04\x00\x00\x00\x00\x00"
        img = b"\x2C" + struct.pack("<HHHH", 0, 0, 2, 2) + b"\x00\x02\x02ab\x00"
        return out + (gce + img if animated else img) + b"\x3B"

    cases = [("static", build(False)), ("animated", build(True)),
             ("app-extension", build_app(False)), ("app-ext + GCE", build_app(True))]
    for label, data in cases:
        boundary = _gif_end(Src(data), 0, 1 << 20)
        assert boundary.end == len(data), (
            f"GIF ({label}) did not reach its trailer: end={boundary.end}, "
            f"expected {len(data)}; notes={boundary.notes}"
        )
