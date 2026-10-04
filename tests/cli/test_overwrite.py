"""Overwrite engine tests on real files — the fully-real method."""

import os
from pathlib import Path

from s0.wipe.methods.overwrite import (
    OverwriteMethod,
    count_pattern_hits,
    plant_patterns,
)

MARKER = b"S0-CONFIDENTIAL-AADHAAR-XXXX-XXXX"


def make_image(tmp_path, size=8 * 1024 * 1024):
    img = tmp_path / "disk.img"
    with open(img, "wb") as f:
        f.truncate(size)  # sparse: zeros, no disk cost until planted
    return str(img)


def test_plant_then_zero_wipe_removes_all_hits(tmp_path):
    from s0.cli.devices import image_target

    path = make_image(tmp_path)
    target = image_target(path)

    # Fill the sparse file with a non-zero pattern first so zeros actually
    # change bytes (a sparse file is already zero-filled).
    with open(path, "r+b") as f:
        f.write(b"\xa5" * os.path.getsize(path))
    offsets = [i * 1024 * 512 for i in range(16)]
    plant_patterns(path, [(o, MARKER) for o in offsets])
    assert count_pattern_hits(path, MARKER) == 16

    progress = []
    result = OverwriteMethod(passes=1, pattern="zero").run(target, lambda m: progress.append(m))
    assert result.status == "success"
    assert result.bytes_processed == os.path.getsize(path)
    assert len(progress) >= 4  # streamed progress lines
    assert count_pattern_hits(path, MARKER) == 0
    assert count_pattern_hits(path, b"\xa5" * 64) == 0


def test_random_single_pass_changes_content_and_reports_bytes(tmp_path):
    from s0.cli.devices import image_target

    path = make_image(tmp_path)
    with open(path, "r+b") as f:
        f.write(b"\x00" * os.path.getsize(path))
    before = Path(path).read_bytes()

    result = OverwriteMethod(passes=1, pattern="random").run(image_target(path), lambda m: None)
    after = Path(path).read_bytes()
    assert result.status == "success"
    assert before != after
    # CSPRNG output across 8 MiB colliding with all-zeros in any 1KiB window
    # is ~2^-8136; a stable all-zero region means the pass didn't run.
    assert after[:1024] != b"\x00" * 1024


def test_multi_pass_counts_all_bytes(tmp_path):
    from s0.cli.devices import image_target

    path = make_image(tmp_path, size=1024 * 1024)
    size = os.path.getsize(path)
    result = OverwriteMethod(passes=3, pattern="random").run(image_target(path), lambda m: None)
    assert result.bytes_processed == 3 * size


def test_method_id_reflects_policy_choice():
    assert OverwriteMethod(passes=1, pattern="zero").id == "OVERWRITE_ZERO_1PASS"
    assert OverwriteMethod(passes=3, pattern="random").id == "SHRED_RANDOM_NPASS"


def test_unwritable_target_fails_cleanly(tmp_path):
    from s0.cli.devices import Target

    bad = Target(
        path=str(tmp_path / "nope" / "missing.img"),
        kind="image",
        capacity_bytes=4096,
        storage_type="IMAGE_FILE",
    )
    result = OverwriteMethod().run(bad, lambda m: None)
    assert result.status == "failure"
    assert result.errors and "cannot open" in result.errors[0]


def test_plan_honest_about_clear_tier(tmp_path):
    from s0.cli.devices import image_target

    plan = OverwriteMethod(passes=2).plan(image_target(make_image(tmp_path)))
    assert plan.nist_category == "Clear"
    assert any("cannot reach remapped" in w for w in plan.warnings)
    assert any("theater" in w for w in plan.warnings)  # multi-pass honesty note
