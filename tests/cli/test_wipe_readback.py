"""Post-wipe readback must not certify unreadable space as wiped space.

Regression (H2): ``_read_samples`` padded every short read with ``b"\\x00"``
and swallowed all read exceptions, so a device whose readback partially failed
produced zero-filled "samples" that matched the zero wipe pattern -- and the
signed certificate asserted ``all_samples_match_wipe_pattern: true`` for a
medium whose failed sectors were never actually verified as wiped.
"""

from __future__ import annotations

from s0.wipe.methods.base import Target
from s0.wipe.planner import _read_samples, verify_wipe


def _target(path, capacity):
    return Target(
        path=str(path), kind="image", capacity_bytes=capacity, sector_size=512, storage_type="UNKNOWN"
    )


def test_a_failed_read_inside_the_medium_is_reported_not_certified(tmp_path):
    """The core regression: a device that claims 4096 bytes but only serves the
    first 512 used to read back as zeros at the dead offset and PASS."""
    img = tmp_path / "dead_sector.img"
    img.write_bytes(b"\x00" * 512)  # wiped where readable; nothing beyond

    # Capacity claims 4096; the read at offset 2048 hits dead space.
    verif, post = verify_wipe(_target(img, 4096), "zero", offsets=[0, 2048], sample_bytes=512)

    assert verif["all_samples_match_wipe_pattern"] is False, (
        "an incomplete readback must never be certified as a passing wipe"
    )
    assert verif["samples_failed"] == 1
    assert "could not be read" in verif["verification_error"]
    assert verif["samples_checked"] == 1
    assert post[0] == b"\x00" * 512  # the readable sample came through
    assert post[1] is None  # the dead one is None, not zero-filled fiction


def test_a_read_failure_at_the_capacity_edge_is_eof_not_an_error(tmp_path):
    """offset + sample_bytes past the end is a legitimate EOF short read: pad
    to the expected length and keep verifying."""
    img = tmp_path / "edge.img"
    img.write_bytes(b"\x00" * 4096)

    verif, post = verify_wipe(_target(img, 4096), "zero", offsets=[2048], sample_bytes=4096)

    assert verif["all_samples_match_wipe_pattern"] is True
    assert "samples_failed" not in verif
    assert post[0] == b"\x00" * 2048  # padded to expected, not to sample_bytes


def test_an_unopenable_target_yields_zero_read_samples(tmp_path):
    missing = tmp_path / "gone.img"
    verif, post = verify_wipe(_target(missing, 4096), "zero", offsets=[0], sample_bytes=4096)
    assert verif["all_samples_match_wipe_pattern"] is False
    assert verif["samples_checked"] == 0
    assert "could not be read" in verif["verification_error"]
    assert "cannot open" in verif["verification_error"]
    assert post == [None]


def test_an_empty_offset_list_reports_zero_samples(tmp_path):
    img = tmp_path / "empty.img"
    img.write_bytes(b"\x00" * 4096)
    verif, post = verify_wipe(_target(img, 4096), "zero", offsets=[], sample_bytes=4096)
    assert verif["all_samples_match_wipe_pattern"] is False
    assert "Zero readback samples" in verif["verification_error"]
    assert post == []


def test_read_errors_are_listed_per_offset(tmp_path):
    img = tmp_path / "dead_sector.img"
    img.write_bytes(b"\x00" * 512)
    samples, errors = _read_samples(str(img), [0, 2048], 512, capacity=4096)
    assert samples[0] == b"\x00" * 512
    assert samples[1] is None
    assert len(errors) == 1 and "offset 2048" in errors[0]


def test_random_pattern_with_partially_failed_pre_samples_still_compares_pairs(tmp_path):
    """Pre and post samples are aligned with the offsets; a ``None`` on either
    side drops that pair instead of comparing fiction against fiction."""
    import os

    img = tmp_path / "random.img"
    img.write_bytes(os.urandom(64 * 1024))
    target = _target(img, 64 * 1024)

    # Pre-sampling before the wipe: one offset comes back unreadable (None).
    offs = [0, 1024, 4096]
    pre = [os.urandom(1024), None, os.urandom(1024)]
    # Post-wipe the whole image is random again (a random-pattern wipe), so the
    # two surviving pairs both read and count as changed.
    img.write_bytes(os.urandom(64 * 1024))

    verif, post = verify_wipe(target, "random", offsets=offs, sample_bytes=1024, pre_samples=pre)

    assert verif["method"] == "sampled_readback_changed_vs_pre"
    assert verif["samples_checked"] == 3
    assert post[1] is not None  # the post read itself succeeded
    assert verif["all_samples_match_wipe_pattern"] is True


# --------------------------------------------------------------------------- #
# the certificate names the platform it actually ran on
# --------------------------------------------------------------------------- #


def test_certificate_platform_matches_the_host(monkeypatch):
    """Regression: both certificate builders asserted platform='linux'
    unconditionally, so a file erase on macOS or Windows produced a compliance
    document claiming Linux."""
    from s0.wipe import planner

    for sysname, expected in (("linux", "linux"), ("darwin", "macos"), ("win32", "windows")):
        monkeypatch.setattr(planner.sys, "platform", sysname)
        assert planner._platform_name() == expected
