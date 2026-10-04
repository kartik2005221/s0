"""A progress bar must never claim work that did not happen.

Three separate lies were reachable from the CLI, all of which looked like
progress reporting and all of which were worse than no bar at all in a tool whose
output ends up attached to a chain-of-custody record:

* A file batch drew one bar with the *summed* size of every target as its total
  and fed it each file's own byte count, so a small file rendered `0 B / 293 KiB`
  -- a denominator belonging to no file the operator was looking at.
* `image` created its bar up front with a placeholder total of 1 byte, so a
  refusal before the first byte was copied printed `1 B / 1 B | 100.0%`.
* `finish()` forced the current position to the total, so every bar ended at
  100% regardless of outcome, and it redrew a frame the producer had already
  drawn, printing the final line twice.
"""

from __future__ import annotations

import io

import pytest

from s0.progress import ProgressBar


def _bar(**kwargs):
    stream = io.StringIO()
    bar = ProgressBar(stream=stream, unicode=True, color=False, **kwargs)
    bar.is_tty = True  # force the newline so line counting is meaningful
    return bar, stream


def test_finish_does_not_force_the_bar_to_100_percent():
    """The core defect: finishing used to imply completion regardless of progress."""
    bar, stream = _bar(total_bytes=1000)
    bar.update(250)
    bar.finish()
    out = stream.getvalue()
    assert "100.0%" not in out, f"a quarter-written bar claimed 100%: {out!r}"
    assert "25.0%" in out, f"the true position was not shown: {out!r}"


def test_abort_states_an_outcome_instead_of_showing_a_percentage():
    bar, stream = _bar(total_bytes=1000)
    bar.update(0)
    bar.abort("REFUSED")
    out = stream.getvalue()
    assert "REFUSED" in out, f"abort did not name the outcome: {out!r}"
    assert "Done in" not in out, f"a refused bar claimed completion: {out!r}"


def test_a_refused_operation_never_draws_a_full_bar():
    """Regression: `1 B / 1 B | 100.0%` for an acquisition that never began."""
    bar, stream = _bar(total_bytes=1)  # the old placeholder total
    bar.abort("REFUSED")
    out = stream.getvalue()
    assert "100.0%" not in out
    assert "1 B / 1 B" not in out, f"the placeholder total was reported as real: {out!r}"


def test_the_final_frame_is_drawn_once():
    """Producers report the last chunk via update(), then call finish()."""
    bar, stream = _bar(total_bytes=1000)
    bar.update(1000)
    bar.finish()
    finals = [ln for ln in stream.getvalue().splitlines() if "100.0%" in ln]
    assert len(finals) == 1, f"the completed bar was printed {len(finals)} times: {finals}"


def test_finish_is_still_idempotent():
    bar, stream = _bar(total_bytes=1000)
    bar.update(1000)
    bar.finish()
    bar.finish()
    bar.close()
    finals = [ln for ln in stream.getvalue().splitlines() if "100.0%" in ln]
    assert len(finals) == 1, f"repeated finish() redrew the bar: {len(finals)}"


class TestPerFileBars:
    def test_each_file_gets_its_own_total(self):
        """The reported per-file total is the denominator, not the batch sum."""
        from s0.cli.ui import UI, OutputPolicy

        ui = UI(OutputPolicy(), "wipe")
        fp = ui.file_progress("s0 wipe")
        totals: list[tuple[int, int]] = []

        class Spy:
            total = 0
            disabled = True  # suppress drawing; we only inspect what it was told

            def update(self, cur, extra=""):
                totals.append((self.total, cur))

            def finish(self, extra=""):
                pass

            def abort(self, reason=""):
                pass

        made: list[int] = []
        real_progress = ui.progress

        def fake_progress(total, **kw):
            made.append(total)
            b = Spy()
            b.total = total
            return b

        ui.progress = fake_progress  # type: ignore[method-assign]
        try:
            fp.update("big.bin", 400_000, 400_000)
            fp.update("small.bin", 900, 900)
            fp.close()
        finally:
            ui.progress = real_progress  # type: ignore[method-assign]

        assert made == [400_000, 900], f"bars were sized {made}, expected one per file"

    def test_a_zero_byte_file_does_not_create_a_bar(self):
        from s0.cli.ui import UI, OutputPolicy

        ui = UI(OutputPolicy(), "wipe")
        fp = ui.file_progress("s0 wipe")
        created: list[int] = []
        ui.progress = lambda total, **kw: created.append(total)  # type: ignore[method-assign]
        fp.update("empty.bin", 0, 0)
        fp.close()
        assert created == [], "a zero-byte file produced a progress bar"


@pytest.mark.parametrize("total", [1, 2, 999])
def test_no_placeholder_total_is_reported_as_real_progress(total):
    """A bar whose total was never learned must not print a confident percentage."""
    bar, stream = _bar(total_bytes=total)
    bar.abort("REFUSED")
    assert "Done in" not in stream.getvalue()
