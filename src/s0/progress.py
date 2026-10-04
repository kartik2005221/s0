"""Unified progress bar engine for S0 CLI operations.

Features:
- In-place single-line ANSI progress bar when running in a TTY (\r + \033[K)
- Rate-throttled redraws (default min_interval=0.2s) to prevent terminal lag
- Dynamic speed calculation and ETA estimation
- Support for extra status labels (temperature, candidate count, passes)
- Graceful line-by-line fallback when output is redirected (non-TTY)
"""

from __future__ import annotations

import os
import shutil
import sys
import time


def _human(n: float) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(n) < 1024 or unit == "TiB":
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TiB"


def _fmt_time(seconds: float) -> str:
    if seconds < 0:
        return "00s"
    if seconds < 60:
        return f"{int(seconds):02d}s"
    m, s = divmod(int(seconds), 60)
    if m < 60:
        return f"{m:02d}m {s:02d}s"
    h, m = divmod(m, 60)
    return f"{h}h {m:02d}m"


class ProgressBar:
    """Unified terminal progress indicator for wiping and carving."""

    BLOCK_FULL = "█"
    BLOCK_EMPTY = "░"
    BAR_WIDTH = 20

    def __init__(
        self,
        total_bytes: int,
        operation: str = "s0",
        stream=None,
        min_interval: float = 0.2,
        disable: bool = False,
        unicode: bool | None = None,
        color: bool | None = None,
    ):
        self.total = max(int(total_bytes), 1)
        self.operation = operation
        self.stream = stream or sys.stderr
        self.is_tty = hasattr(self.stream, "isatty") and self.stream.isatty()
        self.min_interval = min_interval
        # --quiet, --format json, and non-TTY all suppress the bar entirely.
        # A forensic tool that scribbles redraws into a CI log is unusable.
        self.disabled = bool(disable)
        if unicode is None:
            enc = (getattr(self.stream, "encoding", None) or "").lower()
            unicode = self.is_tty and ("utf" in enc or os.environ.get("S0_FORCE_UNICODE") == "1")
        self.unicode = bool(unicode)
        self.color = bool(color) if color is not None else self.is_tty
        self.block_full = "\u2588" if self.unicode else "#"
        self.block_empty = "\u2591" if self.unicode else "."
        self.bar_width = 20

        self._start_time = time.monotonic()
        self._last_draw = 0.0
        self._current = 0
        self._extra = ""
        self._finished = False
        # Whether the last frame already drawn was the final one. Producers
        # routinely report the last chunk via `update(written == total)` and then
        # call `finish()`. Without this, `finish()` drew the identical 100% frame
        # a second time, so every completed wipe printed its final bar twice.
        self._drew_final = False

    def update(self, current_bytes: int, extra: str = "") -> None:
        if self.disabled:
            return
        self._current = min(max(int(current_bytes), 0), self.total)
        self._extra = extra
        now = time.monotonic()
        if (now - self._last_draw) < self.min_interval and self._current < self.total:
            return
        self._last_draw = now
        self._draw()

    def finish(self, extra: str = "") -> None:
        """Close the bar, reporting only the progress that actually happened.

        This used to set ``_current = self.total`` before drawing, which made
        every bar end at 100% no matter how little was written. For a refused or
        failed operation that is the worst possible output: a full, green-looking
        bar for work that never occurred. A producer that reports every byte
        already reaches ``total`` on its own, so nothing is lost by not forcing
        it, and a short final frame is the truth.
        """
        if self.disabled or self._finished:
            return
        if extra:
            self._extra = extra
        self._finished = True
        if not self._drew_final or extra:
            self._draw()
        self._newline()

    def abort(self, reason: str = "") -> None:
        """Close the bar without claiming the work completed.

        Distinct from ``finish(extra=...)``: this states an outcome, so the frame
        says so in words rather than relying on a percentage the operator has to
        interpret.
        """
        if self.disabled or self._finished:
            return
        label = f"STOPPED: {reason}" if reason else "STOPPED"
        self._extra = f"{self._extra} | {label}" if self._extra else label
        self._finished = True
        self._draw()
        self._newline()

    def _newline(self) -> None:
        if self.is_tty:
            self.stream.write("\n")
            self.stream.flush()

    def close(self) -> None:
        self.finish()

    def _draw(self) -> None:
        self._drew_final = self._finished or self._current >= self.total
        elapsed = max(time.monotonic() - self._start_time, 0.001)
        pct = (self._current / self.total) * 100.0
        speed = self._current / elapsed

        filled = int(self.bar_width * min(pct, 100.0) / 100.0)
        bar = self.block_full * filled + self.block_empty * (self.bar_width - filled)

        if pct >= 100.0:
            eta_str = f"Done in {_fmt_time(elapsed)}"
        elif speed > 0:
            remaining = (self.total - self._current) / speed
            eta_str = f"ETA: {_fmt_time(remaining)}"
        else:
            eta_str = "ETA: --"

        # The leading segments and the trailing label are load-bearing: the first
        # tell you which operation this is, the last tells you how it ended. The
        # middle ones are decoration. This used to build one string and slice it to
        # the terminal width, which silently cut the trailing label -- so on a
        # narrow terminal a REFUSED or CANCELLED bar rendered as an unfinished-looking
        # bar that named no outcome at all. Drop the optional segments instead.
        head = [
            f"[{self.operation}]",
            f"[{bar}]",
            f"{pct:5.1f}%",
            f"{_human(self._current)} / {_human(self.total)}",
        ]
        middle = [
            f"{_human(speed)}/s",
            f"Elapsed: {_fmt_time(elapsed)}",
            eta_str,
        ]
        tail = [self._extra] if self._extra else []

        def join(parts: list[str]) -> str:
            return " | ".join(p for p in parts if p)

        try:
            cols = shutil.get_terminal_size().columns
        except Exception:
            cols = 120

        line = join(head + middle + tail)
        # Give up the decoration in order of how little it matters: the rate, then
        # elapsed time, then the ETA (which on a finished bar is the least useful
        # thing on the line). Each pass drops one more, so a very narrow terminal
        # still keeps the operation, the bar, the byte counts and the outcome.
        for drop in range(len(middle) + 1):
            if len(line) <= cols - 1:
                break
            line = join(head + middle[drop:] + tail)

        if len(line) > cols - 1:
            # Even with every decorative segment gone the operation name, the byte
            # counts and the outcome can exceed a very narrow terminal. Squeeze the
            # head rather than slicing the assembled line, so the outcome is never
            # the thing that gets cut. Overflowing instead would wrap the line and
            # leave a trail of stale bars on a real terminal.
            tail_text = f" | {join(tail)}" if tail else ""
            budget = max(cols - 1 - len(tail_text), 16)
            line = join(head)[:budget].rstrip(" |") + tail_text

        if self.is_tty:
            self.stream.write(f"\r{line}\033[K")
            self.stream.flush()
        else:
            # For non-TTY: emit throttled log lines
            self.stream.write(f"{line}\n")
            self.stream.flush()
