"""Unified progress bar engine for S0 CLI operations.

Features:
- In-place single-line ANSI progress bar when running in a TTY (\r + \033[K)
- Rate-throttled redraws (default min_interval=0.2s) to prevent terminal lag
- Dynamic speed calculation and ETA estimation
- Support for extra status labels (temperature, candidate count, passes)
- Graceful line-by-line fallback when output is redirected (non-TTY)
"""

from __future__ import annotations

import shutil
import sys
import time
from typing import Optional


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
    ):
        self.total = max(int(total_bytes), 1)
        self.operation = operation
        self.stream = stream or sys.stderr
        self.is_tty = hasattr(self.stream, "isatty") and self.stream.isatty()
        self.min_interval = min_interval

        self._start_time = time.monotonic()
        self._last_draw = 0.0
        self._current = 0
        self._extra = ""
        self._finished = False

    def update(self, current_bytes: int, extra: str = "") -> None:
        self._current = min(max(int(current_bytes), 0), self.total)
        self._extra = extra
        now = time.monotonic()
        if (now - self._last_draw) < self.min_interval and self._current < self.total:
            return
        self._last_draw = now
        self._draw()

    def finish(self, extra: str = "") -> None:
        if self._finished:
            return
        self._current = self.total
        if extra:
            self._extra = extra
        self._finished = True
        self._draw()
        if self.is_tty:
            self.stream.write("\n")
            self.stream.flush()

    def close(self) -> None:
        self.finish()

    def _draw(self) -> None:
        elapsed = max(time.monotonic() - self._start_time, 0.001)
        pct = (self._current / self.total) * 100.0
        speed = self._current / elapsed

        filled = int(self.BAR_WIDTH * min(pct, 100.0) / 100.0)
        bar = self.BLOCK_FULL * filled + self.BLOCK_EMPTY * (self.BAR_WIDTH - filled)

        if self._finished or pct >= 100.0:
            eta_str = f"Done in {_fmt_time(elapsed)}"
        elif speed > 0:
            remaining = (self.total - self._current) / speed
            eta_str = f"ETA: {_fmt_time(remaining)}"
        else:
            eta_str = "ETA: --"

        parts = [
            f"[{self.operation}]",
            f"[{bar}]",
            f"{pct:5.1f}%",
            f"{_human(self._current)} / {_human(self.total)}",
            f"{_human(speed)}/s",
            f"Elapsed: {_fmt_time(elapsed)}",
            eta_str,
        ]
        if self._extra:
            parts.append(self._extra)

        line = " | ".join(p for p in parts if p)

        if self.is_tty:
            try:
                cols = shutil.get_terminal_size().columns
            except Exception:
                cols = 120
            if len(line) >= cols:
                line = line[: cols - 1]
            self.stream.write(f"\r{line}\033[K")
            self.stream.flush()
        else:
            # For non-TTY: emit throttled log lines
            self.stream.write(f"{line}\n")
            self.stream.flush()
