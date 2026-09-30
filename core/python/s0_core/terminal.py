"""Unified CLI presentation policy.

Every s0 subcommand renders through this module so that output is identical in
shape across the whole surface, and so that the same environment produces the
same output on a developer's terminal, in CI, in a piped shell, and in the
live-ISO kiosk where there is no TTY at all.

The rules, and why:

* **stdout carries data, stderr carries chrome.** Progress bars, banners,
  warnings and prompts go to stderr. Only the result goes to stdout. This is
  what lets `s0 audit list --json | jq` work.
* **Colour is opt-out, never opt-in.** `NO_COLOR` disables it, `CLICOLOR_FORCE`
  and `FORCE_COLOR` enable it, `--color` overrides both, and otherwise it
  follows `isatty()`.
* **A non-TTY degrades, it does not change format.** Piped text output becomes
  one record per line with no box drawing, no colour and no progress redraw. It
  never silently switches to JSON, because that hides intent.
* **Status is never conveyed by colour alone.** Every state carries a glyph and
  a word, so the output survives `--no-color`, a monochrome terminal, a printed
  report and a screen reader.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence

# --------------------------------------------------------------------------- #
# exit codes -- sysexits.h, because "1 means everything" is not an API
# --------------------------------------------------------------------------- #

EX_OK = 0
EX_FAILURE = 1
EX_USAGE = 64            # bad flags or arguments
EX_DATAERR = 65          # user-supplied data is malformed
EX_NOINPUT = 66          # input file missing or unreadable
EX_NOUSER = 67
EX_NOHOST = 68
EX_UNAVAILABLE = 69      # a required program or service is unavailable
EX_SOFTWARE = 70         # internal error
EX_OSERR = 71
EX_CANTCREAT = 73        # output file cannot be created
EX_IOERR = 74            # I/O error during the operation
EX_TEMPFAIL = 75         # temporary failure, retryable (device busy)
EX_NOPERM = 77           # permission denied
EX_CONFIG = 78           # configuration error
EX_INTERRUPTED = 130     # SIGINT

EXIT_MEANINGS = {
    EX_OK: "success",
    EX_FAILURE: "completed with an integrity finding",
    EX_USAGE: "invalid usage",
    EX_DATAERR: "malformed input data",
    EX_NOINPUT: "input missing or unreadable",
    EX_UNAVAILABLE: "required capability unavailable",
    EX_SOFTWARE: "internal error",
    EX_CANTCREAT: "cannot create output",
    EX_IOERR: "I/O error",
    EX_TEMPFAIL: "temporary failure, safe to retry",
    EX_NOPERM: "permission denied",
    EX_CONFIG: "configuration error",
    EX_INTERRUPTED: "interrupted by the operator",
}

# --------------------------------------------------------------------------- #
# colour
# --------------------------------------------------------------------------- #

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"

STATUS_STYLES = {
    "ok": (GREEN, "✓", "OK"),
    "warn": (YELLOW, "!", "WARN"),
    "error": (RED, "✗", "ERROR"),
    "info": (BLUE, "i", "INFO"),
    "skip": (DIM, "-", "SKIP"),
}

# Box drawing is only safe on a UTF-8 TTY.
UNICODE_BOX = {
    "h": "─", "v": "│", "tl": "┌", "tr": "┐", "bl": "└", "br": "┘",
}
ASCII_BOX = {"h": "-", "v": "|", "tl": "+", "tr": "+", "bl": "+", "br": "+"}


@dataclass
class OutputPolicy:
    """Resolved presentation settings for one process."""

    color: Optional[bool] = None
    quiet: bool = False
    verbose: int = 0
    fmt: str = "text"                 # text | json | csv
    # Streams default to the real stdout/stderr but are injectable so tests and
    # the ISO kiosk can render into a buffer.
    stream: Optional[Any] = None
    err_stream: Optional[Any] = None

    def __post_init__(self) -> None:
        self.stream = self.stream if self.stream is not None else sys.stdout
        self.err_stream = self.err_stream if self.err_stream is not None else sys.stderr

    # -- capability detection ------------------------------------------------
    @property
    def is_tty(self) -> bool:
        try:
            return bool(self.stream.isatty())
        except Exception:
            return False

    @property
    def err_is_tty(self) -> bool:
        try:
            return bool(self.err_stream.isatty())
        except Exception:
            return False

    @property
    def use_color(self) -> bool:
        if self.color is not None:
            return self.color
        if os.environ.get("NO_COLOR"):
            return False
        if os.environ.get("CLICOLOR_FORCE") or os.environ.get("FORCE_COLOR"):
            return True
        if os.environ.get("TERM") == "dumb":
            return False
        return self.is_tty

    @property
    def use_unicode(self) -> bool:
        if not self.is_tty:
            return False
        enc = (getattr(self.stream, "encoding", None) or "").lower()
        if "utf" in enc:
            return True
        for var in ("LC_ALL", "LC_CTYPE", "LANG"):
            if "utf" in (os.environ.get(var, "").lower()):
                return True
        return False

    @property
    def box(self) -> Dict[str, str]:
        return UNICODE_BOX if self.use_unicode else ASCII_BOX

    @property
    def width(self) -> int:
        try:
            cols = shutil.get_terminal_size(fallback=(100, 24)).columns
        except Exception:
            cols = 100
        return max(60, min(cols, 200))

    # -- writing -------------------------------------------------------------
    def out(self, text: str = "") -> None:
        """Result data. stdout only."""
        self.stream.write(text + "\n")

    def raw(self, text: str) -> None:
        self.stream.write(text)

    def err(self, text: str = "") -> None:
        """Human chrome. stderr only, suppressed by --quiet."""
        if not self.quiet:
            self.err_stream.write(text + "\n")
            try:
                self.err_stream.flush()
            except Exception:
                pass

    def note(self, text: str) -> None:
        """Operator-facing prose: always shown, even when quiet."""
        self.err_stream.write(text + "\n")

    def warn(self, text: str) -> None:
        self.err(f"{self.glyph('warn')} {text}")

    def error(self, text: str) -> None:
        self.err_stream.write(f"{self.glyph('error')} {text}\n")

    def glyph(self, state: str) -> str:
        """A coloured status marker. Never the sole carrier of meaning."""
        colour, mark, _ = STATUS_STYLES.get(state, ("", "?", ""))
        return f"{colour}{mark}{RESET}" if colour and self.use_color else mark

    def paint(self, status: str, text: str = "") -> str:
        colour = STATUS_STYLES.get(status, ("", "", ""))[0]
        if not colour or not self.use_color or not text:
            return text
        return f"{colour}{text}{RESET}"

    def status(self, state: str, label: str = "") -> str:
        """`OK label`, always with glyph and word so colour is never the only cue."""
        colour, glyph, word = STATUS_STYLES.get(state, ("", "?", "UNKNOWN"))
        text = f"{glyph} {word}" + (f" {label}" if label else "")
        if colour and self.use_color:
            return f"{colour}{text}{RESET}"
        return text

    def banner(self, title: str) -> None:
        b = self.box
        inner = self.width - 2
        self.err(f"{b['tl']}{b['h'] * inner}{b['tr']}")
        self.err(self._centre(title, inner))
        self.err(f"{b['bl']}{b['h'] * inner}{b['br']}")

    def _centre(self, text: str, inner: int) -> str:
        b = self.box
        pad = max(0, inner - len(text))
        left = pad // 2
        right = pad - left
        if self.use_color:
            text = f"{BOLD}{text}{RESET}"
            # reset codes are invisible, so pad using the raw length
            plain_len = len(text) - len(BOLD) - len(RESET)
            pad = max(0, inner - plain_len)
            left = pad // 2
            right = pad - left
        return f"{b['v']}{' ' * left}{text}{' ' * right}{b['v']}"

    def rule(self) -> None:
        self.err(self.box["h"] * self.width)

    def json(self, obj: Any) -> None:
        self.stream.write(json.dumps(obj, indent=2, sort_keys=False) + "\n")

    def kv(self, key: str, value: Any, key_width: int = 22) -> None:
        self.err(f"  {self.paint('info', key.ljust(key_width))}{value}")


# --------------------------------------------------------------------------- #
# tables
# --------------------------------------------------------------------------- #


@dataclass
class Column:
    title: str
    align: str = "l"                 # l | r
    max_width: Optional[int] = None
    min_width: int = 0


def render_table(policy: OutputPolicy, columns: Sequence[Column],
                 rows: Iterable[Sequence[Any]], *, max_rows: int = 0) -> None:
    """Render a table to stderr so it never contaminates piped stdout data.

    Numeric columns are right-aligned, long paths are ellipsised from the left
    (the tail is what identifies a file), and the truncation notice follows the
    established "and N more" convention.
    """
    rows = [[("" if c is None else str(c)) for c in row] for row in rows]
    truncated = 0
    if max_rows and len(rows) > max_rows:
        truncated = len(rows) - max_rows
        rows = rows[:max_rows]
    if not rows:
        return

    widths = []
    for i, col in enumerate(columns):
        longest = max([len(col.title)] + [len(r[i]) for r in rows])
        if col.max_width:
            longest = min(longest, col.max_width)
        widths.append(max(col.min_width, longest))

    header = "  ".join(
        c.title.ljust(w) if c.align == "l" else c.title.rjust(w)
        for c, w in zip(columns, widths))
    policy.err("  " + header)
    policy.err("  " + policy.box["h"] * len(header))
    for row in rows:
        cells = []
        for value, col, w in zip(row, columns, widths):
            value = _ellipsise_left(value, w) if col.align == "l" else _ellipsise_right(value, w)
            cells.append(value.ljust(w) if col.align == "l" else value.rjust(w))
        policy.err("  " + "  ".join(cells))
    if truncated:
        policy.err(f"  ... and {truncated} more (see the machine-readable index or use --limit 0)")


def _ellipsise_left(value: str, width: int) -> str:
    if len(value) <= width:
        return value
    if width <= 3:
        return value[-width:]
    return "..." + value[-(width - 3):]


def _ellipsise_right(value: str, width: int) -> str:
    if len(value) <= width:
        return value
    if width <= 3:
        return value[:width]
    return value[:width - 3] + "..."


def human_bytes(n: Optional[int], *, binary: bool = True) -> str:
    if n is None:
        return "-"
    step = 1024 if binary else 1000
    units = ("B", "KiB", "MiB", "GiB", "TiB", "PiB") if binary else ("B", "kB", "MB", "GB", "TB", "PB")
    if n < step:
        return f"{n} B"
    value = float(n)
    for unit in units[1:]:
        value /= step
        if value < step:
            return f"{value:.2f} {unit}"
    return f"{value:.2f} {units[-1]}"


def human_int(n: int) -> str:
    return f"{n:,}"


def plural(n: int, singular: str, plural_form: Optional[str] = None) -> str:
    return f"{human_int(n)} {singular if n == 1 else (plural_form or singular + 's')}"


# --------------------------------------------------------------------------- #
# output envelope -- one schema for every subcommand
# --------------------------------------------------------------------------- #


def envelope(command: str, *, status: str, result: Any = None,
             artifacts: Optional[List[Dict[str, Any]]] = None,
             warnings: Optional[List[str]] = None,
             errors: Optional[List[Dict[str, Any]]] = None,
             audit: Optional[Dict[str, Any]] = None,
             signature: Optional[Dict[str, Any]] = None,
             started_at: Optional[str] = None,
             finished_at: Optional[str] = None,
             duration_seconds: Optional[int] = None,
             args: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Build the versioned machine-readable envelope every `--json` uses.

    Invariants (see core/CANONICAL_JSON.md rule 5): integers only, absolute
    paths, RFC 3339 UTC timestamps with a `Z` suffix.
    """
    from .config import CONFIG

    body: Dict[str, Any] = {
        "schema": f"s0.{command}/1",
        "schema_version": "1.0.0",
        "tool": {
            "name": "s0",
            "version": str(CONFIG.get("version", "0")),
            "platform": sys.platform,
        },
        "invocation": {
            "command": command,
            "args": args or {},
            "started_at": started_at,
            "finished_at": finished_at,
            "duration_seconds": duration_seconds,
        },
        "status": status,
        "warnings": list(warnings or []),
        "errors": list(errors or []),
        "result": result if result is not None else {},
    }
    if artifacts:
        body["artifacts"] = artifacts
    if audit:
        body["audit"] = audit
    if signature:
        body["signature"] = signature
    return body


def artifact(path, kind: str, sha256: Optional[str] = None,
             size_bytes: Optional[int] = None) -> Dict[str, Any]:
    from pathlib import Path
    p = Path(path)
    entry: Dict[str, Any] = {"kind": kind, "path": str(p.resolve())}
    if sha256:
        entry["sha256"] = sha256
    try:
        entry["size_bytes"] = p.stat().st_size
    except OSError:
        pass
    return entry
