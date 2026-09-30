"""Presentation layer for the s0 CLI.

The whole surface renders through here so that every subcommand obeys the same
contract:

* **stdout is data, stderr is chrome.** Progress bars, banners, warnings and
  prompts never touch stdout, so ``s0 audit list --json | jq`` is always safe.
* **Identical global flags** on every command: ``--format``, ``--json``,
  ``--quiet``, ``--verbose``, ``--color``, ``--no-color``, ``--yes``, ``--dry-run``.
* **Identical exit codes** from ``sysexits.h``.
* **Status is never colour alone** -- glyph plus word, always.

Commands ask this module for a printer; they never call ``print()`` directly.
"""

from __future__ import annotations

import io
import os
import sys
from typing import Any, Dict, List, Optional, Sequence

from s0.terminal import (  # re-exported so callers need one import
    EX_CANTCREAT,
    EX_CONFIG,
    EX_DATAERR,
    EX_FAILURE,
    EX_INTERRUPTED,
    EX_IOERR,
    EX_NOINPUT,
    EX_NOPERM,
    EX_OK,
    EX_SOFTWARE,
    EX_TEMPFAIL,
    EX_UNAVAILABLE,
    EX_USAGE,
    Column,
    OutputPolicy,
    artifact,
    envelope,
    human_bytes,
    human_int,
    plural,
    render_table,
)

__all__ = [
    "EX_OK", "EX_FAILURE", "EX_USAGE", "EX_DATAERR", "EX_NOINPUT",
    "EX_UNAVAILABLE", "EX_SOFTWARE", "EX_CANTCREAT", "EX_IOERR",
    "EX_TEMPFAIL", "EX_NOPERM", "EX_CONFIG", "EX_INTERRUPTED",
    "OutputPolicy", "Column", "render_table", "human_bytes", "human_int",
    "plural", "envelope", "artifact", "UI", "add_global_arguments",
    "policy_from_args", "GLOBAL_HELP",
]

GLOBAL_HELP = "output and execution controls (available on every s0 subcommand)"


def add_global_arguments(parser) -> None:
    """Attach the global flags, skipping any a subcommand already declares.

    Idempotence matters: several subcommands already had a bespoke ``--json`` or
    ``--quiet`` of their own, and attaching a second definition would make
    argparse fail at import time. Partial application is therefore the
    correct behaviour, not a fallback.
    """
    existing = {opt for action in parser._actions for opt in action.option_strings}

    group = parser.add_argument_group("output")
    def add(group, *flags, **kwargs):
        if any(f in existing for f in flags):
            return
        group.add_argument(*flags, **kwargs)
        existing.update(flags)

    add(group, "--format", choices=("text", "json", "csv"), default=None,
        metavar="{text,json,csv}",
        help="output format; 'text' degrades to one record per line "
             "when stdout is not a terminal")
    add(group, "--json", action="store_true",
        help="shorthand for --format json")
    add(group, "--quiet", "-q", action="store_true",
        help="suppress progress bars and banners; results are unaffected")
    add(group, "--verbose", "-v", action="count", default=0,
        help="increase diagnostic detail on stderr (-v info, -vv debug)")
    add(group, "--color", choices=("auto", "always", "never"), default=None,
        help="colour output; 'auto' honours NO_COLOR and TTY detection")
    add(group, "--no-color", action="store_true",
        help="disable colour output (same as --color never)")

    group2 = parser.add_argument_group("execution")
    add(group2, "--yes", "-y", action="store_true",
        help="assume yes for destructive confirmations")
    add(group2, "--dry-run", action="store_true",
        help="plan only; never write to the target")


def policy_from_args(args, *, stdout=None, stderr=None) -> OutputPolicy:
    colour: Optional[bool] = None
    fmt = "text"
    if getattr(args, "no_color", False) or getattr(args, "color", None) == "never":
        colour = False
    elif getattr(args, "color", None) == "always":
        colour = True
    if getattr(args, "json", False):
        fmt = "json"
    elif getattr(args, "format", None):
        fmt = args.format
    return OutputPolicy(
        color=colour,
        quiet=bool(getattr(args, "quiet", False)),
        verbose=int(getattr(args, "verbose", 0) or 0),
        fmt=fmt,
        stream=stdout,
        err_stream=stderr,
    )


class UI:
    """A command-scoped printer bound to one :class:`OutputPolicy`."""

    def __init__(self, policy: OutputPolicy, command: str):
        self.policy = policy
        self.command = command
        self._warnings: List[str] = []

    # -- data (stdout) ----------------------------------------------------
    def line(self, text: str = "") -> None:
        self.policy.out(text)

    def data(self, text: str) -> None:
        self.policy.raw(text)

    def emit_json(self, obj: Any) -> None:
        self.policy.json(obj)

    # -- chrome (stderr) --------------------------------------------------
    def note(self, text: str = "") -> None:
        self.policy.err(text)

    def banner(self, title: str) -> None:
        self.policy.banner(title)

    def heading(self, text: str) -> None:
        self.policy.err("")
        self.policy.err(self.policy.paint("info", text))

    def key(self, k: str, v: Any, width: int = 24) -> None:
        self.policy.kv(k, v, width)

    def warn(self, text: str) -> None:
        self._warnings.append(text)
        self.policy.warn(text)

    def error(self, text: str) -> None:
        self.policy.error(text)

    def status(self, state: str, label: str = "") -> str:
        return self.policy.status(state, label)

    def rule(self) -> None:
        self.policy.err()

    def table(self, columns: Sequence[Column], rows: Sequence[Sequence[Any]],
              max_rows: int = 0) -> None:
        render_table(self.policy, columns, rows, max_rows=max_rows)

    def progress(self, *args, **kwargs):
        """A progress bar that is silent off-TTY and under --quiet/--format json."""
        from s0.progress import ProgressBar
        disabled = self.policy.quiet or self.policy.fmt != "text"
        kwargs.setdefault("stream", self.policy.err_stream)
        kwargs.setdefault("unicode", self.policy.use_unicode)
        kwargs.setdefault("color", self.policy.use_color)
        return ProgressBar(*args, disable=disabled, **kwargs)

    @property
    def warnings(self) -> List[str]:
        return list(self._warnings)

    # -- envelope ---------------------------------------------------------
    def envelope(self, **kwargs) -> Dict[str, Any]:
        return envelope(self.command, **kwargs)

    def finish(self, *, result: Any, status: str = "success",
               artifacts: Optional[List[Dict[str, Any]]] = None,
               errors: Optional[List[Dict[str, Any]]] = None,
               **kwargs) -> None:
        """Emit the machine-readable envelope when a structured format is asked for."""
        if self.policy.fmt == "json":
            self.policy.json(self.envelope(
                result=result, status=status, artifacts=artifacts,
                errors=errors, warnings=self._warnings, **kwargs))


def fail(ui: "UI", code: int, message: str, *, hint: str = "") -> int:
    """Report a failure the one way every command reports failures."""
    if ui is not None:
        ui.error(message)
        if hint:
            ui.policy.err(f"  {hint}")
    else:
        sys.stderr.write(f"error: {message}\n")
        if hint:
            sys.stderr.write(f"  {hint}\n")
    return code
