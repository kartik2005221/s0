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

import argparse
import csv
import json
import sys
import time
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

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
    "EX_OK",
    "EX_FAILURE",
    "EX_USAGE",
    "EX_DATAERR",
    "EX_NOINPUT",
    "EX_UNAVAILABLE",
    "EX_SOFTWARE",
    "EX_CANTCREAT",
    "EX_IOERR",
    "EX_TEMPFAIL",
    "EX_NOPERM",
    "EX_CONFIG",
    "EX_INTERRUPTED",
    "OutputPolicy",
    "Column",
    "render_table",
    "human_bytes",
    "human_int",
    "plural",
    "envelope",
    "artifact",
    "UI",
    "add_global_arguments",
    "policy_from_args",
    "GLOBAL_HELP",
]

GLOBAL_HELP = "output and execution controls (available on every s0 subcommand)"


def add_global_arguments(parser, *, suppress_defaults: bool = False) -> None:
    """Attach the global flags, skipping any a subcommand already declares.

    Idempotence matters: several subcommands already had a bespoke ``--json`` or
    ``--quiet`` of their own, and attaching a second definition would make
    argparse fail at import time. Partial application is therefore the
    correct behaviour, not a fallback.

    ``suppress_defaults`` exists for the copies attached to subparsers. argparse
    parses the top-level flags first and writes them into the namespace, then the
    subparser parses and overwrites the same keys with *its own* defaults. So
    ``s0 --json list`` set ``json=True`` and then had it silently reset to
    ``False``: the command printed human text to stderr, wrote nothing to stdout,
    and exited 0. A script piping to ``jq`` got empty input and no error, which is
    the worst possible failure for this flag. ``SUPPRESS`` means "only set the key
    if the user actually gave the flag here", so the parent's value survives and
    both placements work.
    """
    existing = {opt for action in parser._actions for opt in action.option_strings}

    group = parser.add_argument_group("output")

    def add(group, *flags, **kwargs):
        if any(f in existing for f in flags):
            return
        if suppress_defaults:
            kwargs["default"] = argparse.SUPPRESS
        group.add_argument(*flags, **kwargs)
        existing.update(flags)

    add(
        group,
        "--format",
        choices=("text", "json", "csv"),
        default=None,
        metavar="{text,json,csv}",
        help="output format. 'text' is for humans and is written to stderr, "
        "tables and all; stdout stays empty. Use 'json' or 'csv' to get "
        "anything on stdout that a script can read",
    )
    add(group, "--json", action="store_true", help="shorthand for --format json")
    add(
        group,
        "--quiet",
        "-q",
        action="store_true",
        help="suppress progress bars and banners; results are unaffected",
    )
    add(
        group,
        "--verbose",
        "-v",
        action="count",
        default=0,
        help="increase diagnostic detail on stderr (-v info, -vv debug)",
    )
    add(
        group,
        "--color",
        choices=("auto", "always", "never"),
        default=None,
        help="colour output; 'auto' honours NO_COLOR and TTY detection",
    )
    add(group, "--no-color", action="store_true", help="disable colour output (same as --color never)")

    group2 = parser.add_argument_group("execution")
    add(group2, "--yes", "-y", action="store_true", help="assume yes for destructive confirmations")
    add(group2, "--dry-run", action="store_true", help="plan only; never write to the target")


def policy_from_args(args, *, stdout=None, stderr=None) -> OutputPolicy:
    colour: bool | None = None
    fmt = "text"
    if getattr(args, "no_color", False) or getattr(args, "color", None) == "never":
        colour = False
    elif getattr(args, "color", None) == "always":
        colour = True
    # `--format` is authoritative and `--json` is the shorthand that defers to it.
    # The order matters: `--json` used to win, so `s0 list --json --format csv`
    # silently produced JSON while the operator had last asked for csv on the same
    # command line. A shorthand that overrides the long form is not a shorthand.
    if getattr(args, "format", None):
        fmt = args.format
    elif getattr(args, "json", False):
        fmt = "json"
    return OutputPolicy(
        color=colour,
        quiet=bool(getattr(args, "quiet", False)),
        verbose=int(getattr(args, "verbose", 0) or 0),
        fmt=fmt,
        stream=stdout,
        err_stream=stderr,
    )


def _utc_now() -> str:
    """RFC 3339 UTC with a Z suffix, as the canonical-JSON rules require."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


#: Flags whose value must never reach stdout, because stdout is the envelope.
_SECRET_BEARING = ("--key", "--signing-key", "--key-path", "--token", "--auth-token")


def _redact_argv(argv: list[str]) -> dict[str, Any]:
    """Summarise argv for the envelope, with secret-bearing values replaced.

    Records the flags actually used, because that is what makes an envelope useful
    for correlating a machine-readable result with what was run. A key *path* is not
    itself a secret, but it is a filesystem detail that has no business in output
    meant to be archived, and a `--key` value could be a literal PEM if a caller ever
    allowed that.
    """
    recorded: dict[str, Any] = {}
    redact_next = False
    for token in argv:
        if redact_next:
            # Consumed as a value. It must not become a key: recording
            # `{"/secret/path.pem": "<redacted>"}` puts the very value it was
            # supposed to hide into the key position.
            redact_next = False
            continue
        if token in _SECRET_BEARING:
            recorded[token] = "<redacted>"
            redact_next = True
        elif token.startswith("--"):
            recorded[token] = True
        else:
            # A positional or a flag value; count it without inventing structure.
            recorded["_args"] = recorded.get("_args", 0) + 1
    return recorded


if TYPE_CHECKING:
    from s0.progress import ProgressBar


class UI:
    """A command-scoped printer bound to one :class:`OutputPolicy`."""

    def __init__(self, policy: OutputPolicy, command: str, argv: list[str] | None = None):
        self.policy = policy
        self.command = command
        self._warnings: list[str] = []
        # Populated here rather than by each caller. The envelope has always
        # advertised `invocation.args`, `started_at`, `finished_at` and
        # `duration_seconds`, and every one of them was permanently null or `{}` --
        # a field every call site has to remember is a field none of them remember,
        # and the schema promised something the tool never emitted.
        #
        # `args` is the argv tail after the subcommand, with the signing key path and
        # any other secret-bearing value redacted: this envelope goes to stdout, which
        # is exactly where a key path must not appear.
        self._argv = list(argv or [])
        self._started_monotonic = time.monotonic()
        self._started_at = _utc_now()
        self._errors: list[str] = []
        self._finished: bool = False

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
        self._errors.append(text)
        self.policy.error(text)

    def status(self, state: str, label: str = "") -> str:
        return self.policy.status(state, label)

    def rule(self) -> None:
        self.policy.err()

    def table(self, columns: Sequence[Column], rows: Sequence[Sequence[Any]], max_rows: int = 0) -> None:
        render_table(self.policy, columns, rows, max_rows=max_rows)

    def progress(self, *args, **kwargs) -> ProgressBar:
        """A progress bar that is silent off-TTY and under --quiet/--format json."""
        from s0.progress import ProgressBar  # local: keeps ui importable without a TTY

        disabled = self.policy.quiet or self.policy.fmt != "text"
        kwargs.setdefault("stream", self.policy.err_stream)
        kwargs.setdefault("unicode", self.policy.use_unicode)
        kwargs.setdefault("color", self.policy.use_color)
        return ProgressBar(*args, disable=disabled, **kwargs)

    def file_progress(self, operation: str) -> PerFileProgress:
        """A progress tracker that draws one bar per file, sized for that file."""
        return PerFileProgress(self, operation)

    @property
    def warnings(self) -> list[str]:
        return list(self._warnings)

    # -- envelope ---------------------------------------------------------
    def envelope(self, **kwargs) -> dict[str, Any]:
        return envelope(self.command, **kwargs)

    def finish(
        self,
        *,
        result: Any,
        status: str = "success",
        artifacts: list[dict[str, Any]] | None = None,
        errors: list[dict[str, Any]] | None = None,
        **kwargs,
    ) -> None:
        """Emit the machine-readable envelope when a structured format is asked for.

        `csv` is rendered from the same `result` payload as `json`, generically,
        rather than per command. Only `s0 list` had a CSV renderer; the other eight
        call sites tested `fmt in ("json", "csv")`, skipped their human branch, and
        then this method emitted nothing at all -- so `s0 plan --format csv > p.csv`
        produced a zero-byte file and exited 0. A flag that is accepted, does
        nothing, and reports success is worse than a flag that is absent.
        """
        self._finished = True
        if self.policy.fmt == "json":
            finished_at = _utc_now()
            kwargs.setdefault("args", _redact_argv(self._argv))
            kwargs.setdefault("started_at", self._started_at)
            kwargs.setdefault("finished_at", finished_at)
            kwargs.setdefault("duration_seconds", int(time.monotonic() - self._started_monotonic))
            self.policy.json(
                self.envelope(
                    result=result,
                    status=status,
                    artifacts=artifacts,
                    errors=errors,
                    warnings=self._warnings,
                    **kwargs,
                )
            )
        elif self.policy.fmt == "csv":
            write_csv_rows(result, stream=sys.stdout)


def _csv_cell(value: Any) -> str:
    """One CSV cell.

    Nested structures are JSON-encoded rather than str()'d, because Python's repr
    uses single quotes and is not valid JSON -- a CSV consumer would choke. `None`
    is the empty cell, matching every spreadsheet's expectation.
    """
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, sort_keys=True, separators=(",", ":"))
    return str(value)


def write_csv_rows(result: Any, *, stream=None) -> None:
    """Render an envelope `result` payload as CSV.

    Three shapes, because subcommands return three shapes:

    * a list of flat dicts -- the common "many records" case (`carve` files,
      `audit` blocks, `image` artifacts). One row per record, columns are the
      union of keys in first-seen order so the output is stable.
    * a single dict -- one row, one column per key.
    * anything else -- one row, one `value` column.

    An empty result still emits a header, so a downstream `csv.DictReader` gets a
    valid (if empty) document rather than an error.
    """
    out = stream if stream is not None else sys.stdout

    if isinstance(result, list) and result and all(isinstance(r, dict) for r in result):
        columns: list[str] = []
        for row in result:
            for key in row:
                if key not in columns:
                    columns.append(key)
        writer = csv.writer(out, lineterminator="\n")
        writer.writerow(columns)
        for row in result:
            writer.writerow([_csv_cell(row.get(c)) for c in columns])
        return

    if isinstance(result, dict):
        # If the payload wraps a single list of records (the shape `audit list` uses:
        # {"block_count": 50, "blocks": [...]}), expand that list to one row per
        # record and carry the sibling scalars down as extra columns. Otherwise the
        # entire ledger collapses into one unreadable JSON cell.
        record_lists = [
            (k, v)
            for k, v in result.items()
            if isinstance(v, list) and v and all(isinstance(r, dict) for r in v)
        ]
        if len(record_lists) == 1:
            key, records = record_lists[0]
            siblings = [k for k in result if k != key]
            columns: list[str] = list(records[0].keys()) + siblings
            writer = csv.writer(out, lineterminator="\n")
            writer.writerow(columns)
            for row in records:
                writer.writerow(
                    [_csv_cell(row.get(c)) for c in columns[: len(records[0])]]
                    + [_csv_cell(result[s]) for s in siblings]
                )
            return

        columns = list(result.keys())
        writer = csv.writer(out, lineterminator="\n")
        writer.writerow(columns)
        writer.writerow([_csv_cell(result[c]) for c in columns])
        return

    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(["value"])
    writer.writerow([_csv_cell(result)])


def fail(ui: UI, code: int, message: str, *, hint: str = "") -> int:
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


class PerFileProgress:
    """One bar per file, each sized from the total reported for *that* file.

    The batch file eraser reports progress as ``(path, written, file_total)``,
    one file at a time. The obvious wiring is a single bar created from the sum of
    all target sizes, and that is what this replaced -- which meant file 3 of 9
    could render ``12.0 KiB / 293.0 KiB``, a denominator belonging to no file the
    operator was looking at, and a small file in a mixed batch looked barely
    started. The per-file total is already in the callback; it just has to be used
    as the bar's total instead of discarded.

    The bar is closed and a fresh one opened when the path changes, so each file
    gets its own final line instead of overwriting the last.
    """

    def __init__(self, ui: UI, operation: str):
        self._ui = ui
        self._operation = operation
        self._path: str | None = None
        self._bar: ProgressBar | None = None

    def update(self, path_str: str, written: int, total_for_file: int) -> None:
        if self._bar is None or path_str != self._path:
            self.close()
            self._path = path_str
            if total_for_file > 0:
                self._bar = self._ui.progress(
                    total_for_file,
                    operation=self._operation,
                    min_interval=0.05,
                )
        if self._bar is not None:
            self._bar.update(written, extra=Path(path_str).name[:20])

    def close(self, extra: str = "") -> None:
        if self._bar is not None:
            if extra:
                self._bar.abort(extra)
            else:
                self._bar.finish()
            self._bar = None
        self._path = None
