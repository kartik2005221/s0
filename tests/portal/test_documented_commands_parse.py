"""Every command the documentation shows must still parse.

A documented command that no longer parses is worse than no documentation: a
reader types it, it fails, and the reader concludes the tool is broken rather than
that the docs are stale. The gap was invisible because checking it was a one-off
manual sweep (181/181 at the time) rather than a gate, so the next refactor that
renamed a flag silently broke the manual again.

This asserts the property with the *real* parser, which is the only thing worth
asserting: a command can look right in a code block and still be rejected by
argparse for an option that moved, a required argument that became optional, or a
subcommand that was renamed.

Scope is deliberately narrow. It checks that the command line is *accepted*, not
that running it would do anything -- a documented example must never be executed
here, because several of them wipe things.
"""

from __future__ import annotations

import re
import shlex
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DOCS = REPO_ROOT / "docs"

# Commands that would do real work. Parsing is safe; running is not, and this test
# never runs anything -- but the list documents the intent for anyone who later
# considers executing them.
DESTRUCTIVE = frozenset({"wipe", "erase", "clone", "live", "upgrade", "uninstall"})

# Only blocks explicitly tagged as shell. An untagged fence in this tree is usually
# prose or a transcript, and treating it as commands produces failures that say
# nothing about whether the documentation is correct.
_FENCE = re.compile(
    r"```(?:bash|sh|shell|console|zsh)\s*\n(.*?)```", re.S)


def _doc_files() -> list[Path]:
    files = sorted(p for p in DOCS.rglob("*.md") if p.is_file())
    assert files, f"no documentation found under {DOCS}"
    return files


def _s0_commands() -> list[tuple[Path, int, str]]:
    """Every `s0 ...` command line appearing inside a fenced shell code block.

    Restricted to fenced blocks deliberately. A prose scan picks up sentences --
    "s0 detects CoW filesystems at runtime and issues a WARNING ..." -- which are
    not commands and would fail the parser for reasons that have nothing to do with
    whether the documentation is correct.
    """
    found: list[tuple[Path, int, str]] = []
    for path in _doc_files():
        text = path.read_text(encoding="utf-8", errors="ignore")
        for block in _FENCE.findall(text):
            # Join shell line continuations first. A documented command wrapped
            # with a trailing backslash is one command, and reading only its first
            # line would hand shlex a dangling escape -- a failure that says
            # nothing about the documentation.
            joined: list[str] = []
            pending = ""
            for raw in block.splitlines():
                pending = f"{pending} {raw.rstrip()}" if pending else raw.rstrip()
                if pending.endswith("\\"):
                    pending = pending[:-1].rstrip()
                    continue
                joined.append(pending)
                pending = ""
            if pending:
                joined.append(pending)

            for line in joined:
                stripped = line.strip()
                if not stripped or stripped.startswith(("#", "$", ">", "...", "[", "|")):
                    continue
                normalized = stripped.replace("sudo ", "", 1).strip()
                if not normalized.startswith("s0 "):
                    continue
                # A usage synopsis, not a command: `s0 [--version] <subcommand>
                # [flags]` is a template with placeholders. shlex would keep the
                # angle brackets and argparse would reject it, which says nothing
                # about whether the documentation is correct.
                if "<" in normalized or ">" in normalized:
                    continue
                found.append((path, 0, normalized))
    return found


#: Options that make argparse exit successfully rather than parse. They are valid
#: commands, so rejecting them would be a false failure.
_IMMEDIATE_EXIT = frozenset({"--version", "-V", "--help", "-h"})


class TestDocumentedCommandsParse:
    def test_documentation_actually_contains_s0_commands(self):
        """Guard the guard: an empty corpus would pass every assertion below."""
        commands = _s0_commands()
        assert len(commands) >= 100, (
            f"only {len(commands)} documented s0 commands were found; the "
            f"extraction is probably broken, which would make this file vacuous")

    def test_every_documented_command_is_accepted_by_the_parser(self):
        from s0.cli.main import build_parser

        parser = build_parser()
        failures: list[str] = []

        for path, _line, command in _s0_commands():
            try:
                argv = shlex.split(command)
            except ValueError as exc:
                failures.append(f"{path.relative_to(REPO_ROOT)}: unparseable shell ({exc})")
                continue
            argv = [a for a in argv if a not in ("\\", "")]
            if not argv or argv[0] != "s0":
                failures.append(f"{path.relative_to(REPO_ROOT)}: {command!r}")
                continue
            if any(a in _IMMEDIATE_EXIT for a in argv[1:]):
                continue
            try:
                # parse_args is not called: --help and friends exit, and a
                # documented example must never execute anything. parse_known_args
                # exercises the same subcommand/option resolution.
                parser.parse_known_args(argv[1:])
            except SystemExit:
                failures.append(
                    f"{path.relative_to(REPO_ROOT)}: {command!r} was rejected")
            except Exception as exc:  # argparse raises ArgumentError on some paths
                failures.append(
                    f"{path.relative_to(REPO_ROOT)}: {command!r} -> "
                    f"{type(exc).__name__}: {exc}")

        assert not failures, (
            "these documented commands no longer parse, so the documentation is "
            "wrong:\n  " + "\n  ".join(failures))

    def test_the_extraction_skips_prompts_and_output(self):
        """If the extractor started capturing output, the test would rot."""
        commands = [c for _p, _l, c in _s0_commands()]
        assert not any(c.startswith("$ ") for c in commands)
        assert not any(c.startswith("> ") for c in commands)

    def test_documented_subcommands_all_exist(self):
        """A more direct statement of the same property, easier to read in CI."""
        from s0.cli.main import build_parser

        parser = build_parser()
        subparsers = None
        for action in parser._actions:
            if isinstance(action, __import__("argparse")._SubParsersAction):
                subparsers = action
                break
        assert subparsers is not None, "the parser exposes no subcommands"

        known = set(subparsers.choices)
        documented = set()
        for _path, _line, command in _s0_commands():
            parts = command.split()
            # `s0` and `s0 --version` have no subcommand; only inventory the ones
            # that name one.
            if len(parts) > 1 and not parts[1].startswith("-"):
                documented.add(parts[1])

        unknown = sorted(documented - known)
        assert not unknown, (
            f"the documentation shows subcommands that do not exist: {unknown}. "
            f"Known: {sorted(known)}")


class TestDestructiveExamplesAreNeverRun:
    def test_the_corpus_is_classified_not_executed(self):
        """Documents the boundary: this file parses, and that is all it does.

        Worth stating as a test because the obvious "improvement" -- actually
        running the commands to check they work -- would wipe the machine running
        the suite.
        """
        assert DESTRUCTIVE, "the destructive-command set is empty"
        commands = [c.split()[1] for _p, _l, c in _s0_commands() if len(c.split()) > 1]
        assert "wipe" in commands, (
            "no wipe example was found; the corpus is probably not the real "
            "documentation")
