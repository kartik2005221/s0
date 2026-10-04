"""Guard against silently deleting public API that is consumed reflectively.

`s0.audit.verify.DEFAULT_AUDIT_DB` was imported but never used inside its own
module. Ruff read that as an unused import and removed it, which broke 37 tests
with `AttributeError: module 's0.audit.verify' has no attribute
'DEFAULT_AUDIT_DB'` -- because the only consumer patched it by *string path*
(`monkeypatch.setattr("s0.audit.verify.DEFAULT_AUDIT_DB", ...)`), which no static
import analysis can follow.

These tests make that failure mode loud instead of silent.
"""

from __future__ import annotations

import ast
import importlib
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[2]
SRC = REPO / "src"

# `monkeypatch.setattr("pkg.mod.NAME", ...)`, `importlib.import_module("a.b").c`
SCAN_ROOTS = ("src", "tests", "tools")


def _python_files() -> list[pathlib.Path]:
    out: list[pathlib.Path] = []
    for root in SCAN_ROOTS:
        base = REPO / root
        if not base.is_dir():
            continue
        for path in base.rglob("*.py"):
            if "__pycache__" in path.parts or ".venv" in path.parts:
                continue
            out.append(path)
    return out


def _referenced_dotted_names() -> set[tuple[str, str]]:
    """Every `<module>.<attr>` passed as a string to `setattr`-style calls.

    AST rather than a regex: a plain string scan also matches bare module paths
    like `import_module("s0.audit.verify")`, which would be read as the bogus
    attribute `s0.audit.verify` on a module called `s0.audit`.
    """
    found: set[tuple[str, str]] = set()
    for path in _python_files():
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError, OSError):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
            if name not in {"setattr", "delattr"}:
                continue
            first = node.args[0]
            if not isinstance(first, ast.Constant) or not isinstance(first.value, str):
                continue
            module, sep, attr = first.value.rpartition(".")
            if sep and module and attr:
                found.add((module, attr))
    return found


def _declared_all(module_name: str) -> list[str] | None:
    """Read `__all__` without importing, so a broken module still gets checked."""
    rel = module_name.split(".")
    path = SRC.joinpath(*rel).with_suffix(".py")
    if not path.is_file():
        path = SRC.joinpath(*rel, "__init__.py")
    if not path.is_file():
        return None
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except SyntaxError:
        return None
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == "__all__":
                try:
                    return [ast.literal_eval(elt) for elt in node.value.elts]
                except (ValueError, TypeError):
                    return None
    return None


REFERENCED = _referenced_dotted_names()


def test_scanner_found_the_known_case() -> None:
    """If this finds nothing, the regex is broken and every test below is vacuous."""
    assert ("s0.audit.verify", "DEFAULT_AUDIT_DB") in REFERENCED


@pytest.mark.parametrize(("module_name", "attr"), sorted(REFERENCED))
def test_string_referenced_name_is_declared_in_dunder_all(
    module_name: str, attr: str
) -> None:
    """A reflectively-referenced attribute must be an explicit export.

    Otherwise a lint autofix is free to delete it, and the breakage only shows up
    at runtime in code that static analysis never reads.
    """
    if not (module_name == "s0" or module_name.startswith("s0.")):
        # The string reference resolved to something outside the package, e.g.
        # `builtins` or `sys.stdin`. There is no __all__ to check and none is
        # expected.
        pytest.skip(f"{module_name} is not an s0 module")

    declared = _declared_all(module_name)
    if declared is None:
        # Importable, but declares no __all__. The old message said "not an
        # importable s0 module" for this case too, which is simply false: s0.cli.main
        # imports fine. It hid the fact that these modules have no explicit export
        # list at all -- which is the exact condition this file exists to
        # establish, since an implicit export is what a lint autofix deletes.
        pytest.skip(
            f"{module_name} declares no __all__, so its exports cannot be checked. "
            f"Add an explicit __all__ to make them live.")
    assert attr in declared, (
        f"{module_name}.{attr} is referenced as a string path in the repo but is "
        f"not in __all__. Add it to __all__ so linters treat it as a live export."
    )


def test_verify_module_exposes_everything_it_promises() -> None:
    """A name in `__all__` that does not exist breaks star-imports at runtime."""
    module = importlib.import_module("s0.audit.verify")
    missing = [name for name in module.__all__ if not hasattr(module, name)]
    assert not missing, f"__all__ advertises undefined names: {missing}"


def test_capabilities_star_import_works() -> None:
    """Regression: `PURGE_METHODS` was in `__all__` but never defined."""
    namespace: dict[str, object] = {}
    exec("from s0.wipe.methods.capabilities import *", namespace)  # noqa: S102
    assert "Tiers" in namespace
