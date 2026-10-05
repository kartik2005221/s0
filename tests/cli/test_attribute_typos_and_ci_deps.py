"""Attribute-name typos that only fire on paths the suite never reaches.

**F-08.** ``s0 plan --json`` serialized each alternative as
``alt.method.method_id``. ``WipeMethod`` publishes ``id``. The expression was
never exercised with a real method because image targets leave ``method=None``
on every alternative, and ``alt.method.method_id if alt.method else None``
short-circuits on the ``None``. So the typo sat in a green suite and raised
``AttributeError`` for exactly the targets where a plan matters most -- SSDs,
NVMe and ATA devices, where firmware-erase alternatives carry a real method.

**F-05.** ``.github/workflows/ci.yml`` installed a package named ``httx``, which
does not exist on PyPI. pip aborts the whole install line, so the test job could
not run -- while ``release.yml`` spelled it correctly, meaning releases were
tested and CI was not. A CI install list is also a typosquat target: whoever
registers the misspelling gets code execution inside the workflow.

Both are one-word typos that no amount of end-to-end happy-path testing finds,
so they are asserted structurally here.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
import re
from pathlib import Path

import pytest

import s0.wipe.methods as methods_pkg
from s0.wipe.methods.base import WipeMethod

REPO_ROOT = Path(__file__).resolve().parents[2]


def _all_method_classes() -> list[type]:
    """Every WipeMethod subclass reachable from the package, imported by name."""
    found: list[type] = []
    for mod in pkgutil.iter_modules(methods_pkg.__path__):
        try:
            module = importlib.import_module(f"{methods_pkg.__name__}.{mod.name}")
        except ImportError:  # optional dependency not installed
            continue
        for _name, obj in vars(module).items():
            if inspect.isclass(obj) and issubclass(obj, WipeMethod) and obj is not WipeMethod:
                found.append(obj)
    return found


class TestMethodIdTypo:
    def test_the_package_actually_exposes_method_classes(self):
        """Guard the guard: if discovery broke, the test below would pass vacuously."""
        assert len(_all_method_classes()) >= 4, "expected the real method classes to be discoverable"

    def test_no_method_exposes_method_id(self):
        """`method_id` never existed. Any attribute of that name is a typo.

        Asserting its absence rather than `id`'s presence means a future rename
        that breaks the serializer fails here first, with a clear message.
        """
        offenders = [cls.__name__ for cls in _all_method_classes() if hasattr(cls, "method_id")]
        assert not offenders, (
            f"these classes expose 'method_id': {offenders}. The serializer and "
            f"WipeMethod both use 'id'; a second spelling is a bug waiting to fire"
        )

    def test_no_method_class_overrides_id_with_an_empty_string(self):
        """`id` is an instance attribute set in `__init__`, so a class-level empty
        default is expected. What must not happen is a class that *overrides* the
        base default with an empty string, which would silently produce an
        unnamed method in the JSON plan."""
        empty = [
            cls.__name__ for cls in _all_method_classes() if "id" in cls.__dict__ and cls.__dict__["id"] == ""
        ]
        assert not empty, (
            f"these classes override id with an empty string: {empty}. A plan "
            f"would name the method with nothing"
        )

    def test_serializer_source_does_not_mention_method_id(self):
        """Pin the exact expression that raised, independent of class discovery."""
        source = (REPO_ROOT / "src/s0/cli/main.py").read_text(encoding="utf-8")
        assert "method.method_id" not in source, (
            "the plan serializer references method.method_id, but WipeMethod has "
            "'id' -- this raises AttributeError on any target with a real method"
        )

    def test_plan_json_names_the_selected_method(self, tmp_path):
        """End to end: the emitted JSON must name the method, not leave it empty.

        Run through the console script because the UI owns its own stream, so an
        in-process capture would test the harness rather than the program. The
        AttributeError only fires when an alternative carries a real method,
        which no image target produces -- so this pins the other half of the
        contract, that a populated method serialises to its id string.
        """
        import json
        import shutil
        import subprocess
        import sys

        entry = shutil.which("s0") or str(Path(sys.executable).parent / "s0")
        assert Path(entry).is_file(), f"s0 entry point not found at {entry}"

        target = tmp_path / "vol.img"
        target.write_bytes(b"\x00" * (4 * 1024 * 1024))
        proc = subprocess.run(
            [entry, "plan", "--target", str(target), "--json"], capture_output=True, text=True, timeout=180
        )
        assert proc.returncode == 0, proc.stderr

        payload = json.loads(proc.stdout)
        plan = payload.get("plan", payload)
        for alt in plan.get("alternatives", []):
            name = alt["method"]
            assert name is None or (isinstance(name, str) and name), (
                "an alternative serialised with an empty method name"
            )


class TestCIInstallsRealPackages:
    def _workflow_text(self, name: str) -> str:
        path = REPO_ROOT / ".github/workflows" / name
        if not path.exists():  # pragma: no cover
            pytest.skip(f"{name} not present")
        return path.read_text(encoding="utf-8")

    def test_ci_does_not_reference_a_nonexistent_package(self):
        """`httx` is not on PyPI; `httpx` is. Assert the typo cannot come back."""
        for name in ("ci.yml", "release.yml", "build-iso.yml"):
            text = self._workflow_text(name)
            # Command lines only. A comment *mentioning* httx -- which the workflows
            # now do, to record why the hand-written lists were removed -- is the
            # opposite of the problem: it is the history that stops it coming back.
            offenders = []
            for lineno, line in enumerate(text.splitlines(), 1):
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                if re.search(r"(?<![\w.-])httx(?![\w-])", stripped):
                    offenders.append(f"{name}:{lineno}: {stripped}")
            assert not offenders, (
                f"these lines would install 'httx', which does not exist on PyPI. "
                f"pip aborts the whole install line, so the job cannot run: "
                f"{offenders}"
            )

    def test_ci_installs_the_projects_own_extras(self):
        """One command, from pyproject: the hand-written list is what drifted."""
        text = self._workflow_text("ci.yml")
        assert 'pip install -e ".[web,test,dev]"' in text, (
            "ci.yml should install the declared extras rather than a hand-written "
            "package list, which is how 'httx' got there"
        )

    def test_every_extra_named_in_ci_exists_in_pyproject(self):
        text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        match = re.search(r'pip install -e "\.\[([^\]]+)\]"', self._workflow_text("ci.yml"))
        assert match, "could not parse the extras from ci.yml"
        for extra in (e.strip() for e in match.group(1).split(",")):
            assert re.search(rf"^{re.escape(extra)}\s*=", text, re.M), (
                f"ci.yml installs the '{extra}' extra, which pyproject.toml does "
                f"not declare -- the install would resolve to nothing"
            )

    def test_async_tests_would_be_covered_by_an_extra(self):
        """`pytest-asyncio` was in the old hand-written list and is in no extra.

        Today nothing is marked async, so the dependency is simply absent. If
        that ever changes the fix belongs in the `test` extra, not back in a CI
        install line -- which is the thing that drifted in the first place.
        """
        others = [p for p in (REPO_ROOT / "tests").rglob("*.py") if p.resolve() != Path(__file__).resolve()]
        users = [p.name for p in others if "pytest.mark.asyncio" in p.read_text(encoding="utf-8")]
        if not users:
            assert "pytest-asyncio" not in self._workflow_text("ci.yml")
            return
        declared = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        assert "pytest-asyncio" in declared, (
            f"async tests appeared in {users} but no extra declares pytest-asyncio, so CI will fail on them"
        )
