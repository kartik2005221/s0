"""`requirements.lock` is the pinned side of the build, and nothing was checking it.

`pyproject.toml` declares lower bounds only, which is right for a library and wrong
for the things this project *builds* -- ISO, container, release tarball. Those resolve
"whatever is newest at build time", so two builds of the same commit can contain
different code. The lock exists to stop that, and `pip install --require-hashes -r
requirements.lock` refuses to install anything whose artefact hash is not listed.

Three things were wrong with it:

* **It carried a local scratch path in ten places.** pip-compile records its own
  invocation in the generated header, so whoever ran it from `/tmp/opencode` wrote
  `/tmp/opencode/reqs.in` and `/tmp/opencode/requirements.lock` into a committed file.
* **The generator refused to run on a working environment.** Its pip-tools check was
  `python -m piptools --version`, which is not a valid invocation -- piptools is a
  command group and exits 2 with a usage message -- so it reported "not installed"
  where pip-tools was installed and functional.
* **Nothing installed from it.** A pin that stopped resolving, or an artefact whose
  wheel is cp3XX-only, would have been found by whoever tried it first.

These assert the properties that make the lock usable. They do not substitute for
installing it on each interpreter, which is what the new `lockfile` CI job does.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
LOCK = REPO_ROOT / "requirements.lock"
LOCK_IN = REPO_ROOT / "requirements.in"
SCRIPT = REPO_ROOT / "tools" / "lock_dependencies.sh"
CI = REPO_ROOT / ".github" / "workflows" / "ci.yml"


def test_the_lock_exists_and_pins_something():
    assert LOCK.is_file(), f"{LOCK} is missing"
    text = LOCK.read_text(encoding="utf-8")
    pins = re.findall(r"^([A-Za-z0-9_.-]+)==", text, re.MULTILINE)
    assert pins, "the lock pins nothing"
    assert len(pins) > 20, f"only {len(pins)} pins; this is not a full resolution"


def test_the_lock_header_names_no_local_path():
    """A scratch path in a committed file is a bug that survives for years.

    It is not merely untidy: the path is a record of the machine that produced the
    file, and if that machine was a developer's laptop the header is the only thing
    telling a future reader which resolution they are looking at.
    """
    text = LOCK.read_text(encoding="utf-8")
    local = re.findall(r"(?:^|\s)(/tmp/|/home/|/Users/|/private/var/|/var/folders/)", text)
    assert not local, (
        f"requirements.lock contains {len(local)} local filesystem reference(s), e.g. "
        f"{local[:3]}. Regenerate with tools/lock_dependencies.sh, which now passes "
        f"relative paths and suppresses the index URL."
    )


def test_every_pin_is_hash_pinned():
    """Without a hash line, `--require-hashes` is not actually enforcing anything."""
    text = LOCK.read_text(encoding="utf-8")
    blocks = [b for b in re.split(r"\n\n+", text) if "==" in b]
    unpinned = []
    for block in blocks:
        m = re.search(r"^([A-Za-z0-9_.-]+)==", block, re.MULTILINE)
        if m and "--hash=sha256:" not in block:
            unpinned.append(m.group(1))
    assert not unpinned, f"these pins have no --hash line: {unpinned}"


def test_the_lock_is_a_superset_of_the_declared_dependencies():
    """A dependency added to requirements.in but not resolved into the lock is invisible."""
    declared = set()
    for line in LOCK_IN.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        name = re.split(r"[<>=!~\[; ]", line, maxsplit=1)[0].strip()
        if name:
            declared.add(name.lower().replace("_", "-"))

    pinned = {
        m.group(1).lower().replace("_", "-")
        for m in re.finditer(r"^([A-Za-z0-9_.-]+)==", LOCK.read_text(encoding="utf-8"), re.MULTILINE)
    }
    # `qrcode[pil]` declares Pillow as an extra; both appear in the lock.
    missing = sorted(d for d in declared if d not in pinned)
    assert not missing, f"declared in requirements.in but absent from the lock: {missing}"


def _script_code(text: str) -> str:
    """The script's code lines, with comments removed.

    The generator documents *why* the old probe was wrong, and that explanation
    necessarily quotes the broken invocation. A substring test over the whole file
    would therefore fail on its own comment.
    """
    out = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        out.append(line.split(" #", 1)[0] if " #" in line else line)
    return "\n".join(out)


def test_the_generator_can_detect_its_own_tool():
    """Regression: `python -m piptools --version` is not a valid invocation.

    piptools is a command group, so that invocation exits 2 with a usage message. The
    script treated a non-zero exit as "pip-tools is not installed" and refused to run on
    an environment where it was installed and working -- which is how the lock ended up
    stale, since nobody could regenerate it.
    """
    code = _script_code(SCRIPT.read_text(encoding="utf-8"))
    assert "-m piptools --version" not in code, (
        "the pip-tools probe uses an invocation that always fails, so the script "
        "reports 'not installed' on a working environment"
    )
    assert "import piptools" in code, (
        "the pip-tools probe should import the module, which is a real availability check"
    )


def test_the_generator_records_no_absolute_paths():
    """pip-compile writes its own invocation into the header, so the paths matter."""
    code = _script_code(SCRIPT.read_text(encoding="utf-8"))
    assert '--output-file "$LOCK_OUT"' in code or "--output-file=$LOCK_OUT" in code, (
        "the generator does not pass a relative --output-file, so the lock header "
        "records whatever directory it was run from"
    )
    assert "/tmp" not in code, "the generator itself hard-codes a scratch path"
    assert "--no-emit-index-url" in code, (
        "the generated header records the configured index URL, which differs per machine"
    )


def test_the_generator_parses_as_a_shell_script():
    proc = subprocess.run(["bash", "-n", str(SCRIPT)], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, f"tools/lock_dependencies.sh does not parse: {proc.stderr}"


def test_ci_installs_the_lock_on_every_supported_version():
    """Nothing installed from the lock, so a broken pin surfaced at release time."""
    ci = CI.read_text(encoding="utf-8")
    assert "--require-hashes" in ci, "no CI step installs the lock with hash checking"
    assert "requirements.lock" in ci

    import yaml

    workflow = yaml.safe_load(ci)
    job = workflow["jobs"].get("lockfile")
    assert job is not None, "there is no CI job that checks the lock file"

    versions = job["strategy"]["matrix"]["python-version"]
    floor = re.search(r'requires-python\s*=\s*">=(\d+)\.(\d+)"', (REPO_ROOT / "pyproject.toml").read_text())
    assert floor, "pyproject.toml does not declare requires-python"
    assert versions[0] == f"{floor.group(1)}.{floor.group(2)}", (
        f"the lock job starts at {versions[0]} but the declared floor is "
        f"{floor.group(1)}.{floor.group(2)}; the floor is where resolution breaks first"
    )
    assert len(versions) >= 4, (
        f"the lock job covers only {versions}; the lock was compiled on one "
        f"interpreter and a pin can be unavailable on another"
    )


def test_ci_pins_every_action_by_commit_sha():
    for path in sorted((REPO_ROOT / ".github" / "workflows").glob("*.yml")):
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            m = re.search(r"uses:\s*(\S+)", line)
            if not m:
                continue
            ref = m.group(1)
            assert re.search(r"@[0-9a-f]{40}$", ref), (
                f"{path.name}:{lineno} pins {ref} to a tag or branch, not a commit SHA"
            )
