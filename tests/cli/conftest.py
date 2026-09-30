"""Path bootstrap so the suite runs even without an editable install.

Preferred setup (used by tools/build_all.sh):
    .venv/bin/pip install -e .
"""

import sys
from pathlib import Path


def _repo_root() -> Path:
    """Walk up to the checkout root.

    Deliberately does not import ``s0.resources``: that module is inside the
    package this bootstrap is trying to make importable.
    """
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "pyproject.toml").is_file() and (parent / ".git").exists():
            return parent
    raise RuntimeError("could not locate the repository root from " + str(here))


try:  # pragma: no cover - import side effect
    import s0 as _s0  # noqa: F401
except ImportError:  # pragma: no cover - import side effect
    sys.path.insert(0, str(_repo_root() / "src"))
