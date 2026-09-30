"""Path bootstrap so the suite runs even without an editable install.

Preferred setup (used by scripts/build_all.sh):
    .venv/bin/pip install -e .
"""

import sys
from pathlib import Path

try:  # pragma: no cover - import side effect
    import s0 as _s0  # noqa: F401
except ImportError:  # pragma: no cover - import side effect
    sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "src"))
