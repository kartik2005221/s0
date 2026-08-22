"""Path bootstrap so the suite runs even without editable installs.

Preferred setup (used by scripts/build_all.sh):
    .venv/bin/pip install -e core/python -e linux/cli
"""

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
for p in (REPO / "core" / "python", REPO / "linux" / "cli"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))
