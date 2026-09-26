import sys
from pathlib import Path

# Ensure repository root is on sys.path so sibling platform modules (windows, macos) can be imported
_repo_root = Path(__file__).resolve().parents[3]
if (_repo_root / "windows").is_dir() and str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

try:
    from s0_core.config import CONFIG
    __version__ = CONFIG.get("version", "2.4.3")
except ImportError:
    __version__ = "2.4.3"
