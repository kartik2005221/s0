import sys
from pathlib import Path

# Ensure repository root is on sys.path so sibling platform modules (windows, macos) can be imported
_repo_root = Path(__file__).resolve().parents[3]
if (_repo_root / "windows").is_dir() and str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

try:
    from s0_core.config import CONFIG
    __version__ = CONFIG.get("version", "2.4.4")
except ImportError:
    __version__ = "2.4.4"


def _get_git_commit() -> str:
    import os
    env_commit = os.environ.get("S0_GIT_COMMIT", "").strip()
    if env_commit:
        return env_commit[:8]
    try:
        import subprocess
        res = subprocess.run(
            ["git", "-C", str(_repo_root), "rev-parse", "--short=8", "HEAD"],
            capture_output=True, text=True, check=False, timeout=2
        )
        if res.returncode == 0 and res.stdout.strip():
            return res.stdout.strip()
    except Exception:
        pass
    try:
        head_path = _repo_root / ".git" / "HEAD"
        if head_path.is_file():
            content = head_path.read_text().strip()
            if content.startswith("ref:"):
                ref = content.split(" ", 1)[1].strip()
                ref_path = _repo_root / ".git" / ref
                if ref_path.is_file():
                    return ref_path.read_text().strip()[:8]
            elif len(content) >= 8:
                return content[:8]
    except Exception:
        pass
    return ""


__git_commit__ = _get_git_commit()
__version_str__ = f"{__version__} (commit {__git_commit__})" if __git_commit__ else __version__
