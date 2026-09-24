"""s0: Secure Sanitization Platform (Windows Native).

Backward-compatible re-export module: Implementation lives in windows/cli/s0_eraser.py.
"""

from windows.cli.s0_eraser import *  # noqa: F401,F403
from windows.cli.s0_eraser import main  # noqa: F401

if __name__ == "__main__":
    import sys
    sys.exit(main())
