"""TrustWipe Module 2: Secure Sanitization Platform (macOS Native).

Backward-compatible re-export module: Implementation lives in macos/cli/trustwipe_eraser.py.
"""

from macos.cli.trustwipe_eraser import *  # noqa: F401,F403
from macos.cli.trustwipe_eraser import main  # noqa: F401

if __name__ == "__main__":
    import sys
    sys.exit(main())
