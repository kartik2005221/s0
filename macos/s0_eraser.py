"""s0: Secure Sanitization Platform (macOS Native).

Backward-compatible launcher. The implementation now ships inside the package as
``s0.platform.macos.s0_eraser`` so that package installations include it; this
module remains so the repository-root launcher (``s0.sh``) and any existing
checkout keep working.
"""

from s0.platform.macos.s0_eraser import *  # noqa: F401,F403
from s0.platform.macos.s0_eraser import main  # noqa: F401

if __name__ == "__main__":
    import sys

    sys.exit(main())
