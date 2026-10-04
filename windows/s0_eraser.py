"""s0: Secure Sanitization Platform (Windows Native).

Backward-compatible launcher. The implementation now ships inside the package as
``s0.platform.windows.s0_eraser`` so that ``pip install s0`` includes it; this
module remains so the repository-root launchers (``s0.ps1``, ``s0.bat``) and any
existing checkout keep working.
"""

from s0.platform.windows.s0_eraser import *  # noqa: F401,F403
from s0.platform.windows.s0_eraser import main  # noqa: F401

if __name__ == "__main__":
    import sys
    sys.exit(main())
