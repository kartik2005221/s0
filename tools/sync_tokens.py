#!/usr/bin/env python3
"""Compatibility wrapper for sync_assets.py."""

import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.exit(subprocess.run([sys.executable, str(REPO / "tools" / "sync_assets.py")] + sys.argv[1:]).returncode)
