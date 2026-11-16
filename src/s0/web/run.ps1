# Launch the s0 local Web Dashboard on Windows (PowerShell). Binds 127.0.0.1 only.
# For an installed s0, prefer `s0 web`. This script targets a source checkout:
# the venv sits at the repo root, two levels up from this directory.
$ErrorActionPreference = 'Stop'
$WebDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$SrcDir = Split-Path -Parent $WebDir
$Repo = Split-Path -Parent $SrcDir
$Port = if ($env:S0_PORT) { $env:S0_PORT } else { '8669' }
if (Test-Path "$Repo\.venv\Scripts\python.exe") {
    & "$Repo\.venv\Scripts\python.exe" -m uvicorn s0.web.app:app --host 127.0.0.1 --port $Port
} else {
    python -m uvicorn s0.web.app:app --host 127.0.0.1 --port $Port
}
