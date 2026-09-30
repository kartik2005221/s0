# Launch the s0 local Web Dashboard on Windows (PowerShell). Binds 127.0.0.1 only.
$ErrorActionPreference = 'Stop'
$WebDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Repo = Split-Path -Parent $WebDir
$Port = if ($env:S0_PORT) { $env:S0_PORT } else { '8669' }
& "$Repo\.venv\Scripts\python.exe" -m uvicorn app:app --host 127.0.0.1 --port $Port
