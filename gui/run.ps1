# Launch the s0 local GUI on Windows (PowerShell). Binds 127.0.0.1 only.
$ErrorActionPreference = 'Stop'
$GuiDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Repo = Split-Path -Parent $GuiDir
$Port = if ($env:S0_PORT) { $env:S0_PORT } else { '8000' }
& "$Repo\.venv\Scripts\python.exe" -m uvicorn app:app --host 127.0.0.1 --port $Port
