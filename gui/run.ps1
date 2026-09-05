# Launch the TrustWipe local GUI on Windows (PowerShell). Binds 127.0.0.1 only.
$ErrorActionPreference = 'Stop'
$GuiDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Repo = Split-Path -Parent $GuiDir
$Port = if ($env:TRUSTWIPE_PORT) { $env:TRUSTWIPE_PORT } else { '8000' }
& "$Repo\.venv\Scripts\python.exe" -m uvicorn app:app --host 127.0.0.1 --port $Port
