# S0 (Sector Zero) Windows Unified Forensic Sanitization & Recovery CLI
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$CliPy = Join-Path $ScriptDir "cli\s0_eraser.py"

python $CliPy @args
exit $LASTEXITCODE
