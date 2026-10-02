<#
.SYNOPSIS
    Helper script to launch the static Verification Portal locally on Windows (PowerShell)
#>
param(
    [string]$Port = "8080"
)
$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PortalDir = Join-Path (Split-Path -Parent $ScriptDir) "site/verify"
Set-Location $PortalDir

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " s0 Verification Portal (Pure Client-Side Zero-Trust Web)" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "Serving directory: $PortalDir"
Write-Host "URL: http://127.0.0.1:$Port"
Write-Host "Press Ctrl+C to stop."
Write-Host "=================================================================" -ForegroundColor Cyan

python -m http.server $Port
