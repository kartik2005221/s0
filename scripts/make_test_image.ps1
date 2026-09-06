<#
.SYNOPSIS
    Helper script to create a sparse/zeroed disk image file for testing on Windows (PowerShell)
    Smart India Hackathon 2026 (SIH26149) - NTRO
#>
param(
    [string]$ImagePath = "test_drive.img",
    [int]$SizeMB = 256
)
$ErrorActionPreference = 'Stop'
$Bytes = [int64]$SizeMB * 1MB

Write-Host "==> Creating $SizeMB MiB test disk image at $ImagePath ($Bytes bytes)..." -ForegroundColor Yellow
$fs = [System.IO.File]::Create($ImagePath)
$fs.SetLength($Bytes)
$fs.Close()

Write-Host "==> Created successfully!" -ForegroundColor Green
Write-Host "==> You can test wiping on this image target:"
Write-Host "    windows\cli\s0-eraser.bat --wipe-drive `"$ImagePath`" --yes"
