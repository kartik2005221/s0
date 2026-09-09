<#
.SYNOPSIS
    S0 (Sector Zero) — Download Pre-Built Live ISO for Windows
    Usage: irm https://raw.githubusercontent.com/kartik2005221/s0/master/scripts/download_iso.ps1 | iex
#>
$ErrorActionPreference = 'Stop'

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║      S0 (Sector Zero) — Live ISO Downloader & Verifier           ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

$Repo = "kartik2005221/s0"
$ApiUrl = "https://api.github.com/repos/$Repo/releases/latest"
$OutDir = if ($env:USERPROFILE) { Join-Path $env:USERPROFILE "Downloads" } else { "." }
$OutFile = Join-Path $OutDir "s0-live-amd64.hybrid.iso"

Write-Host "==> Checking latest releases on GitHub ($Repo)..." -ForegroundColor Cyan
try {
    $release = Invoke-RestMethod -Uri $ApiUrl -Headers @{ "User-Agent" = "s0-iso-downloader" }
    $asset = $release.assets | Where-Object { $_.name -like "*.iso" } | Select-Object -First 1
    
    if (-not $asset) {
        Write-Host "[INFO] No release asset .iso attached yet on GitHub." -ForegroundColor Yellow
        Write-Host "       You can build the ISO locally using Docker or WSL2:" -ForegroundColor White
        Write-Host "         .\scripts\build_iso.ps1" -ForegroundColor Cyan
        Write-Host "       Or trigger the automated GitHub Actions workflow: '.github/workflows/build-iso.yml'" -ForegroundColor Gray
        return
    }

    Write-Host "==> Found release: $($release.tag_name) ($($asset.name))" -ForegroundColor Green
    Write-Host "==> Downloading to: $OutFile..." -ForegroundColor Cyan
    
    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $OutFile
    
    Write-Host "`n✅ Download complete!" -ForegroundColor Green
    Write-Host "   Path: $OutFile" -ForegroundColor White
    
    # Calculate SHA256
    Write-Host "==> Computing SHA-256 Checksum..." -ForegroundColor Cyan
    $hash = (Get-FileHash -Path $OutFile -Algorithm SHA256).Hash
    Write-Host "   SHA-256: $hash" -ForegroundColor Yellow
    
    Write-Host "`n==> Flashing to USB Drive:" -ForegroundColor Cyan
    Write-Host "   1. Download Rufus from: https://rufus.ie/" -ForegroundColor White
    Write-Host "   2. Insert USB flash drive (>= 4 GB)." -ForegroundColor White
    Write-Host "   3. Select '$OutFile' and choose 'DD Image Mode' when prompted." -ForegroundColor White
} catch {
    Write-Host "`n[ERROR] Failed to query releases: $_" -ForegroundColor Red
    Write-Host "       To build from source on Windows, run: .\scripts\build_iso.ps1" -ForegroundColor Yellow
}
