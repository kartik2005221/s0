<#
.SYNOPSIS
    S0 (Sector Zero) — Download Pre-Built Live ISO for Windows
    Usage: irm https://sector-zero.pages.dev/download-iso-ps1 | iex
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
        Write-Host "         .\tools\build_iso.ps1" -ForegroundColor Cyan
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
    $hash = (Get-FileHash -Path $OutFile -Algorithm SHA256).Hash.ToLower()
    Write-Host "   Computed SHA-256: $hash" -ForegroundColor Yellow
    
    $checksumAsset = $release.assets | Where-Object { $_.name -eq "$($asset.name).sha256" -or $_.name -eq "SHA256SUMS.txt" -or $_.name -like "*.sha256" } | Select-Object -First 1
    if ($checksumAsset) {
        Write-Host "==> Fetching official release checksum ($($checksumAsset.name))..." -ForegroundColor Cyan
        $chkContent = (Invoke-RestMethod -Uri $checksumAsset.browser_download_url -Headers @{ "User-Agent" = "s0-iso-downloader" })
        $expectedHash = ""
        foreach ($line in ($chkContent -split "`n")) {
            if ($line -match "([0-9a-fA-F]{64})") {
                if ($line -like "*$($asset.name)*" -or [string]::IsNullOrWhiteSpace($expectedHash)) {
                    $expectedHash = $Matches[1].ToLower()
                    if ($line -like "*$($asset.name)*") { break }
                }
            }
        }
        if ($expectedHash) {
            Write-Host "   Official SHA-256: $expectedHash" -ForegroundColor Yellow
            if ($hash -eq $expectedHash) {
                Write-Host "✅ SHA-256 checksum VERIFIED against official release!" -ForegroundColor Green
            } else {
                Write-Host "❌ [CRITICAL SECURITY ERROR] SHA-256 checksum MISMATCH!" -ForegroundColor Red
                Write-Host "   Expected: $expectedHash" -ForegroundColor Red
                Write-Host "   Computed: $hash" -ForegroundColor Red
                Write-Host "   Removing compromised/corrupted download: $OutFile" -ForegroundColor Red
                Remove-Item -Path $OutFile -Force -ErrorAction SilentlyContinue
                exit 1
            }
        } else {
            Write-Host "⚠️  [WARNING] Could not parse hash from official checksum file." -ForegroundColor Yellow
        }
    } else {
        Write-Host "⚠️  [WARNING] Official checksum asset not found on release; manual verification recommended." -ForegroundColor Yellow
    }
    
    Write-Host "`n==> Flashing to USB Drive:" -ForegroundColor Cyan
    Write-Host "   1. Download Rufus from: https://rufus.ie/" -ForegroundColor White
    Write-Host "   2. Insert USB flash drive (>= 4 GB)." -ForegroundColor White
    Write-Host "   3. Select '$OutFile' and choose 'DD Image Mode' when prompted." -ForegroundColor White
} catch {
    Write-Host "`n[ERROR] Failed to query releases: $_" -ForegroundColor Red
    Write-Host "       To build from source on Windows, run: .\tools\build_iso.ps1" -ForegroundColor Yellow
}
