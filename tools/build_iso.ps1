<#
.SYNOPSIS
    S0 (Sector Zero) — Windows Bootable Live ISO Build Orchestrator
    Builds the bare-metal Debian live ISO from Windows using Docker Desktop or WSL2.
    Usage: .\tools\build_iso.ps1
#>
$ErrorActionPreference = 'Stop'

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║      S0 (Sector Zero) — Windows Live ISO Build Orchestrator      ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $RepoRoot

# Method 1: Docker Desktop (Preferred for clean containerized builds)
Write-Host "[1/3] Checking Docker Desktop..." -ForegroundColor Cyan -NoNewline
$hasDocker = $false
try {
    $dockerInfo = docker info 2>$null
    if ($LASTEXITCODE -eq 0) { $hasDocker = $true }
} catch {}

if ($hasDocker) {
    Write-Host " found & running!" -ForegroundColor Green
    Write-Host "`n==> Building S0 Live ISO via Docker container..." -ForegroundColor Yellow
    Write-Host "    (Requires privileged mode for loop device mounts & debootstrap)" -ForegroundColor Gray
    
    docker build -t s0-live-builder -f iso/Dockerfile iso
    if ($LASTEXITCODE -ne 0) {
        Write-Host "`n[ERROR] Docker image build failed." -ForegroundColor Red
        return
    }

    Write-Host "==> Running live-build in container..." -ForegroundColor Yellow
    docker run --rm --privileged -v "${RepoRoot}:/workspace" s0-live-builder
    
    $isoPath = Join-Path $RepoRoot "s0-live-amd64.hybrid.iso"
    if (Test-Path $isoPath) {
        Write-Host "`n✅ SUCCESS! Bootable ISO generated at:" -ForegroundColor Green
        Write-Host "   $isoPath" -ForegroundColor White
        Write-Host "   Flash to USB using Rufus (https://rufus.ie/) in DD Image mode." -ForegroundColor Cyan
        return
    }
} else {
    Write-Host " not running / not installed" -ForegroundColor Yellow
}

# Method 2: WSL2 (Windows Subsystem for Linux)
Write-Host "[2/3] Checking Windows Subsystem for Linux (WSL2)..." -ForegroundColor Cyan -NoNewline
$hasWsl = $false
try {
    $wslList = wsl -l -q 2>$null
    if ($LASTEXITCODE -eq 0 -and $wslList) { $hasWsl = $true }
} catch {}

if ($hasWsl) {
    Write-Host " found!" -ForegroundColor Green
    Write-Host "`n==> Building S0 Live ISO via WSL2..." -ForegroundColor Yellow
    
    # Convert Windows path to WSL path
    $wslPath = (& wsl wslpath -u ($RepoRoot -replace '\\', '/')).Trim()
    
    Write-Host "    Workspace: $wslPath" -ForegroundColor Gray
    Write-Host "    Installing prerequisites inside WSL (live-build, xorriso)..." -ForegroundColor Gray
    
    wsl -u root bash -c "apt-get update -qq && apt-get install -y -qq live-build xorriso squashfs-tools debootstrap"
    wsl -u root bash -c "cd '$wslPath/iso' && ./build.sh"
    
    $isoPath = Join-Path $RepoRoot "linux\iso\live-image-amd64.hybrid.iso"
    if (Test-Path $isoPath) {
        $targetIso = Join-Path $RepoRoot "s0-live-amd64.hybrid.iso"
        Copy-Item $isoPath $targetIso -Force
        Write-Host "`n✅ SUCCESS! Bootable ISO generated at:" -ForegroundColor Green
        Write-Host "   $targetIso" -ForegroundColor White
        Write-Host "   Flash to USB using Rufus (https://rufus.ie/) in DD Image mode." -ForegroundColor Cyan
        return
    }
} else {
    Write-Host " not found" -ForegroundColor Yellow
}

# Method 3: Explain Native OS Constraints & Provide Download / Install Guide
Write-Host "[3/3] Native Windows Constraint Analysis" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Debian Live ISO generation requires Linux kernel subsystems:" -ForegroundColor Yellow
Write-Host "    - debootstrap & chroot (POSIX root isolation & device node creation)"
Write-Host "    - loopback block device driver (losetup for squashfs root filesystem)"
Write-Host "    - xorriso with hybrid MBR/GPT UEFI boot catalogs"
Write-Host ""
Write-Host "  To build the ISO from Windows, please do ONE of the following:" -ForegroundColor White
Write-Host "    Option A: Start Docker Desktop (free from https://www.docker.com/products/docker-desktop/)" -ForegroundColor Cyan
Write-Host "              Then re-run: .\tools\build_iso.ps1"
Write-Host "    Option B: Enable WSL2: Open PowerShell as Administrator and run:" -ForegroundColor Cyan
Write-Host "              wsl --install -d Debian"
Write-Host "              Then re-run: .\tools\build_iso.ps1"
Write-Host "    Option C: Download the pre-built, verified ISO directly:" -ForegroundColor Cyan
Write-Host "              irm https://s0-install.pages.dev/download-iso-ps1 | iex"
Write-Host ""
