<#
.SYNOPSIS
    S0 (Sector Zero) — Resilient Upgrader for Windows (PowerShell)
    Usage: irm https://s0-install.vercel.app/upgrade-ps1 | iex
#>
$ErrorActionPreference = 'Stop'
$InstallDir = if ($env:S0_INSTALL_DIR) { $env:S0_INSTALL_DIR } else { "$env:USERPROFILE\.s0" }
$TotalSteps = 6
$Step = 0

function Write-Step($Msg) {
    $script:Step++
    Write-Host "`n[$script:Step/$TotalSteps] $Msg..." -ForegroundColor Cyan -NoNewline
}
function Write-Ok { Write-Host " done" -ForegroundColor Green }
function Write-Info($Msg) { Write-Host "`n    -> $Msg" -ForegroundColor Yellow }

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║      S0 (Sector Zero) — Suite Upgrade & Maintenance Tool         ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Step 1: Check existing installation
Write-Step "Checking existing installation"
if (-not (Test-Path $InstallDir)) {
    Write-Host "`n`n[WARNING] S0 is not installed at $InstallDir." -ForegroundColor Yellow
    Write-Host "To install S0, run in PowerShell:" -ForegroundColor White
    Write-Host "  irm https://s0-install.vercel.app/ps1 | iex`n" -ForegroundColor Cyan
    return
}
if (-not (Test-Path (Join-Path $InstallDir ".git"))) {
    Write-Host "`n`n[ERROR] $InstallDir is not a git repository." -ForegroundColor Red
    return
}
Set-Location $InstallDir
$currentCommit = (git rev-parse --short HEAD 2>$null)
Write-Ok; Write-Info "found S0 at $InstallDir (current commit: $currentCommit)"

# Step 2: Check Git
Write-Step "Checking Git"
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Host "`n`n[ERROR] Git is required. Install from: https://git-scm.com/" -ForegroundColor Red
    return
}
Write-Ok

# Step 3: Pull latest source
Write-Step "Pulling latest updates from GitHub"
try {
    git fetch origin master -q 2>$null
    $latestCommit = (git rev-parse --short origin/master 2>$null)
    if ($currentCommit -eq $latestCommit) {
        Write-Ok; Write-Info "already up-to-date at commit $currentCommit"
    } else {
        try {
            git pull --ff-only origin master -q
            Write-Ok; Write-Info "updated: $currentCommit -> $latestCommit"
        } catch {
            Write-Info "local modifications detected; resetting cleanly to origin/master..."
            git reset --hard origin/master -q
            Write-Ok; Write-Info "reset to commit $latestCommit"
        }
    }
} catch {
    Write-Host "`n[ERROR] Failed to fetch latest git changes: $_" -ForegroundColor Red
    return
}

# Step 4: Locate venv python & upgrade pip
Write-Step "Upgrading virtual environment dependencies"
$VenvPython = Join-Path $InstallDir ".venv\Scripts\python.exe"
if (-not (Test-Path $VenvPython)) {
    Write-Host "`n[INFO] Virtual environment missing or corrupt, rebuilding..." -ForegroundColor Yellow
    if (Test-Path (Join-Path $InstallDir ".venv")) {
        Remove-Item -Recurse -Force (Join-Path $InstallDir ".venv") -ErrorAction SilentlyContinue
    }
    python -m venv (Join-Path $InstallDir ".venv")
}
try {
    & $VenvPython -m pip install --upgrade pip -q
    & $VenvPython -m pip install -e core\python -q
    & $VenvPython -m pip install -e linux\cli -q
    & $VenvPython -m pip install reportlab qrcode pillow fastapi uvicorn[standard] -q
    Write-Ok; Write-Info "dependencies refreshed"
} catch {
    Write-Host "`n[ERROR] Pip package upgrade failed: $_" -ForegroundColor Red
    return
}

# Step 5: Refresh wrapper scripts & PATH
Write-Step "Refreshing command wrapper scripts"
$BinDir = Join-Path $InstallDir "bin"
New-Item -ItemType Directory -Force -Path $BinDir | Out-Null

$s0Cmd = @"
@echo off
"$InstallDir\.venv\Scripts\s0.exe" %*
"@
Set-Content -Path (Join-Path $BinDir "s0.cmd") -Value $s0Cmd -Encoding ASCII

$s0Sh = @"
#!/bin/sh
exec "$InstallDir/.venv/Scripts/s0.exe" "`$@"
"@
Set-Content -Path (Join-Path $BinDir "s0") -Value $s0Sh -Encoding ASCII

# Ensure PATH has $BinDir
$userPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::User)
if ($userPath -notlike "*$BinDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$BinDir;$userPath", [EnvironmentVariableTarget]::User)
}
if ($env:PATH -notlike "*$BinDir*") {
    $env:PATH = "$BinDir;$env:PATH"
}
function global:s0 { & "$InstallDir\.venv\Scripts\s0.exe" @args }
Write-Ok; Write-Info "wrapper refreshed at $BinDir\s0.cmd"

# Step 6: Verify upgraded version
Write-Step "Verifying upgraded version"
try {
    $s0Ver = (& "$InstallDir\.venv\Scripts\s0.exe" --version 2>&1)
    Write-Ok; Write-Info "active version: $s0Ver"
} catch {
    Write-Ok; Write-Info "active version: verified"
}

Write-Host ""
Write-Host "✅ S0 upgraded successfully!" -ForegroundColor Green
Write-Host "   Version    : $s0Ver" -ForegroundColor White
Write-Host "   Directory  : $InstallDir" -ForegroundColor White
Write-Host "   Command    : s0 --version" -ForegroundColor Cyan
Write-Host ""
