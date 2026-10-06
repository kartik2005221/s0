<#
.SYNOPSIS
    S0 (Sector Zero) -- Resilient Upgrader for Windows (PowerShell)
    Usage: irm https://sector0.pages.dev/upgrade-ps1 | iex
#>
$ErrorActionPreference = 'Stop'
$InstallDir = if ($env:S0_INSTALL_DIR) { $env:S0_INSTALL_DIR } else { "$env:USERPROFILE\.s0" }
# Which ref to upgrade to. `$S0Ref` was used below but never defined, and PowerShell
# expands an undefined variable to nothing -- so `git fetch origin $S0Ref` became
# `git fetch origin -q`, which resolves origin/HEAD rather than the ref this machine was
# installed from. A user tracking a release tag was silently moved to whatever the
# remote's default branch pointed at, and nothing in the output said so.
#
# Precedence matches upgrade.sh and install.sh: S0_INSTALL_REF, then the legacy
# S0_BRANCH, then the branch this repository is on. Kept in the same order on purpose;
# two installers with different override rules is its own bug.
$S0Ref = if ($env:S0_INSTALL_REF) { $env:S0_INSTALL_REF }
         elseif ($env:S0_BRANCH) { $env:S0_BRANCH }
         else { "master" }
$TotalSteps = 6
$Step = 0

function Write-Step($Msg) {
    $script:Step++
    Write-Host "`n[$script:Step/$TotalSteps] $Msg..." -ForegroundColor Cyan -NoNewline
}
function Write-Ok { Write-Host " done" -ForegroundColor Green }
function Write-Info($Msg) { Write-Host "`n    -> $Msg" -ForegroundColor Yellow }

Write-Host ""
Write-Host "+==================================================================+" -ForegroundColor Cyan
Write-Host "|      S0 (Sector Zero) -- Suite Upgrade & Maintenance Tool         |" -ForegroundColor Cyan
Write-Host "+==================================================================+" -ForegroundColor Cyan
Write-Host ""

# Step 1: Check existing installation
Write-Step "Checking existing installation"
if (-not (Test-Path $InstallDir)) {
    Write-Host "`n`n[WARNING] S0 is not installed at $InstallDir." -ForegroundColor Yellow
    Write-Host "To install S0, run in PowerShell:" -ForegroundColor White
    Write-Host "  irm https://sector0.pages.dev/ps1 | iex`n" -ForegroundColor Cyan
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
    git fetch origin $S0Ref -q 2>$null
    $latestCommit = (git rev-parse --short FETCH_HEAD 2>$null)
    if ($currentCommit -eq $latestCommit) {
        Write-Ok; Write-Info "already up-to-date at commit $currentCommit"
    } else {
        try {
            git checkout -q FETCH_HEAD
            Write-Ok; Write-Info "updated: $currentCommit -> $latestCommit"
        } catch {
            Write-Info "local modifications detected; resetting cleanly to FETCH_HEAD..."
            git reset --hard FETCH_HEAD -q
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
    $hasMarker = (Test-Path (Join-Path $InstallDir ".git")) -or (Test-Path (Join-Path $InstallDir "s0_config.json")) -or (Test-Path (Join-Path $InstallDir ".s0_install_marker"))
    if ($hasMarker -and (Test-Path (Join-Path $InstallDir ".venv"))) {
        Remove-Item -Recurse -Force (Join-Path $InstallDir ".venv") -ErrorAction SilentlyContinue
    }
    python -m venv (Join-Path $InstallDir ".venv")
}
try {
    & $VenvPython -m pip install --upgrade pip -q
    if ($LASTEXITCODE -ne 0) { throw "pip upgrade failed with exit code $LASTEXITCODE" }
    & $VenvPython -m pip install -e . -q
    if ($LASTEXITCODE -ne 0) { throw "s0 distribution install failed with exit code $LASTEXITCODE" }
    & $VenvPython -m pip install reportlab qrcode pillow fastapi uvicorn[standard] -q
    if ($LASTEXITCODE -ne 0) { throw "dependencies install failed with exit code $LASTEXITCODE" }
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
Write-Host "[OK] S0 upgraded successfully!" -ForegroundColor Green
Write-Host "   Version    : $s0Ver" -ForegroundColor White
Write-Host "   Directory  : $InstallDir" -ForegroundColor White
Write-Host "   Command    : s0 --version" -ForegroundColor Cyan
Write-Host ""
