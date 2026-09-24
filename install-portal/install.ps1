<#
.SYNOPSIS
    S0 (Sector Zero) — Resilient One-Line Installer for Windows (PowerShell)
    Usage: irm https://s0-install.pages.dev/ps1 | iex
#>
$ErrorActionPreference = 'Stop'
$Repo = "https://github.com/kartik2005221/s0.git"
$InstallDir = if ($env:S0_INSTALL_DIR) { $env:S0_INSTALL_DIR } else { "$env:USERPROFILE\.s0" }
$TotalSteps = 9
$Step = 0

function Write-Step($Msg) {
    $script:Step++
    Write-Host "`n[$script:Step/$TotalSteps] $Msg..." -ForegroundColor Cyan -NoNewline
}
function Write-Ok { Write-Host " done" -ForegroundColor Green }
function Write-Info($Msg) { Write-Host "`n    -> $Msg" -ForegroundColor Yellow }

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║      S0 (Sector Zero) — Digital Forensic & Sanitization Suite   ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Step 1: Detect / Install Python 3.10+
Write-Step "Detecting Python 3.10+"
$PythonCmd = $null; $PythonArgs = @()
foreach ($c in @(
    @{ Cmd = 'python';  Args = @() },
    @{ Cmd = 'py';      Args = @('-3') },
    @{ Cmd = 'python3'; Args = @() }
)) {
    if (Get-Command $c.Cmd -ErrorAction SilentlyContinue) {
        try {
            $testArgs = $c.Args + @('-c', 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)')
            & $c.Cmd $testArgs 2>$null
            if ($LASTEXITCODE -eq 0) { $PythonCmd = $c.Cmd; $PythonArgs = $c.Args; break }
        } catch {}
    }
}
if (-not $PythonCmd) {
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Write-Host "`n[!] Python 3.10+ was not found." -ForegroundColor Yellow
        $resp = Read-Host "Would you like s0 to install Python 3.12 via Windows Package Manager (winget)? [Y/n]"
        if ($resp -eq '' -or $resp -match '^(y|yes)$') {
            Write-Host "Installing Python via winget..." -ForegroundColor Cyan
            winget install Python.Python.3.12 --accept-package-agreements --accept-source-agreements
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
            if (Get-Command python -ErrorAction SilentlyContinue) {
                $PythonCmd = 'python'; $PythonArgs = @()
            }
        }
    }
    if (-not $PythonCmd) {
        Write-Host "`n[ERROR] Python 3.10+ is required." -ForegroundColor Red
        Write-Host "        Please install Python from: https://www.python.org/downloads/" -ForegroundColor Yellow
        Write-Host "        Be sure to check 'Add python.exe to PATH' during setup." -ForegroundColor Yellow
        return
    }
}
$pyVer = (& $PythonCmd ($PythonArgs + @('-c', 'import sys; print(sys.version.split()[0])'))) 2>$null
Write-Ok; Write-Info "python $pyVer via '$PythonCmd'"

# Step 2: Check / Install Git
Write-Step "Checking Git"
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Write-Host "`n[!] Git was not found." -ForegroundColor Yellow
        $resp = Read-Host "Would you like s0 to install Git via Windows Package Manager (winget)? [Y/n]"
        if ($resp -eq '' -or $resp -match '^(y|yes)$') {
            Write-Host "Installing Git via winget..." -ForegroundColor Cyan
            winget install Git.Git --accept-package-agreements --accept-source-agreements
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
        }
    }
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        Write-Host "`n[ERROR] Git is required. Install from: https://git-scm.com/" -ForegroundColor Red
        return
    }
}
$gitVer = (git --version) -replace "git version ", ""
Write-Ok; Write-Info "git $gitVer"

# Step 3: Deploy / Update Repository
Write-Step "Deploying S0 to $InstallDir"
if (Test-Path $InstallDir) {
    Set-Location $InstallDir
    try { git pull --ff-only -q 2>$null } catch {}
    Write-Ok; Write-Info "existing install updated"
} else {
    try {
        git clone --depth 1 -q $Repo $InstallDir
    } catch {
        git clone -q $Repo $InstallDir
    }
    Write-Ok; Write-Info "cloned from $Repo"
}
Set-Location $InstallDir

# Step 4: Virtual Environment
Write-Step "Creating Python virtual environment"
$VenvDir = Join-Path $InstallDir ".venv"
$VenvPython = Join-Path $VenvDir "Scripts\python.exe"
if ((Test-Path $VenvDir) -and (-not (Test-Path $VenvPython))) {
    Remove-Item -Recurse -Force $VenvDir -ErrorAction SilentlyContinue
}
if (-not (Test-Path $VenvPython)) {
    & $PythonCmd ($PythonArgs + @('-m', 'venv', '.venv'))
}
if (-not (Test-Path $VenvPython)) {
    Write-Host "`n`n[ERROR] Failed to create virtual environment at $VenvDir" -ForegroundColor Red
    return
}
Write-Ok

# Step 5: Upgrade pip
Write-Step "Upgrading pip"
& $VenvPython -m pip install --upgrade pip -q
Write-Ok

# Step 6: Install S0 packages
Write-Step "Installing S0 packages"
Write-Info "core cryptographic library..."
& $VenvPython -m pip install -e core\python -q
Write-Info "CLI and Windows forensic engines..."
& $VenvPython -m pip install -e linux\cli -q
Write-Info "PDF, QR generation and web dashboard..."
& $VenvPython -m pip install reportlab qrcode pillow fastapi uvicorn[standard] -q
Write-Ok

# Step 7: Create bin/ launchers
Write-Step "Creating command launchers"
$BinDir = Join-Path $InstallDir "bin"
if (-not (Test-Path $BinDir)) { New-Item -ItemType Directory -Path $BinDir -Force | Out-Null }
$CmdContent = "@echo off`r`n`"%~dp0..\\.venv\\Scripts\\s0.exe`" %*`r`nexit /b %ERRORLEVEL%`r`n"
[System.IO.File]::WriteAllText((Join-Path $BinDir "s0.cmd"), $CmdContent, [System.Text.Encoding]::ASCII)
$ShContent  = "#!/usr/bin/env sh`nbasedir=`$(dirname `"`$0`")`nexec `"`$basedir/../.venv/Scripts/s0.exe`" `"`$@`"`n"
[System.IO.File]::WriteAllText((Join-Path $BinDir "s0"), $ShContent, [System.Text.Encoding]::ASCII)
Write-Ok; Write-Info "$BinDir\s0.cmd"

# Step 8: Update current session PATH
Write-Step "Adding to current session PATH"
$currentPaths = ($env:PATH -split ';') | Where-Object { $_ -ne '' }
if ($currentPaths -notcontains $BinDir) { $env:PATH = "$BinDir;$env:PATH" }
Write-Ok

# Step 9: Persist to User PATH registry
Write-Step "Persisting to User PATH (registry)"
try {
    $userPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::User)
    $userPathList = if ($userPath) { ($userPath -split ';') | Where-Object { $_ -ne '' } } else { @() }
    if ($userPathList -notcontains $BinDir) {
        $newUserPath = if ($userPath) { "$BinDir;$userPath" } else { $BinDir }
        [Environment]::SetEnvironmentVariable("Path", $newUserPath, [EnvironmentVariableTarget]::User)
    }
    Write-Ok
} catch {
    Write-Host " warning: $_" -ForegroundColor Yellow
}

# Register instant same-session function
function global:s0 { & "$InstallDir\.venv\Scripts\s0.exe" @args }

Write-Host ""
Write-Host "✅ S0 installed successfully!" -ForegroundColor Green
Write-Host "   Command : s0" -ForegroundColor Green
Write-Host "   Binary  : $InstallDir\.venv\Scripts\s0.exe" -ForegroundColor Gray
Write-Host "   Run     : s0 --version" -ForegroundColor Green
Write-Host "   Web UI  : s0 web" -ForegroundColor Green
Write-Host ""
Write-Host "⚖  LEGAL NOTICE: Only operate on storage devices and files you legally own" -ForegroundColor Yellow
Write-Host "   or have explicit written authorization to process." -ForegroundColor Yellow
Write-Host "   Legal FAQ: https://s0-docs.pages.dev/faq" -ForegroundColor Gray
Write-Host ""
