<#
.SYNOPSIS
    S0 (Sector Zero) — One-Line Installer for Windows (PowerShell)
    Usage: irm https://raw.githubusercontent.com/kartik2005221/s0/master/scripts/install.ps1 | iex
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

# Step 1: Detect Python 3.10+
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
    Write-Host "`n`n[ERROR] Python 3.10+ was not found." -ForegroundColor Red
    Write-Host "        Install from: https://www.python.org/downloads/ (check 'Add python.exe to PATH')" -ForegroundColor Yellow
    return
}
$pyVer = (& $PythonCmd ($PythonArgs + @('-c', 'import sys; print(sys.version.split()[0])'))) 2>$null
Write-Ok; Write-Info "python $pyVer via '$PythonCmd'"

# Step 2: Check Git
Write-Step "Checking Git"
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Host "`n`n[ERROR] Git is required. Install from: https://git-scm.com/" -ForegroundColor Red
    return
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
    git clone --depth 1 -q $Repo $InstallDir
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
Write-Info "CLI and dependencies..."
& $VenvPython -m pip install -e linux\cli -q
Write-Info "PDF / QR generation..."
& $VenvPython -m pip install reportlab qrcode pillow -q
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
Write-Host ""

