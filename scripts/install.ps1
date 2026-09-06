<#
.SYNOPSIS
    S0 (Sector Zero) — One-Line Installer for Windows (PowerShell)
    Usage: irm https://raw.githubusercontent.com/kartik2005221/s0/master/scripts/install.ps1 | iex
#>
$ErrorActionPreference = 'Stop'
$Repo = "https://github.com/kartik2005221/s0.git"
$InstallDir = if ($env:S0_INSTALL_DIR) { $env:S0_INSTALL_DIR } else { "$env:USERPROFILE\.s0" }

Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║      S0 (Sector Zero) — Digital Forensic & Sanitization Suite   ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

# 1. Detect functional Python 3.10+ (ignoring WindowsApps store execution aliases)
$PythonCmd = $null
$PythonArgs = @()

$Candidates = @(
    @{ Cmd = 'python';  Args = @() },
    @{ Cmd = 'py';      Args = @('-3') },
    @{ Cmd = 'python3'; Args = @() }
)

foreach ($c in $Candidates) {
    if (Get-Command $c.Cmd -ErrorAction SilentlyContinue) {
        try {
            $testArgs = $c.Args + @('-c', 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)')
            & $c.Cmd $testArgs 2>$null
            if ($LASTEXITCODE -eq 0) {
                $PythonCmd = $c.Cmd
                $PythonArgs = $c.Args
                break
            }
        } catch {
            # Continue checking next candidate
        }
    }
}

if (-not $PythonCmd) {
    Write-Host "`n❌ Error: Python 3.10+ was not found on your system." -ForegroundColor Red
    Write-Host "   Please install Python 3.10 or newer from: https://www.python.org/downloads/" -ForegroundColor Yellow
    Write-Host "   NOTE: During installation, be sure to check 'Add python.exe to PATH'." -ForegroundColor Yellow
    return
}

# 2. Check Git
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Host "`n❌ Error: Git is required. Please install Git from: https://git-scm.com/" -ForegroundColor Red
    return
}

# 3. Deploy/Update Repository
Write-Host "==> Deploying S0 to $InstallDir..." -ForegroundColor Yellow
if (Test-Path $InstallDir) {
    Set-Location $InstallDir
    try { git pull --ff-only } catch {}
} else {
    git clone --depth 1 $Repo $InstallDir
}
Set-Location $InstallDir

# 4. Configure Virtual Environment
Write-Host "==> Setting up Python virtual environment..." -ForegroundColor Yellow
$VenvDir = Join-Path $InstallDir ".venv"
$VenvPython = Join-Path $VenvDir "Scripts\python.exe"

# If .venv exists from an incomplete previous attempt, remove it
if ((Test-Path $VenvDir) -and (-not (Test-Path $VenvPython))) {
    Remove-Item -Recurse -Force $VenvDir -ErrorAction SilentlyContinue
}

if (-not (Test-Path $VenvPython)) {
    $venvArgs = $PythonArgs + @('-m', 'venv', '.venv')
    & $PythonCmd $venvArgs
}

if (-not (Test-Path $VenvPython)) {
    Write-Host "`n❌ Error: Failed to create Python virtual environment at $VenvDir" -ForegroundColor Red
    return
}

# 5. Install Dependencies (Use "$VenvPython -m pip" to avoid Windows file locks)
Write-Host "==> Installing S0 packages and dependencies..." -ForegroundColor Yellow
& $VenvPython -m pip install --upgrade pip -q
& $VenvPython -m pip install -e core\python -e linux\cli -q
& $VenvPython -m pip install reportlab qrcode pillow -q

# 6. Create clean bin/ directory with command wrappers
$BinDir = Join-Path $InstallDir "bin"
if (-not (Test-Path $BinDir)) {
    New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
}

# s0.cmd launcher for Command Prompt and PowerShell
$CmdLauncher = Join-Path $BinDir "s0.cmd"
$CmdContent = "@echo off`r`n`"%~dp0..\.venv\Scripts\s0.exe`" %*`r`nexit /b %ERRORLEVEL%`r`n"
[System.IO.File]::WriteAllText($CmdLauncher, $CmdContent, [System.Text.Encoding]::ASCII)

# POSIX s0 wrapper for Git Bash / MSYS2 / WSL
$ShLauncher = Join-Path $BinDir "s0"
$ShContent = "#!/usr/bin/env sh`nbasedir=`$(dirname `"`$0`")`nexec `"`$basedir/../.venv/Scripts/s0.exe`" `"`$@`"`n"
[System.IO.File]::WriteAllText($ShLauncher, $ShContent, [System.Text.Encoding]::ASCII)

# 7. Add to Current Session PATH
$currentPaths = ($env:PATH -split ';') | Where-Object { $_ -ne '' }
if ($currentPaths -notcontains $BinDir) {
    $env:PATH = "$BinDir;$env:PATH"
}

# 8. Add to Persistent User PATH (Registry)
try {
    $userPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::User)
    $userPathList = if ($userPath) { ($userPath -split ';') | Where-Object { $_ -ne '' } } else { @() }
    if ($userPathList -notcontains $BinDir) {
        $newUserPath = if ($userPath) { "$BinDir;$userPath" } else { $BinDir }
        [Environment]::SetEnvironmentVariable("Path", $newUserPath, [EnvironmentVariableTarget]::User)
    }
} catch {
    Write-Warning "Could not update User PATH environment variable: $_"
}

# 9. Register global PowerShell function for instant access in current session
function global:s0 { & "$InstallDir\.venv\Scripts\s0.exe" @args }

Write-Host "`n✅ S0 installed successfully!" -ForegroundColor Green
Write-Host "   Command: s0" -ForegroundColor Green
Write-Host "   Binary:  $InstallDir\.venv\Scripts\s0.exe" -ForegroundColor Gray
Write-Host "   Run:     s0 --version" -ForegroundColor Green
