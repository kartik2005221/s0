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
Write-Host "║      National Technical Research Organisation (NTRO)              ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Error "Python 3.10+ is required. Please install Python from https://www.python.org/"
    exit 1
}
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Error "Git is required. Please install Git from https://git-scm.com/"
    exit 1
}

Write-Host "==> Deploying S0 to $InstallDir..." -ForegroundColor Yellow
if (Test-Path $InstallDir) {
    Set-Location $InstallDir
    try { git pull --ff-only } catch {}
} else {
    git clone --depth 1 $Repo $InstallDir
}
Set-Location $InstallDir

Write-Host "==> Setting up Python virtual environment..." -ForegroundColor Yellow
python -m venv .venv
& .\.venv\Scripts\pip.exe install --upgrade pip -q
& .\.venv\Scripts\pip.exe install -e core\python -e linux\cli -q
& .\.venv\Scripts\pip.exe install reportlab qrcode pillow -q

Write-Host "`n✅ S0 installed successfully!" -ForegroundColor Green
Write-Host "   Binary: $InstallDir\.venv\Scripts\s0.exe" -ForegroundColor Green
Write-Host "   Run:    $InstallDir\.venv\Scripts\s0.exe --version" -ForegroundColor Green
