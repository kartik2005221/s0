<#
.SYNOPSIS
    S0 (Sector Zero) — Uninstaller for Windows (PowerShell)
    Usage: irm https://s0-install.pages.dev/uninstall-ps1 | iex
#>
$ErrorActionPreference = 'Stop'
$InstallDir = if ($env:S0_INSTALL_DIR) { $env:S0_INSTALL_DIR } else { "$env:USERPROFILE\.s0" }
$BinDir = Join-Path $InstallDir "bin"

Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║      S0 (Sector Zero) — Uninstaller                             ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

# Navigate away from InstallDir in case the terminal is currently inside it
Set-Location $env:USERPROFILE

# Confirmation prompt
$isYes = ($env:S0_UNINSTALL_YES -eq "1") -or ($args -contains "-y") -or ($args -contains "--yes")
if (-not $isYes -and [Environment]::UserInteractive) {
    $confirm = Read-Host "Are you sure you want to completely remove S0 from $InstallDir? [y/N]"
    if ($confirm -notmatch '^(y|yes)$') {
        Write-Host "Uninstallation aborted." -ForegroundColor Yellow
        exit 0
    }
}

# 1. Remove from Persistent User PATH (Registry)
try {
    $userPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::User)
    if ($userPath) {
        $filtered = ($userPath -split ';') | Where-Object { 
            $_ -ne '' -and $_ -ne $BinDir -and $_ -ne "$InstallDir\.venv\Scripts"
        }
        $newUserPath = $filtered -join ';'
        [Environment]::SetEnvironmentVariable("Path", $newUserPath, [EnvironmentVariableTarget]::User)
    }
} catch {
    Write-Warning "Could not update User PATH environment variable: $_"
}

# 2. Remove from Current Session PATH
$currentPaths = ($env:PATH -split ';') | Where-Object { 
            $_ -ne '' -and $_ -ne $BinDir -and $_ -ne "$InstallDir\.venv\Scripts"
}
$env:PATH = $currentPaths -join ';'

# 3. Remove session function / alias if defined
if (Get-Command s0 -CommandType Function -ErrorAction SilentlyContinue) {
    Remove-Item Function:\s0 -Force -ErrorAction SilentlyContinue
}
if (Get-Command s0 -CommandType Alias -ErrorAction SilentlyContinue) {
    Remove-Item Alias:\s0 -Force -ErrorAction SilentlyContinue
}

# 4. Remove installation directory
if (Test-Path $InstallDir) {
    $defaultDir = "$env:USERPROFILE\.s0"
    $isDefault = ($InstallDir.TrimEnd('\') -eq $defaultDir.TrimEnd('\'))
    $hasMarker = (Test-Path (Join-Path $InstallDir ".s0_install_marker")) -or (Test-Path (Join-Path $InstallDir "s0_config.json")) -or (Test-Path (Join-Path $InstallDir ".git"))
    if (-not $isDefault -and -not $hasMarker) {
        Write-Error "ERROR: Refusing to delete $InstallDir — directory does not appear to be an S0 installation (missing .s0_install_marker, s0_config.json, or .git)."
        exit 1
    }
    Write-Host "==> Removing $InstallDir..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force $InstallDir -ErrorAction SilentlyContinue
}

Write-Host "`n✅ S0 has been completely uninstalled from your system." -ForegroundColor Green
