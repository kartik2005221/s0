@echo off
REM S0 (Sector Zero) — Uninstaller for Windows (CMD)
REM Usage: curl -fsSL https://sector-zero.pages.dev/uninstall-cmd -o s0-uninstall.cmd && s0-uninstall.cmd && del s0-uninstall.cmd
set "INSTALL_DIR=%USERPROFILE%\.s0"
set "BIN_DIR=%USERPROFILE%\.s0\bin"

echo ==================================================================
echo   S0 (Sector Zero) — Uninstaller
echo ==================================================================

REM Navigate away from INSTALL_DIR in case current directory is inside it
cd /d "%USERPROFILE%"

if "%S0_UNINSTALL_YES%"=="1" goto :do_uninstall
if "%1"=="-y" goto :do_uninstall
if "%1"=="--yes" goto :do_uninstall

set "CONFIRM=n"
set /p "CONFIRM=Are you sure you want to completely remove S0 from %INSTALL_DIR%? [y/N]: "
if /i not "%CONFIRM%"=="y" if /i not "%CONFIRM%"=="yes" (
    echo Uninstallation aborted.
    exit /b 0
)

:do_uninstall

REM 1. Remove from Persistent User PATH via PowerShell
powershell -NoProfile -ExecutionPolicy Bypass -Command "$b = '%BIN_DIR%'; $s = '%INSTALL_DIR%\.venv\Scripts'; $p = [Environment]::GetEnvironmentVariable('Path', 'User'); if ($p) { $new = (($p -split ';') | Where-Object { $_ -ne '' -and $_ -ne $b -and $_ -ne $s }) -join ';'; [Environment]::SetEnvironmentVariable('Path', $new, 'User') }" >nul 2>&1

REM 2. Remove from Current Session PATH
powershell -NoProfile -ExecutionPolicy Bypass -Command "$b = '%BIN_DIR%'; $s = '%INSTALL_DIR%\.venv\Scripts'; $p = $env:PATH; $new = (($p -split ';') | Where-Object { $_ -ne '' -and $_ -ne $b -and $_ -ne $s }) -join ';'; Write-Output $new" > "%TEMP%\_s0_newpath.txt" 2>nul
if exist "%TEMP%\_s0_newpath.txt" (
    set /p PATH=<"%TEMP%\_s0_newpath.txt"
    del /f /q "%TEMP%\_s0_newpath.txt" >nul 2>&1
)

REM 3. Remove Installation Directory
if exist "%INSTALL_DIR%" (
    echo ==^> Removing %INSTALL_DIR%...
    rmdir /s /q "%INSTALL_DIR%" 2>nul
)

echo.
echo [SUCCESS] S0 has been completely uninstalled from your system.
