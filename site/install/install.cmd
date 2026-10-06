@echo off
REM S0 (Sector Zero) — Resilient One-Line Installer for Windows (CMD)
REM Usage: curl -fsSL https://sector-zero.pages.dev/cmd -o s0-install.cmd && s0-install.cmd && del s0-install.cmd
set "REPO=https://github.com/kartik2005221/s0.git"
set "INSTALL_DIR=%USERPROFILE%\.s0"
set "STEP=0"
set "TOTAL=8"

:: Admin-elevation advisory
net session >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo.
    echo WARNING: Running as Administrator.
    echo    S0 installs to "%USERPROFILE%\.s0" ^(your user profile^).
    echo    Running without elevation is recommended.
    echo.
)

echo.
echo ==================================================================
echo   S0 (Sector Zero) -- Digital Forensic ^& Sanitization Suite
echo ==================================================================
echo.

REM ── Step 1: Detect Python 3.11+ ────────────────────────────────────
set /a STEP=STEP+1
echo [%STEP%/%TOTAL%] Detecting Python 3.11+...
set "PYTHON_BIN="
set "PYTHON_ARGS="

python -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>&1
if %ERRORLEVEL% equ 0 set "PYTHON_BIN=python"

if not defined PYTHON_BIN (
    py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>&1
    if %ERRORLEVEL% equ 0 (
        set "PYTHON_BIN=py"
        set "PYTHON_ARGS=-3"
    )
)

if not defined PYTHON_BIN (
    python3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>&1
    if %ERRORLEVEL% equ 0 set "PYTHON_BIN=python3"
)

if not defined PYTHON_BIN (
    echo   [!] Python 3.11+ was not found. Trying winget...
    winget --version >nul 2>&1
    if %ERRORLEVEL% equ 0 (
        echo   Installing Python 3.12 via winget...
        winget install Python.Python.3.12 --accept-package-agreements --accept-source-agreements
        set "PYTHON_BIN=python"
    )
)

if not defined PYTHON_BIN (
    echo   [ERROR] Python 3.11+ was not found.
    echo   Install from: https://www.python.org/downloads/
    echo   Check "Add python.exe to PATH" during installation.
    exit /b 1
)
echo   [OK] Found: %PYTHON_BIN%

REM ── Step 2: Check Git ───────────────────────────────────────────────
set /a STEP=STEP+1
echo [%STEP%/%TOTAL%] Checking Git...
git --version >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo   [!] Git not found. Trying winget...
    winget install Git.Git --accept-package-agreements --accept-source-agreements
)
git --version >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo   [ERROR] Git is required. Install from: https://git-scm.com/
    exit /b 1
)
echo   [OK] Git found

REM ── Step 3: Deploy / Update Repository ─────────────────────────────
set /a STEP=STEP+1
echo [%STEP%/%TOTAL%] Deploying S0 to %INSTALL_DIR%...
if exist "%INSTALL_DIR%" (
    cd /d "%INSTALL_DIR%"
    git pull --ff-only -q 2>nul
    if %ERRORLEVEL% neq 0 (
        echo   [!] git pull failed; continuing with existing files.
    ) else (
        echo   [OK] Existing install updated
    )
) else (
    git clone --depth 1 -q "%REPO%" "%INSTALL_DIR%" 2>nul
    if %ERRORLEVEL% neq 0 (
        echo   Shallow clone failed, attempting full clone...
        git clone -q "%REPO%" "%INSTALL_DIR%" 2>nul
        if %ERRORLEVEL% neq 0 (
            echo   [ERROR] git clone failed. Check your network connection.
            exit /b 1
        )
    )
    echo   [OK] Cloned from %REPO%
)
cd /d "%INSTALL_DIR%"

REM ── Step 4: Virtual Environment ────────────────────────────────────
set /a STEP=STEP+1
echo [%STEP%/%TOTAL%] Creating Python virtual environment...
if exist "%INSTALL_DIR%\.venv" (
    if not exist "%INSTALL_DIR%\.venv\Scripts\python.exe" (
        rmdir /s /q "%INSTALL_DIR%\.venv" 2>nul
    )
)
if not exist "%INSTALL_DIR%\.venv\Scripts\python.exe" (
    %PYTHON_BIN% %PYTHON_ARGS% -m venv "%INSTALL_DIR%\.venv"
)
if not exist "%INSTALL_DIR%\.venv\Scripts\python.exe" (
    echo   [ERROR] Failed to create virtual environment.
    exit /b 1
)
echo   [OK] Virtual environment ready

REM ── Step 5: Upgrade pip ─────────────────────────────────────────────
set /a STEP=STEP+1
echo [%STEP%/%TOTAL%] Upgrading pip...
"%INSTALL_DIR%\.venv\Scripts\python.exe" -m pip install --upgrade pip -q
if %ERRORLEVEL% neq 0 (
    echo   [ERROR] pip upgrade failed.
    exit /b 1
)
echo   [OK] pip upgraded

REM ── Step 6: Install S0 packages ─────────────────────────────────────
set /a STEP=STEP+1
echo [%STEP%/%TOTAL%] Installing S0 packages...
echo   -^> s0 distribution (core, CLI and forensic engines)...
"%INSTALL_DIR%\.venv\Scripts\python.exe" -m pip install -e . -q
if %ERRORLEVEL% neq 0 (
    echo   [ERROR] Failed to install the s0 distribution.
    exit /b 1
)
echo   -^> PDF, QR generation and web dashboard...
"%INSTALL_DIR%\.venv\Scripts\python.exe" -m pip install reportlab qrcode pillow fastapi uvicorn[standard] -q
if %ERRORLEVEL% neq 0 (
    echo   [ERROR] Failed to install web and PDF dependencies.
    exit /b 1
)
echo   [OK] All packages installed

REM ── Step 7: Create bin/ launcher ───────────────────────────────────
set /a STEP=STEP+1
echo [%STEP%/%TOTAL%] Creating s0 command launcher...
if not exist "%INSTALL_DIR%\bin" mkdir "%INSTALL_DIR%\bin"
(
    echo @echo off
    echo "%%~dp0..\\.venv\\Scripts\\s0.exe" %%*
    echo exit /b %%ERRORLEVEL%%
) > "%INSTALL_DIR%\bin\s0.cmd"
type nul > "%INSTALL_DIR%\.s0_install_marker" 2>nul
echo   [OK] %INSTALL_DIR%\bin\s0.cmd

REM ── Step 8: Update PATH ─────────────────────────────────────────────
set /a STEP=STEP+1
echo [%STEP%/%TOTAL%] Adding to PATH...
set "PATH=%INSTALL_DIR%\bin;%PATH%"
REM The path is passed through the environment rather than interpolated into the
REM -Command string. A user directory containing an apostrophe -- C:\Users\O'Brien --
REM terminated the PowerShell single-quoted string early, so everything after it was
REM parsed as code: an installer that could be made to run arbitrary PowerShell by
REM naming a folder. $env: is data, not syntax, so no path can alter the command.
set "S0_BIN_TO_PATH=%INSTALL_DIR%\bin"
powershell -NoProfile -ExecutionPolicy Bypass -Command "$b = $env:S0_BIN_TO_PATH; $p = [Environment]::GetEnvironmentVariable('Path', 'User'); if (($p -split ';') -notcontains $b) { [Environment]::SetEnvironmentVariable('Path', $b + ';' + $p, 'User') }" >nul 2>&1
echo   [OK] PATH updated

echo.
echo [SUCCESS] S0 installed successfully!
echo Command : s0
echo Binary  : %INSTALL_DIR%\.venv\Scripts\s0.exe
echo Run     : s0 --version
echo Web UI  : s0 web
echo.
echo LEGAL: s0 is a digital forensic sanitization and recovery tool. Only operate on storage media you own
echo        or have documented authorization to process.
echo.
