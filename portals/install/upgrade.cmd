@echo off
REM S0 (Sector Zero) — Resilient Upgrader for Windows (CMD)
REM Usage: curl -fsSL https://s0-install.pages.dev/upgrade-cmd -o s0-upgrade.cmd && s0-upgrade.cmd && del s0-upgrade.cmd
setlocal EnableDelayedExpansion

set "INSTALL_DIR=%USERPROFILE%\.s0"
set "STEP=0"
set "TOTAL=6"

echo.
echo ==================================================================
echo   S0 (Sector Zero) -- Suite Upgrade ^& Maintenance Tool
echo ==================================================================
echo.

REM ── Step 1: Check installation directory ───────────────────────────
set /a STEP=STEP+1
echo [%STEP%/%TOTAL%] Checking existing installation...
if not exist "%INSTALL_DIR%" (
    echo   [WARNING] S0 is not installed at %INSTALL_DIR%.
    echo   To install S0, run in CMD:
    echo     curl -fsSL https://s0-install.pages.dev/cmd -o s0-install.cmd ^&^& s0-install.cmd ^&^& del s0-install.cmd
    exit /b 1
)
if not exist "%INSTALL_DIR%\.git" (
    echo   [ERROR] %INSTALL_DIR% is not a git repository.
    exit /b 1
)
cd /d "%INSTALL_DIR%"
echo   [OK] Found S0 at %INSTALL_DIR%

REM ── Step 2: Check Git ───────────────────────────────────────────────
set /a STEP=STEP+1
echo [%STEP%/%TOTAL%] Checking Git...
git --version >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo   [ERROR] Git is required. Install from: https://git-scm.com/
    exit /b 1
)
echo   [OK] Git found

REM ── Step 3: Pull latest updates ────────────────────────────────────
set /a STEP=STEP+1
echo [%STEP%/%TOTAL%] Pulling latest updates from GitHub...
git fetch origin master -q 2>nul
git pull --ff-only origin master -q 2>nul
if %ERRORLEVEL% neq 0 (
    echo   [!] Fast-forward pull failed, resetting cleanly to origin/master...
    git reset --hard origin/master -q
)
echo   [OK] Repository updated

REM ── Step 4: Upgrade pip & dependencies ──────────────────────────────
set /a STEP=STEP+1
echo [%STEP%/%TOTAL%] Upgrading virtual environment packages...
set "VENV_PYTHON=%INSTALL_DIR%\.venv\Scripts\python.exe"
if not exist "%VENV_PYTHON%" (
    echo   [ERROR] Virtual environment python missing at %VENV_PYTHON%
    exit /b 1
)

"%VENV_PYTHON%" -m pip install --upgrade pip -q
if %ERRORLEVEL% neq 0 (
    echo   [ERROR] pip upgrade failed.
    exit /b 1
)
"%VENV_PYTHON%" -m pip install -e . -q
if %ERRORLEVEL% neq 0 (
    echo   [ERROR] Failed to upgrade the s0 distribution.
    exit /b 1
)
"%VENV_PYTHON%" -m pip install reportlab qrcode pillow fastapi uvicorn[standard] -q
if %ERRORLEVEL% neq 0 (
    echo   [ERROR] Failed to upgrade dependencies.
    exit /b 1
)
echo   [OK] Dependencies refreshed

REM ── Step 5: Refresh command wrapper ────────────────────────────────
set /a STEP=STEP+1
echo [%STEP%/%TOTAL%] Refreshing command wrappers...
set "BIN_DIR=%INSTALL_DIR%\bin"
if not exist "%BIN_DIR%" mkdir "%BIN_DIR%"

(
echo @echo off
echo "%INSTALL_DIR%\.venv\Scripts\s0.exe" %%*
) > "%BIN_DIR%\s0.cmd"

echo   [OK] Wrapper refreshed at %BIN_DIR%\s0.cmd

REM ── Step 6: Verify upgraded version ────────────────────────────────
set /a STEP=STEP+1
echo [%STEP%/%TOTAL%] Verifying upgraded version...
"%BIN_DIR%\s0.cmd" --version
echo.
echo ==================================================================
echo   [SUCCESS] S0 upgraded successfully!
echo   Executable : %BIN_DIR%\s0.cmd
echo   Run        : s0 --version
echo ==================================================================
echo.
exit /b 0
