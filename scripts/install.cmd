@echo off
REM S0 (Sector Zero) — One-Line Installer for Windows (CMD)
REM Usage: curl -sSL https://raw.githubusercontent.com/kartik2005221/s0/master/scripts/install.cmd | cmd
set "REPO=https://github.com/kartik2005221/s0.git"
set "INSTALL_DIR=%USERPROFILE%\.s0"
set "STEP=0"
set "TOTAL=8"

echo.
echo ==================================================================
echo   S0 (Sector Zero) -- Digital Forensic ^& Sanitization Suite
echo ==================================================================
echo.

REM ── Step 1: Detect Python 3.10+ ────────────────────────────────────
set /a STEP=STEP+1
echo [%STEP%/%TOTAL%] Detecting Python 3.10+...
set "PYTHON_BIN="
set "PYTHON_ARGS="

python -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>&1
if %ERRORLEVEL% equ 0 set "PYTHON_BIN=python"

if not defined PYTHON_BIN (
    py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>&1
    if %ERRORLEVEL% equ 0 (
        set "PYTHON_BIN=py"
        set "PYTHON_ARGS=-3"
    )
)

if not defined PYTHON_BIN (
    python3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>&1
    if %ERRORLEVEL% equ 0 set "PYTHON_BIN=python3"
)

if not defined PYTHON_BIN (
    echo   [ERROR] Python 3.10+ was not found.
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
    echo   [OK] Existing install updated
) else (
    git clone --depth 1 -q "%REPO%" "%INSTALL_DIR%"
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
echo   [OK] pip upgraded

REM ── Step 6: Install S0 packages ─────────────────────────────────────
set /a STEP=STEP+1
echo [%STEP%/%TOTAL%] Installing S0 packages...
echo   -^> core cryptographic library...
"%INSTALL_DIR%\.venv\Scripts\python.exe" -m pip install -e core\python -q
echo   -^> CLI and dependencies...
"%INSTALL_DIR%\.venv\Scripts\python.exe" -m pip install -e linux\cli -q
echo   -^> PDF / QR generation...
"%INSTALL_DIR%\.venv\Scripts\python.exe" -m pip install reportlab qrcode pillow -q
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
echo   [OK] %INSTALL_DIR%\bin\s0.cmd

REM ── Step 8: Update PATH ─────────────────────────────────────────────
set /a STEP=STEP+1
echo [%STEP%/%TOTAL%] Adding to PATH...
set "PATH=%INSTALL_DIR%\bin;%PATH%"
powershell -NoProfile -ExecutionPolicy Bypass -Command "$b = '%INSTALL_DIR%\bin'; $p = [Environment]::GetEnvironmentVariable('Path', 'User'); if (($p -split ';') -notcontains $b) { [Environment]::SetEnvironmentVariable('Path', $b + ';' + $p, 'User') }" >nul 2>&1
echo   [OK] PATH updated

echo.
echo [SUCCESS] S0 installed successfully!
echo Command : s0
echo Binary  : %INSTALL_DIR%\.venv\Scripts\s0.exe
echo Run     : s0 --version
echo.
