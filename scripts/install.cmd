@echo off
REM S0 (Sector Zero) — One-Line Installer for Windows (CMD)
REM Usage: curl -sSL https://raw.githubusercontent.com/kartik2005221/s0/master/scripts/install.cmd | cmd
set "REPO=https://github.com/kartik2005221/s0.git"
set "INSTALL_DIR=%USERPROFILE%\.s0"

echo ==================================================================
echo   S0 (Sector Zero) — Digital Forensic & Sanitization Suite
echo ==================================================================

REM 1. Detect functional Python 3.10+ (ignoring WindowsApps dummy alias)
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
    echo [ERROR] Python 3.10+ was not found on your system.
    echo Please install Python 3.10+ from https://www.python.org/downloads/
    echo NOTE: During installation, check the box "Add python.exe to PATH".
    exit /b 1
)

REM 2. Check Git
git --version >nul 2>&1 || (echo [ERROR] Git is required. Please install Git from https://git-scm.com/ & exit /b 1)

REM 3. Deploy/Update Repository
echo ==^> Deploying S0 to %INSTALL_DIR%...
if exist "%INSTALL_DIR%" (
    cd /d "%INSTALL_DIR%"
    git pull --ff-only 2>nul
) else (
    git clone --depth 1 "%REPO%" "%INSTALL_DIR%"
)
cd /d "%INSTALL_DIR%"

REM 4. Configure Virtual Environment
echo ==^> Setting up virtual environment...
if exist "%INSTALL_DIR%\.venv" (
    if not exist "%INSTALL_DIR%\.venv\Scripts\python.exe" (
        rmdir /s /q "%INSTALL_DIR%\.venv" 2>nul
    )
)

if not exist "%INSTALL_DIR%\.venv\Scripts\python.exe" (
    %PYTHON_BIN% %PYTHON_ARGS% -m venv "%INSTALL_DIR%\.venv"
)

if not exist "%INSTALL_DIR%\.venv\Scripts\python.exe" (
    echo [ERROR] Failed to create virtual environment.
    exit /b 1
)

REM 5. Install Dependencies (Use python.exe -m pip to avoid Windows file locks)
echo ==^> Installing S0 packages and dependencies...
"%INSTALL_DIR%\.venv\Scripts\python.exe" -m pip install --upgrade pip -q
"%INSTALL_DIR%\.venv\Scripts\python.exe" -m pip install -e core\python -e linux\cli -q
"%INSTALL_DIR%\.venv\Scripts\python.exe" -m pip install reportlab qrcode pillow -q

REM 6. Create clean bin/ directory with command launcher
if not exist "%INSTALL_DIR%\bin" mkdir "%INSTALL_DIR%\bin"
(
    echo @echo off
    echo "%%~dp0..\.venv\Scripts\s0.exe" %%*
    echo exit /b %%ERRORLEVEL%%
) > "%INSTALL_DIR%\bin\s0.cmd"

REM 7. Add to Current Session PATH & Persistent User PATH (Registry)
set "PATH=%INSTALL_DIR%\bin;%PATH%"
powershell -NoProfile -ExecutionPolicy Bypass -Command "$b = '%INSTALL_DIR%\bin'; $p = [Environment]::GetEnvironmentVariable('Path', 'User'); if (($p -split ';') -notcontains $b) { [Environment]::SetEnvironmentVariable('Path', $b + ';' + $p, 'User') }" >nul 2>&1

echo.
echo [SUCCESS] S0 installed successfully!
echo Command: s0
echo Binary:  %INSTALL_DIR%\.venv\Scripts\s0.exe
echo Run:     s0 --version
