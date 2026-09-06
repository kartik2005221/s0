@echo off
REM S0 (Sector Zero) — One-Line Installer for Windows (CMD)
REM Usage: curl -sSL https://raw.githubusercontent.com/kartik2005221/s0/master/scripts/install.cmd | cmd
set "REPO=https://github.com/kartik2005221/s0.git"
set "INSTALL_DIR=%USERPROFILE%\.s0"

echo ==================================================================
echo   S0 (Sector Zero) — Digital Forensic & Sanitization Suite
echo ==================================================================

python --version >nul 2>&1 || (echo ERROR: Python 3.10+ required. & exit /b 1)
git --version >nul 2>&1 || (echo ERROR: Git required. & exit /b 1)

echo ==^> Deploying S0 to %INSTALL_DIR%...
if exist "%INSTALL_DIR%" (
    cd /d "%INSTALL_DIR%"
    git pull --ff-only 2>nul
) else (
    git clone --depth 1 "%REPO%" "%INSTALL_DIR%"
)
cd /d "%INSTALL_DIR%"

echo ==^> Setting up virtual environment...
python -m venv .venv
"%INSTALL_DIR%\.venv\Scripts\pip.exe" install --upgrade pip -q
"%INSTALL_DIR%\.venv\Scripts\pip.exe" install -e core\python -e linux\cli -q
"%INSTALL_DIR%\.venv\Scripts\pip.exe" install reportlab qrcode pillow -q

echo.
echo S0 installed successfully!
echo Binary: %INSTALL_DIR%\.venv\Scripts\s0.exe
echo Run:    %INSTALL_DIR%\.venv\Scripts\s0.exe --version
