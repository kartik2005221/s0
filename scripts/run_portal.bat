@echo off
REM Helper script to launch the static Verification Portal locally on Windows (CMD)
REM National Technical Research Organisation (NTRO)

cd /d "%~dp0..\verification-portal"
set "PORT=%~1"
if "%PORT%"=="" set "PORT=8080"

echo =================================================================
echo  s0 Verification Portal (Pure Client-Side Zero-Trust Web)
echo =================================================================
echo URL: http://127.0.0.1:%PORT%
echo Press Ctrl+C to stop.
echo =================================================================

python -m http.server %PORT%
