@echo off
REM Launch the TrustWipe local GUI on Windows. Binds 127.0.0.1 only.
cd /d "%~dp0"
set REPO=%~dp0..
if defined TRUSTWIPE_PORT (set PORT=%TRUSTWIPE_PORT%) else (set PORT=8000)
"%REPO%\.venv\Scripts\python.exe" -m uvicorn app:app --host 127.0.0.1 --port %PORT%
