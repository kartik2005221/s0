@echo off
REM Launch the s0 local GUI on Windows. Binds 127.0.0.1 only.
cd /d "%~dp0"
set REPO=%~dp0..
if defined S0_PORT (set PORT=%S0_PORT%) else (set PORT=8000)
"%REPO%\.venv\Scripts\python.exe" -m uvicorn app:app --host 127.0.0.1 --port %PORT%
