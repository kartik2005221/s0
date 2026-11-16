@echo off
REM Launch the s0 local Web Dashboard on Windows. Binds 127.0.0.1 only.
REM For an installed s0, prefer `s0 web`. This script targets a source checkout:
REM the venv sits at the repo root, two levels up from this directory.
setlocal
cd /d "%~dp0"
set REPO=%~dp0..\..
if defined S0_PORT (set PORT=%S0_PORT%) else (set PORT=8669)
if exist "%REPO%\.venv\Scripts\python.exe" (
    "%REPO%\.venv\Scripts\python.exe" -m uvicorn s0.web.app:app --host 127.0.0.1 --port %PORT%
) else (
    python -m uvicorn s0.web.app:app --host 127.0.0.1 --port %PORT%
)
