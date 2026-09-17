@echo off
REM s0 Windows Unified Forensic Sanitization & Recovery CLI
python "%~dp0cli\s0_eraser.py" %*
exit /b %ERRORLEVEL%
