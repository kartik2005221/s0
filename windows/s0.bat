@echo off
REM s0 Windows Unified Forensic Sanitization & Recovery CLI
python "%~dp0..\src\s0\platform\windows\s0_eraser.py" %*
exit /b %ERRORLEVEL%
