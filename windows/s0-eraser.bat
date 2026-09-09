@echo off
REM s0 Windows Secure Sanitization Platform Launcher (Root Delegation)
call "%~dp0cli\s0-eraser.bat" %*
exit /b %ERRORLEVEL%
