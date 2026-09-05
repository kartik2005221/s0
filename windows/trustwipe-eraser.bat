@echo off
REM TrustWipe Windows Secure File & Folder Eraser Launcher
REM Smart India Hackathon 2026 (SIH26149) - NTRO

if "%~1"=="" (
    echo Usage: trustwipe-eraser.bat ^<target_file_or_folder^> [passes] [pattern]
    echo Example: trustwipe-eraser.bat C:\Confidential\evidence.docx 1 zero
    exit /b 1
)

set TARGET=%~1
set PASSES=%~2
if "%PASSES%"=="" set PASSES=1
set PATTERN=%~3
if "%PATTERN%"=="" set PATTERN=zero

python "%~dp0trustwipe_eraser.py" --targets "%TARGET%" --passes %PASSES% --pattern %PATTERN%
