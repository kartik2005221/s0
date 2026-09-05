@echo off
REM TrustWipe Windows Secure Sanitization Platform Launcher (Files, Partitions, USB Drives)
REM Smart India Hackathon 2026 (SIH26149) - NTRO

if "%~1"=="" (
    echo Usage:
    echo   File/Folder Erasure: trustwipe-eraser.bat ^<target_file_or_folder^> [passes] [pattern]
    echo   Secondary Partition: trustwipe-eraser.bat --wipe-partition D: --yes
    echo   USB / Pen Drive:     trustwipe-eraser.bat --wipe-drive \\.\PhysicalDrive1 --yes
    echo.
    echo Example:
    echo   trustwipe-eraser.bat C:\Confidential\evidence.docx 1 zero
    echo   trustwipe-eraser.bat --wipe-partition E: --pattern zero --yes
    exit /b 1
)

set FIRST_ARG=%~1
if "%FIRST_ARG:~0,2%"=="--" (
    python "%~dp0windows\cli\trustwipe_eraser.py" %*
    exit /b %ERRORLEVEL%
)

set TARGET=%~1
set PASSES=%~2
if "%PASSES%"=="" set PASSES=1
set PATTERN=%~3
if "%PATTERN%"=="" set PATTERN=zero

python "%~dp0windows\cli\trustwipe_eraser.py" --targets "%TARGET%" --passes %PASSES% --pattern %PATTERN%
