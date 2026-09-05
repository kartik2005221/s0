@echo off
REM Helper script to create a sparse/zeroed disk image file for testing on Windows
REM Usage: make_test_image.bat [image_path] [size_in_mb]
REM Smart India Hackathon 2026 (SIH26149) - NTRO

set "IMG_PATH=%~1"
if "%IMG_PATH%"=="" set "IMG_PATH=test_drive.img"
set "SIZE_MB=%~2"
if "%SIZE_MB%"=="" set "SIZE_MB=256"

set /a BYTES=%SIZE_MB% * 1048576

echo ==> Creating %SIZE_MB% MiB test drive image at %IMG_PATH% (%BYTES% bytes)...
fsutil file createnew "%IMG_PATH%" %BYTES%
if %ERRORLEVEL% equ 0 (
    echo ==> Created successfully!
    echo ==> You can now test wiping on this image target:
    echo     windows\cli\trustwipe-eraser.bat --wipe-drive "%IMG_PATH%" --yes
) else (
    echo ==> Failed to create test image via fsutil. Trying Python fallback...
    python -c "with open('%IMG_PATH%', 'wb') as f: f.truncate(%BYTES%)"
    if %ERRORLEVEL% equ 0 (
        echo ==> Created successfully via Python!
    )
)
