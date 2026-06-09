@echo off
setlocal enabledelayedexpansion


title nanahira quick-spoof

echo.
echo  â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
echo   nanahira â€” Quick Binary Re-Spoof
echo  â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
echo.

if not exist "%~dp0output\driver.sys" (
    echo  [x] output\driver.sys not found
    echo  [x] Run build_release.bat first
    pause
    exit /b 1
)

if not exist "%~dp0output\nanahira.exe" (
    echo  [x] output\nanahira.exe not found
    echo  [x] Run build_release.bat first
    pause
    exit /b 1
)

echo  Current hashes:
echo  â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
certutil -hashfile "%~dp0output\driver.sys" SHA256 2>nul | findstr /v "hash certutil"
echo   ^ driver.sys
certutil -hashfile "%~dp0output\nanahira.exe" SHA256 2>nul | findstr /v "hash certutil"
echo   ^ nanahira.exe
echo.

where pwsh >nul 2>&1
if %errorLevel% neq 0 (
    echo  [!] PowerShell 7 (pwsh) not found, trying Windows PowerShell...
    set "PWSH=powershell"
) else (
    set "PWSH=pwsh"
)

echo  Applying 10 PE mutations...
echo  â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

%PWSH% -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\signature_randomizer.ps1" -Files "%~dp0output\driver.sys","%~dp0output\nanahira.exe"

echo.
echo  â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
echo   RE-SPOOF COMPLETE â€” New unique signatures
echo  â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
echo.

pause
