@echo off
setlocal enabledelayedexpansion

:: ============================================================================
:: nanahira — Quick Binary Re-Spoof
:: Re-applies PE mutations without recompiling
:: Instantly generates new SHA256 hashes
:: Source: https://github.com/Kiy0w0/kernel-mmi
:: ============================================================================

title nanahira quick-spoof

echo.
echo  ══════════════════════════════════════════════
echo   nanahira — Quick Binary Re-Spoof
echo  ══════════════════════════════════════════════
echo.

:: Check if output files exist
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

:: Show current hashes
echo  Current hashes:
echo  ──────────────────────────────────────────────
certutil -hashfile "%~dp0output\driver.sys" SHA256 2>nul | findstr /v "hash certutil"
echo   ^ driver.sys
certutil -hashfile "%~dp0output\nanahira.exe" SHA256 2>nul | findstr /v "hash certutil"
echo   ^ nanahira.exe
echo.

:: Check for PowerShell 7
where pwsh >nul 2>&1
if %errorLevel% neq 0 (
    echo  [!] PowerShell 7 (pwsh) not found, trying Windows PowerShell...
    set "PWSH=powershell"
) else (
    set "PWSH=pwsh"
)

:: Apply PE mutations
echo  Applying 10 PE mutations...
echo  ──────────────────────────────────────────────

%PWSH% -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\signature_randomizer.ps1" -Files "%~dp0output\driver.sys","%~dp0output\nanahira.exe"

echo.
echo  ══════════════════════════════════════════════
echo   RE-SPOOF COMPLETE — New unique signatures
echo  ══════════════════════════════════════════════
echo.

pause
