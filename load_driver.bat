@echo off
setlocal enabledelayedexpansion

title Nanahira Driver Loader

net session >nul 2>&1
if not %errorLevel% == 0 (
    echo.
    echo  [x] This script must be run as Administrator.
    echo      Right-click ^> "Run as administrator"
    echo.
    pause
    exit /b 1
)

set DRIVER_NAME=nanahira
set DRIVER_PATH=%~dp0driver.sys

echo.
echo   N A N A H I R A  ^|  Driver Setup
echo   ----------------------------------------
echo.

if not exist "%DRIVER_PATH%" (
    echo  [x] driver.sys not found at:
    echo      %DRIVER_PATH%
    echo.
    echo      Build the project first and make sure driver.sys is
    echo      placed in the same folder as this script.
    echo.
    pause
    exit /b 1
)

sc query %DRIVER_NAME% >nul 2>&1
if %errorLevel% == 0 (
    echo  [*] Removing existing service entry...
    sc stop  %DRIVER_NAME% >nul 2>&1
    sc delete %DRIVER_NAME% >nul 2>&1
    timeout /t 1 /nobreak >nul
)

echo  [*] Checking test signing status...
bcdedit | findstr /i "testsigning" | findstr /i "yes" >nul 2>&1
if not %errorLevel% == 0 (
    echo.
    echo  [!] Test signing is NOT enabled.
    echo      Without it the driver will fail to load after reboot.
    echo.
    set /p ENABLE_TS="  Enable test signing now? (Y/N): "
    if /i "!ENABLE_TS!"=="Y" (
        bcdedit /set testsigning on >nul
        bcdedit /set nointegritychecks on >nul
        echo  [+] Test signing enabled. Will take effect after restart.
    ) else (
        echo  [!] Skipping. Driver may not load without test signing.
    )
    echo.
)

echo  [*] Registering driver as Boot-Start service...
sc create %DRIVER_NAME% binPath= "%DRIVER_PATH%" type= kernel start= boot DisplayName= "Nanahira Driver" >nul 2>&1

if not %errorLevel% == 0 (
    echo  [x] Failed to register driver. Error: %errorLevel%
    echo      Make sure you are running as Administrator and driver.sys exists.
    echo.
    pause
    exit /b 1
)

echo  [+] Driver registered successfully.
echo.
echo  ----------------------------------------
echo   IMPORTANT - READ BEFORE RESTARTING
echo  ----------------------------------------
echo   The driver will load automatically on the next boot.
echo   After restarting, run nanahira.exe to verify it loaded.
echo.
echo   If the system fails to start, boot into Safe Mode and run:
echo     sc delete %DRIVER_NAME%
echo   to remove the driver entry.
echo  ----------------------------------------
echo.

set /p REBOOT="  Restart now to load the driver? (Y/N): "
if /i "%REBOOT%"=="Y" (
    echo.
    echo  [*] Restarting in 5 seconds... Close any open work now.
    shutdown /r /t 5 /c "Rebooting to load Nanahira driver..."
) else (
    echo.
    echo  [*] Restart manually when you are ready.
    echo      The driver will load on next boot.
)

echo.
pause
