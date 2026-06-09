@echo off
setlocal

title Nanahira — Sign Driver

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo.
    echo  [x] Run as Administrator required.
    echo  Right-click sign_driver.bat ^> Run as administrator
    echo.
    pause
    exit /b 1
)

if exist "%~dp0driver.sys" (
    set "DRIVER=%~dp0driver.sys"
) else (
    set "DRIVER=%~dp0output\driver.sys"
)

if not exist "%DRIVER%" (
    echo.
    echo  [x] driver.sys not found at:
    echo      %DRIVER%
    echo.
    echo  Build the driver project first ^(Release x64^).
    echo.
    pause
    exit /b 1
)

echo.
echo  N A N A H I R A  --  Driver Signing Tool
echo  ==========================================
echo.
echo  Driver : %DRIVER%
echo.

if exist "%~dp0tools\sign_driver.ps1" (
    set "PS_SCRIPT=%~dp0tools\sign_driver.ps1"
) else (
    set "PS_SCRIPT=%~dp0..\tools\sign_driver.ps1"
)

where pwsh >nul 2>&1
if %errorLevel% equ 0 (
    pwsh -NoProfile -ExecutionPolicy Bypass -File "%PS_SCRIPT%" -DriverPath "%DRIVER%"
) else (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%PS_SCRIPT%" -DriverPath "%DRIVER%"
)
if %errorLevel% neq 0 (
    echo.
    echo  [x] Signing failed. Ensure PowerShell 7 is installed.
    echo      winget install Microsoft.PowerShell
    echo.
    pause
    exit /b 1
)

echo.
echo  [+] driver.sys signed successfully.
echo  [+] You can now run nanahira.exe to load the driver.
echo.
pause
