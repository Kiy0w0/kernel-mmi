@echo off
setlocal enabledelayedexpansion

:: ============================================================================
:: nanahira — Full Build Pipeline (5 Steps)
:: 
::   1. Source mutation (randomize identifiers)
::   2. Compile driver.sys
::   3. Compile nanahira.exe
::   4. Restore source to original
::   5. Binary PE mutation (10 mutations)
::
:: Every run produces completely unique binaries.
:: Source: https://github.com/Kiy0w0/kernel-mmi
:: ============================================================================

title nanahira build

echo.
echo  ╔══════════════════════════════════════════════════════════╗
echo  ║                                                          ║
echo  ║   ███╗   ██╗ █████╗ ███╗   ██╗ █████╗ ██╗  ██╗██╗██████╗  █████╗   ║
echo  ║   ██╔██╗ ██║███████║██╔██╗ ██║███████║███████║██║██████╔╝███████║  ║
echo  ║   ██║ ╚████║██║  ██║██║ ╚████║██║  ██║██║  ██║██║██║  ██║██║  ██║  ║
echo  ║   ╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚═╝  ╚═╝  ║
echo  ║                                                          ║
echo  ║   Release Build Pipeline                                 ║
echo  ╚══════════════════════════════════════════════════════════╝
echo.

:: ── Check admin ──
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo  [x] Administrator privileges required.
    echo  [x] Right-click ^> Run as administrator
    pause
    exit /b 1
)
echo  [+] Running as Administrator

:: ── Find VS2022 ──
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo  [x] Visual Studio 2022 not found!
    echo  [x] Install VS2022 with "Desktop development with C++" workload
    pause
    exit /b 1
)

for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -property installationPath`) do set "VSINSTALL=%%i"

if not defined VSINSTALL (
    echo  [x] Could not locate Visual Studio installation
    pause
    exit /b 1
)

echo  [+] VS2022: %VSINSTALL%

:: ── Load build environment ──
call "%VSINSTALL%\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if %errorLevel% neq 0 (
    echo  [x] Failed to load vcvars64.bat
    pause
    exit /b 1
)
echo  [+] Build environment loaded

:: ── Check PowerShell ──
where pwsh >nul 2>&1
if %errorLevel% neq 0 (
    echo  [!] PowerShell 7 (pwsh) not found — source mutation will be skipped
    echo  [!] Install: winget install Microsoft.PowerShell
    set "HAS_PWSH=0"
) else (
    set "HAS_PWSH=1"
    echo  [+] PowerShell 7 found
)

:: Create directories
if not exist output mkdir output
if not exist build mkdir build

echo.
echo  ══════════════════════════════════════════════════════════

:: ══════════════════════════════════════════════════════════════
:: Step 1/5 — Source Mutation
:: ══════════════════════════════════════════════════════════════
echo.
echo  [1/5] Source-level mutation...
echo  ──────────────────────────────────────────────

if "%HAS_PWSH%"=="1" (
    pwsh -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\source_randomizer.ps1" -Action mutate
    if !errorLevel! neq 0 (
        echo  [!] Source mutation failed — building with original values
    )
) else (
    echo  [!] Skipped — requires PowerShell 7
)

:: ══════════════════════════════════════════════════════════════
:: Step 2/5 — Compile driver.sys
:: ══════════════════════════════════════════════════════════════
echo.
echo  [2/5] Compiling driver.sys (kernel mode)...
echo  ──────────────────────────────────────────────

msbuild "%~dp0nanahira.sln" /t:driver /p:Configuration=Release /p:Platform=x64 /v:minimal /nologo

if %errorLevel% neq 0 (
    echo.
    echo  [x] Driver compilation FAILED
    :: Restore source before exiting
    if "%HAS_PWSH%"=="1" (
        pwsh -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\source_randomizer.ps1" -Action restore
    )
    pause
    exit /b 1
)

if exist "%~dp0output\driver.sys" (
    for %%f in ("%~dp0output\driver.sys") do echo  [+] driver.sys — %%~zf bytes
) else (
    echo  [x] driver.sys not found in output/
    if "%HAS_PWSH%"=="1" (
        pwsh -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\source_randomizer.ps1" -Action restore
    )
    pause
    exit /b 1
)

:: ══════════════════════════════════════════════════════════════
:: Step 3/5 — Compile nanahira.exe
:: ══════════════════════════════════════════════════════════════
echo.
echo  [3/5] Compiling nanahira.exe (usermode)...
echo  ──────────────────────────────────────────────

msbuild "%~dp0nanahira.sln" /t:usermode /p:Configuration=Release /p:Platform=x64 /v:minimal /nologo

if %errorLevel% neq 0 (
    echo.
    echo  [x] Usermode compilation FAILED
    if "%HAS_PWSH%"=="1" (
        pwsh -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\source_randomizer.ps1" -Action restore
    )
    pause
    exit /b 1
)

if exist "%~dp0output\nanahira.exe" (
    for %%f in ("%~dp0output\nanahira.exe") do echo  [+] nanahira.exe — %%~zf bytes
) else (
    echo  [x] nanahira.exe not found in output/
    if "%HAS_PWSH%"=="1" (
        pwsh -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\source_randomizer.ps1" -Action restore
    )
    pause
    exit /b 1
)

:: ══════════════════════════════════════════════════════════════
:: Step 4/5 — Restore Source
:: ══════════════════════════════════════════════════════════════
echo.
echo  [4/5] Restoring source to original...
echo  ──────────────────────────────────────────────

if "%HAS_PWSH%"=="1" (
    pwsh -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\source_randomizer.ps1" -Action restore
) else (
    echo  [!] Skipped — no mutation was applied
)

:: ══════════════════════════════════════════════════════════════
:: Step 5/5 — Binary PE Mutation
:: ══════════════════════════════════════════════════════════════
echo.
echo  [5/5] Binary PE mutation (10 mutations)...
echo  ──────────────────────────────────────────────

if "%HAS_PWSH%"=="1" (
    pwsh -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\signature_randomizer.ps1" -Files "%~dp0output\driver.sys","%~dp0output\nanahira.exe"
) else (
    echo  [!] Skipped — requires PowerShell 7
)

:: ══════════════════════════════════════════════════════════════
:: Summary
:: ══════════════════════════════════════════════════════════════
echo.
echo  ╔══════════════════════════════════════════════════════════╗
echo  ║                                                          ║
echo  ║   BUILD COMPLETE                                         ║
echo  ║                                                          ║
echo  ╚══════════════════════════════════════════════════════════╝
echo.

echo  Output:
for %%f in ("%~dp0output\driver.sys") do echo    driver.sys    — %%~zf bytes
for %%f in ("%~dp0output\nanahira.exe") do echo    nanahira.exe  — %%~zf bytes

echo.
echo  SHA256 Hashes (unique per build):
echo  ──────────────────────────────────────────────
certutil -hashfile "%~dp0output\driver.sys" SHA256 2>nul | findstr /v "hash certutil"
echo    ^ driver.sys
certutil -hashfile "%~dp0output\nanahira.exe" SHA256 2>nul | findstr /v "hash certutil"
echo    ^ nanahira.exe

echo.
echo  Next steps:
echo    1. kdmapper.exe output\driver.sys
echo    2. Launch target application
echo    3. output\nanahira.exe ^<process^> ^<dll_path^>
echo.
echo  Re-spoof without rebuilding: quick_spoof.bat
echo.

pause
