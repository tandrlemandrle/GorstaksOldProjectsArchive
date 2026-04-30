@echo off
setlocal enabledelayedexpansion

:: ============================================================
:: Gorstak EDR - Full Build Pipeline
:: Usage:
::   build.cmd                        Build only (no signing)
::   build.cmd sign cert.pfx pass     Build + sign + installer
::   build.cmd installer              Build + installer (no signing)
:: ============================================================

set CSC=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe
if not exist "%CSC%" set CSC=C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe
if not exist "%CSC%" (
    echo ERROR: csc.exe not found. Install .NET Framework 4.x.
    exit /b 1
)

set ISCC="C:\Program Files (x86)\Inno Setup 6\ISCC.exe"

:: Parse arguments
set MODE=%~1
set PFX=%~2
set PASS=%~3

:: ---- Step 1: Compile ----
if not exist bin mkdir bin

echo.
echo [1/4] Compiling Gorstak EDR...
"%CSC%" /nologo /target:exe /out:bin\GEdr.exe /platform:anycpu /optimize+ ^
  /win32manifest:app.manifest ^
  /win32icon:GEdr.ico ^
  /reference:System.dll ^
  /reference:System.Core.dll ^
  /reference:System.Management.dll ^
  /reference:System.ServiceProcess.dll ^
  /reference:System.Drawing.dll ^
  /reference:System.Windows.Forms.dll ^
  /reference:System.IO.Compression.dll ^
  /reference:System.IO.Compression.FileSystem.dll ^
  /recurse:*.cs

if %ERRORLEVEL% NEQ 0 (
    echo [!] Build FAILED.
    exit /b 1
)
echo [+] Compile succeeded: bin\GEdr.exe

:: ---- Step 2: Copy rules ----
echo.
echo [2/4] Copying YARA rules...
if not exist bin\Rules mkdir bin\Rules
xcopy /Y /Q Rules\*.yar bin\Rules\ >nul 2>&1
echo [+] Rules copied to bin\Rules\

:: ---- Step 3: Sign (optional) ----
if /i "%MODE%"=="sign" (
    echo.
    echo [3/4] Signing GEdr.exe...

    if "%PFX%"=="" (
        echo [!] Usage: build.cmd sign certificate.pfx password
        exit /b 1
    )

    set SIGNTOOL=
    for /f "delims=" %%i in ('where signtool.exe 2^>nul') do set SIGNTOOL=%%i
    if "!SIGNTOOL!"=="" (
        for /f "delims=" %%i in ('dir /s /b "C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe" 2^>nul') do set SIGNTOOL=%%i
    )
    if "!SIGNTOOL!"=="" (
        echo [!] signtool.exe not found. Install Windows SDK.
        echo [!] Skipping signing step.
        goto :installer
    )

    "!SIGNTOOL!" sign /f "%PFX%" /p "%PASS%" /tr http://timestamp.sectigo.com /td sha256 /fd sha256 /v bin\GEdr.exe
    if %ERRORLEVEL% NEQ 0 (
        echo [!] Signing FAILED.
        exit /b 1
    )
    echo [+] GEdr.exe signed successfully

    "!SIGNTOOL!" verify /pa bin\GEdr.exe >nul 2>&1
    if %ERRORLEVEL% EQU 0 (
        echo [+] Signature verified
    ) else (
        echo [!] Signature verification warning
    )
) else (
    echo.
    echo [3/4] Signing skipped (no cert provided^)
)

:: ---- Step 4: Installer ----
:installer
if /i "%MODE%"=="sign" goto :buildinstaller
if /i "%MODE%"=="installer" goto :buildinstaller

echo.
echo [4/4] Installer skipped (use 'build.cmd sign' or 'build.cmd installer'^)
goto :done

:buildinstaller
echo.
echo [4/4] Building installer...

if not exist %ISCC% (
    echo [!] InnoSetup not found at %ISCC%
    echo [!] Install from: https://jrsoftware.org/isinfo.php
    exit /b 1
)

%ISCC% Installer\setup.iss
if %ERRORLEVEL% NEQ 0 (
    echo [!] Installer build FAILED.
    exit /b 1
)
echo [+] Installer created in bin\

:done
echo.
echo ============================================
echo   Build complete!
echo.
if exist bin\GEdr.exe echo   EXE:       bin\GEdr.exe
if exist "bin\GEdr-Setup-2.0.0.exe" echo   Installer: bin\GEdr-Setup-2.0.0.exe
echo.
echo   Usage:
echo     build.cmd                       Compile only
echo     build.cmd installer             Compile + installer
echo     build.cmd sign cert.pfx pass    Compile + sign + installer
echo ============================================
