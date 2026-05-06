@echo off
setlocal

:: GIDR - Gorstaks Intrusion Detection and Response - Code Signing Script
:: Usage: sign.cmd path\to\certificate.pfx password
::
:: Prerequisites:
::   - Windows SDK signtool.exe (comes with Visual Studio or Windows SDK)
::   - Your Certum Open Source Code Signing certificate (.pfx file)

if "%~1"=="" (
    echo Usage: sign.cmd certificate.pfx password
    echo.
    echo Get signtool.exe from:
    echo   - Visual Studio: already included
    echo   - Windows SDK: https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/
    echo   - Standalone: https://aka.ms/SignTool
    exit /b 1
)

set PFX=%~1
set PASS=%~2
set TIMESTAMP=http://timestamp.sectigo.com

:: Find signtool.exe
set SIGNTOOL=
for /f "delims=" %%i in ('where signtool.exe 2^>nul') do set SIGNTOOL=%%i
if "%SIGNTOOL%"=="" (
    for /f "delims=" %%i in ('dir /s /b "C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe" 2^>nul') do set SIGNTOOL=%%i
)
if "%SIGNTOOL%"=="" (
    echo ERROR: signtool.exe not found. Install Windows SDK.
    exit /b 1
)

echo [*] Using signtool: %SIGNTOOL%
echo [*] Certificate: %PFX%
echo.

:: Sign the main executable
echo [*] Signing GIDR.exe...
"%SIGNTOOL%" sign /f "%PFX%" /p "%PASS%" /tr %TIMESTAMP% /td sha256 /fd sha256 /v bin\GIDR.exe
if %ERRORLEVEL% NEQ 0 (
    echo [!] Signing FAILED for GIDR.exe
    exit /b 1
)
echo [+] GIDR.exe signed successfully
echo.

:: Verify signature
echo [*] Verifying signature...
"%SIGNTOOL%" verify /pa /v bin\GIDR.exe
echo.

echo [+] Signing complete. You can now build the installer with InnoSetup.
echo     iscc.exe Installer\setup.iss
