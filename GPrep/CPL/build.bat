@echo off
REM Build GPrep.cpl - requires Visual Studio or Windows SDK
REM Run from Developer Command Prompt, or adjust path to cl.exe

setlocal
set CPATH=%~dp0

where cl.exe >nul 2>&1
if errorlevel 1 (
    echo Looking for Visual Studio...
    for /f "usebackq tokens=*" %%i in (`powershell -NoProfile -Command "& {'$(dir /b /ad "C:\Program Files\Microsoft Visual Studio\2022\*" 2^>nul)'}"`) do set VSDIR=%%i
    if defined VSDIR (
        call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" 2>nul
        if errorlevel 1 call "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 2>nul
    )
)

where cl.exe >nul 2>&1
if errorlevel 1 (
    echo.
    echo ERROR: cl.exe not found. Please run from "Developer Command Prompt for VS"
    echo   or install Visual Studio Build Tools.
    echo.
    echo Alternative: Use MinGW:
    echo   gcc -shared -o GPrep.cpl GPrep.c -lshell32 -lole32 -s
    exit /b 1
)

echo Building GPrep.cpl...
cl /nologo /LD /O2 /W3 GPrep.c shell32.lib /Fe:GPrep.cpl /link /DEF:GPrep.def
if errorlevel 1 exit /b 1

echo.
echo Build complete: %CPATH%GPrep.cpl
echo Copy GPrep.cpl, GPrepUI.hta, GPrepHelper.ps1, and manifest.json to the same folder.
exit /b 0
