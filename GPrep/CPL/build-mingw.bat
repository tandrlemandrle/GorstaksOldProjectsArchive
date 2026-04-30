@echo off
REM Build GPrep.cpl using MinGW (if cl.exe not available)

setlocal
cd /d "%~dp0"

where gcc.exe >nul 2>&1
if errorlevel 1 (
    echo GCC not found. Install MinGW-w64 and add to PATH.
    exit /b 1
)

echo Building GPrep.cpl with MinGW...
gcc -shared -o GPrep.cpl GPrep.c -lshell32 -s -Os
if errorlevel 1 exit /b 1

echo Build complete: %CD%\GPrep.cpl
exit /b 0
