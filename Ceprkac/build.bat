@echo off
echo Building Ceprkac v0.6.5.0...
echo.

echo Step 1: Publishing application...
dotnet publish Ceprkac.csproj -c Release -r win-x64 --self-contained true -o bin\publish
if errorlevel 1 goto error

echo.
echo Step 2: Copying icon...
copy /Y Ceprkac.ico bin\publish\

echo.
echo Step 3: Building installer...
"C:\Program Files (x86)\Inno Setup 6\ISCC.exe" Ceprkac.iss
if errorlevel 1 goto error

echo.
echo Build complete!
echo Output: releases\0.6.5.0\Ceprkac-0.6.5.0-Setup.exe
goto end

:error
echo.
echo BUILD FAILED!
exit /b 1

:end
