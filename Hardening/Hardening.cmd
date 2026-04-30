@echo off
:: Advanced Windows Hardening Batch Script
:: Run as Administrator
:: Date: December 2025 - Covers common HTB/THM Windows exploits

:: Step 1: Elevate
>nul 2>&1 fsutil dirty query %systemdrive% || echo CreateObject^("Shell.Application"^).ShellExecute "%~0", "ELEVATED", "", "runas", 1 > "%temp%\uac.vbs" && "%temp%\uac.vbs" && exit /b
DEL /F /Q "%temp%\uac.vbs"

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo This script must be run as Administrator.
    pause
    exit /b 1
)

echo Starting Windows Hardening...
echo.

:: 1. Disable SMBv1 (EternalBlue protection)
echo Disabling SMBv1...
powershell -command "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart"
sc config lanmanserver start= demand >nul 2>&1

:: 2. Harden NTLM and disable weak auth
echo Hardening NTLM and disabling LM hashes...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel /t REG_DWORD /d 5 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v NoLMHash /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v NtlmMinClientSec /t REG_DWORD /d 536870912 /f

:: 3. Firewall Hardening
echo Hardening Windows Firewall...
netsh advfirewall set allprofiles state on
netsh advfirewall firewall add rule name="Block SMB Inbound" dir=in action=block protocol=TCP localport=445
netsh advfirewall firewall add rule name="Block RDP Inbound" dir=in action=block protocol=TCP localport=3389
netsh advfirewall firewall add rule name="Block WinRM Inbound" dir=in action=block protocol=TCP localport=5985-5986

:: 4. Disable Vulnerable Services
echo Disabling high-risk services...
sc stop Spooler >nul 2>&1
sc config Spooler start= disabled
sc config RemoteRegistry start= disabled
sc config Browser start= disabled >nul 2>&1
sc config XblAuthManager start= disabled >nul 2>&1
sc config XblGameSave start= disabled >nul 2>&1

:: 5. Account Hardening
echo Hardening user accounts...
net user Guest /active:no
net user Administrator /active:no
net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30

:: 6. UAC and Permissions
echo Enabling strict UAC...
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f

:: 7. Disable Autorun and USB Storage
echo Disabling autorun and USB mass storage...
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR" /v Start /t REG_DWORD /d 4 /f

:: 8. Office Macro Protection (all users via HKLM where possible)
echo Blocking Office macros from internet...
reg add "HKLM\SOFTWARE\Microsoft\Office\16.0\Word\Security" /v VBAWarnings /t REG_DWORD /d 4 /f
reg add "HKLM\SOFTWARE\Microsoft\Office\16.0\Excel\Security" /v VBAWarnings /t REG_DWORD /d 4 /f
reg add "HKLM\SOFTWARE\Microsoft\Office\16.0\PowerPoint\Security" /v VBAWarnings /t REG_DWORD /d 4 /f
reg add "HKLM\SOFTWARE\Microsoft\Office\16.0\Common\Security" /v BlockContentExecutionFromInternet /t REG_DWORD /d 1 /f

:: 9. Enable Some Defender Features via PowerShell
echo Enabling Controlled Folder Access and basic ASR...
powershell -command "Set-MpPreference -EnableControlledFolderAccess Enabled"
powershell -command "Set-MpPreference -AttackSurfaceReductionRules_Ids 56a863a9-2176-51f7-4304-bb80f7e852a8 -AttackSurfaceReductionRules_Actions Enabled"
powershell -command "Set-MpPreference -AttackSurfaceReductionRules_Ids d4f940ab-401b-4efc-aadc-ad5f3c50688a -AttackSurfaceReductionRules_Actions Enabled"

:: 10. Clean Temp Files
echo Cleaning temporary files...
del /q /f /s "%TEMP%\*" >nul 2>&1
del /q /f /s "C:\Windows\Temp\*" >nul 2>&1

echo.
echo ================================================
echo Hardening complete!
echo Most changes require a reboot to take full effect.
echo.
echo For advanced features (BitLocker, Credential Guard, full ASR):
echo   - Use Group Policy in enterprise environments
echo   - Or run the full PowerShell version for deeper control
echo.
echo Stay safe - this blocks the vast majority of HTB/THM Windows techniques.
echo ================================================

