; GIDR - Gorstaks Intrusion Detection and Response - InnoSetup Installer Script
; Requires InnoSetup 6.x (https://jrsoftware.org/isinfo.php)

#define MyAppName "GIDR"
#define MyAppVersion "6.3.0"
#define MyAppPublisher "Gorstak"
#define MyAppURL "https://github.com/gorstak/GIDR"
#define MyAppExeName "GIDR.exe"

[Setup]
AppId={{539EF6B5-578B-4AF3-A5C7-FD564CB9C8FB}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
DefaultDirName={autopf}\GIDR
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
PrivilegesRequired=admin
OutputDir=..\bin
OutputBaseFilename=GIDR-Setup-{#MyAppVersion}
SetupIconFile=..\GIDR.ico
UninstallDisplayIcon={app}\GIDR.exe
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
; Sign the installer too (uncomment when you have the cert):
; SignTool=signtool sign /f "$path_to_pfx" /p "$password" /tr http://timestamp.sectigo.com /td sha256 /fd sha256 $f

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "adddefenderexclusion"; Description: "Add Windows Defender exclusion for install directory"; GroupDescription: "Security:"
Name: "registerservice"; Description: "Install as Windows service (auto-start on boot)"; GroupDescription: "Service:"

[Files]
; Main executable
Source: "..\bin\GIDR.exe"; DestDir: "{app}"; Flags: ignoreversion
; Create subdirectories
Source: "..\bin\GIDR.exe"; DestDir: "{app}"; AfterInstall: CreateSubDirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Parameters: "monitor"
Name: "{group}\{#MyAppName} Info"; Filename: "{app}\{#MyAppExeName}"; Parameters: "info"
Name: "{group}\{#MyAppName} Health Check"; Filename: "{app}\{#MyAppExeName}"; Parameters: "health"
Name: "{group}\{#MyAppName} Report"; Filename: "{app}\{#MyAppExeName}"; Parameters: "report"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Parameters: "monitor"; Tasks: desktopicon

[Run]
; Add additional Defender exclusion for quarantine path (post-install)
Filename: "{cmd}"; Parameters: "/c powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ""Add-MpPreference -ExclusionPath '{app}\Quarantine'"""; StatusMsg: "Adding quarantine exclusion..."; Flags: runhidden waituntilterminated; Tasks: adddefenderexclusion

; Generate default config
Filename: "{app}\{#MyAppExeName}"; Parameters: "config"; StatusMsg: "Creating default configuration..."; Flags: runhidden waituntilterminated

; Register as service with auto-restart on failure
Filename: "{sys}\sc.exe"; Parameters: "create GIDR binPath= ""{app}\{#MyAppExeName} monitor"" start= auto DisplayName= ""GIDR - Gorstaks Intrusion Detection and Response"""; StatusMsg: "Registering service..."; Flags: runhidden waituntilterminated; Tasks: registerservice
Filename: "{sys}\sc.exe"; Parameters: "description GIDR ""GIDR - Gorstaks Intrusion Detection and Response"""; Flags: runhidden waituntilterminated; Tasks: registerservice
; Configure service recovery: restart after 10s on first failure, 30s on second, 60s on subsequent
Filename: "{sys}\sc.exe"; Parameters: "failure GIDR reset= 86400 actions= restart/10000/restart/30000/restart/60000"; StatusMsg: "Configuring service recovery..."; Flags: runhidden waituntilterminated; Tasks: registerservice
; Start the service
Filename: "{sys}\sc.exe"; Parameters: "start GIDR"; StatusMsg: "Starting GIDR service..."; Flags: runhidden waituntilterminated; Tasks: registerservice

[UninstallRun]
; Stop and remove service
Filename: "{sys}\sc.exe"; Parameters: "stop GIDR"; Flags: runhidden waituntilterminated; RunOnceId: "StopService"
Filename: "{sys}\sc.exe"; Parameters: "delete GIDR"; Flags: runhidden waituntilterminated; RunOnceId: "DeleteService"
; Remove Defender exclusion
Filename: "{cmd}"; Parameters: "/c powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ""Remove-MpPreference -ExclusionPath '{app}'; Remove-MpPreference -ExclusionProcess 'GIDR.exe'"""; Flags: runhidden waituntilterminated; RunOnceId: "RemoveExclusion"

[UninstallDelete]
Type: filesandordirs; Name: "{app}\Logs"
Type: filesandordirs; Name: "{app}\Data"
Type: filesandordirs; Name: "{app}\Tools"
Type: filesandordirs; Name: "{app}\Reports"
; Quarantine is NOT deleted on uninstall (user may want to review)

[Code]
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  // Add Defender exclusion BEFORE files are copied so Defender doesn't quarantine GIDR.exe
  Exec(ExpandConstant('{cmd}'),
    '/c powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Add-MpPreference -ExclusionPath ''' + ExpandConstant('{app}') + '''"',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  // Also exclude the exe by name in case the path exclusion isn't applied yet
  Exec(ExpandConstant('{cmd}'),
    '/c powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Add-MpPreference -ExclusionProcess ''GIDR.exe''"',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Result := '';
end;

procedure CreateSubDirs;
begin
  ForceDirectories(ExpandConstant('{app}\Logs'));
  ForceDirectories(ExpandConstant('{app}\Quarantine'));
  ForceDirectories(ExpandConstant('{app}\Data'));
  ForceDirectories(ExpandConstant('{app}\Reports'));
  ForceDirectories(ExpandConstant('{app}\Tools'));
end;
