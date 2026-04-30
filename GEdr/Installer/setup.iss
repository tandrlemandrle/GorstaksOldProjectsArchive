; Gorstak EDR - InnoSetup Installer Script
; Requires InnoSetup 6.x (https://jrsoftware.org/isinfo.php)

#define MyAppName "Gorstak EDR"
#define MyAppVersion "6.0.0"
#define MyAppPublisher "Gorstak"
#define MyAppURL "https://github.com/gorstak/gorstak-edr"
#define MyAppExeName "GEdr.exe"

[Setup]
AppId={{539EF6B5-578B-4AF3-A5C7-FD564CB9C8FB}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
DefaultDirName={autopf}\GEdr
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
PrivilegesRequired=admin
OutputDir=..\bin
OutputBaseFilename=GEdr-Setup-{#MyAppVersion}
SetupIconFile=..\GEdr.ico
UninstallDisplayIcon={app}\GEdr.exe
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
Name: "bootstrapyara"; Description: "Download YARA scanner (requires internet)"; GroupDescription: "Components:"

[Files]
; Main executable
Source: "..\bin\GEdr.exe"; DestDir: "{app}"; Flags: ignoreversion
; YARA rules
Source: "..\Rules\*.yar"; DestDir: "{app}\Rules"; Flags: ignoreversion recursesubdirs createallsubdirs
; Create subdirectories
Source: "..\bin\GEdr.exe"; DestDir: "{app}"; AfterInstall: CreateSubDirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Parameters: "monitor"
Name: "{group}\{#MyAppName} Scanner"; Filename: "{app}\{#MyAppExeName}"; Parameters: "scan"
Name: "{group}\{#MyAppName} Info"; Filename: "{app}\{#MyAppExeName}"; Parameters: "info"
Name: "{group}\{#MyAppName} Health Check"; Filename: "{app}\{#MyAppExeName}"; Parameters: "health"
Name: "{group}\{#MyAppName} Report"; Filename: "{app}\{#MyAppExeName}"; Parameters: "report"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Parameters: "monitor"; Tasks: desktopicon

[Run]
; Add additional Defender exclusion for quarantine path (post-install)
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -Command ""Add-MpPreference -ExclusionPath '{app}\Quarantine'"""; StatusMsg: "Adding quarantine exclusion..."; Flags: runhidden waituntilterminated; Tasks: adddefenderexclusion

; Bootstrap YARA
Filename: "{app}\{#MyAppExeName}"; Parameters: "bootstrap"; StatusMsg: "Downloading YARA scanner..."; Flags: runhidden waituntilterminated; Tasks: bootstrapyara

; Generate default config
Filename: "{app}\{#MyAppExeName}"; Parameters: "config"; StatusMsg: "Creating default configuration..."; Flags: runhidden waituntilterminated

; Register as service with auto-restart on failure
Filename: "sc.exe"; Parameters: "create GEdr binPath= ""{app}\{#MyAppExeName} monitor"" start= auto DisplayName= ""Gorstak EDR"""; StatusMsg: "Registering service..."; Flags: runhidden waituntilterminated; Tasks: registerservice
Filename: "sc.exe"; Parameters: "description GEdr ""Gorstak EDR - Unified Endpoint Defense Platform"""; Flags: runhidden waituntilterminated; Tasks: registerservice
; Configure service recovery: restart after 10s on first failure, 30s on second, 60s on subsequent
Filename: "sc.exe"; Parameters: "failure GEdr reset= 86400 actions= restart/10000/restart/30000/restart/60000"; StatusMsg: "Configuring service recovery..."; Flags: runhidden waituntilterminated; Tasks: registerservice
; Start the service
Filename: "sc.exe"; Parameters: "start GEdr"; StatusMsg: "Starting EDR service..."; Flags: runhidden waituntilterminated; Tasks: registerservice

[UninstallRun]
; Stop and remove service
Filename: "sc.exe"; Parameters: "stop GEdr"; Flags: runhidden waituntilterminated; RunOnceId: "StopService"
Filename: "sc.exe"; Parameters: "delete GEdr"; Flags: runhidden waituntilterminated; RunOnceId: "DeleteService"
; Remove Defender exclusion
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -Command ""Remove-MpPreference -ExclusionPath '{app}'; Remove-MpPreference -ExclusionProcess 'GEdr.exe'"""; Flags: runhidden waituntilterminated; RunOnceId: "RemoveExclusion"

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
  // Add Defender exclusion BEFORE files are copied so Defender doesn't quarantine GEdr.exe
  Exec('powershell.exe',
    '-NoProfile -ExecutionPolicy Bypass -Command "Add-MpPreference -ExclusionPath ''' + ExpandConstant('{app}') + '''"',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  // Also exclude the exe by name in case the path exclusion isn't applied yet
  Exec('powershell.exe',
    '-NoProfile -ExecutionPolicy Bypass -Command "Add-MpPreference -ExclusionProcess ''GEdr.exe''"',
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
  ForceDirectories(ExpandConstant('{app}\Rules'));
end;
