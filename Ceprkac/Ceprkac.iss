; Ceprkac Inno Setup Script
#define MyAppName "Ceprkac"
#define MyAppVersion "0.6.5.0"
#define MyAppPublisher "Ceprkac"
#define MyAppExeName "Ceprkac.exe"
#define MyAppIcon "Ceprkac.ico"

[Setup]
AppId={{8a7b3c2d-1e4f-5a6b-9c8d-7e0f1a2b3c4d}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
UninstallDisplayIcon={app}\{#MyAppIcon}
SetupIconFile={#MyAppIcon}
Compression=lzma2
SolidCompression=yes
OutputDir=releases\{#MyAppVersion}
OutputBaseFilename=Ceprkac-{#MyAppVersion}-Setup
ArchitecturesInstallIn64BitMode=x64
WizardStyle=modern

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "bin\publish\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "bin\publish\{#MyAppIcon}"; DestDir: "{app}"; Flags: ignoreversion
Source: "bin\publish\*.dll"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs
Source: "bin\publish\*.json"; DestDir: "{app}"; Flags: ignoreversion
Source: "bin\publish\blocklist.txt"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\{#MyAppIcon}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\{#MyAppIcon}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent
