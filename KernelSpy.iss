; ─────────────────────────────────────────────────────────────
;  KernelSpy Scanner — Professional Windows Installer Script
;  Build:  ISCC.exe "KernelSpy.iss"
; ─────────────────────────────────────────────────────────────

#define MyAppName "KernelSpy Scanner"
#define MyAppVersion "1.1.0"
#define MyAppPublisher "The L house"
#define MyAppExeName "KernelSpy Scanner.exe"

[Setup]
AppId={{7E1F4C2A-9B3D-4E8F-A5C6-KERNELSPY001}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL=https://github.com/kernelspy
AppSupportURL=https://github.com/kernelspy/issues
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
OutputDir=installer
OutputBaseFilename=KernelSpy_Scanner_Setup_{#MyAppVersion}
Compression=lzma2/max
SolidCompression=yes
LZMANumBlockThreads=2
SetupIconFile=icon.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=lowest
WizardStyle=modern
DisableProgramGroupPage=yes
DisableWelcomePage=no
ShowLanguageDialog=no
SetupLogging=yes
MinVersion=10.0

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "contextmenu"; Description: "Add 'Scan with KernelSpy' to folder right-click menu"; GroupDescription: "Integration:"; Flags: checkedonce

[Files]
Source: "dist\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "icon.ico"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Registry]
; Explorer right-click integration: scan any folder directly
Root: HKCU; Subkey: "Software\Classes\Directory\shell\KernelSpyScanner"; ValueType: string; ValueData: "Scan with KernelSpy"; Flags: uninsdeletekey; Tasks: contextmenu
Root: HKCU; Subkey: "Software\Classes\Directory\shell\KernelSpyScanner"; ValueType: string; ValueName: "Icon"; ValueData: "{app}\{#MyAppExeName}"; Flags: uninsdeletekey; Tasks: contextmenu
Root: HKCU; Subkey: "Software\Classes\Directory\shell\KernelSpyScanner\command"; ValueType: string; ValueData: """{app}\{#MyAppExeName}"" ""%1"""; Flags: uninsdeletekey; Tasks: contextmenu
; Store per-user preferences location hint
Root: HKCU; Subkey: "Software\KernelSpy"; ValueType: string; ValueName: "InstallPath"; ValueData: "{app}"; Flags: uninsdeletekey

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,KernelSpy Scanner}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Clean up runtime artifacts left by the app inside its install folder (none expected, safe)
Type: filesandordirs; Name: "{app}\__pycache__"
