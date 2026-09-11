; ???????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????
;  KernelSpy Scanner ??? Professional Windows Installer (Inno Setup 6)
;
;  Build:  ISCC.exe "KernelSpy_pro.iss"
;  Prereq: dist\KernelSpy Scanner.exe  (built via PyInstaller spec, v1.2.0+)
;
;  Professional features:
;    - Single-instance setup mutex + AppMutex running-instance detection
;      (the app publishes the "KernelSpyScannerRunning" mutex; Setup offers
;       to close it automatically before installing/uninstalling)
;    - Full version metadata on both app and setup executables
;    - Explorer integration: right-click ON a folder and INSIDE a folder
;    - Per-user install (no admin required), clean upgrade path from 1.0.x
;    - Complete uninstall: app files + registry keys; user reports preserved
;    - Copy/paste support in AI chat and text inputs
;    - Improved UI design and color scheme
;    - Fixed tree-sitter integration
;    - Enhanced context-aware analysis with reduced false positives
; ???????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????

#define MyAppName "KernelSpy Scanner"
#define MyAppVersion "1.2.0"
#define MyAppPublisher "The L house"
#define MyAppURL "https://github.com/kernelspy"
#define MyAppExeName "KernelSpy Scanner.exe"

[Setup]
; Same AppId as 1.0.0 so upgrades replace the previous installation cleanly.
AppId={{7E1F4C2A-9B3D-4E8F-A5C6-KERNELSPY001}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}/issues
AppUpdatesURL={#MyAppURL}/releases
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}

; Detect a running instance of the app and offer to close it.
AppMutex=KernelSpyScannerRunning

; ?????? Setup binary metadata ??????
VersionInfoVersion={#MyAppVersion}.0
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription=KernelSpy Scanner Setup
VersionInfoProductName={#MyAppName}
VersionInfoProductVersion={#MyAppVersion}.0
VersionInfoCopyright=(c) The L house

; ?????? Behavior / robustness ??????
SetupMutex=KernelSpySetupMutex,global
RestartApplications=no
ChangesEnvironment=no
UninstallLogMode=new

OutputDir=installer
OutputBaseFilename=KernelSpy_Scanner_Setup_PRO_{#MyAppVersion}
Compression=lzma2/max
SolidCompression=yes
LZMANumBlockThreads=4
SetupIconFile=icon.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
WizardStyle=modern
DisableProgramGroupPage=yes
DisableWelcomePage=no
ShowLanguageDialog=no
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog commandline
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
SetupLogging=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "quicklaunchicon"; Description: "{cm:CreateQuickLaunchIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "contextmenu"; Description: "Add 'Scan with KernelSpy' to folder right-click menu"; GroupDescription: "Integration:"; Flags: checkedonce

[Files]
Source: "dist\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "icon.ico"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon
Name: "{userappdata}\Microsoft\Internet Explorer\Quick Launch\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: quicklaunchicon

[Registry]
; Explorer right-click ON a folder -> Scan with KernelSpy
Root: HKCU; Subkey: "Software\Classes\Directory\shell\KernelSpyScanner"; ValueType: string; ValueData: "Scan with KernelSpy"; Flags: uninsdeletekey; Tasks: contextmenu
Root: HKCU; Subkey: "Software\Classes\Directory\shell\KernelSpyScanner"; ValueType: string; ValueName: "Icon"; ValueData: "{app}\{#MyAppExeName}"; Flags: uninsdeletekey; Tasks: contextmenu
Root: HKCU; Subkey: "Software\Classes\Directory\shell\KernelSpyScanner\command"; ValueType: string; ValueData: """{app}\{#MyAppExeName}"" ""%1"""; Flags: uninsdeletekey; Tasks: contextmenu

; Explorer right-click INSIDE a folder (background) -> Scan this folder
Root: HKCU; Subkey: "Software\Classes\Directory\Background\shell\KernelSpyScanner"; ValueType: string; ValueData: "Scan this folder with KernelSpy"; Flags: uninsdeletekey; Tasks: contextmenu
Root: HKCU; Subkey: "Software\Classes\Directory\Background\shell\KernelSpyScanner"; ValueType: string; ValueName: "Icon"; ValueData: "{app}\{#MyAppExeName}"; Flags: uninsdeletekey; Tasks: contextmenu
Root: HKCU; Subkey: "Software\Classes\Directory\Background\shell\KernelSpyScanner\command"; ValueType: string; ValueData: """{app}\{#MyAppExeName}"" ""%V"""; Flags: uninsdeletekey; Tasks: contextmenu

; Per-user preferences hint
Root: HKCU; Subkey: "Software\KernelSpy"; ValueType: string; ValueName: "InstallPath"; ValueData: "{app}"; Flags: uninsdeletekey
Root: HKCU; Subkey: "Software\KernelSpy"; ValueType: string; ValueName: "Version"; ValueData: "{#MyAppVersion}"; Flags: uninsdeletekey

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,KernelSpy Scanner}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Runtime artifacts only. User scan reports live in %USERPROFILE%\KernelSpy_Output
; and are intentionally preserved across uninstall.
Type: filesandordirs; Name: "{app}\__pycache__"
Type: filesandordirs; Name: "{app}\core\__pycache__"

[Code]
// Gracefully stop any running instance during uninstall.
// (Install-time detection is handled natively via AppMutex above.)
function InitializeUninstall(): Boolean;
var
  ResCode: Integer;
begin
  Result := True;
  // Stop the app if running, then give Windows a moment to release its
  // AppMutex handles - an immediate uninstall right after a hard kill
  // could otherwise trip Inno's internal mutex check.
  Exec('taskkill.exe', '/IM "{#MyAppExeName}"',
       '', SW_HIDE, ewWaitUntilTerminated, ResCode);
  Sleep(1500);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
    RegWriteStringValue(HKEY_CURRENT_USER,
      'Software\KernelSpy', 'LastSetupVersion', '{#MyAppVersion}');
end;
