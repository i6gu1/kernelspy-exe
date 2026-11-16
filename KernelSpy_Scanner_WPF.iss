; ============================================================
;  KernelSpy Scanner - WPF Edition
;  Professional Inno Setup script (Inno Setup 6.6+)
;
;  Build:  powershell -ExecutionPolicy Bypass -File build-installer.ps1
;  Or:     "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" KernelSpy_Scanner_WPF.iss
; ============================================================

#define MyAppName "KernelSpy Scanner"
#define MyAppVersion "1.4.4"
#define MyAppPublisher "The L house"
#define MyAppExeName "KernelSpy Scanner.exe"
#define MyAppMutex "KernelSpyScannerWpfRunning"
#define MySetupMutex "KernelSpyScannerSetupMutex"

[Setup]
; ---- Identity ----------------------------------------------------------
AppId={{8E4B6D2A-6C1F-4A7B-9E2D-2C5A7F1B3D90}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
VersionInfoVersion={#MyAppVersion}.0
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription={#MyAppName} Installer
VersionInfoProductName={#MyAppName}
VersionInfoProductVersion={#MyAppVersion}
VersionInfoCopyright=(c) {#MyAppPublisher}

; ---- Appearance: always dark, never light ------------------------------
; "dark"  forces the built-in dark wizard style regardless of the Windows
;         theme, so the installer never renders in light mode.
; "includetitlebar" also paints the wizard's title bar/border dark instead
;         of using the system's native (possibly light) one.
; Custom WizardImageFile/WizardSmallImageFile are deliberately NOT set so
; the built-in dark-mode wizard images are used.
WizardStyle=modern dark includetitlebar
WizardResizable=yes

; ---- Output ------------------------------------------------------------
OutputDir=installer
OutputBaseFilename=KernelSpy_Scanner_Setup_WPF_{#MyAppVersion}
SetupIconFile=icon.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppName}
; No compression: Inno Setup packages the 1+ GB standalone payload directly.
; This is the fastest reliable way to produce a valid setup for this payload.
Compression=none
SolidCompression=no

; ---- Machine / privileges ---------------------------------------------
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
UsePreviousAppDir=yes
UsePreviousGroup=yes
UsePreviousTasks=yes

; ---- Behaviour ---------------------------------------------------------
CloseApplications=yes
RestartApplications=no
AppMutex={#MyAppMutex}
SetupMutex={#MySetupMutex}
ChangesAssociations=no
ShowLanguageDialog=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional icons:"
Name: "quicklaunchicon"; Description: "Create a &Quick Launch shortcut"; GroupDescription: "Additional icons:"; Flags: unchecked

[Files]
; Entire standalone publish output: the .NET runtime, application files,
; Rules, and the complete tools tree (Node.js, ESLint, Semgrep).
; Inno Setup handles the Unicode filenames in the Semgrep fixtures natively.
Source: "publish\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon
Name: "{userappdata}\Microsoft\Internet Explorer\Quick Launch\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: quicklaunchicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
Type: filesandordirs; Name: "{app}\tools"
Type: filesandordirs; Name: "{app}\Rules"
Type: dirifempty; Name: "{app}"

[Code]
procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    ForceDirectories(ExpandConstant('{app}\tools'));
  end;
end;
