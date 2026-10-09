; ====================================================================
;  KernelSpy Scanner 1.4.3 - Professional Windows Installer (Inno Setup 6)
;
;  Build:  ISCC.exe "KernelSpy_pro_1.4.3.iss"
;  Prereq: dist\KernelSpy Scanner.exe  (built via PyInstaller spec, v1.4.3)
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
;    - KernelSpy 1.3: cross-analyzer dedup/layering (one record per bug),
;      comment-aware SQL sink checks (prepared statements no longer fire),
;      context-gated CPG concat findings, Bandit findings mapped to native
;      categories + remediation, AI API key actually sent with each request
;
;  KernelSpy 1.4.0:
;    - AI model selector: lists every generateContent model the configured
;      Google API key can actually use (live /v1beta/models query, with a
;      built-in fallback catalogue when offline or rate-limited)
;    - "Refresh models" button (AI Chat + Settings); choice is saved to
;      settings and applied instantly to the analyzer
;    - Model dropdowns on both the AI Chat and Settings pages stay in sync
;    - Successful "Test Key" auto-refreshes the model list
;
;  KernelSpy 1.4.1:
;    - New "Analyze Findings with AI" button on the Results page: sends the
;      current report to the active provider in the background and opens the
;      answer in a copyable dialog
;    - Report analysis is stateless - it no longer appends its answer to the
;      AI Chat conversation
;    - AI Chat history is bounded (40 messages / 24 000 characters incl. the
;      system prompt) with room reserved for the in-flight turn, which fixes
;      the HTTP 400 "input token limit exceeded" on long conversations
;    - Oversized chat messages are rejected with a clear message instead of a
;      provider error
;    - Local GGUF requests keep the "system" role instead of degrading it to
;      "user"
;    - Model dropdowns resync automatically after a model fallback reply
;
;  KernelSpy 1.4.3:
;    - Go: tainted channel tracking -  ch <- tainted  poisons the channel,
;      v := <-ch (or  for v := range ch) inherits the taint, so a sink on
;      the next line is caught (previously invisible to the engine)
;    - Node.js: object reference tracking - a handler table such as
;      const h = { html: (x) => res.send(x) }  is remembered while parsing;
;      h[key](param) with key === "html" is resolved to res.send(param)
;      before the taint check (dynamic dispatch / indirect sinks)
;    - Python: constant folding & propagation -  "ev" + "al"  is folded
;      while scanning, so globals()[name]() / locals().get(name) /
;      getattr(obj, name) resolve to eval / os.system / pickle.loads ...
;    - Google AI: region blocks are detected properly.  Google answers
;      "User location is not supported" - that string used to be mistaken
;      for a bad model name, which burned every fallback and ended with a
;      misleading "model X is not available for this API key".  The app now
;      explains the geography block and points at VPN / local GGUF instead
;    - New application icon
; ====================================================================

#define MyAppName "KernelSpy Scanner"
#define MyAppVersion "1.4.3"
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

; ----- Setup binary metadata -----
VersionInfoVersion={#MyAppVersion}.0
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription=KernelSpy Scanner Setup
VersionInfoProductName={#MyAppName}
VersionInfoProductVersion={#MyAppVersion}.0
VersionInfoCopyright=(c) The L house

; ----- Behavior / robustness -----
SetupMutex=KernelSpySetupMutex,global
RestartApplications=no
ChangesEnvironment=no
UninstallLogMode=new

OutputDir=installer
OutputBaseFilename=KernelSpy_Scanner_Setup_PRO_{#MyAppVersion}_MultiLang
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
