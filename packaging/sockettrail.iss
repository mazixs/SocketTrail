; Windows installer, built by packaging/build-win-setup.sh with Inno Setup 6.
; Packs the folder staged by packaging/build-win.sh: target/windows/SocketTrail.
; The version comes from Cargo.toml: ISCC -DAppVersion=<version>.

#ifndef AppVersion
  #error AppVersion is not defined, build with packaging/build-win-setup.sh
#endif

#define AppName "SocketTrail"
#define AppExe "sockettrail.exe"
#define AppUrl "https://github.com/mazixs/SocketTrail"
#define Stage "..\target\windows\SocketTrail"

[Setup]
; AppId ties upgrades and the uninstaller to one installation, never change it.
AppId={{98C6C04C-CD89-4B2A-B466-675B482351EE}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher=mazixs
AppPublisherURL={#AppUrl}
AppSupportURL={#AppUrl}/issues
AppUpdatesURL={#AppUrl}/releases
VersionInfoVersion={#AppVersion}
VersionInfoProductName={#AppName}
VersionInfoDescription={#AppName} Setup
; Program Files for all users by default; the dialog offers a per-user install
; into %LOCALAPPDATA%\Programs without administrator rights.
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog commandline
DefaultDirName={autopf}\{#AppName}
DisableProgramGroupPage=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
WizardStyle=modern
SetupIconFile=..\assets\sockettrail.ico
UninstallDisplayIcon={app}\{#AppExe}
UninstallDisplayName={#AppName}
OutputDir=..\target\windows
OutputBaseFilename={#AppName}-{#AppVersion}-windows-x64-setup
Compression=lzma2/max
SolidCompression=yes
; The program has no window of its own (the interface is a browser window), so the
; Restart Manager cannot ask it to close: after the user agrees it is terminated.
CloseApplications=force
RestartApplications=no

[Languages]
Name: "en"; MessagesFile: "compiler:Default.isl"
Name: "ru"; MessagesFile: "compiler:Languages\Russian.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "{#Stage}\{#AppExe}"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#Stage}\README.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#Stage}\LICENSE.txt"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Run]
; postinstall entries run as the user who started the installer, not elevated.
Filename: "{app}\{#AppExe}"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Stop only the installed copy: a portable copy elsewhere keeps running.
; Dumps, cache and settings in the user profile are kept.
Filename: "powershell.exe"; Parameters: "-NoProfile -NonInteractive -Command ""Get-Process sockettrail -ErrorAction SilentlyContinue | Where-Object Path -eq '{app}\{#AppExe}' | Stop-Process -Force"""; Flags: runhidden waituntilterminated; RunOnceId: "StopSocketTrail"
