#define AppVersion "0.4.0"
#define AppName "OTS System Sanitizer"
[Setup]
AppId={{4FA33E75-8824-4C7E-8B2B-AB5BE5064799}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher=Ohana Tech Solutions
AppPublisherURL=https://github.com/ohanatechsolutions/OTS_System_Santizer
DefaultDirName={autopf}\OTS System Sanitizer
DefaultGroupName=OTS System Sanitizer
DisableProgramGroupPage=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
WizardStyle=modern
Compression=lzma2
SolidCompression=yes
OutputDir=output
OutputBaseFilename=OTSSystemSanitizerSetup-x64
UninstallDisplayIcon={app}\OTSSystemSanitizer.exe
SetupIconFile=..\src\OTSSystemSanitizer.Desktop\Assets\OTSSystemSanitizer.ico
LicenseFile=..\LICENSE
[InstallDelete]
; Remove the superseded executable when upgrading an older installation.
Type: files; Name: "{app}\AegisPrime.exe"

[Files]
Source: "..\artifacts\publish\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
[Icons]
Name: "{autoprograms}\OTS System Sanitizer"; Filename: "{app}\OTSSystemSanitizer.exe"
Name: "{autodesktop}\OTS System Sanitizer"; Filename: "{app}\OTSSystemSanitizer.exe"; Tasks: desktopicon
[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"
[Run]
Filename: "{app}\OTSSystemSanitizer.exe"; Description: "Launch OTS System Sanitizer"; Flags: nowait postinstall skipifsilent
