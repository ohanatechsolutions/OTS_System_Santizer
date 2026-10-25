#define AppVersion "0.1.0"
#define AppName "Aegis Prime"
[Setup]
AppId={{4FA33E75-8824-4C7E-8B2B-AB5BE5064799}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher=Ohana Tech Solutions
AppPublisherURL=https://github.com/ohanatechsolutions/Aegis_Prime
DefaultDirName={autopf}\Aegis Prime
DefaultGroupName=Aegis Prime
DisableProgramGroupPage=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
WizardStyle=modern
Compression=lzma2
SolidCompression=yes
OutputDir=output
OutputBaseFilename=AegisPrimeSetup-x64
UninstallDisplayIcon={app}\AegisPrime.exe
SetupIconFile=..\src\AegisPrime.Desktop\Assets\AegisPrime.ico
LicenseFile=..\LICENSE
[Files]
Source: "..\artifacts\publish\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
[Icons]
Name: "{autoprograms}\Aegis Prime"; Filename: "{app}\AegisPrime.exe"
Name: "{autodesktop}\Aegis Prime"; Filename: "{app}\AegisPrime.exe"; Tasks: desktopicon
[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"
[Run]
Filename: "{app}\AegisPrime.exe"; Description: "Launch Aegis Prime"; Flags: nowait postinstall skipifsilent
