# OTS System Sanitizer

**Windows Anti-Malware: Search and Destroy** for Windows 10/11 x64.

Developed by **Ohana Tech Solutions**. Local-first Windows threat searching,
reviewable quarantine, and conservative storage recovery. No account connection,
cloud service, repository browser or subscription is needed to run the application.

> **Preview v0.4.0:** This is **not** a replacement for Microsoft Defender or another
> antivirus product. Local findings are *heuristics*, not proof of infection.
> Defender scanning is requested when available; coverage depends on Windows
> permissions and installed security providers. There is no kernel driver,
> protected-process bypass or kernel-enforced quarantine.

## Install

1. Go to the repository **Actions** tab, open the most recent **successful**
   `OTS System Sanitizer — Windows build, tests and installer` run, and download
   `OTSSystemSanitizer-Windows-Installer-x64`.
2. Extract the artifact ZIP and run `OTSSystemSanitizerSetup-x64.exe`.
3. A successful main-branch build also publishes the compiled EXE to
   [installer/OTSSystemSanitizerSetup-x64.exe](installer/OTSSystemSanitizerSetup-x64.exe)
   when the repository's Actions write permission permits it.
4. Verify the matching SHA-256 using
   `(Get-FileHash .\OTSSystemSanitizerSetup-x64.exe -Algorithm SHA256).Hash`.
   The companion digest file is
   [installer/OTSSystemSanitizerSetup-x64.sha256](installer/OTSSystemSanitizerSetup-x64.sha256).

The `.iss` file is Inno Setup source, **not** a runnable Windows installer.
Unsigned preview builds may trigger SmartScreen warnings.

## 0.4 visual refresh

The Windows WPF interface now uses the slate and steel-blue design system:
`#0F172A`, `#1E293B`, `#34587C`, `#24405E`, `#4E79A7`,
`#8BA8CD`, and high-contrast white. Rounded translucent-looking cards,
thin borders, restrained selection glows, accessible keyboard focus states,
sidebar navigation, and a top filter field keep the search-and-destroy workflow
organized. The filter searches findings already loaded in Threat Review; it
**does not initiate a new security search**.

The supplied shield/check/gear/magnifier branding is installed as
[PNG](src/OTSSystemSanitizer.Desktop/Assets/OTSSystemSanitizer.png)
for the application's header and as
[ICO](src/OTSSystemSanitizer.Desktop/Assets/OTSSystemSanitizer.ico)
for the Windows application icon, installer, and shortcuts.
The artwork was resized for efficient desktop display; its recognizable
visual identity is retained.

This is a WPF-native glass-style theme rather than true system acrylic
backdrop blur. All quarantine safeguards, manual confirmations, and
offline-only behavior are preserved.

## Search and Destroy workflow

- **Quick Search:** local user startup, temporary and download paths; process
  metadata and selected persistence indicators, plus a requested Defender quick scan.
- **Deep Search:** read-only searching of accessible fixed volumes with bounded
  workers, plus a requested Defender full scan.
- **Search duration:** live `HH:MM:SS` stopwatch through the full search operation;
  the final duration remains visible after completion, cancellation or failure.
- **Threat search:** findings show severity, title, source, location and concrete
  recorded evidence. Select eligible user files individually or use **Select all**.
  Informational history records and protected/inaccessible paths are not selectable.
- **Quarantine & investigate checked:** moves each confirmed eligible selected file
  into the user-scoped encrypted quarantine; the original finding's evidence and
  reason for flagging are saved with the vault metadata.
- **Investigate selected:** in Quarantine, displays recorded evidence, explanation,
  SHA-256 and limitations for a selected file. **Destroy reviewed file** remains
  disabled until the selected item has been investigated in this session.
- **Destroy reviewed file:** *separate explicit confirmation* removes that item's
  encrypted vault contents and manifest. This is irreversible; no secure overwrite
  or complete physical erasure of SSD blocks is claimed.
- **Restore selected file:** returns quarantined data to its original path after
  confirmation and verified decryption, provided the destination is safe and vacant.
- **Space recovery:** find older user Temp and CrashDumps files; optionally include
  browser cache. Individually check candidates or select all, then confirm
  **Destroy checked cleanup files**. No arbitrary Windows-system directory deletion.
- **Installed applications:** read-only inventory with Windows Settings for removal.

The **Clean & Secure** shortcut performs Quick Search followed by storage analysis.
It never automatically destroys findings or cleanup candidates.

## No repository auditing features

This product is exclusively for local Windows maintenance and threat searching.
It has **no repository-browser tab, remote repository access, connected account
management, personal access token storage or source-code/security-audit engine**.
Those are separate product responsibilities and are not bundled here.

Existing versions may have created an encrypted
`%LOCALAPPDATA%\OTSSystemSanitizer\github-accounts.json` or legacy
`%LOCALAPPDATA%\AegisPrime\github-accounts.json` credential file.
Version 0.3 no longer reads, maintains or updates those files.
If you choose to clean up old account credentials, ensure you have no other
application that relies on them and delete **only the specifically named file**.
Also revoke no-longer-needed access tokens in the account provider's settings.
Do **not** delete the parent data folder: it can contain valuable quarantine data.

## Upgrade compatibility

Version 0.2.0 renamed the executable and app from Aegis Prime.
The Inno Setup AppId, per-user quarantine directory compatibility and encrypted
quarantine format are preserved to allow upgrading without losing restore capability.
The application continues reading legacy quarantine metadata when present.

The GitHub repository is currently named `ohanatechsolutions/OTS_System_Santizer`;
the displayed application and installer are correctly named **OTS System Sanitizer**.

## Build locally

Requires Windows 10/11, .NET 10 SDK and Inno Setup 6 for installer builds:

```powershell
dotnet build src/OTSSystemSanitizer.Desktop/OTSSystemSanitizer.Desktop.csproj -c Release
dotnet run --project tests/OTSSystemSanitizer.SmokeTests/OTSSystemSanitizer.SmokeTests.csproj -c Release
dotnet publish src/OTSSystemSanitizer.Desktop/OTSSystemSanitizer.Desktop.csproj -c Release -r win-x64 --self-contained true -o artifacts/publish
& "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer\OTSSystemSanitizer.iss
```

CI compiles and validates the actual installer and checks installation/uninstallation.
See [architecture](docs/ARCHITECTURE.md),
[release readiness](docs/RELEASE_CHECKLIST.md) and [security](SECURITY.md).

**Windows 10:** Standard support ended October 14, 2025; unpatched systems remain at risk.
