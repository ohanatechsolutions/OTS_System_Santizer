# Aegis Prime

**Windows-native security inspection and conservative storage recovery** for Windows 10/11 x64.

Developed by **Ohana Tech Solutions**. Open-source, offline-first, and free of subscription requirements.

> **Preview build 0.1.0.** Aegis Prime is **not a replacement for Microsoft Defender or another antivirus product**. Its own findings are local heuristics, not verified malware diagnoses. Scan coverage is limited by Windows access controls and antivirus availability. There is no kernel driver, protected-process bypass, scheduled-task inspector, generalized registry cleaner or encrypted quarantine vault in this build. Do not use this application as the sole basis for believing a system is safe.

## Download / install

1. Open [Actions](https://github.com/ohanatechsolutions/Aegis_Prime/actions/workflows/windows-build.yml), select the latest **successful** Windows build, and download the `AegisPrime-Windows-Installer-x64` artifact.
2. Extract the artifact ZIP and run `AegisPrimeSetup-x64.exe`.
3. The build pipeline also places the compiled installer at [installer/AegisPrimeSetup-x64.exe](installer/AegisPrimeSetup-x64.exe) after a successful main-branch build when repository Actions write permission allows it.
4. No paid tools are required to run the software. Builds are currently unsigned; Windows SmartScreen may warn. Verify the repository and published SHA-256 before installation.

**Source installers:** `installer/AegisPrime.iss` is the Inno Setup project, **not** an executable. Use the compiled `.exe` for installation.

## Usage

- **Quick Scan:** read-only inspection of selected user startup/temporary/download paths, running process metadata and unusual registry startup entries; also requests a Microsoft Defender quick scan where available.
- **Deep Scan:** bounded multi-worker read-only inspection of fixed, accessible volumes, plus Microsoft Defender full scan when available.
- **Findings:** evidence-first, source-labelled review items. Suspicious locations and double extensions are heuristics. They are not automatic infection verdicts.
- **Space recovery:** discover old user Temp and CrashDumps files; optionally include Chrome/Edge default-profile cache. Files are **never selected for deletion automatically**.
- **Delete checked files:** user-confirmed permanent deletion with stale-file checks, category allowlist and reparse-point checks. No raw WinSxS/Windows Installer deletion.
- **Quarantine:** explicitly selected, accessible user-profile files may be moved to an app-local vault and restored. Basic user-mode isolation only: the vault is **not encrypted or kernel protected**, and this is **not suitable for handling high-risk live malware**.

**Clean & Secure** performs a quick inspection and discovers storage candidates, but it does **not** silently remediate or delete anything.

## Build locally

Install [Visual Studio 2022 or later](https://visualstudio.microsoft.com/) with the **.NET desktop development** workload or the .NET 10 SDK on Windows, then run:

```powershell
dotnet build src/AegisPrime.Desktop/AegisPrime.Desktop.csproj -c Release
dotnet run --project tests/AegisPrime.SmokeTests/AegisPrime.SmokeTests.csproj -c Release
dotnet publish src/AegisPrime.Desktop/AegisPrime.Desktop.csproj -c Release -r win-x64 --self-contained true -o artifacts/publish
& "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer\AegisPrime.iss
```

The produced executable installer is `installer/output/AegisPrimeSetup-x64.exe`. Windows runners compile it in GitHub Actions.

## Security design

- No always-on services, background telemetry, cloud uploads or paid APIs.
- Ordinary desktop process; administrator access is not silently requested by the UI. Setup requests UAC to install under Program Files.
- Defender controls antivirus detection and remediation. Aegis Prime only requests supported on-demand scans, and reports when invoking them fails.
- File changes require a separate confirmation and are restricted to user-profile scope.
- Filesystem traversal skips reparse points; inaccessible paths are not reported as clean.
- No system-critical registry/file deletion.

See [architecture](docs/ARCHITECTURE.md), [security policy](SECURITY.md), and [known limitations](docs/RELEASE_CHECKLIST.md).

**Windows 10:** standard support ended October 14, 2025. Compatible systems can run Aegis Prime, but an unpatched OS remains at risk.
