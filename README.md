# Aegis Prime

**Windows-native security inspection and conservative storage recovery** for Windows 10/11 x64.

Developed by **Ohana Tech Solutions**. Open-source, offline-first, and free of subscription requirements.

> **Preview build 0.1.0.** Aegis Prime is **not a replacement for Microsoft Defender or another antivirus product**. Its own findings are local heuristics, not verified malware diagnoses. Scan coverage is limited by Windows access controls and antivirus availability. There is no kernel driver, protected-process bypass, scheduled-task inspector, generalized registry cleaner or kernel-enforced quarantine vault in this build. Do not use this application as the sole basis for believing a system is safe.

## Download / install

1. Open [Actions](https://github.com/ohanatechsolutions/Aegis_Prime/actions/workflows/windows-build.yml), select the latest **successful** Windows build, and download the `AegisPrime-Windows-Installer-x64` artifact.
2. Extract the artifact ZIP and run `AegisPrimeSetup-x64.exe`.
3. The build pipeline also places the compiled installer at [installer/AegisPrimeSetup-x64.exe](installer/AegisPrimeSetup-x64.exe) after a successful main-branch build when repository Actions write permission allows it.
4. Verify the installer against [installer/AegisPrimeSetup-x64.sha256](installer/AegisPrimeSetup-x64.sha256) with Windows PowerShell: `(Get-FileHash .\\AegisPrimeSetup-x64.exe -Algorithm SHA256).Hash`.
5. No paid tools are required to run the software. Builds are currently unsigned; Windows SmartScreen may warn. Verify the repository and published SHA-256 before installation.

**Source installers:** `installer/AegisPrime.iss` is the Inno Setup project, **not** an executable. Use the compiled `.exe` for installation.

## Usage

- **Quick Scan:** read-only inspection of selected user startup/temporary/download paths, accessible process metadata and unusual Run/RunOnce, service and scheduled-task commands; also requests a Microsoft Defender quick scan where available.
- **Deep Scan:** bounded multi-worker read-only inspection of fixed, accessible volumes, plus Microsoft Defender full scan when available.
- **Findings:** evidence-first, source-labelled review items. Suspicious locations and double extensions are heuristics. They are not automatic infection verdicts.
- **GitHub repositories (read-only):** connect multiple GitHub.com accounts with separate fine-grained personal access tokens; browse repository lists, folders and text-file previews without modifying code. Tokens are encrypted with Windows DPAPI in `%LOCALAPPDATA%\\AegisPrime\\github-accounts.json` and are accessible only to the current Windows user. This is a repository browser, **not yet an online security auditor**.
- **Installed applications:** inspect registered software, publisher, estimated size, uninstaller availability and missing install folder hints. Removal is delegated to Windows Settings.
- **Space recovery:** discover old user Temp and CrashDumps files; optionally include Chrome/Edge default-profile cache. Files are **never selected for deletion automatically**. After analyzing storage, use **Select all** to check or uncheck every listed candidate at once; individual checkboxes remain editable and the selection count updates live.
- **Delete checked files:** user-confirmed permanent deletion with stale-file checks, category allowlist and reparse-point checks. No raw WinSxS/Windows Installer deletion.
- **Quarantine:** explicitly selected, accessible user-profile files may be moved to an app-local vault and restored. AES-256-GCM encryption with a unique Windows DPAPI user-wrapped key per item, integrity verification and explicit restore. This is **not kernel-enforced antivirus isolation** and does not protect against malware already running as the same user.

**Clean & Secure** performs a quick inspection and discovers storage candidates, but it does **not** silently remediate or delete anything.

## Connecting multiple GitHub accounts

1. In GitHub, go to **Settings → Developer settings → Personal access tokens → Fine-grained tokens**, and create a token for each GitHub account you want to connect. Limit it to the repositories you want Aegis Prime to read.
2. Grant **Metadata: Read** (automatic for fine-grained tokens) and **Contents: Read** repository permissions. Do not grant write permissions or paste tokens into issues, source files or the Activity log. Some organizations require approval or SSO authorization to read private repositories.
3. Open Aegis Prime's **GitHub repositories** tab. Paste one token into the masked field and click **Connect account**. The app verifies its owner using GitHub's authenticated user endpoint, then stores the credential encrypted on this Windows user profile.
4. Repeat for the next account. Choose **All accounts** and **Refresh repositories** to see repositories from all connected accounts together, each labelled with its account. Select a repository → **Browse selected repository** → select a folder/file → **Open selected**.
5. To remove an account, choose it in the Account menu and click **Disconnect selected**. This only removes local storage; revoke its token in GitHub Settings if it may have been compromised.

Only HTTPS requests to the official `api.github.com` REST API are used. No OAuth client secret is required, and the app does not run `git push`, `git clone` or any write API operation. Individual folder listings are limited by GitHub's Contents API and text-file preview is limited to 1 MB. Authentication requires internet access; local scans remain offline-first. Account tokens remain valid until revoked/expired. **GitHub Copilot is not needed.**

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
