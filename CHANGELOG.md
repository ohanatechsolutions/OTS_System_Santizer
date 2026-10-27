# Changelog

All notable changes to OTS System Sanitizer are recorded here.

## [0.3.0] — Search and Destroy and product separation

- Added elapsed search timer, Quick Search / Deep Search names and the
  **Windows Anti-Malware: Search and Destroy** header.
- Added checkbox selection and Select all for eligible user-file findings.
- Added user-confirmed batch quarantine and a mandatory investigation view
  before explicitly destroying an encrypted quarantined file.
- Persisted original finding evidence and plain-language rationale in quarantine metadata.
- Removed the repository browser, account connections, credentials handling,
  repository reader service and related tests/documentation from this product.
- Retained Windows-only local threat-searching and storage recovery responsibilities.

## [0.2.0] — Rebrand

- Changed the product name from Aegis Prime to **OTS System Sanitizer**.
- Renamed the Windows executable, .NET projects, namespaces, icon resources, installer script and release artifacts.
- Kept the installer application ID and encrypted quarantine file format stable to preserve upgrade compatibility.
- Preserved access to previous user-profile vault items. (Earlier versions also contained a repository browser, removed in v0.3.)
- Updated documentation and CI/CD installer packaging.

## [0.1.0] — Initial preview

- Windows WPF dashboard with quick/deep inspection and Microsoft Defender integration.
- User-reviewed cleanup, installed application inventory and encrypted quarantine.
- Build, smoke-test, and installer verification workflows.

> Earlier published artifacts remain available in Git history; do not confuse their names or checksums with the renamed release.
