# Aegis Prime architecture — implementation map

## UI process
`src/AegisPrime.Desktop`: WPF XAML + code-behind state management. Runs unelevated by default, keeps scan work asynchronous, presents evidence and asks for explicit confirmation before any destructive action. Custom shield icon and About/footer subtly credit Ohana Tech Solutions.

## Core services
`src/AegisPrime.Core` is Windows-targeted and has no third-party package dependencies.

| Service | Responsibility | Trust limitations |
| --- | --- | --- |
| ThreatScanner | Bounded `Channel<string>` with 2–6 consumers; fixed-drive/full or high-value/quick root enumeration, SHA-256 on selected suspicious artifacts | Heuristics only, no antivirus signatures or in-memory disassembly |
| PersistenceInspector | Inspect Run/RunOnce registry keys, service commands, readable scheduled-task XML and accessible process modules | No protected-process access, scheduled-task inventory or complete hook inspection |
| DefenderIntegration | Invoke Defender `Start-MpScan` through static PowerShell arguments, await exit and report errors | Not guaranteed available/active; no independent AV verdict |
| InstalledAppsService | Read-only uninstall registry inventory and missing-install-location hints | No direct app deletion or arbitrary uninstaller execution |
| CleanupService | Discover age-qualified old files in user Temp/CrashDumps and opt-in browser cache | Estimates sum logical sizes; doesn't imply physical disk space will be reclaimed |
| PathPolicy | Conservative full-path containment and reparse-point rejection | Not a kernel enforcement boundary; races remain possible |
| QuarantineService | Move selected user-profile file to staging, AES-256-GCM stream encryption, DPAPI-wrapped key, SHA-256 verified restore | User-scoped, not kernel-enforced; same-user malware remains a threat |

## Future production hardening
- Genuine Windows Security Center provider-status integration, verified Defender detection event ingestion, more complete persistence vectors and verified signature evaluation.
- Authenticated, temporary elevated remediation broker with immutable action plans, user identity binding and handle-based target validation.
- Restricted-ACL hardening, crash-recovery of incomplete staging operations, transactional rollback; path-race and reparse adversarial tests.
- Privacy-preserving SQLite history and structured exportable reports.
- VM-based real Windows 10/11 malware-test fixtures, usability/accessibility audit, signed binaries.
- Optional safely supported DISM/Windows-managed storage cleanup.

**Safety invariant:** do not label a heuristic as confirmed malware and do not automatically delete critical system files.
