# Release readiness checklist

## Included in preview
- [x] WPF desktop dashboard for Windows x64
- [x] Quick/Deep scan actions, progress and cancellation
- [x] Bounded multi-threaded recursive file inspection
- [x] Process and Run/RunOnce, service and readable scheduled-task anomaly inspection
- [x] Historical Defender detection records clearly labeled as past events
- [x] Installed applications registry inventory
- [x] Microsoft Defender on-demand scan invocation with failure reporting
- [x] Itemized user-temp/crashdump/browser-cache discovery
- [x] Size reporting and individually selected cleanup
- [x] Confirmation and conservative path checks on deletion
- [x] AES-256-GCM encrypted manual quarantine, Windows DPAPI per-item key and hash-verified restore
- [x] Inno Setup EXE installer automated by Windows GitHub Actions
- [x] Local automated smoke tests
- [x] Honest safety disclaimers and architecture documentation

## Not release-grade: verify before version 1.0
- [ ] Independently verify clean builds on Windows 10 and Windows 11
- [ ] Harden against all filesystem TOCTOU cases with handle-based checks
- [ ] Full ACL hardening, crash-recovery and hostile-process quarantine testing
- [ ] Implement safe privileged remediation broker and UAC transaction protocol
- [ ] Integrate reliable active antivirus provider health/detection records
- [ ] Expand scheduled tasks, services, WMI persistence and accessible memory analysis
- [ ] Separate scan cancellation of inspection from native antivirus jobs
- [ ] Add realistic malware-safe fixture tests and high-volume performance benchmarks
- [ ] Add screen reader, DPI, contrast and keyboard accessibility testing
- [ ] Code sign EXE and installer with trusted certificate
- [ ] Pen-test recovery, symlink/race handling, and installer update/uninstall
