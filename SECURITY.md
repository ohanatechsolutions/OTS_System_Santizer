# Security policy

Aegis Prime is security-sensitive preview software. Report exploitable defects through the repository's private vulnerability reporting mechanism or privately contact the maintainer. Do not post exploit details or live malware samples in public issues.

## Threat boundaries
- No UI-level operation is an elevation broker; Windows system-level remediation is **not** implemented in preview.
- Quarantine uses AES-256-GCM encrypted content and a DPAPI-wrapped per-item key; it is user-scoped and not kernel protected. Malware already running as the same user could potentially access decrypted content.
- Automated detection is limited to supported Microsoft Defender invocations, past Defender detection records, and described local heuristics; no on-access protections or kernel inspection.
- Windows Defender can continue working after a cancelled `Start-MpScan` call.
- File deletion is permanent after user selection and explicit consent. It does not provide undo.
- Never blindly delete or quarantine files within Windows, WinSxS, Windows Installer, Program Files or another user account's directories.

For any confirmed infection, use Microsoft Defender/Windows Security or trusted incident-response tooling to remediate it.
