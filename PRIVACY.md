# OTS System Sanitizer privacy

The application inspects accessible local Windows files and metadata and
optionally requests on-demand Microsoft Defender scans. It does not have
built-in telemetry, cloud upload, GitHub integration or account management.

The encrypted quarantine vault and activity records remain in your Windows
user profile. Quarantine uses AES-256-GCM with per-item DPAPI-wrapped keys;
it is not a protected kernel sandbox. Destruction removes vault files and
manifests but is not a forensic physical overwrite.

Earlier previews offered a repository browser and may have stored
`github-accounts.json` using Windows DPAPI. New builds neither read nor
create these files. See README.md for optional safe cleanup of old data.
