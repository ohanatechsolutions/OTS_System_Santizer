# Contributing to OTS System Sanitizer

Ohana Tech Solutions maintains OTS System Sanitizer as a Windows-only,
local security inspection and conservative cleanup utility.

Contributions should provide scoped pull requests with descriptions of
user-visible changes, threat boundaries, manual-risk assessment and test plans.

- Build against .NET 10 on Windows; run the smoke tests and Windows CI pipeline.
- Avoid introducing cloud connectivity, repository browsing or account token
  management. These are outside this application's scope.
- Any file-altering operation must retain clear opt-in, path restrictions and
  confirmation before irreversible action.
- Only use harmless test fixtures; never commit real malware, customer scan
  results, credentials, access tokens, encrypted user vaults or private data.
- Do not imply heuristic findings are confirmed infections.
- Report vulnerabilities privately per SECURITY.md.

See README.md, docs/ARCHITECTURE.md and docs/RELEASE_CHECKLIST.md.
