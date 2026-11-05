# VirusTotal missing-report submission

**Goal:** When an enabled malware check receives HTTP 404 for its canonical URL report, submit that URL for analysis automatically.

## Behavior

- Submit only `https://<monitored-domain>/`, after a missing-report response. Valid reports and provider/authentication errors never trigger submissions.
- Charge GET and POST separately against the configured limiter, using the existing private VirusTotal proxy for both.
- Persist an owner-scoped submission claim and analysis identifier in SQLite. Prevent concurrent/restarted checks from submitting the same URL more than once in 24 hours.
- Return UNKNOWN while analysis is pending; show a neutral “Analysis pending” label and an allowlisted explanation publicly. Never imply a clean result before observations exist.
- Retry report retrieval at subsequent configured checks; bypass cached UNKNOWN malware results by default.
- Keep public GET/HEAD requests read-only. Do not expose analysis IDs, raw diagnostics, keys or proxy credentials.
- Definite rejected submissions release their claim; ambiguous network failures retain the cooldown to avoid duplicate submissions.

## Tasks

- [x] Add failing tests for submission, repeat/concurrent suppression, quota/proxy routing, rejection, recovery, ownership and safe pending UI.
- [x] Implement SQLite claims and the provider request flow.
- [x] Update cache policy, pending presentation, translations and documentation.
- [x] Run full tests, back up SQLite, rebuild local services and verify a bounded real URL submission/report read-back.

VirusTotal receives the URL and can add it to its shared dataset. Reference: https://docs.virustotal.com/reference/scan-url.
