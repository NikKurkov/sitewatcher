# VirusTotal automatic submission verification — 2026-11-05

An enabled malware check now submits `https://<domain>/` to VirusTotal only when the URL report returns HTTP 404. Existing reports and provider/authentication errors do not trigger POST. Each GET and POST consumes its own configured rate-limit slot and uses the same private proxy.

SQLite keeps an owner/URL claim and private analysis ID. Claims prevent concurrent and restarted checks from repeating a submission for 24 hours. Definite rejected requests release their claim; ambiguous timeouts, cancellation or invalid success replies retain it. Pending reports stay UNKNOWN and neutral, display “Проверяется”, and bypass the UNKNOWN cache by default. Report retrieval occurs on subsequent configured or manual checks; public reads do not submit anything.

## Validation

- Full suite: **990 passed**; Ruff and gettext checks passed.
- Tests cover canonical form submission, recovery, quota accounting, concurrent/durable/owner-scoped claims, rejected and ambiguous attempts, proxy routing, partial reports, cache bypass and public metadata filtering.
- Backup verified before the additive schema change: `/data/backups/before-vt-auto-submit-20261105T065538Z.sqlite3`, mode 0600, integrity check OK.
- Rebuilt local web and worker. All 26 changed package files match both running import paths. Web is healthy; the scheduler ownership lock is held.
- Real acceptance: submitted the published `https://a.tabak-pochtoy.com/` URL using the configured credentials/proxy. VirusTotal confirmed an analysis ID. The public page showed a neutral pending state and exposed no analysis ID.
- A subsequent check from the worker container received a completed report and returned **OK**. The original claim timestamp was unchanged, confirming no repeat submission. The saved public result is OK and its pending marker has cleared.
- Firefox MCP confirmed the public pending text during analysis; the final public DTO was independently read back after completion.

Submitted URLs can enter VirusTotal's shared dataset: [Scan URL API](https://docs.virustotal.com/reference/scan-url).
