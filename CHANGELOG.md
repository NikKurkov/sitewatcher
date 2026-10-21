# Changelog

## Unreleased

- Add browser management for domains, inherited settings, live checks, history, owner alerts and CSV, with typed deletion confirmation and an explicit `--read-only` fallback.
- Protect web mutations with strict same-origin POST/CSRF validation, bounded native form parsing and atomic duplicate/stale-edit guards.
- Add persistent Day/Night/System themes; a small optional script preserves unsaved forms while switching.

- Add a Docker image and Compose setup for one-command startup with persistent SQLite data.
- Add a loopback-only, read-only web dashboard with fixed owner isolation, search, status filters, saved check details and JSON output. No frontend framework or runtime dependency is required.
- Add sanitized `doctor` diagnostics for local configuration, schema, database integrity and permissions; retain native SQLite reader locks during concurrent checkpoints.
- Make storage updates atomic, preserve concurrent settings changes, and prevent completed jobs from restoring deleted domains.
- Retry undelivered incident transitions and summaries without consuming their state; serialize concurrent delivery and respect alert toggles.
- Apply the Telegram proxy to both ordinary Bot API calls and long polling.
- Validate domain settings and YAML before use, preserve explicit zero values, and give safe field-specific error messages.
- Fail closed on corrupt stored settings; allow an explicit full reset without exposing malformed content.
- Bound page downloads before decompression, including redirect bodies, and reject incomplete content without reporting a clean result.
- Save wizard and CSV domain creation together with settings in one transaction, and inherit the configured check defaults.
- Correct TLS wildcard matching, redirect failure severity, incomplete DNSBL/RKN coverage, WHOIS fallback/cache paths and per-domain HTTP proxies.
- Preserve IP-change baselines during temporary DNS failures; require completed, valid VirusTotal observations before reporting a clean result.
- Isolate IP-change baselines by owner and ad hoc scans, preserving legacy cache migration without consuming another owner's change.
- Fix same-day history filtering, lossless CSV keyword/port round trips, zero history retention and UTC maintenance scheduling.
- Honor `/check example.com --force` as documented, preserving the prefix flag form.
- Detect history transitions before filtering their status and order simultaneous events by insertion ID.
- Test supported Python versions 3.12–3.14, including real loopback HTTPS/proxy and cancellation flows.
- Require python-telegram-bot 22.4 or newer for native polling startup on Python 3.14; offload history cleanup and compaction so they do not block the Telegram event loop.
- Exclude private YAML, environment files, runtime SQLite sidecars and cache archives from Docker builds; test the installed assets and build boundary with synthetic canaries.

## 0.2.0 — 2026-09-30

- Start with built-in defaults when no YAML file is present.
- Run scheduled checks according to their own intervals and per-domain overrides.
- Keep each owner's settings isolated and combine recent results before deciding alert severity.
- Fix CLI checks, ad-hoc bot checks, HTTP proxies, ports, WHOIS initialization, and `.env` database path loading.
- Keep partial YAML domain check flags layered over global defaults; reject invalid CLI domains and check names.
- Keep VirusTotal quota state across checks and prevent cached manual results from extending their own TTL.
- Save each run's history in one SQLite transaction and close database connections promptly.
- Remove an unused RKN implementation and its 67 MB legacy index. The active checker builds its SQLite index on demand beside the configured database.
- Add offline regression tests and GitHub Actions CI for Python 3.12 and 3.13.
- Simplify installation and update the English documentation.
