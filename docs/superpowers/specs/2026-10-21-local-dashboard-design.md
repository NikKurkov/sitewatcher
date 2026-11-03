# Local monitoring dashboard

User authorized autonomous product improvement and previously asked how to view a web version. Add a useful local, read-only view of the same monitoring database after the reliability checkpoint `b469df7`. Keep Ponytail constraints: standard library, no frontend framework, no new service dependency, no remote publishing.

## Product behavior

`sitewatcher web --owner 123 --port 8080` serves an HTML dashboard at `http://127.0.0.1:8080`. It reads saved monitoring results; the existing Telegram process continues performing checks. An explicit positive owner is mandatory. Bind only IPv4 loopback. Reject unexpected Host and Origin headers; never enable CORS. Expose no write, check-trigger, configuration, or credential endpoint.

The HTML dashboard shows summary counts, searchable/filterable domains, last check and next due times, paused/overdue state, and expandable per-check results. All content is escaped. It works without JavaScript and refreshes every 30 seconds. CSS is a packaged local asset. `GET /api/status` provides the same owner-scoped snapshot as JSON; `GET /healthz` reports database readability, not whether monitored sites are healthy. Missing or incompatible data produces a sanitized 503. Responses are non-cacheable with CSP, frame denial, and nosniff headers.

## Component contract

`reporting.build_snapshot(cfg, owner_id, *, now=None) -> dict` uses a read-only SQLite connection and one consistent read transaction. Never initialize or modify application tables. Fetch domains, overrides and latest per-check histories for exactly one owner using bounded query count. No user profiles, raw settings, proxies, tokens, or metrics blobs in output.

Snapshot keys:
- `generated_at`: aware UTC ISO timestamp.
- `summary`: integers `total`, `ok`, `warn`, `crit`, `unknown`, `paused`, `stale`.
- `domains`: dictionaries containing `name`, `overall` (OK/WARN/CRIT/UNKNOWN), `paused`, `stale`, `last_checked_at`, `next_due_at`, `checks`, `error` (safe message or null).
- Each check: `name`, `status`, `message`, `checked_at`, `stale`, `missing`.

Only enabled checks contribute. Missing checks are UNKNOWN; if none have results overall is UNKNOWN, otherwise UNKNOWN contributes WARN as in alerts. Overdue healthy results contribute UNKNOWN; existing problems are not downgraded. Paused domains retain last known status without becoming overdue. Invalid stored settings produce a visible UNKNOWN row without revealing raw values or breaking other domains. Datetimes use UTC; next_due_at is the earliest configured due time and null when paused.

`web.create_server(cfg, owner_id, *, port=8080) -> ThreadingHTTPServer` binds 127.0.0.1 and accepts port=0 for tests. Calls the reporting function at request time and `render_dashboard(snapshot, query='', status='all') -> str` from `dashboard.py`. Supported view statuses: all, problems, ok, warn, crit, unknown, paused, stale. Only GET/HEAD supported; all other paths/methods fail safely. No access-log query strings or source exceptions in responses.

## Verification

Use temporary databases, two owners, malicious HTML, missing/stale results, paused intervals and invalid settings. Exercise real HTTP over loopback, Host/Origin rejection and readonly behavior. Test the installed wheel includes HTML/CSS and starts from another directory. Preview desktop/mobile output with a local headless browser when available.
