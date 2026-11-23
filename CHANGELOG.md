# Changelog

## 0.4.0

### Added

- Organize sites into collapsible groups and move them between groups from the overview.
  Status pages can show selected sites and groups, including sites added to those groups later.
- Create multiple public or private status pages with their own titles and editable public addresses.
  Open and copy newly issued private links in settings. Existing links survive the upgrade and can
  be reissued if you need to copy them from settings.
- Pick email, Telegram, or both for each site. Email has its own delivery status and retries.
- Follow checks in the Signal room, see network routes in the workspace, and keep unresolved
  critical checks visible until the check confirms recovery. The public view shows activity for
  the selected sites with a limited set of fields.
- Rename a monitored site or set a specific HTTP or HTTPS path. Keep its settings and history.
- Optionally stay signed in for 30 days. The default sign-in lasts 12 hours.

### Changed

- Load checks and charts when you expand a site on the overview or a status page. Reserve space
  for the chart during loading. Show a gap after a scheduled HTTP check is overdue and no result
  has been saved. Include 30-day averages and keep confirmation attempts visible in full history.
  [Chart loading](docs/screenshots/response-chart-loading.png) ·
  [Missed HTTP check](docs/screenshots/response-chart-missed-check.png)
- Recheck sharp increases in scheduled HTTP response times. Successful confirmation contributes
  one median measurement to the chart and averages. HTTP and connection failures still appear
  immediately.
- Cache TLS and WHOIS metadata for 24 hours with targeted refresh controls. Preserve the last
  known registration expiry when RDAP cannot supply a usable date, and respect provider retry delays.
- Submit missing VirusTotal reports for analysis and keep a daily cooldown across restarts. Pending
  submissions appear as unknown. Configure a dedicated proxy for VirusTotal in the workspace.
- Start the Django app directly from the CLI and reuse the Docker dependency layer for source changes.

### Fixed

- Measure the full HTTP redirect chain, inspect keywords on the successful final response, and
  limit defacement checks to HTML. Try TCP ping when ICMP gets no answer.
- Confirm new DNS address sets before reporting a change. Keep an eligible previous registry index
  available during an RKN refresh and validate DNS blocklist sources before using their verdicts.
- Keep port checks on their configured schedule and show manual checks in progress.
- Honor individual status filters in detailed Telegram reports and serialize SQLite initialization
  when web and monitoring processes start together.

Back up persistent data and the web secret before upgrading. Startup applies database migrations.
See [operations and rollback](docs/operations.md).

## 0.3.0 — 2026-11-03

### Added

- Authenticated Django workspace with domain management, history, CSV backups and
  optional Telegram notifications. A standalone worker runs scheduled monitoring.
- English and Russian panel languages, per-account timezone settings, persistent themes
  and revocable public status pages for selected domains.
- Favorite domains, atomic addition of up to 50 comma-separated domains, history filters,
  interactive response-time charts and status details on hover or keyboard focus.
- Docker Compose setup with a nonroot web/worker image, persistent data and local-only
  port binding. `doctor` checks configuration, schema, integrity and permissions.

### Changed

- RKN checks use Antifilter with bol-van as fallback. Domain listings are Critical;
  shared-IP listings are Warning. Source dates and complete bundles are checked before
  publishing an index. Stale or incomplete data cannot confirm a clean result.
- Domain forms show inherited defaults and accept readable keyword/port lists. Existing
  RKN configuration keys, schedules and CSV headers remain supported.
- Python 3.12–3.14 are covered by CI, including installed-package and container checks.

### Fixed

- Keep owner settings, history, IP-change baselines and public selections isolated.
  Reject duplicate creation, stale edits and malformed stored settings safely.
- Save domain/settings changes atomically and avoid recreating deleted domains when
  in-flight checks finish. Serialize shared RKN index publication across processes.
- Preserve pending alerts after delivery failures and apply Telegram proxies to polling
  as well as ordinary Bot API calls. Maintenance no longer blocks the bot event loop.
- Correct TLS wildcard matching, redirect severity, bounded/decompressed HTTP reads,
  WHOIS fallbacks, DNSBL coverage and incomplete external-service results.
- Preserve CSV list values and legacy RKN merge settings. Make analytics date-boundary
  tests independent of the wall clock.

Back up persistent data before upgrading. Startup applies additive database migrations;
see [operations and rollback](docs/operations.md).

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
