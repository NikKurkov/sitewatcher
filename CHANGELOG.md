# Changelog

## Unreleased

- Use a radar icon and the Signal room label for the monitoring-map toggle.

- Compact signal-room events into single rows with full labels on hover and
  internal horizontal scrolling on phones.

- Highlight critical signal-room events with a red background and pulse active
  critical domain cards; respect pause and reduced-motion preferences.

- Place the signal-room event console on the map beside the monitoring hub and
  domain cards. Show time, check, domain, result and duration as readable fields;
  preserve follow/pause/replay and use a stacked layout on narrow screens.

- Align signal-room speed selection with adjacent controls on desktop and mobile.

- Include all check types for selected domains in the public signal room, while
  keeping diagnostic messages, metrics and private domains out of the public feed.

- Clarify expanded domain details in the workspace and public status page: compact
  response-time captions, labelled chart axes, shared check timestamps, neutral stale
  result indicators and lighter successful statuses.
- Persist WHOIS refresh attempts alongside cached results. Reuse the daily cache after
  provider failures, respect longer `Retry-After` delays and prevent concurrent or
  restarted workers from repeatedly querying RDAP during the cooldown.
- Remove unused management markup, internal compatibility wrappers, obsolete planning
  documents and unreferenced images. Share response metrics and use standard ordered
  deduplication without changing monitoring settings or supported configuration keys.
- Start the Django application directly from the CLI and cache Docker dependencies
  separately from application source.
- Respect individual status filters in detailed Telegram status reports.

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
