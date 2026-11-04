# Operations and recovery

For installation and everyday use, start with the [English user guide](usage.en.md)
or the [Russian user guide](usage.ru.md).

See the [reliability report](verification-2026-10-21.md) for recovery/performance
and the [web management report](verification-web-management-2026-10-22.md) for browser,
security and installed-package verification.

## Verify an installation

Use the same working directory, `DATABASE_PATH`, configuration and account as the bot:

```bash
sitewatcher doctor --json
sitewatcher check_all --owner 123456789 --only http_basic,tls_cert
sitewatcher web --owner 123456789 --port 8080
```

The second command runs real probes and saves results; omit it when only diagnosing local storage. `doctor` makes no network calls or application-data writes. Normal SQLite reads may create or update WAL/SHM reader metadata beside an existing database; they retain SQLite's protection against concurrent checkpoints. Its successful result does not verify a Telegram token, proxy, public API, or firewall. Check a saved result and an authorized Telegram interaction separately when deploying.

Run `sitewatcher setup` once to create the local owner, then start `sitewatcher web`
and `sitewatcher worker` with the same database and YAML. On an existing Telegram
installation, choose the legacy owner explicitly with `setup --owner <id>`; omitting
it deliberately creates a fresh monitoring identity. `--owner` on web only asserts
this binding and never bypasses login. `--read-only` rejects monitoring mutations
while retaining authentication, password recovery and private exports.

Compose startup is `docker compose run --rm --build setup` followed by
`docker compose up -d`, with no compulsory environment file. The host mapping is
loopback-only even though web binds 0.0.0.0 inside the container. One worker or scheduled
bot owns the database lock; optional Compose bot polling uses `--no-scheduler`.
`/healthz` checks the database and minimal monitoring/authentication schema without
initializing storage or running an integrity scan. A fresh migrated database is web-ready
even before account setup; missing/incompatible/unreadable storage returns 503. Health
200 is not evidence that a worker runs or that any monitored site is healthy.

Docker images include application code and packaged examples only. Private YAML, environment files, SQLite files/sidecars and compressed caches are excluded from the build context. Mount custom configuration at runtime rather than baking it into an image.

## Web management

- Choose the account binding during setup and use the same YAML as the worker. Existing settings are shared through SQLite; the next scheduler tick reads them.
- Domain check selectors support inherit/on/off. Blank numeric/list fields inherit; `-` clears keyword/port lists (`[]` remains accepted for older submissions). `interval_minutes: 0` pauses a domain. Reset removes every per-domain override.
- A stale edit is rejected. Use “Reload saved settings” before editing again; repeated submission cannot silently overwrite concurrent changes.
- Proxy input stays blank. “Clear domain override” selects the common HTTP client, which may still use a global proxy; global proxy configuration is not changed by the form.
- CSV exports may contain proxy credentials. Imports apply valid rows independently, reject concurrently changed merge targets, retain domains absent from the file and display added/updated/skipped counts. On errors, reselect the file or paste again; private CSV content is not redisplayed.
- One web manual-check batch can run at a time. Other requests remain available. No separate scheduler or notification sender runs in the web process. A running bot sees newly saved states on its next tick.
- Light/dark theme is a non-sensitive browser cookie. A small optional script changes the theme without discarding drafts; without JavaScript, theme links reload the saved page.
- Every owner route requires login. Django sessions and CSRF protect mutations; login attempts are throttled. HTTPS deployments require explicit allowed hosts, secure cookies and a trusted proxy as described in the [user guide](usage.en.md#remote-access-and-accounts). Public bearer links expose only selected HTTP observations and scoped HTTP lifecycle events; disabling or rotating them revokes access immediately.

## Back up and restore

Protect backups like `.env`: domain configuration and history may be private. Use SQLite's backup API for a consistent backup while the bot runs, rather than copying a live database without its WAL:

```bash
python - /absolute/path/sitewatcher.db /safe/path/sitewatcher-backup.db <<'PY'
import sqlite3
import sys
from contextlib import closing
from pathlib import Path

source, target = map(Path, sys.argv[1:])
with closing(sqlite3.connect(source.resolve().as_uri() + "?mode=ro", uri=True)) as db:
    target.touch(mode=0o600, exist_ok=False)  # private file; refuses an existing destination
    with closing(sqlite3.connect(target)) as backup:
        db.backup(backup)
        assert backup.execute("PRAGMA integrity_check").fetchone() == ("ok",)
PY
```

Keep `.env`, custom YAML, `<database>.web-secret`, `<database>.telegram-token`, `<database>.telegram-proxy`, `<database>.virustotal-key` and `<database>.virustotal-proxy` separately with restrictive permissions (private credential files require mode 0600). Stop writes to settings while taking a coordinated backup; for the simplest consistent full backup, stop web, worker and bot first. Never put runtime credentials in release archives. `/export_csv` backs up domain settings only; it does not include history, alert state, or shared caches. Its keyword/port cells use JSON when needed; ordinary comma-separated keyword input remains accepted.

To restore, stop every worker, bot and web process, retain the current database **and its sidecars together** in a rollback directory, place the verified backup at `DATABASE_PATH`, restore its matching web-secret/token/proxy/VirusTotal key and proxy files, and restore file ownership and mode 0600. Do not reuse stale WAL/SHM files with a restored database. Start with `doctor`, then restart web and the single scheduler. Do not overlay an old database while a process still has it open. RKN indexes can be rebuilt; a configured standalone WHOIS/IP-change database needs its own backup if retaining that state matters.

## Live check activity

The optional overview panel reads `/api/activity` every two seconds while enabled and
visible. It never starts probes. Lifecycle rows are shared through SQLite across web,
worker and bot; the table retains at most 1,000 rows per owner and the API returns the
latest 100. Cached and ephemeral probes do not create activity. Telemetry writes have
a short timeout and cannot prevent a monitoring probe when telemetry storage fails.
When a positive domain timeout is configured, a missing finish beyond that timeout
plus ten seconds is shown as interrupted, not as a successful response. Without an
execution deadline the panel waits for a completion without inferring interruption.
Stopping/restarting a worker can leave unfinished rows.

The domain-row overdue notice waits for two configured check intervals. Saved-result
freshness and scheduling still use the original interval.

VirusTotal keys and its dedicated proxy can be stored in Settings → VirusTotal. `VIRUSTOTAL_API_KEY` overrides
YAML `malware.vt_api_key`, which overrides the private saved file. Every probe reloads
the effective key. Missing configuration and missing passive reports remain UNKNOWN.

## Configuration and maintenance

- Use one scheduler per database: worker or scheduled bot. Command-only bot polling can coexist. Use one web process; manual-check and cold analytics build locks are process-local.
- Empty `TELEGRAM_ALLOWED_USER_IDS` intentionally permits everyone. Malformed nonempty values stop bot startup.
- Telegram proxy settings apply to Bot API replies, `getUpdates` polling and web connection checks. HTTP(S), SOCKS5 and Telegram SOCKS links are accepted. A nonempty `TELEGRAM_PROXY` overrides the private saved proxy; without either, standard HTTPX proxy environment variables still apply. The worker reloads changes between ticks; restart polling after a change. These settings are separate from HTTP-check proxies.
- Daily history cleanup uses `history.cleanup_time` in UTC. `retention_days: 0` removes history older than the current time; it does not disable cleanup. Weekly compaction runs on Sunday in UTC.
- Cleanup and compaction run in worker threads. Cancelling the scheduler does not interrupt a SQLite maintenance operation that has already started; allow it to finish before replacing the database.
- Per-domain `interval_minutes: 0` pauses scheduled checks. Manual checks remain available. Explicit zero latency/alert thresholds are preserved.
- `/history changes` finds transitions before applying the requested status filter, so recovery does not hide a later incident. It examines a bounded recent window of at most 1,000 rows; select a domain/check or increase `limit` (maximum 200) to inspect a more focused stream.
- Unknown YAML keys and invalid combinations are errors. `/cfg_set` and CSV imports validate overrides before saving; `/cfg_unset` also validates the settings that will be inherited.
- `http.proxy` (or the `http.proxies` scheme map) configures the common HTTP client. `defaults.proxy` and domain overrides select a separate client for HTTP status, keyword and defacement checks. External API calls retain the common client, except VirusTotal when its dedicated proxy is configured. Clearing a domain proxy returns to that common client; connection limits apply to mapped proxies too.
- `http.max_response_bytes` limits page downloads for HTTP status, keyword and defacement checks (default 8 MiB). Both downloaded and decoded bytes count across redirects. Oversized, incomplete or unsupported compressed bodies are unknown rather than inspected partially; an observed HTTP error status remains an error. Gzip and deflate are supported. This setting does not limit external feeds or reputation APIs.
- Invalid port banner regular expressions are rejected before saving. A storage read failure stops a probe rather than discarding the owner's overrides.
- IP-change state defaults to the main database and is separate for each owner and ad hoc scans. Set `ipchange.db_path` to retain a legacy `ipchange_cache.sqlite` baseline: each scope copies the old baseline once, preserving its timestamp, then updates its own state. The old baseline and file are never deleted automatically.
- RKN checks require a complete, dated Antifilter bundle or the bol-van fallback. Download, validation or freshness failures produce UNKNOWN and retain the previous index. Domain listings are Critical; shared-IP listings are Warning. The old Zapret-Info index is rebuilt automatically on upgrade, so allow time and disk space for the first refresh.

The monitoring process creates an additional latest-history index during its first initialization after upgrade. Allow free disk space and a short writer lock while it builds; a synthetic 4.36-million-row measurement used 151 MiB for this index. Web/setup and worker initialization apply additive migrations, including history provenance, workspace language and domain favorites. Existing accounts default to English, existing domains start without a favorite flag, and legacy history keeps its `legacy` source label. Back up large installations before upgrading, then run `doctor` and inspect a saved result.

VirusTotal is a passive lookup, not an active site scan. A missing/incomplete report is unknown. A clean verdict requires valid explicit zero detection counts and completed observations; positive malicious/suspicious counts remain visible. The upstream fields are documented in the [VirusTotal URL object reference](https://docs.virustotal.com/reference/url-object).

No live credentials, public-service probes, or real Telegram sends are needed for the offline test suite. A passing suite is not evidence of deployment or external-service availability.

## Upgrade and rollback rehearsal

Stop all three services and make a verified SQLite backup plus copies of all private
sidecar credentials before installing a release. Setup/web migrations add framework
tables and `history.source`; they do not rename monitoring tables or move owners.
Corrupt legacy overrides are retained and shown as errors, never silently reset.
On the domain history page choose **Recover domain settings** (or **Edit** in the
Overview), expand **Reset domain settings**, then choose **Reset all overrides**.
This keeps saved history and applies workspace defaults. If another editor changed
settings since the page was loaded, reset returns a conflict; reload before deciding
again. A read-only workspace cannot reset settings.
Existing installations with an owner account need migration/startup, not another setup.

After upgrade check `/healthz`, login, an existing domain/history, settings and the next
scheduled observation. For rollback stop all processes again, retain the failed state
with WAL/SHM sidecars for diagnosis, restore the pre-upgrade database/credentials and
install the previous release. Verify with `doctor` before restarting. Do not merely
downgrade code over a live migrated database. The release rehearsal used two owners with
identical domain names, corrupt overrides, legacy history, idempotent migrations and
both old-schema and current-schema restore; see the dated verification report.

## RKN refresh on small servers

Registry components are streamed to a private temporary directory beside the index,
then validated into a temporary SQLite index with a bounded page cache. Domain rows
and IP ranges are not collected into Python sets. A complete, dated bundle with the
expected distinct entry counts is published in one transaction; malformed, stale,
truncated or suspiciously reduced bundles leave the previous index intact. Allow
space for the downloads, staging index and the previous index during refresh.

The source's 150-second network deadline is separate from parsing/publication.
Cancellation drains an active disk operation before removing temporary files; it
does not start an overlapping fallback parser. The unchanged SQLite index remains
rebuildable cache, separate from monitoring history.

## Dedicated VirusTotal proxy switch

Settings provides a checkbox for VirusTotal's dedicated proxy. When enabled, enter
an HTTP(S) or SOCKS5 URL; an optional username/password can be included in that URL.
The secret input stays blank on subsequent visits: blank means retain the saved
address. Turning the checkbox off retains the saved address and forces VirusTotal
to use its normal connection on the next probe. Other checks' clients are unchanged.
The switch takes effect without restarting; environment/YAML still determine the
proxy address when configured, but an explicitly disabled switch suppresses it.

Keep `<database>.virustotal-proxy` and `<database>.virustotal-proxy-enabled` in
restricted backups alongside the API key. Existing installations without a switch
file keep their prior configured-proxy behavior.
