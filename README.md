# SiteWatcher

SiteWatcher monitors websites in a private browser workspace, with optional Telegram alerts and a revocable public status page. A web process and a monitoring worker share SQLite; no external database is needed.

Checks: HTTP status and latency, TLS certificate, ping, page keywords, defacement markers, RKN listing, IP changes, IP blocklists, TCP ports, WHOIS/RDAP, and passive VirusTotal reputation. RKN has two independent checks: **RKN domain blocking** (`rkn_domain`) reports Critical for a domain or parent-domain listing, while **RKN IP listing** (`rkn_ip`) reports Warning for a listed DNS-resolved IPv4 address, which may belong to shared hosting. Both use the same cached index from Antifilter, with bol-van/rulist as fallback; neither proves actual provider-level blocking. IPv6 is not checked. Legacy `checks.rkn_block` and `schedules.rkn_block` configure both checks unless explicit new keys override them; `rkn.check_ip: false` globally disables the IP check. Existing combined results remain in history as **Legacy RKN blocking** and are not reused by the new checks. CSV backups include separate columns and still accept the old format.

Expensive checks are off by default or run less often. Each Telegram user owns their own domain list and overrides.

## Quick start with Docker

Install Docker with the Compose plugin, then run these two commands from the checkout:

```bash
docker compose run --rm --build setup
docker compose up -d
```

Setup asks you to choose a username and hidden password. Open **http://127.0.0.1:8080**,
sign in and add your first domain. No `.env`, Telegram token or YAML editing is required.
The nonroot web and worker containers share `sitewatcher-data`; database, web secret
and optional Telegram connection survive restarts. The host port binds only to loopback.
Use `SITEWATCHER_PORT=8081` with both commands if port 8080 is occupied.

`docker compose logs -f web worker` shows service logs. Stop with `docker compose down`;
keep the volume (do not add `-v`). Back up before rebuilding/upgrading. For a standalone
probe, use `docker compose run --rm web sitewatcher scan example.com --only http_basic,tls_cert`.
The container always uses `/data/sitewatcher.db`.

After connecting Telegram in Settings, optional command polling starts with
`docker compose --profile telegram up -d`. This bot uses `--no-scheduler`; the worker
remains the sole scheduler. Restrict Telegram user IDs and pass optional Telegram proxy
settings through a local Compose override before enabling a private bot. A native
`sitewatcher bot` still runs the original combined bot/scheduler; stop the worker first,
or use `sitewatcher bot --no-scheduler` for command polling alongside it.

## Quick start with Python

Python 3.12 or newer is required.

```bash
python3.12 -m venv .venv
. .venv/bin/activate
pip install -e .
sitewatcher setup
sitewatcher web
# In a second terminal, activate the same environment and use the same working directory:
sitewatcher worker
```

The bot starts with built-in settings. An optional YAML file can be supplied with `--config config.yaml`; copy [the example](sitewatcher/data/config.yaml.example) and edit it. An explicitly specified but missing file causes an error. The `DATABASE_PATH` environment variable defaults to `./sitewatcher.db`. Its parent directory must exist. The process needs write access there and, when RKN is enabled, to the nearby `z_i_index.db` index.

Set `TELEGRAM_PROXY` for the bot connection. Set `http.proxy` in YAML for HTTP requests made by the checks. Set `TELEGRAM_ALERT_CHAT_ID` to send alerts to a fixed chat, otherwise they go to the user's most recent chat. VirusTotal needs `malware.vt_api_key` in YAML and the malware check enabled; its free-tier request limits are configurable. Protect that YAML file as a secret.

Unknown configuration keys, invalid thresholds, and malformed allowlists are rejected at startup. An empty `TELEGRAM_ALLOWED_USER_IDS` allows everyone; a private bot needs an explicit comma-separated list of positive user IDs. Domain overrides are validated before being saved. An explicit `0` keeps its documented meaning rather than selecting a default.

For optional colored console logs, install `pip install -e '.[rich]'` and set `logging.pretty.use_rich: true` in YAML.

## Bot commands

| Command | Purpose |
| --- | --- |
| `/add example.com` | Add domains with the short keyword and interval wizard. |
| `/add_domain example.com` | Add a domain immediately with defaults. |
| `/remove example.com`, `/remove_all`, `/list` | Manage your domains. |
| `/check example.com`, `/check_all` | Run checks; add `--force` to skip cached results. An unknown domain is checked without adding it or sending alerts. |
| `/status`, `/history` | Read saved results without running checks. |
| `/cfg example.com`, `/cfg_set`, `/cfg_unset` | View and change a domain's settings. |
| `/export_csv`, `/import_csv` | Back up and restore domains with overrides. |
| `/clear_cache` | Clear WHOIS and RKN caches. |
| `/stop_alerts`, `/start_alerts` | Toggle your alerts. |
| `/help` | Show detailed syntax in the bot. |

A per-domain `interval_minutes` override applies to all enabled checks for that domain. Set it to `0` to stop scheduled checks. Without an override, every check uses its own `schedules.<check>.interval_minutes` value. The scheduler wakes every minute by default; a larger `scheduler.interval_minutes` gives coarser timing. Manual checks can use cached history according to `cache_ttl_minutes`; scheduled checks run live when due.

## CLI

```bash
sitewatcher scan example.com --only http_basic,tls_cert
sitewatcher check_domain example.com --owner 123456789 --force
sitewatcher check_all --owner 123456789
sitewatcher doctor
sitewatcher doctor --json
```

`scan` does not add a domain, save monitoring history, or send alerts. Some checks maintain their own local caches. `check_domain` and `check_all` save results. Use `--config path/to/config.yaml` with any command.

`doctor` checks configuration, database schema/integrity and local permissions without initializing a database, running network checks, or contacting Telegram. Its exit code is `0` when the installation is ready and `1` when action is needed. JSON output contains credential presence flags, never their values. Web startup migrates storage additively; `--read-only` still requires owner authentication. A missing database with a writable parent is a valid fresh-install state for `doctor`.

## Local owner account

Create the local dashboard account on the server with `sitewatcher setup`. It prompts for a username and a hidden password twice; passwords must be at least 12 characters and pass Django's common/numeric/personal-value checks. A terminal with hidden input is required. Setup is local only: there is no public registration or email reset.

Without `--owner`, setup creates a fresh local monitoring identity without Telegram and does not adopt any existing Telegram history. To deliberately bind the initial account to an existing monitoring owner, use `sitewatcher setup --owner <owner_id>`. Setup refuses a second account and never rebinds an existing workspace.

For recovery, run `sitewatcher password` on the server. This resets the configured owner's password, clears its login lockout and invalidates existing authenticated sessions while preserving monitoring data. It requires no browser session and never displays the password. Browser password changes keep the current session and invalidate other sessions. Authentication uses database sessions with a 12-hour expiry and locks a username/client-address pair after five failures for 15 minutes; forwarded client-address headers are ignored.

## Unattended monitoring without Telegram

After `sitewatcher setup`, start automatic monitoring independently from the web process:

```bash
sitewatcher worker
# In a separate process, using the same DATABASE_PATH and YAML:
sitewatcher web --port 8080
```

The worker runs scheduled checks and UTC history cleanup without a Telegram token or update polling. If Telegram is configured, it uses the same destinations, incident retry and cooldown policy as the bot. Changes to stored domain settings and notification preferences take effect on later ticks. Startup warmup finishes before periodic work; paused domains remain idle. Only one scheduler may own a database: stop the scheduled bot before starting a worker, or disable the bot's scheduler for command-only polling. The shared lock is held until shutdown and released automatically after a crash.

Last checked timestamps, measurement ages and overdue states describe saved observations; the dashboard does not claim a worker is running. Keep a worker or scheduled bot running for automatic checks. Ctrl-C and service-manager SIGTERM close active resources cleanly. History cleanup runs once per UTC day while the worker is up, with a catch-up on startup if today's cleanup time has passed; normal retention and optional Sunday optimization still apply.

## Local web dashboard

Run this alongside a worker or bot, with the same `DATABASE_PATH` and YAML configuration:

```bash
sitewatcher web --port 8080
# Open http://127.0.0.1:8080
```

Sign in with the account created by `sitewatcher setup`. Each account sees only its
own domains and history. `--owner <owner_id>` verifies an existing workspace binding;
it never grants access to another owner.

### Domains and history

- Add one domain or up to 50 comma-separated domains with shared settings. The whole
  batch is validated before saving; an invalid or duplicate domain leaves it unsaved.
- Star a domain to keep it at the top. Within the favorite and ordinary groups,
  problems appear first. Favorites do not change monitoring settings.
- Hover or focus a Critical/Warning badge to see the affected checks, their diagnostics
  and individual observation times. Missing and overdue checks are identified explicitly.
- Open a domain for 24-hour, 7-day or 30-day HTTP history. Hover or focus a graph point
  for its time and response latency. Empty intervals remain empty.
- Search and status filters apply automatically; search waits briefly for typing to stop.
- Filter recent check history by date range, check and state. Changes apply automatically. Dates use the workspace
  timezone, include both selected days, and return the latest 100 matching records.
  These filters do not change the graph period.

**Successful checks** is the share of successful recorded HTTP checks among successful
and failed checks. Unknown observations are excluded; this is not continuous-time uptime.
The chart data table is also available without JavaScript. Current state, historical
percentages and manual/scheduled observation counts remain separate.

Use the icon buttons at the top of a domain page to edit, check, pause/resume or remove
it. Removal requires typed confirmation. **Check all domains now** is at the top of the
overview. Manual checks save fresh results without sending Telegram messages; the
worker evaluates saved state on its next tick. One manual run is allowed at a time in
the web process, with the configured per-domain timeout (120 seconds by default).

### Settings and notifications

**Settings → Language** switches between English (default) and Russian. The choice is
saved per account and remembered on the sign-in page. Browser language headers do not
override it. Public pages use their publisher's language. Probe diagnostics and API/CSV
identifiers retain their original format.

The workspace timezone defaults to `Europe/Moscow`; observations are stored in UTC.
The header's sun/switch/moon control remembers the chosen theme. Switching themes with
JavaScript preserves unsaved forms; native theme links work without JavaScript.

New domain forms prefill the check interval and show inherited values as **Default
(On/Off)** or numeric placeholders. Required keywords accept a comma-separated list
(quote phrases containing commas). TCP ports accept numbers and inclusive ranges such
as `1-1024, 2205`. Blank lists inherit defaults; `-` clears them. Saved probe options are
retained for ports kept in the list.

Settings reject stale edits rather than overwriting concurrent changes. Proxy
credentials are never redisplayed: keep, inherit, clear or set a new override. Clearing
a domain proxy returns to the common HTTP client, which can have its own proxy.
Private CSV backups may contain proxy credentials. Imports validate each row, skip
concurrently changed merge targets and report failures. Replace affects listed domains
only.

Telegram is optional. To enable it, save a BotFather token in **Settings → Advanced**,
open the bot and send `/start`, then choose **Find chats**, save a destination and use
**Send test notification**. Saving settings sends no message. Discovery does not consume
updates; a webhook or an active polling process can prevent discovery, so manual numeric
chat IDs remain available.

The token is stored beside the database as `<database-filename>.telegram-token` with
mode `0600`. `TELEGRAM_TOKEN` in the environment takes precedence. Restart a running bot
after changing its token; the worker reloads it at tick boundaries. Delivery uses
`alerts.chat_id` from YAML, then the owner's saved chat, then `TELEGRAM_ALERT_CHAT_ID`.
Settings shows the effective destination. Changing it does not change domain ownership
or historical data. Bot API calls use `TELEGRAM_PROXY` and a finite timeout.

### Public status

Sharing is off by default. In **Settings → Public status page**, select owned domains
and choose **Enable public status**. Copy the issued link immediately: it appears only
in that response. **Rotate link** revokes the old link; **Disable public status** revokes
all public access. An empty selection publishes an empty page.

The link grants read-only aggregates for selected domains: HTTP history, percentages,
response times and current freshness/paused state. It exposes no owner ID, private
domains, diagnostic messages, raw metrics or management actions. Append `data` to the
link for JSON. Responses use no-store, no-referrer and noindex headers; only the token's
SHA-256 digest is stored.

Keep public links private until you intend to share them, and rotate a link if exposed
accidentally. Application logs redact bearer paths and Uvicorn access logging is
disabled. A reverse proxy must also suppress or redact logs for `/status/`.

### Operating the panel

Keep one web process and one scheduler per database. `/healthz` checks database/schema
readability, not worker activity or site health. The overview and public pages can
refresh every minute; refresh pauses for a filter draft, open disclosure or status
popup. Edit/settings/login pages never refresh automatically.

For viewing only, use `sitewatcher web --read-only`. Monitoring and preference changes
are rejected; password changes, sessions and login-attempt tracking still write to the
database. History, private CSV downloads and theme switching remain available. Global
YAML, API credentials and scheduler configuration are deployment settings.

The server binds to IPv4 loopback by default. To use a remote installation, forward its
port from your computer:

```bash
ssh -N -L 8080:127.0.0.1:8080 your-server
```

Then open the same local URL. Port `0` selects an available port and prints its URL.
Owner routes require login even through a tunnel. Management forms use session/CSRF
protection and reject duplicate fields or bodies over 1 MiB. Back up the database and
its private `.web-secret`/`.telegram-token` files before upgrading; upgrades add workspace
language and domain favorite fields. Sessions remain valid across restarts when the
web secret is retained. See [operations and recovery](docs/operations.md).

## Run as a service

Install into a persistent directory and use an absolute `DATABASE_PATH`. A minimal systemd service uses `WorkingDirectory` to locate `.env` and the SQLite file:

```ini
[Unit]
Description=SiteWatcher monitoring worker
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=sitewatcher
WorkingDirectory=/opt/sitewatcher
ExecStart=/opt/sitewatcher/.venv/bin/sitewatcher worker
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Use a single bot instance against the database. Back up the SQLite database and your YAML and `.env` files. The RKN index can be rebuilt. Checks that query public services need network access; ping may require operating-system ICMP permissions.

Alert delivery failures leave the pending state available for the next scheduler tick. Worsening states and recovery bypass the repeat cooldown; repeated alerts at the same severity honor it. Missing or failed checks produce an unknown result rather than a clean bill of health. Recovery requires recent enabled checks.

The IP-change baseline lives in the main database by default, including Docker's persistent volume. Each owner and ad hoc scans have separate baselines. To retain an existing standalone baseline, set `ipchange.db_path` to its old path; each scope copies that legacy baseline once without modifying it. Otherwise the first run establishes a new baseline. WHOIS/RDAP uses the configured database and can use port 43 for supported Russian TLDs when `whois.fallback_whois_if_missing_expiry` is enabled. DNSBL coverage depends on resolver responses; lookup failures are reported as unknown.

See [operations and recovery](docs/operations.md) for backups, troubleshooting and upgrade verification.

## Development

```bash
pip install -e '.[dev]'
ruff check sitewatcher tests
pytest
```

GitHub Actions runs these checks on Python 3.12, 3.13 and 3.14 for pushes and pull requests. Tests use temporary databases and do not require a bot token or live network.

## Deployment and supported storage

Use Python 3.12–3.14 with SQLite **3.35 or newer and JSON1**. `sitewatcher doctor`
reports the linked SQLite version and analytics support. Reports use at most 120
occupied buckets per period; missing intervals remain unknown. A process-local cache
is capped at 8 entries/4 MiB/60 seconds and serializes cold builds. This installation
supports one owner and one web process; use measurements before adding more processes.

For HTTPS behind a trusted local reverse proxy, set `SITEWATCHER_WEB_ALLOWED_HOSTS`
to explicit names, `SITEWATCHER_WEB_HTTPS=1` for secure session/CSRF cookies, and
`SITEWATCHER_WEB_TRUST_PROXY=1` only when that proxy replaces `X-Forwarded-Proto`.
The proxy must suppress access logs for `/status/` bearer URLs. Keep the application
port private. `SITEWATCHER_WEB_BIND=0.0.0.0` is explicit container-internal binding;
Compose still maps only host loopback. Native launch defaults to `127.0.0.1`.
See [operations and rollback](docs/operations.md) and the
[release verification](docs/verification-owner-public-dashboard-2026-10-22.md).

To update interface translations, edit `sitewatcher/webapp/locale/ru/LC_MESSAGES/django.po` and run `python -m django compilemessages -l ru`. GNU gettext tools are needed only when editing catalogs; compiled translations are included in the package and container.

RKN sources: `https://antifilter.download/list/domains.lst`, `ip.lst` and `subnet.lst` are the primary bundle. The fallback uses `reestr_hostname.txt`, `reestr_ipban4.txt` and `reestr_resolved_ip4.txt` from one pinned commit of `bol-van/rulist`. These include exact IPv4 addresses and CIDR networks; no approximate `/24` summary lists are used. A broken, incomplete or stale primary bundle triggers the fallback as a whole. Results retain provider, source update time and GitHub revision where applicable.

`rkn.cache_ttl_hours` controls index refresh (default 12). `rkn.max_source_age_hours` bounds the declared source age (default 168 hours / 7 days): Antifilter uses the oldest component Last-Modified date; bol-van uses the oldest last-change timestamp of the three required files at its pinned commit (an unrelated newer repository commit cannot refresh old lists). Missing, future or expired timestamps cannot confirm a clean result. This is a conservative file-age check, not proof that every registry entry is current. If both providers fail validation, the previous index stays intact and the check reports UNKNOWN. The legacy index is rebuilt automatically; old z-i results are retained in history but bypassed for current status, cache, notifications and scheduling. Legacy `rkn.source: z-i`/`rkn.z_i_url` settings are accepted for configuration compatibility but never contact Zapret-Info.
