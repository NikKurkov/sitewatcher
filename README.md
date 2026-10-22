# SiteWatcher

SiteWatcher monitors websites in a private browser workspace, with optional Telegram alerts and a revocable public status page. A web process and a monitoring worker share SQLite; no external database is needed.

Checks: HTTP status and latency, TLS certificate, ping, page keywords, defacement markers, RKN listing, IP changes, IP blocklists, TCP ports, WHOIS/RDAP, and passive VirusTotal reputation. Expensive checks are off by default or run less often. Each Telegram user owns their own domain list and overrides.

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

Sign in with the local account created by `sitewatcher setup`. The dashboard derives its owner exclusively from the authenticated account. Optional `--owner <owner_id>` only verifies the existing workspace binding; it never grants access. The dashboard manages only that owner's domains: add a domain, edit its checks/settings, pause/resume, inspect history, reset overrides or remove it with typed confirmation. Use **Check now** on a domain history page or **More actions → Check all domains now** on the overview; results are saved without sending Telegram messages from the web process. One manual run is allowed at a time using a process-local lock; run a single web process. Probes bypass cache and use the configured per-domain timeout (120 seconds by default). The worker or bot continues scheduled monitoring and evaluates saved state on its next tick. Workspace settings configure timezone and owner notifications; CSV import/export uses the same format as Telegram. Search/filter saved results or read `/api/status` as JSON. Overdue results are marked explicitly, paused domains retain their saved state, and timestamps use the workspace timezone (Europe/Moscow by default), with a timezone label next to observation times. Overview and public status refresh every minute when JavaScript is enabled, with a pause checkbox and a manual Refresh now link. Refresh waits while the tab is hidden, a filter draft is being edited or a disclosure is open. Edit/settings/login forms never refresh automatically. `/healthz` performs a minimal read-only database/schema check (503 on failure); it exposes no monitoring data and does not certify worker activity or site health.

Open **Settings** (`/settings` or `/workspace`) to change the display timezone (a native list of locations, default `Europe/Moscow`), enable Telegram notifications, and choose a destination. Stored observations remain in UTC. Telegram is optional: add domains and run checks without a token. For Telegram, create a bot with BotFather, save its token in **Advanced**, open your bot and send `/start`, then use **Find chats**, explicitly save a destination, and **Send test notification**. Discovery only reads recent updates without acknowledging them; existing polling or a webhook can prevent it, so a manual numeric chat ID remains available. Saving settings never sends a message. Test sends one explicit message to the effective destination even if regular notifications are disabled.

The connection token is stored beside the database as `<database-filename>.telegram-token`, atomically with mode `0600`; keep it private in backups alongside `<database-filename>.web-secret`. A nonempty `TELEGRAM_TOKEN` environment variable overrides that file. An already running bot must be restarted after a token change. The worker reloads the private token file at tick boundaries without restarting or resetting alert state. YAML and environment changes require a process restart. Delivery keeps its existing priority: `alerts.chat_id` in YAML, then the owner’s saved chat, then `TELEGRAM_ALERT_CHAT_ID`. Settings shows the effective destination and warns when an installation override wins; changing a destination never changes the owner ID or historical domain ownership. Bot API calls honor `TELEGRAM_PROXY` and have a finite timeout.

Settings forms preserve inherited values and reject stale edits instead of overwriting concurrent changes. Proxy credentials are never redisplayed; choose keep, inherit, clear override or set a new value. Clearing the domain override returns to the common HTTP client, which can have its own proxy. CSV downloads are private configuration backups and can contain proxy credentials. Imports apply valid rows independently, skip concurrently changed merge targets and report skipped rows; replace affects listed domains only.

Use the **sun / switch / moon** control in the header. The browser remembers the choice; switching preserves unsaved input when JavaScript is enabled. Native forms and theme links also work without JavaScript. New domains added through the browser start with website availability and certificate checks enabled; optional checks are off and can be selected under **Advanced checks and settings**. Existing domains keep their settings.

The overview puts problems first, with a table on desktop and the same facts in cards on phones. Open a domain for **24h / 7d / 30d** HTTP history and response times. **Successful checks** means successful recorded HTTP checks divided by successful plus failed checks; unknown observations are excluded, and this is not continuous-time uptime. Empty chart intervals stay empty. The chart data table and recent check history are available in native disclosures, including without JavaScript. Manual, scheduled, and legacy observation counts remain visible.

Public sharing is off by default. In **Settings → Public status page**, select owned domains and choose **Enable public status**. Copy the newly issued link immediately; it is shown only in that response and cannot be recovered later. **Rotate link** creates a new link and revokes the old one immediately; **Disable public status** revokes access. Saving an empty selection deliberately publishes an empty page. A public link grants read-only HTTP aggregates for the selected domains, with 24h / 7d / 30d history, successful and failed check percentages, and native response-time/chart-data disclosures. Current service status reuses the monitoring freshness policy: overdue HTTP observations show no recent data, and paused services are labelled explicitly; historical percentages remain unchanged. It exposes no owner ID, diagnostic messages, raw metrics, private domains, or management actions. The public JSON companion is the same link with `data` appended. Public pages and JSON are served with no-store, no-referrer and noindex headers. Only the SHA-256 token digest is stored; keep the full link private and rotate it if shared accidentally. Uvicorn access logging is disabled, and Django public-path/error diagnostics are redacted. If publishing behind a reverse proxy, disable or redact its access/error URL logs for `/status/` as well; application redaction cannot protect upstream logs. Use HTTPS for remote access.

For viewing only, run `sitewatcher web --read-only`. Monitoring and preference mutations are then rejected; password changes remain available, while authenticated viewing, history, private CSV backup download and the theme switch remain usable. Authentication still writes sessions and login-attempt records. Global YAML, API credentials and scheduler configuration remain deployment settings.

The server binds to IPv4 loopback by default. For a Python installation on another Linux host, keep the server running there and forward its port from your computer:

```bash
ssh -N -L 8080:127.0.0.1:8080 your-server
```

Then open the same local URL. Port `0` selects an available port and prints the actual URL. No Telegram token is required for the dashboard. Owner monitoring pages and APIs require the configured owner login, including over an SSH tunnel; explicitly enabled public links grant only the selected aggregate view. Changes require POST forms protected by Django session and CSRF checks. Forms reject duplicate fields and bodies larger than 1 MiB. Browser sessions and CSRF tokens remain valid across restarts using the persistent private web secret. Keep CSV backups private: they can include proxy credentials.

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
