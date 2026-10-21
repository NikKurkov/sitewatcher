# SiteWatcher

SiteWatcher monitors domains and reports problems through a Telegram bot. It runs as one Python process on Linux, stores users, domains, results, and settings in SQLite, and needs no external database or deployment service.

Checks: HTTP status and latency, TLS certificate, ping, page keywords, defacement markers, RKN listing, IP changes, IP blocklists, TCP ports, WHOIS/RDAP, and passive VirusTotal reputation. Expensive checks are off by default or run less often. Each Telegram user owns their own domain list and overrides.

## Quick start with Docker

Install Docker with the Compose plugin, then run:

```bash
cp .env.example .env
# Set TELEGRAM_TOKEN in .env. Set TELEGRAM_ALLOWED_USER_IDS for a private bot.
docker compose up -d --build
docker compose logs -f sitewatcher
```

The bot runs as a single container. Its SQLite database and RKN index live in the `sitewatcher-data` volume and survive container restarts and rebuilds. Stop it with `docker compose down` (keep the volume). To test a site without starting the bot, run `docker compose run --rm sitewatcher sitewatcher scan example.com --only http_basic,tls_cert`. Docker uses `/data/sitewatcher.db` even if `.env` sets a different `DATABASE_PATH`.

To run the image directly without Compose, build it locally and mount a named volume for the database:

```bash
docker build -t sitewatcher:local .
docker run -d --name sitewatcher --restart unless-stopped \
  --env-file .env -e DATABASE_PATH=/data/sitewatcher.db \
  -v sitewatcher-data:/data sitewatcher:local
docker logs -f sitewatcher
```

Stop and remove that container with `docker stop sitewatcher && docker rm sitewatcher`; the volume remains available for the next run. Choose one launch method for a single bot instance: Compose gives its volume a project-specific name, so the two methods do not share a database automatically.

## Quick start with Python

Python 3.12 or newer is required.

```bash
python3.12 -m venv .venv
. .venv/bin/activate
pip install -e .
cp .env.example .env
# Set TELEGRAM_TOKEN in .env. Set TELEGRAM_ALLOWED_USER_IDS for a private bot.
sitewatcher bot
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

`doctor` checks configuration, database schema/integrity and local permissions without initializing a database, running network checks, or contacting Telegram. Its exit code is `0` when the installation is ready and `1` when action is needed. JSON output contains credential presence flags, never their values. Normal web mode initializes storage for its owner; `--read-only` requires an existing database. A missing database with a writable parent is a valid fresh-install state for `doctor`.

## Local owner account

Create the local dashboard account on the server with `sitewatcher setup`. It prompts for a username and a hidden password twice; passwords must be at least 12 characters and pass Django's common/numeric/personal-value checks. A terminal with hidden input is required. Setup is local only: there is no public registration or email reset.

Without `--owner`, setup creates a fresh local monitoring identity without Telegram and does not adopt any existing Telegram history. To deliberately bind the initial account to an existing monitoring owner, use `sitewatcher setup --owner <owner_id>`. Setup refuses a second account and never rebinds an existing workspace.

For recovery, run `sitewatcher password` on the server. This resets the configured owner's password, clears its login lockout and invalidates existing authenticated sessions while preserving monitoring data. It requires no browser session and never displays the password. Browser password changes keep the current session and invalidate other sessions. Authentication uses database sessions with a 12-hour expiry and locks a username/client-address pair after five failures for 15 minutes; forwarded client-address headers are ignored.

## Local web dashboard

Run this alongside the bot, with the same `DATABASE_PATH` and YAML configuration:

```bash
sitewatcher web --port 8080
# Open http://127.0.0.1:8080
```

Sign in with the local account created by `sitewatcher setup`. The dashboard derives its owner exclusively from the authenticated account. Optional `--owner <owner_id>` only verifies the existing workspace binding; it never grants access. The dashboard manages only that owner's domains: add a domain, edit its checks/settings, pause/resume, inspect history, reset overrides or remove it with typed confirmation. Use **Check now** on a domain history page or **More actions → Check all domains now** on the overview; results are saved without sending Telegram messages from the web process. One manual run is allowed at a time using a process-local lock; run a single web process. Probes bypass cache and use the configured per-domain timeout (120 seconds by default). The bot continues scheduled monitoring and evaluates saved state on its next tick. Workspace settings toggle owner notifications; CSV import/export uses the same format as Telegram. Search/filter saved results or read `/api/status` as JSON. Overdue results are marked explicitly, paused domains retain their saved state, and timestamps use the workspace timezone (Europe/Moscow by default), with a timezone label next to observation times. Pages do not refresh automatically; reload when you want a fresh snapshot. `/healthz` is a public process-health endpoint without monitoring data; it does not certify that monitored sites are healthy.

Settings forms preserve inherited values and reject stale edits instead of overwriting concurrent changes. Proxy credentials are never redisplayed; choose keep, inherit, clear override or set a new value. Clearing the domain override returns to the common HTTP client, which can have its own proxy. CSV downloads are private configuration backups and can contain proxy credentials. Imports apply valid rows independently, skip concurrently changed merge targets and report skipped rows; replace affects listed domains only.

Use the **sun / switch / moon** control in the header. The browser remembers the choice; switching preserves unsaved input when JavaScript is enabled. Native forms and theme links also work without JavaScript. New domains added through the browser start with website availability and certificate checks enabled; optional checks are off and can be selected under **Advanced checks and settings**. Existing domains keep their settings.

The overview puts problems first, with a table on desktop and the same facts in cards on phones. Open a domain for **24h / 7d / 30d** HTTP history and response times. **Successful checks** means successful recorded HTTP checks divided by successful plus failed checks; unknown observations are excluded, and this is not continuous-time uptime. Empty chart intervals stay empty. The chart data table and recent check history are available in native disclosures, including without JavaScript. Manual, scheduled, and legacy observation counts remain visible.

For viewing only, run `sitewatcher web --read-only`. Monitoring mutations are then rejected, while authenticated viewing, history, private CSV backup download and the theme switch remain usable. Authentication still writes sessions and login-attempt records. Global YAML, API credentials and scheduler configuration remain deployment settings.

The server binds to IPv4 loopback only. For a Python installation on another Linux host, keep the server running there and forward its port from your computer:

```bash
ssh -N -L 8080:127.0.0.1:8080 your-server
```

Then open the same local URL. Port `0` selects an available port and prints the actual URL. No Telegram token is required for the dashboard. Monitoring pages and APIs require the configured owner login, including over an SSH tunnel. Changes require POST forms protected by Django session and CSRF checks. Forms reject duplicate fields and bodies larger than 1 MiB. Browser sessions and CSRF tokens remain valid across restarts using the persistent private web secret. Keep CSV backups private: they can include proxy credentials.

## Run as a service

Install into a persistent directory and use an absolute `DATABASE_PATH`. A minimal systemd service uses `WorkingDirectory` to locate `.env` and the SQLite file:

```ini
[Unit]
Description=SiteWatcher Telegram bot
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=sitewatcher
WorkingDirectory=/opt/sitewatcher
ExecStart=/opt/sitewatcher/.venv/bin/sitewatcher bot
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
