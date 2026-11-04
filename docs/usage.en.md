# SiteWatcher user guide

[← About the app](../README.md) · [Русский](usage.ru.md) · **English**

## Find what you need

- [Install with Docker](#install-with-docker) or [run with Python](#run-with-python).
- [Add websites and understand the results](#everyday-use).
- [Watch checks and trace a route](#signal-map-and-network-routes).
- [Connect Telegram](#telegram) or [set up VirusTotal](#virustotal).
- [Choose additional checks](#additional-checks).
- [Share a status page](#public-status-page).
- [Set up remote access](#remote-access-and-accounts).
- [Back up, update and recover](#data-backups-and-updates).
- [Use the command line](#command-line-and-diagnostics) or [work on the code](#development).

## Install with Docker

Install [Docker with Compose](https://docs.docker.com/get-started/get-docker/), download the project and open its folder in a terminal. For a new installation:

```bash
docker compose run --rm --build setup
docker compose up -d
```

Choose a username and password when `setup` asks. Open **http://127.0.0.1:8080** and sign in. A password must be at least 12 characters long and pass the on-screen checks.

No `.env` file, Telegram account or external service key is required to start. Containers run as a regular user. By default, only the local computer can reach the dashboard.

If port 8080 is busy, set `SITEWATCHER_PORT=8081` when starting Compose. The data stays in the `sitewatcher-data` volume when services restart.

Useful commands:

```bash
# Read logs; Ctrl-C stops following them, not the app.
docker compose logs -f web worker

# Stop the app and keep its data.
docker compose down

# Check a website once without adding it.
docker compose run --rm web sitewatcher scan example.com --only http_basic,tls_cert
```

**Do not add `-v` to `docker compose down` if you want to keep your data.**

## Run with Python

Use Python 3.12–3.14 and SQLite 3.35 or newer with JSON1 support.

```bash
python3.12 -m venv .venv
. .venv/bin/activate
pip install -e .
sitewatcher setup
sitewatcher web
```

In a second terminal, in the same folder:

```bash
. .venv/bin/activate
sitewatcher worker
```

Open **http://127.0.0.1:8080**. The web process shows the dashboard; the worker runs scheduled checks and sends configured alerts. Both must use the same database and configuration. The computer and worker must remain running for monitoring to continue.

The default database is `./sitewatcher.db`. For a permanent installation, set `DATABASE_PATH` to an absolute path in a writable directory. Docker uses `/data/sitewatcher.db`. Install the system package `traceroute` if you want route diagnostics outside Docker.

Built-in defaults are enough to begin. To change them, copy the [example configuration](../sitewatcher/data/config.yaml.example) and pass `--config config.yaml` to both processes. Unknown settings, invalid values and an explicitly requested missing configuration file stop startup with an error.

## Everyday use

### Add a website

1. Click **Add domain**, the **+** icon at the top.
2. Enter an address, such as `example.com`, `http://example.com` or `example.com/catalog/`.
3. Keep the suggested settings or choose an interval, then save.

An address without a protocol uses HTTPS. Availability, keyword and defacement checks request the chosen address, including its path. DNS, certificate, registration, RKN and route checks use the hostname.

You can add up to 50 comma-separated addresses with shared settings. The entire list is validated before anything is added. There is one monitor per hostname: use **Edit** to change its protocol or page rather than adding the same host again.

On the edit page, choose HTTP or HTTPS on the left and enter the hostname and optional path on the right. You can rename a domain. Settings, history, favorites, list order and public-page selection are retained. Old host results remain historical; its cached verdicts, route and host-specific state are not reused for the new name. A conflicting or outdated edit is rejected.

### Read the results

| Result | Meaning |
| --- | --- |
| OK | The check completed without detecting a problem. |
| Warning | Something needs attention, such as a slow response or missing information. Hover over the badge for details. |
| Critical | A check detected a serious problem. The badge and history explain which one. |
| No data / unknown | There is not enough information to decide, for example because a provider did not respond. |
| Paused | Scheduled checks are stopped. You can still run a manual check. |

Hover over a warning or critical badge, or focus it with the keyboard, to see the checks and their times. Click the row, website name or its arrow to reveal current checks and the HTTP chart together. The graph spans the full width above the check results, which use two columns on larger screens and one on phones. Several domains can stay open for comparison. Full history is linked inside the disclosure; edit, check, pause, favorites and reorder remain available outside. Without JavaScript, the name links directly to full history. [Inline details](screenshots/overview-inline-details.png). Chart points show their value on hover or focus.

History can be filtered by dates, check and result. Dates include both selected days in your workspace timezone. The results list shows up to 100 matching entries; these filters do not change the chart's selected period. The success percentage describes saved HTTP checks, not a continuous measurement of uptime.

### Find and arrange websites

The overview summary sits between separators beside the SiteWatcher logo and shows the age of the latest saved check result. Hover over that age for the exact date and time. The history period is in the table header, to the right of Last checked. On narrow screens the summary wraps below the logo. Previews: [desktop](screenshots/overview-compact-header-desktop.png), [mobile](screenshots/overview-compact-header-mobile.png).

Search is beside the **Domain** heading. The **Status** heading opens a filter; changes apply automatically. The 24-hour, 7-day and 30-day choices sit in the list header.

Click a star to keep a website in favorites. Drag its handle to move it within the favorites or regular group. Keyboard users can focus the handle and press **Alt + ↑ / ↓**. Order survives page reloads. When a filter is active, hidden rows retain their positions. A failed save restores the previous order.

The top icons add a domain, check all domains, open the signal map, refresh and control automatic refresh. Row icons edit, check and pause/resume a single site. Hover over an icon to read its name.

### Adjust checks

English is the default interface language; choose Russian in **Settings** if needed. The default timezone is `Europe/Moscow`; saved timestamps use UTC. Theme and display choices are remembered.

Inherited options show **Default** and their current value. Blank fields inherit settings. Use `0` as the interval to pause scheduled monitoring.

- **Required keywords:** a comma-separated list, for example `welcome, shop`. Quote a phrase containing a comma: `"Hello, world"`. Use `-` to clear the list.
- **TCP ports:** numbers or ranges, for example `1-1024, 2205`. Valid ports are 1–65535. Use `-` to clear the list.
- **Latency thresholds:** choose when a response becomes slow or critically slow. The critical threshold cannot be lower than the warning threshold.

A domain interval overrides the schedule for all its checks. Without one, individual `schedules.<check>.interval_minutes` values apply. The scheduler normally wakes once per minute. The overdue notice appears after two check intervals without a new result; this does not extend result freshness.

Manual checks save results but do not send Telegram messages directly. The worker evaluates saved state on its next cycle. One manual batch runs at a time in the web process.

CSV export/import carries domain settings and the HTTP address. Exported proxy settings may include credentials: keep the file private. Import validates each row, reports errors and leaves domains absent from the file alone. It is not a backup of your history.

## Signal map and network routes

The signal icon opens the optional map. It shows the saved check events as moving requests and replies. A console below it shows actual timestamps, check names, results and durations. Recorded replays are labeled. Animation speed, pause and fullscreen affect the picture, not the monitoring schedule.

All domains have a place in the map. Click a dot to pin a site. Polling stops when the map is closed or the tab is hidden. Reduced-motion preferences leave a static view and the log. Opening the map does not start a check.

For a selected domain, click **Request route** to let the worker run a UDP traceroute. This enables hourly refreshes; you can turn them off and retain the last result. Click **Route view** to display its hops. The whole chain fits in the scene, including on narrow screens.

The scene shows the selected hop's IP, hostname when available and round-trip time. Hover to inspect another hop, click to pin it, or select a hop from the full list with the keyboard. Short routes also have labels beneath the dots.

Routes are limited to 24 hops and about 30 seconds. A silent router appears as `*`; it does not make the website unavailable. This is the forward UDP route from the worker, which may differ from an HTTPS path. The return animation is illustrative. Internal routes are private; the public map only shows published HTTP events.

## Telegram

Telegram is optional. In **Settings → Advanced settings**:

1. Save the token issued by BotFather.
2. Save a Telegram proxy if required.
3. Open your bot and send `/start`, then click **Find chats** in the dashboard.
4. Save the destination and click **Send test notification**.

Saving settings does not send a message. The test button sends one separate message. Chat discovery reads recent updates without consuming them; an active polling bot or webhook may prevent discovery. You can enter the numeric chat ID manually instead.

Supported proxy formats:

```text
http://proxy.example:8080
https://proxy.example:8443
socks5://proxy.example:1080
https://t.me/socks?server=proxy.example&port=1080
tg://socks?server=proxy.example&port=1080
```

Credentials can be included as `user:password@` or as the SOCKS link's `user` and `pass` parameters. Encode special characters as URL components. Links are converted locally; SiteWatcher does not open `t.me`. `socks5h` is accepted. MTProto links with `secret` are not supported by the bot's HTTPS Bot API client.

Nonempty `TELEGRAM_TOKEN` and `TELEGRAM_PROXY` environment values override saved settings. Without a dedicated Telegram proxy, the standard `HTTPS_PROXY`/`ALL_PROXY` environment behavior applies. The worker reloads Telegram settings between cycles; restart a running polling bot after changing them.

The alert destination is chosen in this order: YAML `alerts.chat_id`, the owner's saved chat, then `TELEGRAM_ALERT_CHAT_ID`. Changing it does not change who owns the monitoring data.

To enable bot commands beside the Compose worker:

```bash
docker compose --profile telegram up -d
```

This bot uses `--no-scheduler`. **Never run a scheduled bot and worker for the same database.** For a private bot, set `TELEGRAM_ALLOWED_USER_IDS` in a local Compose override. An empty allowlist permits everyone; invalid nonempty values stop bot startup.

| Command | Purpose |
| --- | --- |
| `/add`, `/add_domain` | Add domains with the wizard or defaults. |
| `/remove`, `/remove_all`, `/list` | Manage your domain list. |
| `/check`, `/check_all` | Run checks; `--force` bypasses cache. An unknown domain is not added. |
| `/status`, `/history` | Read saved results. |
| `/cfg`, `/cfg_set`, `/cfg_unset` | Read or change a domain's settings. |
| `/export_csv`, `/import_csv` | Export or import domain settings. |
| `/clear_cache` | Clear WHOIS and RKN caches. |
| `/stop_alerts`, `/start_alerts` | Disable or enable your alerts. |
| `/help` | Show full syntax. |

## VirusTotal

Enable the malware check for a domain and save an API key in **Settings → VirusTotal**. The eye button reveals the key only after an explicit authenticated request. Viewing it does not replace the saved key. Blank retains it; the separate checkbox removes it.

Key priority is `VIRUSTOTAL_API_KEY` → YAML `malware.vt_api_key` → saved key. VirusTotal only reads existing reports for the HTTPS home URL. It does not submit a scan. A missing key, missing report, invalid response, quota, network failure or proxy error remains an unknown result, not a clean verdict. An absent report is informational and does not raise the overall warning or appear in the Telegram problem summary. Provider and configuration errors still require attention.

Enable **Use a proxy for VirusTotal** in the same settings section to show the HTTP(S)/SOCKS5 address field. This proxy applies only to VirusTotal. Turning the checkbox off retains the saved address and credentials; other checks keep their existing connections. Proxy priority is `VIRUSTOTAL_PROXY` → YAML `malware.vt_proxy` → saved proxy. Without one, the common HTTP client is used. Blank retains a saved proxy; the separate removal checkbox deletes it. Both the key and proxy are reloaded on the next check. The saved proxy address, including credentials, is visible in owner settings after reloading the page.

In Docker, `127.0.0.1` means the container. A proxy must be reachable from it. If your proxy listens only on the Linux host's loopback interface, you can opt into host networking:

```bash
docker compose -f compose.yaml -f compose.host-network.yaml config --quiet
docker compose -f compose.yaml -f compose.host-network.yaml up -d --build
```

This shares the host network with web and worker, removes published-port mappings and keeps the web server bound to `127.0.0.1:${SITEWATCHER_PORT:-8080}`. TLS verification remains enabled. To remember this choice, copy `compose.host-network.yaml` to the ignored local `compose.override.yaml`. To return to the bridge network, remove that local override and run `docker compose -f compose.yaml up -d`. See [Compose merge rules](https://docs.docker.com/reference/compose-file/merge/).

## Additional checks

Enable only the checks you need in the domain settings. They can have different schedules.

| Check | What it looks at |
| --- | --- |
| Website availability | HTTP result and response time at the chosen URL. |
| TLS certificate | The hostname's certificate and expiry date. |
| Ping | Whether the host responds to the network probe. |
| Required keywords | Whether the page contains your chosen words. |
| Defacement markers | Known signs of a changed or defaced page. |
| Domain registration | Registration/expiry information from WHOIS or RDAP. |
| IP change | Whether the resolved address changed from its saved baseline. |
| IP blocklists | DNS-based reputation lists. |
| TCP ports | Whether selected network ports answer. |
| RKN domain blocking | Whether the domain or a parent domain appears in the source lists; a match is Critical. |
| RKN IP listing | Whether the resolved IPv4 appears in the lists; a match is Warning because shared hosting may be affected. |
| VirusTotal | Existing external reputation reports; an API key is required. |

RKN uses a complete, dated Antifilter bundle first and bol-van as fallback. These are source-list checks, not a test of access from every internet provider. IPv6 is not checked here. The index cache defaults to 12 hours; source files may be at most 168 hours old by default. Missing, future or stale dates do not establish a clean result. A failed refresh keeps the previous index and returns unknown when a clean result cannot be confirmed.

Legacy `checks.rkn_block` and `schedules.rkn_block` configure both split checks unless the new keys are explicit. `rkn.check_ip: false` disables the IP check. Legacy Zapret-Info settings are accepted for migration, but that source is no longer fetched.

WHOIS/RDAP availability depends on the zone; supported Russian zones can fall back to port 43. DNSBL depends on DNS replies. IP-change baselines are separate for each owner and ad hoc scans. To import a legacy standalone baseline once per scope, set `ipchange.db_path`; the old file is retained.

## Public status page

Enable publication in **Settings** and select domains. The persistent public address defaults to `/status`; change it in the public-page settings. The footer opens that address. Changing the address removes the old path, and disabling publication closes it. This is a publicly accessible page, not a secret URL. An additional private link can still be issued and rotated; that token is shown once and only its hash is stored. The page shares the selected sites' HTTP history, response times and scoped HTTP events, plus the latest status and observation time of every enabled check. Missing results are UNKNOWN and overdue observations are marked. The default theme is dark; a visitor's saved choice takes priority. It has no monitoring controls and does not expose private domains, raw diagnostics, internal routes or the owner ID.

The public page uses the same compact header and domain-list layout as the owner workspace. Rows start closed and disclose check statuses plus the HTTP chart. A green HTTP badge means HTTP availability only; other check notices are shown separately. Previews: [desktop](screenshots/public-unified-desktop.png), [mobile](screenshots/public-unified-mobile.png), [expanded](screenshots/public-inline-details.png).

Automatic refresh retains open domains, nested chart data, scroll and keyboard focus, including across period and filter navigation. Reading an open domain does not stop refresh; focused input, unsaved input and dragging defer it. State is scoped to the account/page or public address. Without JavaScript, owner history links and public native disclosures remain usable.

The public map has its own saved on/off setting. Changing the selected domains is reflected on its next poll. Disable publication to close both addresses, or rotate the additional private link to revoke only that token. Treat that private link as a bearer credential; configure reverse-proxy logs to omit or mask `/status/` paths.

## Remote access and accounts

The dashboard requires login. There is no public sign-up or email-based password reset. If you are bringing existing Telegram monitoring into the web dashboard, choose that owner deliberately with `sitewatcher setup --owner <owner_id>`. Setup without an owner ID creates a fresh monitoring identity. The web command's `--owner` option only checks the account binding; it does not bypass login. The default session lasts 12 hours; five failed attempts for the same username/client pair trigger a 15-minute login block.

To reset access on the server:

```bash
sitewatcher password
```

This changes the password and ends existing sessions without deleting monitoring data. Changing a password in Settings keeps the current session and ends the others.

For private access to a remote installation, use an SSH tunnel:

```bash
ssh -N -L 8080:127.0.0.1:8080 your-server
```

Open the same local URL in your browser. For an HTTPS reverse proxy, set explicit `SITEWATCHER_WEB_ALLOWED_HOSTS`, enable `SITEWATCHER_WEB_HTTPS=1`, and set `SITEWATCHER_WEB_TRUST_PROXY=1` only when the trusted proxy rewrites `X-Forwarded-Proto`. Keep the application port private. Compose's internal `0.0.0.0` bind does not make its default host mapping public.

`sitewatcher web --read-only` prevents monitoring/settings changes while retaining login, password recovery and private exports. Sessions and login-attempt bookkeeping still write to the database.

## Data, backups and updates

Docker data is in `/data`, backed by `sitewatcher-data`. A Python installation uses `DATABASE_PATH`, or `./sitewatcher.db` if unset. Keep these matching private sidecars as well as the database:

- `<database>.web-secret`
- `<database>.telegram-token`
- `<database>.telegram-proxy`
- `<database>.virustotal-key`
- `<database>.virustotal-proxy-enabled`
- `<database>.virustotal-proxy`

Also retain custom YAML and `.env` files. Credential files require mode `0600`. Backups and CSV exports may contain secrets; do not put them in Git or release archives.

Use SQLite's backup API for a live database, not a lone copy that omits its WAL. The [operations guide](operations.md#back-up-and-restore) has a ready-to-use backup command and full restore procedure. For a coordinated full backup, stop web, worker and optional bot before copying the volume and credentials. RKN indexes can be rebuilt; standalone legacy state may need its own backup.

After making a backup, update a Git-based Docker installation from the project folder:

```bash
git pull --ff-only
docker compose up -d --build
```

If you installed from ZIP, extract the new version and copy its contents into the same project folder, retaining local settings and data files. Keep the folder name: it determines the Compose project and data-volume selection. Then run `docker compose up -d --build`.

Do not rerun account setup for an existing installation. Check login, an existing site's history and a new scheduled result after updating. Restore matching database/sidecars with all processes stopped if a rollback is needed; see [operations and recovery](operations.md).

One web process and one scheduler should use a database. Compose's optional bot is command-only. The worker runs monitoring and cleanup without Telegram; when configured, it also sends alerts. Delivery errors are retried. Recovery needs fresh successful results from the enabled checks.

History cleanup runs daily in UTC with catch-up at startup; weekly compaction runs on Sunday. `retention_days: 0` removes records older than the current time rather than disabling cleanup. Allow an in-progress maintenance operation to finish before replacing a database.

Logs normally go to the console; use `docker compose logs`. If file logging is enabled, `logging.file` supports rotation by size or time. Console/Docker log retention is controlled by the host or Docker logging settings.

For systemd, run web and worker as separate services under an unprivileged user, with a fixed working directory and the same absolute `DATABASE_PATH`. For example, a worker installed under `/opt/sitewatcher` can use:

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

Set the same absolute `DATABASE_PATH` in each service's environment. Create the service user and give it access to the installation and data directories first.

## Command line and diagnostics

```bash
sitewatcher scan example.com --only http_basic,tls_cert
sitewatcher check_domain example.com --owner 123456789 --force
sitewatcher check_all --owner 123456789
sitewatcher doctor
sitewatcher doctor --json
```

`scan` neither adds a monitor nor saves its monitoring history or sends alerts; individual checks may maintain a cache. `check_domain` and `check_all` save results. Use `--config path/to/config.yaml` consistently when needed.

`doctor` checks configuration, SQLite integrity/schema and permissions without network requests or creating a database. Exit code 0 means ready; 1 means something needs attention. Secret values are not returned. A successful `/healthz` checks local web/database readiness, not worker activity or monitored-site health.

## Development

Create the virtual environment first, then:

```bash
pip install -e '.[dev]'
ruff check sitewatcher tests
pytest
node --check sitewatcher/webapp/static/sitewatcher/theme.js
node tests/test_web_controls.cjs
node tests/test_live_activity.cjs
node tests/test_route_view.cjs
node tests/test_key_visibility.cjs
python -m sitewatcher.main --help
docker compose config --quiet
```

CI covers Python 3.12, 3.13 and 3.14, JavaScript, installed-package smoke checks and the nonroot container. Tests use temporary databases, mocks and local servers, not live Telegram credentials or providers.

Russian translations are in `sitewatcher/webapp/locale/ru/LC_MESSAGES/django.po`. After edits, run `python -m django compilemessages -l ru`. GNU gettext is needed to regenerate catalogs; compiled translations are shipped.

The existing [brand kit](../assets/brand/README.txt) contains light/dark logos and icons. Development and historical verification notes remain in [operations](operations.md) and the dated reports beside it.
