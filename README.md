# SiteWatcher

SiteWatcher monitors domains and reports problems through a Telegram bot, with an optional web control panel. The bot runs as one Python process on Linux; the panel runs as a separate optional process. They share users, domains, results, and settings in SQLite and need no external database or deployment service.

Checks: HTTP status and latency, TLS certificate, ping, page keywords, defacement markers, RKN listing, IP changes, IP blocklists, TCP ports, WHOIS/RDAP, and passive VirusTotal reputation. Expensive checks are off by default or run less often. Each Telegram user owns their own domain list and overrides.

## Quick start with Docker

Install Docker with the Compose plugin, then run:

```bash
cp .env.example .env
# Set TELEGRAM_TOKEN in .env. Set TELEGRAM_ALLOWED_USER_IDS for a private bot.
docker compose up -d --build
docker compose logs -f sitewatcher
```

The bot runs as a single container. Its SQLite database, optional YAML configuration, and RKN index live in the `sitewatcher-data` volume and survive container restarts and rebuilds. Stop it with `docker compose down` (keep the volume). To test a site without starting the bot, run `docker compose run --rm sitewatcher sitewatcher scan example.com --only http_basic,tls_cert`. Docker uses `/data/sitewatcher.db` even if `.env` sets a different `DATABASE_PATH`.

## Optional web panel

The web panel serves one owner. Set `WEB_OWNER_ID` to that owner's Telegram user ID and add `WEB_PASSWORD_HASH` and `WEB_SESSION_SECRET` to `.env`:

```bash
docker compose run --rm sitewatcher sitewatcher hash-password
openssl rand -hex 32
```

The first command prompts for a password and prints a scrypt hash; put that hash in `WEB_PASSWORD_HASH`. Put the second command's output in `WEB_SESSION_SECRET`. Then start both services:

```bash
docker compose --profile web up -d --build
```

Open `http://127.0.0.1:8000` locally. For remote access, put an HTTPS reverse proxy in front of `127.0.0.1:8000` and set `WEB_COOKIE_SECURE=true` in `.env`; keep port 8000 bound to loopback. For example, a Caddy site can use `reverse_proxy 127.0.0.1:8000` under your HTTPS hostname. Keep `.env` private, and back up the shared volume. The panel and bot share SQLite and `/data/config.yaml`; the file is optional until you save global settings. Domain overrides take effect immediately, while changes to global YAML settings require `docker compose restart sitewatcher` to update the bot. Starting Compose without `--profile web` runs only the bot.

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

The bot starts with built-in settings. An optional YAML file can be supplied with `--config config.yaml` or `SITEWATCHER_CONFIG`; copy [the example](sitewatcher/data/config.yaml.example) and edit it. A missing environment-selected file uses built-in defaults, while an explicitly specified but missing `--config` file causes an error. The `DATABASE_PATH` environment variable defaults to `./sitewatcher.db`. Its parent directory must exist. The process needs write access there and, when RKN is enabled, to the nearby `z_i_index.db` index.

Set `TELEGRAM_PROXY` for the bot connection. Set `http.proxy` in YAML for HTTP requests made by the checks. Set `TELEGRAM_ALERT_CHAT_ID` to send alerts to a fixed chat, otherwise they go to the user's most recent chat. VirusTotal needs `malware.vt_api_key` in YAML and the malware check enabled; its free-tier request limits are configurable. Protect that YAML file as a secret.

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
```

`scan` does not add a domain, save monitoring history, or send alerts. Some checks maintain their own local caches. `check_domain` and `check_all` save results. Use `--config path/to/config.yaml` with any command.

For a Python installation of the web panel, install `pip install -e '.[web]'`, set the three `WEB_*` credentials above, and run `uvicorn sitewatcher.web.app:create_app --factory --host 127.0.0.1 --port 8000`. Point the bot and web process at the same `DATABASE_PATH` and `SITEWATCHER_CONFIG`.

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

## Development

```bash
pip install -e '.[dev]'
ruff check sitewatcher tests
pytest
```

GitHub Actions runs these checks on Python 3.12 and 3.13 for pushes and pull requests. Tests use temporary databases and do not require a bot token or live network.
