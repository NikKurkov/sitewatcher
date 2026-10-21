# Operations and recovery

## Verify an installation

Use the same working directory, `DATABASE_PATH`, configuration and account as the bot:

```bash
sitewatcher doctor --json
sitewatcher check_all --owner 123456789 --only http_basic,tls_cert
sitewatcher web --owner 123456789 --port 8080
```

The second command runs real probes and saves results; omit it when only diagnosing local storage. `doctor` makes no network calls. Its successful result does not verify a Telegram token, proxy, public API, or firewall. Check a saved result and an authorized Telegram interaction separately when deploying.

The web view reads existing state and requires an explicit owner. `/healthz` returns 503 for an unavailable/incompatible database. It can still return 200 when monitored domains are down. The server has no write routes or remote bind option.

For a Linux Docker installation, run a separate temporary web process using the bot's data volume and host networking:

```bash
docker build -t sitewatcher:local .
docker run --rm --network host \
  --volumes-from "$(docker compose ps -q sitewatcher)" \
  -e DATABASE_PATH=/data/sitewatcher.db \
  sitewatcher:local sitewatcher web --owner 123456789 --port 8080
```

This leaves the bot running and binds the viewer to host loopback. Supply the same `--config` path if the bot uses custom YAML; that file must also be mounted into the viewer. Host networking here requires Linux. For another host, use the SSH tunnel shown in the README.

Docker images include application code and packaged examples only. Private YAML, environment files, SQLite files/sidecars and compressed caches are excluded from the build context. Mount custom configuration at runtime rather than baking it into an image.

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

Keep `.env` and custom YAML separately with restrictive permissions. `/export_csv` backs up domain settings only; it does not include history, alert state, or shared caches. Its keyword/port cells use JSON when needed; ordinary comma-separated keyword input remains accepted.

To restore, stop the bot and viewer, retain the current database **and its sidecars together** in a rollback directory, place the verified backup at `DATABASE_PATH`, and restore file ownership. Start with `doctor`, then restart the bot. Do not overlay an old database while a process still has it open. RKN indexes can be rebuilt; a configured standalone WHOIS/IP-change database needs its own backup if retaining that state matters.

## Configuration and maintenance

- Use one bot instance per database. The optional viewer is a separate read-only process.
- Empty `TELEGRAM_ALLOWED_USER_IDS` intentionally permits everyone. Malformed nonempty values stop bot startup.
- `TELEGRAM_PROXY` applies to both Bot API replies and `getUpdates` polling. It is separate from the HTTP-check proxy settings.
- Daily history cleanup uses `history.cleanup_time` in UTC. `retention_days: 0` removes history older than the current time; it does not disable cleanup. Weekly compaction runs on Sunday in UTC.
- Cleanup and compaction run in worker threads. Cancelling the scheduler does not interrupt a SQLite maintenance operation that has already started; allow it to finish before replacing the database.
- Per-domain `interval_minutes: 0` pauses scheduled checks. Manual checks remain available. Explicit zero latency/alert thresholds are preserved.
- Unknown YAML keys and invalid combinations are errors. `/cfg_set` and CSV imports validate overrides before saving; `/cfg_unset` also validates the settings that will be inherited.
- `http.proxy` (or the `http.proxies` scheme map) configures the common HTTP client. `defaults.proxy` and domain overrides select a separate client for HTTP status, keyword and defacement checks. External API calls retain the common client. Clearing a domain proxy returns to that common client; connection limits apply to mapped proxies too.
- `http.max_response_bytes` limits page downloads for HTTP status, keyword and defacement checks (default 8 MiB). Both downloaded and decoded bytes count across redirects. Oversized, incomplete or unsupported compressed bodies are unknown rather than inspected partially; an observed HTTP error status remains an error. Gzip and deflate are supported. This setting does not limit external feeds or reputation APIs.
- Invalid port banner regular expressions are rejected before saving. A storage read failure stops a probe rather than discarding the owner's overrides.
- IP-change state defaults to the main database and is separate for each owner and ad hoc scans. Set `ipchange.db_path` to retain a legacy `ipchange_cache.sqlite` baseline: each scope copies the old baseline once, preserving its timestamp, then updates its own state. The old baseline and file are never deleted automatically.
- RKN refresh errors and incomplete partition sets produce an unknown result. The partition list follows the upstream feed layout and may need an update if that layout changes.

The monitoring process creates an additional latest-history index during its first initialization after upgrade. Allow free disk space and a short writer lock while it builds; a synthetic 4.36-million-row measurement used 151 MiB for this index. The viewer never creates it and retains a compatible query for older databases. Back up large installations before upgrading, then run `doctor` and inspect a saved result.

VirusTotal is a passive lookup, not an active site scan. A missing/incomplete report is unknown. A clean verdict requires valid explicit zero detection counts and completed observations; positive malicious/suspicious counts remain visible. The upstream fields are documented in the [VirusTotal URL object reference](https://docs.virustotal.com/reference/url-object).

No live credentials, public-service probes, or real Telegram sends are needed for the offline test suite. A passing suite is not evidence of deployment or external-service availability.
