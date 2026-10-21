# Web management verification — 2026-10-22

## Scope

Requested: browser management alongside Telegram, plus a persistent Day/Night switch.
Runtime checkpoint: `e759910`; base: `6524676`. Work completed on
`feat/web-management`. All fixtures, uploads and monitoring results were synthetic;
no production deployment or real Telegram sends were performed.

## Delivered behavior

- Add domains, edit all per-domain override fields, retain inheritance and explicit zero values, pause/resume, reset overrides and inspect recent history.
- Remove a domain only after typing its name on a separate confirmation page.
- Run live checks for one/all owned domains. One manual batch runs per web process; other requests remain responsive. Results cannot restore a deleted domain.
- Toggle owner notification preference and import/export the existing Telegram CSV format. Valid rows import independently; concurrent merge conflicts are skipped.
- Day/Night/System themes persist in a browser cookie. A 14-line optional native script switches without losing drafts. Native forms and theme links also work without JavaScript.
- Explicit `--read-only` retains viewing-only operation. No runtime dependency was added.

## HTTP and storage boundaries

The owner is fixed at startup. Mutations require POST, a strict same-origin Host/
Origin combination and a per-process CSRF token. Form bodies are capped at 1 MiB;
duplicate fields, conflicting sources and ambiguous framing are rejected. GET/HEAD
never mutate monitoring rows. Normal startup initializes storage; read-only startup
does not create a missing database. Startup failures are sanitized.

Creation detects duplicates inside the write transaction. Edit forms carry a
revision checked inside the same transaction; rejected forms retain the stale
revision until explicitly reloaded. Proxy input is never repopulated. CSV files
may contain credentials and are deliberate private backups; failed imports do not
redisplay their contents and preserve the selected mode.

Browser testing caught Chromium sending Origin:null under Referrer-Policy:
no-referrer. The policy is now same-origin: same-origin forms retain their origin,
while external destinations receive no referrer. No Origin:null exception was added.

## Automated checks

| Environment | Result |
| --- | --- |
| Python 3.12.12 | 527 passed |
| Python 3.13.12 | 527 passed |
| Python 3.14.8 | 527 passed |
| Installed wheel, Python 3.14.8 / PTB 22.4 | 527 passed |
| Installed Docker package, Python 3.12.14 / SQLite 3.46.1 | 527 passed |

Ruff and whitespace checks passed. Docker tests ran with no external network,
a read-only root filesystem and temporary writable storage. All 58 package/resource
files matched between source, wheel, installed image and image source directory.
A fresh wheel installation outside the checkout completed create/edit/delete,
asset serving, diagnostics, owner isolation and SIGTERM shutdown. Disposable Compose
storage survived two starts/stops; both stops exited cleanly as nonroot UID 10001.
Synthetic private configuration/database/cache canaries were excluded from the image.

Regressions cover CSRF and Unicode input, foreign/missing origins, owner isolation,
malformed forms, native multipart CSV, stale-edit resubmission, concurrent CSV
changes, manual-run contention and deletion during a check. Independent review
identified stale-revision retry and lost CSV mode; both were reproduced and fixed.

## Chromium verification

Native forms completed create/edit/pause/resume/delete, owner notification changes,
history and export. Native file upload imported a CSV and its fixture was removed.
Light/dark management pages and the dark inventory were checked at 1440, 390 and
320 CSS pixels with no horizontal overflow. System preference and explicit theme
overrides worked. Changing theme preserved unsaved domain/timeout fields; the
choice survived navigation. With scripts disabled, native add/delete and theme
fallback still worked. Screenshots contain example domains only.

The complete form scenario ran at `8539da0`; native CSV upload and the final demo
readback ran at `e759910`. The later change only added shared CSV revision guards
and their regression; final installed/source suites cover that checkpoint.

## Operating limits and handoff

The web workspace has no separate login. Loopback or a trusted SSH tunnel is the
access boundary. It must not be exposed publicly. Browser management works without
a Telegram token; scheduled checks and notification delivery still require the bot.
Global YAML, credentials and the global scheduler switch remain deployment settings.
Resuming a domain does not enable a globally disabled scheduler.

The demonstration at `http://127.0.0.1:18080` uses a separate synthetic database and
fixed owner 7. Final readback confirmed five example domains, management add/delete,
dark theme and health. The repository's default database remains absent.

The feature's portable patch is based on `6524676`; the earlier reliability archive
is retained separately. The new artifact directory contains the wheel, exact file
manifest, patch proof, checksums, browser scripts/screenshots and test logs.
See [operations](operations.md) for configuration, backups and the read-only fallback.
