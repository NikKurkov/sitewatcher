# SiteWatcher simplification

SiteWatcher remains a single-process Python 3.12+ Telegram bot and CLI with SQLite. Preserve every check, per-user domains and settings, CSV, history, and alert behavior. Existing database and YAML compatibility is not required. Bot-facing text is English.

## Runtime

Use one typed configuration with useful defaults when no YAML file is supplied. Explicit YAML paths fail clearly when missing. Resolve domain settings without mutating shared defaults; owner overrides apply to that owner's domain only. A dispatcher owns an HTTP client and runs selected checks with bounded concurrency, optional cache and timeout. The CLI and Telegram bot share this flow. Invalid check names and domains fail clearly.

## Scheduling and alerts

A periodic tick considers each enabled check's interval, or a positive per-domain interval override. Zero domain interval disables periodic checks. Recent history determines due checks. Startup warmup establishes a baseline without alerts; subsequent ticks run only due checks, persist results, and feed the existing alert policy. Configured scheduler disabled means no monitoring jobs. Avoid repeated SQLite reads where practical.

## Tests and delivery

Tests run without Telegram credentials or live network. Cover configuration isolation, CLI startup and execution, scheduled due selection, storage isolation, and HTTP behavior. CI runs lint and tests on Linux with Python 3.12 and 3.13. Document setup and commands accurately, and record changes in CHANGELOG.md. Open a PR to main; no deployment automation.
