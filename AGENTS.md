# Repository Guidelines

SiteWatcher is a Python 3.12+ asynchronous website monitor with an authenticated Django
workspace, optional Telegram interface, standalone worker and shared SQLite storage.

## Structure

`sitewatcher/main.py` provides CLI commands. `checks/` implements `BaseCheck.run()` and
returns `CheckOutcome`; `dispatcher.py` orchestrates probes. `config.py` validates settings,
`storage.py` owns monitoring persistence, and `webapp/` contains authentication, migrations,
owner/public views, templates and static assets. `worker.py`, `scheduler.py` and
`maintenance.py` run unattended monitoring; `bot/` contains Telegram handlers and alerts.
`web_actions.py` shares domain operations. `data/` holds packaged examples and markers.
Tests live in `tests/`; design and operating notes live in `docs/`.

## Commands

Create a virtual environment before installing dependencies:

```bash
python3.12 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
ruff check sitewatcher tests
pytest
python -m sitewatcher.main --help
```

Local startup: `sitewatcher setup`, then `sitewatcher web` and `sitewatcher worker` in
separate terminals using the same database. Compose startup needs no `.env`:
`docker compose run --rm --build setup`, then `docker compose up -d`.
Validate with `docker compose config --quiet`. Telegram is optional; `bot --no-scheduler`
allows command polling beside a worker. Never run two schedulers for one database.

## Style and tests

Use four spaces, snake_case functions/modules, PascalCase classes and uppercase constants.
Follow existing type annotations and async patterns. Ruff checks F/B rules with a
100-character line length; no formatter is configured. Keep check logic out of handlers.
Use `tests/test_<module>.py`, descriptive test names, temporary databases and mocked
network/Telegram calls. Existing async tests use `asyncio.run()`. Add regression coverage
for owner isolation, scheduling, caching, authentication and alerts. CI tests Python
3.12/3.13/3.14 plus CLI and nonroot container/package smoke checks.

## Changes and security

Use focused `feat:`, `fix:`, `refactor:`, `docs:` or `chore:` commits. PRs explain the
problem, resulting behavior and validation; include screenshots for UI changes. Update
README/configuration examples when behavior changes. Preserve owner_id boundaries.
Back up persistent data before migrations. Never commit or print tokens, `.env`, secret
YAML, runtime databases or private monitoring data. Docker persists data under `/data`.
