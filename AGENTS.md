# Repository Guidelines

## Project Structure & Module Organization

SiteWatcher is a Python 3.12+ asynchronous website monitor with a Telegram interface and SQLite storage. Keep it deployable as one process without external services beyond the APIs it queries.

- `sitewatcher/main.py`: CLI entry point.
- `sitewatcher/checks/`: monitoring checks implementing `BaseCheck.run()` and returning `CheckOutcome`.
- `sitewatcher/dispatcher.py`: check orchestration; `config.py`: settings; `storage.py`: persistence.
- `sitewatcher/bot/`: Telegram application, scheduling, alerts, and command handlers.
- `sitewatcher/utils/`: shared helpers; `sitewatcher/data/`: packaged configuration example, dashboard HTML/CSS, and defacement markers.
- `tests/`: pytest suite. `docs/`: design notes and implementation plans. Root PNG files are documentation assets.

## Build, Test, and Development Commands

Create and activate a virtual environment before installing dependencies:

```bash
python3.12 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
ruff check sitewatcher tests
pytest
python -m sitewatcher.main --help
```

Copy `.env.example` to `.env`, configure the token, and run `sitewatcher bot`. For a standalone check, use `sitewatcher scan example.com --only http_basic,tls_cert`. Build and start the container with `docker compose up -d --build`; validate Compose configuration with `docker compose config --quiet`.

## Coding Style & Naming Conventions

Use four-space indentation, snake_case for modules/functions/variables, PascalCase for classes, and uppercase constants. Follow nearby type annotations and async patterns. Ruff configures a 100-character line length and lint rules `F` and `B`; no formatter is configured. Keep check logic in `checks/` and Telegram interaction in handlers.

## Testing Guidelines

Use `tests/test_<module>.py` and descriptive `test_<behavior>` functions. Mock network clients and Telegram calls; use temporary SQLite databases. Existing async tests use `asyncio.run()`. Tests must work without live network access or bot credentials. Add regression coverage for behavior changes, particularly owner isolation, scheduling, caching, and alerts. No numeric coverage threshold is configured. CI runs Ruff and pytest on Python 3.12, 3.13 and 3.14, plus CLI and container smoke checks.

## Commit & Pull Request Guidelines

Recent commits use prefixes such as `feat:`, `refactor:`, `docs:`, and `chore:`; follow that style with a concise imperative summary. Keep changes focused. PRs should explain the problem, resulting behavior, and validation commands; link relevant issues and include sample output or screenshots for user-visible changes. Update README/configuration examples when behavior or settings change.

## Security & Configuration

Never commit or print tokens, private monitoring data, `.env`, secret YAML, or runtime databases. Preserve `owner_id` boundaries throughout storage and dispatch. Run one bot instance per database; back up persistent data before storage changes. Docker stores persistent data under `/data`.
