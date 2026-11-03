# SiteWatcher reliability design

The user authorized autonomous end-to-end improvement on 2026-10-21, with no approval pauses. Preserve the existing Python 3.12+ single-process Telegram/SQLite product and the completed Ponytail refactor (checkpoint `594437d`). Fix reproduced operational defects before adding features. Do not deploy, send real Telegram messages, access production databases, or introduce service dependencies.

## Required behavior

- Database writes are atomic, settings can actually be unset, and per-owner state remains isolated under concurrent commands.
- A normal authorized bot interaction remembers its alert destination. Busy guards release reliably. Long HTML replies arrive as valid bounded messages rather than disappearing.
- TLS wildcard validation does not accept multiple subdomain levels. DNS state survives container replacement. WHOIS options that are exposed in configuration work and retain error visibility.
- Domain settings are validated consistently at CLI/bot/CSV entry points. Invalid input cannot poison future scheduled runs. Explicit zero values retain their documented meaning.
- Every due check runs at its configured interval. A failed alert delivery remains eligible for retry; cooldowns cannot silently discard a worsening incident or recovery. Scheduled/manual results must not corrupt one another's state.
- Operational diagnostics expose configuration/database health without credentials. Documentation and installed-package/container checks describe actual working commands.

## Implementation constraints

Use standard-library features and installed dependencies. New behavior earns an offline regression test. Tests use temporary SQLite files and fake network/Telegram boundaries. Run the full suite, Ruff, and package smoke checks on Python 3.12 and 3.13. Keep local commits reviewable; preserve the original baseline and all authorized prior work. Record outcomes and any deliberate limitations in the implementation plan and final report.
