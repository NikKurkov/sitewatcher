# Owner Workspace and Public Status Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver an approachable authenticated monitoring workspace and a separate read-only public status page, with honest history charts and unattended monitoring.

**Architecture:** Replace the native HTTP layer with a Django application using server-rendered HTML and native forms. Preserve existing monitoring tables and domain/check logic; Django manages accounts, sessions and workspace preferences in the same SQLite file. One separately supervised scheduler serves both the web experience and optional Telegram delivery.

**Tech Stack:** Python 3.12–3.14, Django 5.2 LTS (>=5.2.8,<5.3; install the latest compatible patch), Uvicorn ASGI, SQLite, existing HTTPX/Pydantic/PTB; django-axes database-backed login throttling; pytest-django as a development dependency. Native SVG/HTML/CSS charts, locally packaged assets, no frontend build system.

**Spec:** `docs/superpowers/specs/2026-10-22-owner-public-dashboard-design.md` (approved by the user).

## Global Constraints

- Single-owner deployment, about 20 domains, 30-day charts, Telegram notifications.
- All interface text is English; default timezone Europe/Moscow; timestamps stored as UTC.
- Preserve the sun / switch / moon theme control, without a System option.
- Public sharing disabled by default; visitors can only read selected stored results.
- Preserve existing monitoring engine, validation, Telegram commands and SQLite tables.
- No React, Redis, Celery, PostgreSQL or external font/CDN requirement.
- Stay loopback-only by default; no external deployment or firewall changes.
- Preserve the already-authorized uncommitted theme-toggle changes.
- Every implementation task follows RED/GREEN verification and ends with a focused commit.
- Never print secrets, private monitoring payloads, passwords or active share links in reports.

## Review Focus

1. Installed wheel started outside the checkout must find templates/assets and the same persistent database; test in Tasks 1 and 10.
2. Two owners using the same domain must remain isolated, including guessed IDs and public graph requests; test in Tasks 3, 6 and 7.
3. Missing measurements, redirects, slow successful HTTP responses and corrupt legacy JSON must not fabricate downtime or 100% success; test in Task 4.
4. Repeated restart, concurrent launch and Telegram failure must not duplicate schedules or mark failed delivery as sent; test in Tasks 8 and 9.
5. Phone touch, keyboard-only operation and timezone boundaries must work without relying on hover, colour or JavaScript; test in Tasks 5, 6 and 10.

## File and interface map

- `sitewatcher/webapp/`: Django settings/bootstrap, URLs, owner views, forms, middleware, models and migrations. Split views by responsibility: accounts, workspace/domains, public status.
- `sitewatcher/webapp/templates/sitewatcher/`: base, login, overview, domain detail/edit, settings, public status and form-error partials.
- `sitewatcher/webapp/static/sitewatcher/`: CSS and small theme/progressive-enhancement scripts; no inline scripts or remote assets.
- `sitewatcher/webapp/analytics.py`: bounded owner-scoped history reads and safe presentation DTOs; no HTTP or writes.
- `sitewatcher/scheduler.py`: shared monitoring tick and callback interfaces extracted from `bot/jobs.py`.
- `sitewatcher/worker.py`, `scheduler_lock.py`: independent loop, process ownership and graceful shutdown.
- `sitewatcher/web.py`: CLI startup adapter for Django/Uvicorn; remove superseded request parsing after parity is verified.
- Existing `storage.py`, `web_actions.py`, `dispatcher.py`, bot handlers and CSV validation remain shared rather than duplicated.
- Tests: new `tests/test_webapp_*.py`, `test_analytics.py`, `test_worker.py`, `test_scheduler_lock.py`; adapt legacy HTTP tests to the authenticated contract, retaining security assertions.

## Phase A — Authenticated owner workspace

### Task 1: Bootable, packaged Django application and safe schema initialization

**Files:** Modify `pyproject.toml`, `sitewatcher/web.py`, `sitewatcher/main.py`; create `sitewatcher/webapp/{__init__,apps,settings,asgi,urls,bootstrap}.py`, templates/static directories and `tests/test_webapp_bootstrap.py`.

**Interfaces:** `bootstrap.configure_web(cfg: AppConfig, *, read_only: bool = False) -> None`; `bootstrap.migrate_web_database() -> None`; `web.run_web(cfg, owner_id, port=8080, *, read_only=False) -> None` remains the CLI adapter. `create_server()` is a legacy internal testing hook and may be replaced after its HTTP guarantees have equivalent tests.

- [ ] Write failing tests: Django starts with `DEBUG=False`; `/healthz` discloses no rows or settings; unknown hosts fail; the configured database matches `storage.DEFAULT_DB`; installing tables preserves pre-existing owners/domains/history. Package loader finds templates and assets outside the checkout.
- [ ] Run `pytest tests/test_webapp_bootstrap.py -q`; confirm tests fail for absent application.
- [ ] Add dependencies and a synchronous-view Django ASGI configuration. Use a persistent random secret in a mode-0600 file adjacent to the database, created atomically without overwriting; allow an explicit deployment secret. No secrets in generated HTML or error responses. Disable Uvicorn access logging to avoid recording public bearer URLs.
- [ ] Serve packaged static assets with an explicit allowlisted asset route, independent of `DEBUG`/collectstatic. Set CSP, frame denial and content-type protection. Default allowed hosts are loopback, not wildcard; trusted remote host/proxy configuration is explicit.
- [ ] Add pytest-django configuration and a fixture aligning the raw storage connection to Django's temporary on-disk database; transaction-enabled tests are required where raw sqlite connections write. Keep existing non-Django tests isolated.
- [ ] Run focused tests, Ruff and package build; commit `feat: bootstrap packaged Django web application`.

### Task 2: Interactive owner setup and framework authentication

**Files:** Create `webapp/models.py`, `webapp/migrations/0001_initial.py`, `webapp/accounts.py`, `webapp/forms.py`, login/password templates and `tests/test_webapp_auth.py`; modify bootstrap, URLs and CLI.

**Interfaces:** `Workspace` fields: one-to-one Django `user`, unique positive `owner_id`, `timezone='Europe/Moscow'`, public-page fields introduced in Task 7. `accounts.setup_owner(*, owner_id: int | None = None) -> None`; CLI `sitewatcher setup [--owner ID]` and `sitewatcher password`. `accounts.require_workspace(request) -> Workspace` denies unmapped accounts.

- [ ] RED: anonymous owner pages redirect to login, owner APIs return 401 JSON, valid login rotates the session, logout requires POST, CSRF failures return 403, password change invalidates other sessions, unmapped users cannot use legacy monitoring owners.
- [ ] RED: setup refuses a second owner, rejects binding to another account, prompts with hidden password entry/validation, and reset never needs a browser session or prints the password. Fresh setup may create a local numeric owner identity without Telegram.
- [ ] Implement Django LoginView, AuthenticationForm, PasswordChangeView and database sessions (12-hour expiry). Bind the mapping server-side. No public registration or email reset flow.
- [ ] Configure django-axes: lock after 5 failed attempts per username/client-address pair for 15 minutes, generic authentication errors, no password storage, no forwarded-client-IP trust by default. Test lock/recovery and forged proxy headers.
- [ ] Run `pytest tests/test_webapp_auth.py tests/test_webapp_bootstrap.py -q`; commit `feat: add owner setup and authenticated sessions`.

### Task 3: Protected management routes over existing domain operations

**Files:** Create `webapp/domains.py`; extend forms/URLs; modify `web_actions.py` only for reusable validation; create `tests/test_webapp_domains.py`; adapt `tests/test_web_management.py` security coverage.

**Interfaces:** Routes `/`, `/domains/new`, `/domains/edit`, `/domains/history`, `/domains/delete`, `/domains/check`, `/workspace`, `/import`, `/export.csv`, `/api/status`; owner derived exclusively from `require_workspace`. `domains.run_manual_checks(cfg: AppConfig, owner_id: int, names: list[str]) -> None` wraps the existing dispatcher path.

- [ ] RED: logged-in CRUD, pause/resume/reset, history, CSV and notifications work; GET/HEAD do not mutate monitoring data; cross-owner domain guesses and submitted owner IDs fail; read-only startup rejects every monitoring mutation.
- [ ] RED: stale edit and CSV conflicts retain existing atomic compare-and-swap semantics; validation retains drafts without redisplaying secrets; deletion cannot resurrect through a concurrent manual check.
- [ ] Implement Django form adapters calling `web_actions`/storage functions. Preserve bounded payload/file sizes and duplicate-field rejection. Protected CSV remains an explicit private backup download.
- [ ] Manual checks use one nonblocking process-local lock and existing timeout, `use_cache=False`, `create_missing=False`; web requests do not send incident notifications. Keep the lock ceiling documented; single web process is the supported local launch.
- [ ] Port HTTP contract tests instead of preserving unauthenticated legacy mutation routes. Run domain, CSV, owner-isolation and existing storage tests; commit `feat: protect owner monitoring management`.

## Phase B — Readable history and redesigned interfaces

### Task 4: Availability observations and bounded analytics

**Files:** Create `webapp/analytics.py`, `tests/test_analytics.py`; modify `storage.py` and measurement callers in web/CLI/bot paths; add narrowly scoped storage migration for history provenance.

**Interfaces:** `storage.save_histories(..., source: str = 'legacy')` accepts `legacy`, `scheduled`, `manual`; skip cached items when recording new observations. `analytics.domain_report(owner_id: int, domain: str, *, days: int, timezone: str) -> dict` and `analytics.overview_report(owner_id: int, *, days: int, timezone: str) -> dict`; allowed days `{1,7,30}`. DTOs contain only safe scalar/status/chart values.

- [ ] RED: HTTP 200/302-to-200 is available, final 503 and structured connection failures are unavailable, slow successful HTTP remains available, certificate warnings do not alter HTTP availability, corrupt/unknown JSON stays unknown, no observations returns percentage `None` rather than 100.
- [ ] RED: count only classified uncached HTTP observations in `successful / (successful + failed) * 100`; identify legacy/manual source; no history interpolation through gaps. Unknown samples remain visible separately. Only allowlisted numeric latency metrics enter graphs; errors' elapsed timeout duration is not a successful-response latency.
- [ ] Add `source` with a transactional, idempotent additive migration defaulting old rows to legacy. Stamp call sites accurately; preserve positional/public storage API compatibility. Preserve legacy error semantics: introduce structured availability/latency fields for new HTTP observations where needed rather than classifying via free-text message substrings.
- [ ] Bound queries to owner, domain and 30 days. Aggregate display points server-side into at most 120 time buckets (success/failure/unknown counts plus successful latency average); provide totals and sample count, never leak raw metrics/messages. Use UTC bucket keys and local labels.
- [ ] Test period boundaries, invalid IANA zones, large history, owner isolation and configuration changes; run existing HTTP/storage/check tests; commit `feat: add honest availability and response-time analytics`.

### Task 5: Calm responsive overview and domain charts

**Files:** Create templates `base.html`, `overview.html`, `domain_detail.html`, `domain_form.html`, chart partials and static `workspace.css`, `theme.js`; extend domain views; create `tests/test_webapp_presentation.py`.

**Interfaces:** Overview/detail templates consume Task 4 DTOs. Shared chart partial receives bounded `points`, accessible `summary`, and data-table rows. Theme is a cosmetic light/dark cookie only, never an authorization input.

- [ ] RED: overview shows a problem-first table, Add domain, correct empty state and real observation time; phone layout exposes the same domain facts. Detail shows 24h/7d/30d links, latency units, Successful checks label/calculation and no-data explanation.
- [ ] Implement neutral surfaces, existing green accents, concise English copy and semantic headings. Desktop rows become cards below 720px. Use CSS variables for both themes and locally authored inline SVG for charts with explicit accessible descriptions/text-table fallback.
- [ ] Keep sun / switch / moon with a native GET cosmetic fallback and optional JS preserving drafts. Include CSP-compatible script files, keyboard controls, visible focus and touch targets at least 44px where interactive.
- [ ] Put advanced fields in a native details disclosure. Retain labels, errors adjacent to inputs, saved/stale feedback and destructive confirmation. No hover-only information or forced auto-refresh during editing.
- [ ] Verify HTML tests and actual browser at 1440px, 390px and 320px in light/dark, keyboard and JS-disabled modes. Commit `feat: redesign monitoring overview and domain history`.

### Task 6: Simple settings, timezone and notification destination

**Files:** Create `webapp/preferences.py`, settings template and `tests/test_webapp_settings.py`; extend models/forms/URLs and bot connection adapter.

**Interfaces:** `/settings` and `/workspace` share the owner-settings view. Validate timezone via `zoneinfo.ZoneInfo`. Existing `storage.set_user_alert_chat_id(owner_id, chat_id)` and alert-enabled API remain the source of delivery destination/preferences.

- [ ] RED: timezone defaults to Europe/Moscow, persists and changes only presentation; invalid zones fail with a field error. Test day rollover in Moscow and a DST-observing zone.
- [ ] Expose timezone, notification toggle, connection status, chat destination, explicit Send test and password change. Keep tokens blank/hidden once configured. Missing Telegram configuration does not prevent saving domains or starting checks.
- [ ] For initial simple Telegram connection, accept a bot token and numeric chat destination in protected advanced connection fields, explain BotFather and `/start` in plain English; persist the token in a mode-0600 local secret file read by both worker and bot, never in public data or an HTML value. Preserve an environment token as the explicit deployment override and show when it overrides stored configuration.
- [ ] Test sends require explicit owner POST, use finite timeout, and report failures without leaking token/URLs. Use a separate mocked test message, never real delivery during automated validation.
- [ ] Existing installations can bind the owner account to its current Telegram owner ID during setup; local identities can set a destination without changing historical owner IDs. Run settings/Telegram proxy and delivery tests; commit `feat: add approachable workspace and notification settings`.

### Task 7: Revocable read-only public status page

**Files:** Create `webapp/public.py`, public template, migration and `tests/test_webapp_public.py`; extend settings and models.

**Interfaces:** Workspace fields `public_enabled=False`, `public_token_hash`, `public_domains` (validated selected owned domain names). `/status/<token>/` returns a public page; any graph JSON route uses the same token/selection guard. Tokens from `secrets.token_urlsafe(32)`; store only SHA-256 digest; show full link only immediately after enable/rotate, with a copy action.

- [ ] RED: disabled page is 404; enabled link exposes only selected domains; guessed tokens, unpublished domains, another owner's identical domain and revoked links return 404. No token accepts an owner API request.
- [ ] Public serializer uses the safe analytics DTOs and sanitized category labels; test sentinel secrets embedded in raw messages/metrics, proxy URLs, tokens, chat IDs and hidden domains never appear in HTML/JSON.
- [ ] Public GET/HEAD performs no dispatch or storage writes. POST and mutation/scanning attempts fail even with owner-shaped fields. Empty selected list is a deliberate empty public page.
- [ ] Implement explicit publish/domain selection/disable/rotate owner POST controls. Add noindex headers/meta and no-referrer on bearer-link pages; avoid access-path logging, third-party assets and caches retaining revoked pages.
- [ ] Use the same visual system and accessible charts, without management controls. Run public and owner HTTP/security tests; commit `feat: publish revocable read-only domain status`.

## Phase C — Unattended operation and delivery

### Task 8: Shared scheduler tick and exclusive process ownership

**Files:** Create `scheduler.py`, `scheduler_lock.py`, `tests/test_scheduler_lock.py`; modify `bot/jobs.py`, `bot/app.py`; extend `tests/test_jobs.py`.

**Interfaces:** `scheduler.due_checks` retains existing signature and remains re-exported by `bot.jobs`; `async scheduler.run_tick(cfg: AppConfig, *, warmup: bool, on_results, run_id: str | None = None) -> None`. Callback `async on_results(owner_id: int, domain: str, results: list, *, warmup: bool) -> None`. `scheduler_lock.acquire(path: Path)` is a context manager held for scheduler process lifetime.

- [ ] RED: extracted tick preserves intervals, pause/config controls, concurrency, warmup baselines, retrying undelivered transitions and no-resurrection persistence. Compare existing bot outcomes before/after.
- [ ] RED using real subprocesses: second process for the same canonical DB path fails promptly; different DB works; SIGTERM/crash releases ownership without deleting a lock another process owns. Use standard OS file locking with a clear unsupported-platform error rather than PID-file guessing.
- [ ] Extract only the current due-selection/dispatch/persistence loop; keep Telegram baseline/deduplication/delivery in bot callbacks. Acquire lock before registering running scheduler jobs and release on every startup/shutdown failure; bot with scheduler disabled does not compete for ownership.
- [ ] Run jobs, warmup, alert retry and subprocess lock tests; commit `refactor: share scheduler tick and prevent duplicate schedulers`.

### Task 9: Standalone worker without mandatory Telegram

**Files:** Create `worker.py`, `tests/test_worker.py`; modify CLI, shared notification token loader and bot adapter as required.

**Interfaces:** CLI `sitewatcher worker`; `async worker.run_worker(cfg: AppConfig) -> None`. Use shared tick/lock, history cleanup and optional configured Telegram adapter. `sitewatcher web` never acquires scheduler ownership or starts jobs.

- [ ] RED: worker without token records real mocked scheduled results; with token retries failed incident delivery correctly; paused/no-domain cases remain idle; cleanup still runs; shutdown closes dispatcher/Telegram clients and releases lock.
- [ ] Run periodic checks with existing warmup/jitter/cadence, cancellation-safe sleeps, and shared maintenance once per UTC day. Telegram client is created only if configured; configuration changes are picked up at safe tick boundaries without resetting incident state.
- [ ] Reuse the existing alert retry/deduplication adapter rather than implement a second policy. Expose stopped/stale worker state as last-measurement age, not a fake always-running indicator.
- [ ] Test concurrent bot/worker launch, restart, Telegram outage and no-token monitoring; commit `feat: run unattended monitoring without Telegram polling`.

### Task 10: Verified startup, migration, browser review and release evidence

**Files:** Modify `compose.yaml`, `Dockerfile`, README, `docs/operations.md`, AGENTS and packaged assets configuration; create `docs/verification-owner-public-dashboard-2026-10-22.md` (use actual completion date if later) and portable validation scripts outside runtime source.

**Interfaces:** Local quick start `sitewatcher setup` then web + worker commands. Compose equivalent: one interactive setup service command followed by one `docker compose up -d` command for web/worker, persistent named volume. Bind host port to loopback. Keep an explicit compatible Telegram bot launch/profile; never enable worker and bot scheduler simultaneously by default.

- [ ] Rehearse migration on a backup copy of a populated legacy DB including corrupt overrides, users with identical domains and existing history; verify raw monitoring tables and counts are retained. Test idempotent migration and restore a backup with all processes stopped.
- [ ] Run Ruff and full pytest on Python 3.12/3.13/3.14. Build/install wheel into a clean environment outside the checkout, verify all templates/static/migrations are packaged, and exercise setup/auth/worker/public routes there.
- [ ] Run nonroot container and Compose lifecycle with persistent volume: setup, login, add domain, worker result, restart, history still present. Test production host/proxy restrictions and secure-cookie settings independently; do not expose a real public port.
- [ ] Browser walkthrough: onboarding, login, add/edit, advanced disclosure, manual check, history/graphs, Telegram mocked test feedback, timezone, themes, public enable/view/revoke and logout. Verify desktop/phone, keyboard, no-JS fallback and no overflow. Save before/after screenshots; fix issues before recording completion.
- [ ] Remove superseded native HTTP/parser/render code only after parity tests cover its guarantees. Keep former CLI options with explicit behavior/help; `--read-only` never bypasses authentication.
- [ ] Produce exact changed-file list, portable patch/archive, hashes, migration/rollback instructions and measured verification results. Stop temporary test servers; preserve/update the user's local preview with synthetic data and no guessed credentials. Document setup rather than publish a password in chat.
- [ ] Commit `docs: document and verify authenticated monitoring workspace` after all required checks pass.

## Self-review and handoff

- Spec sections map to Tasks 1–10; standalone monitoring, default timezone, public disclosure limits and honest statistics have explicit tests.
- New authentication tables do not rename legacy monitoring tables; no anonymous compatibility route survives.
- Synchronous storage functions remain off the ASGI event loop through Django sync views/worker thread offloading.
- Graphs preserve unknown coverage and distinguish sample success from continuous uptime; no unsupported SLA claim.
- Existing dirty theme changes require a reviewed checkpoint before execution/isolation; no wholesale stash or discard.
- Execution method and plan review remain pending. No product implementation is included in this plan commit.

## Primary references checked during planning

- Django 5.2.8 adds Python 3.14 compatibility: https://docs.djangoproject.com/en/5.2/releases/5.2.8/
- Django ASGI/Uvicorn deployment: https://docs.djangoproject.com/en/5.2/howto/deployment/asgi/uvicorn/
- Django authentication/session facilities: https://docs.djangoproject.com/en/5.2/topics/auth/default/
- django-axes database-backed throttling: https://django-axes.readthedocs.io/en/latest/3_usage.html
