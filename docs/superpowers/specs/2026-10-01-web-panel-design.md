# SiteWatcher web panel design

## Goal and scope

Add a complete, English-language alternative to Telegram commands for one owner on a self-hosted Linux/VPS deployment. Keep the bot and its check engine intact. The web interface must cover overview, domains, detail, history, manual checks, domain overrides, alert toggle, CSV import/export, cache clearing, and global configuration. Support desktop and mobile, light/dark themes, and refresh the overview every 45 seconds. Charts allow 24-hour, 7-day, and 30-day periods.

## Choice of framework

Use FastAPI with Jinja2 server-rendered pages, a small local CSS file, and minimal vanilla JavaScript. This matches the Python codebase and avoids a second frontend project, public JSON API, npm build, and browser-side state management. FastAPI provides Jinja2 templates/static files and form handling; Uvicorn serves one web process. An SPA would add build/deployment complexity without a benefit for one administrator. References: [FastAPI templates](https://fastapi.tiangolo.com/advanced/templates/), [forms](https://fastapi.tiangolo.com/tutorial/request-forms/), [Docker](https://fastapi.tiangolo.com/deployment/docker/).

## Deployment and configuration

- Keep one bot process and one optional web process in Docker Compose. Both share `/data` (SQLite and configuration). Expose the web port on `127.0.0.1:8000` so a VPS reverse proxy can terminate HTTPS; do not expose it publicly by default.
- `docker compose --profile web up -d --build` starts both. The existing `docker compose up -d --build` remains bot-only.
- Require `WEB_OWNER_ID`, `WEB_PASSWORD_HASH`, and `WEB_SESSION_SECRET` to enable web. A `sitewatcher hash-password` command generates a scrypt hash without echoing the password. No default password.
- `SITEWATCHER_CONFIG=/data/config.yaml` is optional. If the file does not exist, built-in defaults apply. Web saves validated YAML atomically there. Per-domain DB overrides are live; changes to the global YAML take effect in the bot after a bot restart, clearly signaled in UI.
- The app remains single-owner for web. Every query and mutation uses configured `WEB_OWNER_ID`; no cross-user selector or endpoint.

## Security

- Signed, HttpOnly, SameSite=Strict session cookie, 12-hour expiry; `Secure` is enabled by `WEB_COOKIE_SECURE=true` behind HTTPS. Session holds only owner ID, CSRF token, and password-hash fingerprint. Password changes invalidate sessions.
- Password verification uses stdlib scrypt with constant-time comparison; login attempts are throttled in-process. No password or secret logged.
- All state-changing HTTP routes use POST and validate CSRF tokens. Authentication is required for all panel pages/actions except login and static assets. Domain paths require ownership and domain validation. Form data and rendered check messages are escaped by Jinja2.
- No public JSON API or third-party CDN. Keep reverse proxy/TLS instructions in README. Avoid exposing `.env` or YAML through static routes.
- References: [OWASP password storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html), [CSRF](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html), [sessions](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html).

## UX and flows

- Overview: count of monitored/healthy/warning/critical/unknown domains, problem-first list, age of latest check, quick actions. Auto-refresh every 45 seconds only when the page is visible; no refresh during form editing.
- Domains: searchable/filterable list, add domain, inspect detail, run one/all checks, delete one or all with explicit confirmation. Names use the existing normalize/validation helper. Quick scan checks an untracked domain without persistence or alerts.
- Detail: latest check result for every enabled check, manual check action, period selector, sample-status timeline and HTTP-latency SVG chart. Label sample-based percentages as sampled checks, not continuous uptime. History table is filtered and bounded.
- Domain settings: clear controls for enabled checks, interval, thresholds, keywords, ports, proxy, plus reset to defaults. Show effective settings and overrides without exposing secrets in logs.
- History: domain/check/status/period filters and bounded pagination. CSV export/import retains the existing format and merge/replace modes.
- Settings: Telegram alert toggle, cache clearing, common global settings (schedules/defaults/alerts/history) and an advanced YAML editor for every AppConfig field. Validate before writing; display a restart notice after global updates. Secrets in YAML are only shown to the authenticated owner.
- English copy, responsive sidebar/header, accessible labels and focus states, light/dark mode stored as a non-sensitive browser preference.

## Data and operational behavior

- Reuse `storage`, `Dispatcher`, `resolve_settings`, and `domains_csv`; avoid a second database or check implementation.
- Web manual runs persist results through `storage.save_histories` and do not send Telegram alerts, matching manual CLI behavior. Quick scans of untracked domains use `ephemeral=True` and do not persist.
- Fix history's SQLite text timestamp comparison for period filtering. Keep chart queries owner-scoped and capped at 2,000 samples to bound response size. Existing 30-day retention limits the oldest chart period.
- Add HTTP tests for unauthenticated access, login/logout, CSRF, owner isolation, domain actions, settings, CSV, history periods, and manual runs. CI builds/starts the web container in addition to existing checks.

## Deliberate limits

- One web owner, one web process, no account registration, no public API, no email/webhook alerts. Those need explicit future requirements.
- Global YAML edits require bot restart. The UI and docs state this plainly; automatic Docker control from inside the app is excluded.
