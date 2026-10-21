# SiteWatcher owner workspace and public status page

Date: 2026-10-22
Status: Proposed for user review; implementation has not started.

## Intent and audience

A website owner should be able to start the application with a short documented
setup, sign in, add up to about 20 domains, choose checks and connect notifications.
Monitoring should then run unattended. The owner can return to clear status,
chronology and availability charts. Visitors receive a separate read-only status
link. Desktop and phone are both first-class interfaces.

All interface text is English. Use the current restrained green palette, neutral
surfaces, clear typography and distinct problem colours. Preserve the sun / switch /
moon theme control, without a System option. Avoid bulk tools, team management,
registration, decorative dashboards and routine technical configuration.

## Proposed technical decision

Use Django for the web application: server-rendered templates, native forms,
built-in authentication, sessions, CSRF protection and schema migrations. This
updates the earlier FastAPI preference because authentication and public access
are now core requirements. FastAPI preserves more of the existing HTTP integration
but requires assembling more browser-account infrastructure. Extending the current
stdlib HTTP server would leave that infrastructure entirely in this project.

Keep the existing monitoring engine, domain validation, Telegram commands and
SQLite monitoring tables behind their existing storage functions. Django owns new
account/session/workspace settings tables; do not rename or rebuild legacy tables
merely to adopt an ORM. Map each web account to an explicit existing owner ID;
never accept the owner ID from a form or public URL as authorization.

No React, Redis, Celery, PostgreSQL or external font/CDN requirement. Package all
assets locally. Use an appropriate production web server rather than Django's
development server for the documented deployed launch.

## Owner experience

- Login: one owner account created through interactive local setup; no public
  registration. Password entry is hidden, never a command-line argument. Support
  logout, password change and a documented local password reset command.
- Overview: concise overall status, active problems, last actual measurement,
  availability summary and a domain table. No marketing headline.
- Domain table: name, readable status, recent availability strip, availability
  percentage, response time and last check. One clear Add domain action.
- On phones, the same information becomes readable cards without horizontal
  scrolling. Retain keyboard operation, visible focus and text status labels.
- Add/edit: domain, plain-language check choices, monitoring interval and
  notifications. Supply sensible defaults. Advanced exposes thresholds, proxy,
  keywords and ports; never require understanding these to start monitoring.
- Domain details: current problem explanation, response-time graph, chronological
  availability strip and incident/history list. Periods: 24 hours, 7 days, 30 days.
  Empty history says collecting data and never fabricates a chart.
- Settings: timezone, Telegram connection, notification destination, test message,
  password and public-page controls. Default timezone Europe/Moscow. Store UTC;
  convert presentation with IANA timezone rules. Show timezone beside timestamps.
- Feedback: clear pending/success/error states, preserve drafts on validation
  failure, confirm destructive actions, preserve concurrent-edit protections.

## Monitoring and notifications

Provide a standalone scheduler worker so web monitoring does not depend on owning
a Telegram token. Reuse scheduling decisions from the bot rather than copy them.
Exactly one scheduler may own a database at a time, whether started by the existing
bot or the new worker; duplicate schedulers must fail clearly. Web server workers
must never each start scheduled monitoring.

For this iteration, notifications mean Telegram, with an optional personal or group
chat destination and a simple connection/test flow. Monitoring and graphs continue
without Telegram configured. Do not add email, SMS or webhook setup to the basic UI.
Existing CLI and bot workflows remain supported and share owner-scoped data.

The intended quick start is interactive setup followed by a single documented
launch/Compose command. Include a persistent data volume and clear stop/restart
instructions. Verify the exact commands before documenting them as working.

## Honest availability statistics

Keep availability separate from the worst status across all checks: certificate
expiry, WHOIS or slow-response warnings do not automatically mean the site is down.
HTTP availability follows the effective monitored endpoint and final HTTP outcome;
valid HTTP responses below 400 are available, HTTP errors and connection failures
are unavailable. Unknown/unclassified failures remain unknown, not automatically
site downtime. Response-time charts describe the metric actually measured.

Use the existing raw history for historical response-time charts and an explicitly
labelled successful-check percentage. This is a proportion of classified HTTP
observations, not measured wall-clock uptime. Cached results must not create new
availability observations. Identify manual measurements separately when recording
new results; do not claim legacy history proves scheduled coverage.

Show available, unavailable and no-data segments in the chronology, with visible
coverage and the sample count. Do not interpolate across unmeasured gaps, pauses,
periods before monitoring started or after the last observation. Use the label
Successful checks for the percentage and describe its calculation in a short
accessible explanation. Do not label it SLA or continuous uptime.

Retain the current 30-day raw-history policy for this iteration. If a wider period
is requested later, introduce retention-safe daily aggregates before offering it.
Graphs have a readable textual summary/table and work without hover on phones.

## Public page

Publishing is disabled by default. The owner explicitly selects domains to publish,
enables a page and receives an unguessable revocable link. It is a shareable link,
not authentication: anyone who receives it can view the selected information.
Disable or rotate it immediately from settings. No search-engine indexing by default.

Expose only selected domain names, public availability state, safe aggregates,
response-time charts, chronology and sanitized incident categories. Never expose
raw check messages/metrics, internal addresses, credentials, proxy settings,
Telegram identifiers, private domains or owner exports. Use dedicated serializers
and routes, not the owner response with buttons hidden.

Public routes serve stored results only. They cannot trigger checks, alter
settings or reach management/export APIs, including by crafting direct requests.
Public timezone is the workspace setting and is visibly labelled.

## Authentication and deployment boundaries

Require authentication for every owner page and API except login and minimal
health/assets. Use Django password hashing, expiring sessions, CSRF-protected state
changes, strict host configuration and login throttling. A public-link token must
never grant owner-session access. Log neither passwords nor bearer links.

Stay loopback-only by default. Public Internet deployment is an explicit documented
HTTPS reverse-proxy configuration with secure session cookies and trusted proxy /
host settings. Do not open ports or deploy externally as part of the redesign.

## Verification and acceptance

- Regression checks for existing CLI, checks, owner isolation and bot workflows.
- Authentication, logout, CSRF, expired sessions, login throttling and password reset.
- Direct anonymous/public requests cannot mutate or scan; tokens cannot cross owners;
  revoked links stop working; public payloads exclude secrets and unselected domains.
- Statistics fixtures cover HTTP redirects/errors, warnings, unknowns, missing data,
  cached results, manual runs, timezone boundaries and empty/partial periods.
- Scheduler operates without Telegram; concurrent bot/worker launch cannot duplicate
  scheduled work. Notification connection and test flows report failures accurately.
- Browser verification at desktop and phone sizes in both themes: account setup,
  login, CRUD, configuration, live check, history, public sharing and revocation.
- Keyboard interaction, contrast, touch controls, no horizontal overflow and useful
  no-JavaScript forms; graphs include a textual fallback.
- Migration/backup/rollback rehearsal on a copy of the existing database, packaged
  wheel/container checks and a verified quick-start walkthrough.

## Deliberate limits

Single-owner deployment, about 20 domains, 30-day charts, Telegram notifications.
No teams, subscription billing, email recovery service or new infrastructure stack.
The prior theme-toggle changes in the working tree belong to the already-authorized
UI change and must be preserved when implementing this proposal.
