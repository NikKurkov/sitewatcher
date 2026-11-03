# Web management

The user requests full browser management in addition to Telegram and previously authorized autonomous design and implementation. Retain the existing loopback-only stdlib server and fixed owner. Use native forms and current storage/configuration/CSV/dispatcher functions; add no runtime dependency.

## Scope and flow

- Inventory: add domains, edit all per-domain override fields, pause/resume, reset inherited settings, explicitly confirm deletion, manually run live checks, inspect recent history.
- Workspace: toggle owner notifications, export/import domain CSV (merge or replace listed overrides). Global YAML, credentials and scheduler remain deployment configuration. Browser management works without Telegram credentials; periodic monitoring remains the bot's responsibility.
- Forms use tri-state check selectors (inherit/on/off), nullable numeric overrides, JSON keyword/port lists and a password proxy input that never redisplays credentials. Empty proxy preserves the existing override; explicit inherit/clear/set modes avoid accidental disclosure or replacement.
- A single server-wide nonblocking lock bounds manual runs to one. Execute the existing async dispatcher inside the request worker, save only for an existing domain, send no Telegram messages from the web process. Readers remain responsive. No worker pool, persistent task queue or new scheduling service.

## HTTP boundary

Normal web mode allows management and initializes an empty database; explicit `--read-only` retains viewing-only behavior. GET/HEAD never mutate application data. Writes require POST, exact trusted Host/Origin, a per-process random CSRF token and bounded, unambiguous form bodies. No token in URLs or logs. Use 303 redirects after successful operations; validation failures keep editable input and show sanitized errors. Each action uses the server-fixed owner; ignore no owner supplied by clients. Existing read-only JSON excludes settings/secrets.

Deletion requires a dedicated confirmation page. CSV downloads may contain private domain configuration and are deliberate backups. Settings pages have no auto refresh. Failed checks do not fabricate healthy results or restore removed domains. Reject concurrent manual runs with a useful busy message. Read-only mode contains no mutation controls or CSRF token.

## Theme preference

Day/Night/System controls persist a non-sensitive browser cookie across pages. CSS follows system preference unless explicitly overridden. A tiny optional native script changes theme without reloading or discarding unsaved input; links remain functional without JavaScript. No frontend framework is introduced.

## Verification

Offline tests cover owner isolation, CSRF/origin/length/duplicate-field validation, all CRUD and inheritance, proxy secrecy, CSV round trips, manual-run contention/deletion, graceful shutdown and read-only fallback. Run the full suite on Python 3.12–3.14, installed wheel/container smoke and browser CRUD at desktop/mobile sizes using synthetic data and mocked/local probes.
