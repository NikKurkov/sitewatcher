# Authenticated workspace release verification — 2026-10-22

Initial Task 10 release evidence for `feat/owner-public-dashboard`, starting at
`3b89ea5`. Independent task review and whole-branch review follow this rehearsal;
this document does not claim deployment, final integration or external availability.
All runtime data and credentials used here were disposable synthetic fixtures.

## Delivered behavior

The release ships one authenticated Django web stack and a standalone worker. Compose
startup is exactly `docker compose run --rm --build setup`, then `docker compose up -d`:
setup prompts for a hidden password, no `.env` is required, web/worker share a named
volume, and the host mapping remains loopback-only. Optional Telegram polling runs
with `--no-scheduler`. Native web defaults to loopback; explicit internal container
binding is supported. The old anonymous HTTP server, duplicate parser/renderers and
legacy dashboard assets have been removed.

Health now makes a minimal read-only schema query and returns a generic 503 when the
database is unavailable. Cold analytics builds serialize within the single web process;
SQLite and Python use the same first-value interpretation for duplicate legacy JSON keys.
The doctor reports SQLite >=3.35/JSON1 compatibility. Read-page refresh is pausable and
waits for hidden tabs, focused inputs, filter drafts and open disclosures. Forms never
refresh. Native timezone choices, per-domain mean latency, Just now labels and stronger
text/input contrast complete the small usability corrections found during QA.

## Verification

| Check | Observed result |
| --- | --- |
| Ruff, `ruff check sitewatcher tests` | Passed |
| Full pytest, Python 3.12.12 | 652 passed, 26.72 seconds |
| Full pytest, Python 3.13.12 | 652 passed, 25.62 seconds |
| Full pytest, Python 3.14.8 | 652 passed, 27.87 seconds |
| CLI help, Compose config, whitespace check | Passed |
| Installed wheel outside checkout | Auth/login, owner/detail views, assets, all 7 partials, migrations, public enable/view/revoke passed; legacy assets absent |
| Installed worker, no token or domains | Started and exited 0 after SIGTERM; 2.06 seconds including a 2-second observation |
| Fresh unconfigured installed web | Health 200 after migration; owner route redirects to login |
| Nonroot Compose lifecycle | UID 10001; setup/login/add/edit, scheduled HTTPS result, restart and retained history passed |
| Container build context | Synthetic YAML/SQLite/WAL/environment/web-secret/token canaries absent; installed templates render from `/tmp` |
| Production proxy settings on loopback Compose | Explicit public host accepted, unknown host 400, trusted HTTPS header accepted, secure session/CSRF cookies, foreign Origin 403; local health remains 200 |
| Live missing database | Health 503 with generic body; restore returned 200; worker stopped during fault injection |
| Dependency audit of installed wheel environment | No known vulnerabilities found at verification time |

The 652-test total replaces the prior 687-test baseline: legacy renderer and native
server-only cases were removed after guarantees were covered by Django tests. Existing
owner isolation, CSRF, duplicate/oversized forms, CSV, stale edits, manual-check concurrency,
deleted-domain races, read-only behavior and theme tests remain. New tests cover health,
cold-cache concurrency, duplicate JSON semantics, bind/command-only bot behavior,
SQLite support, per-row latency, reading order and GET/HEAD/security-header parity.

## Migration and recovery

The external migration script extracts the genuinely pre-feature monitoring DDL from
commit `da998dc`: no Django tables and no `history.source`. It creates two owners with
the same domain name, two historical HTTP rows and a corrupt override. A SQLite backup
copy is upgraded twice. All original columns and raw rows in all **8 monitoring tables**
match exactly; both rows receive `source=legacy`. Owner binding and public routes are
then exercised using the installed wheel.

A consistent current-schema database backup and matching mode-0600 web-secret/token
sidecars are restored with application connections closed; history count and SQLite
integrity pass. A separate old-schema restore matches every original row. Production
rollback requires stopping web, worker and bot, retaining current database/sidecars,
restoring the pre-upgrade backup and credentials, and reinstalling the previous release.
See [operations](operations.md) for commands and safeguards.

## Browser evidence

Chromium exercised 1440, 390 and 320 px in light and dark modes: owner overview and
history (12 combinations), public status and expanded chart/data tables (6 combinations),
and settings (6 combinations). No horizontal overflow was found. Screenshots were read
back visually, including phone settings and public status. Keyboard skip link, native
advanced disclosure and graph disclosure work. With author JavaScript disabled, add,
forms, history, theme switching and chart tables remain usable.

Additional flows verify sign-in, add/edit, synthetic manual check and saved provenance,
mocked Telegram test feedback, saved timezone/DST labels, public selection/copy/rotation/
revocation and logout. Refresh tests run the actual scheduled callback without waiting
a minute: filter drafts, focus, open disclosures and the persisted pause prevent reload;
an allowed reload preserves scroll position. A genuinely backgrounded browser tab also
prevents reload. Public links were revoked and no one-time link/token/password was
included in screenshots. Browser credentials remain in private temporary files, not in
release artifacts or the user's installation.

## Artifacts and limits

Evidence is preserved outside the repository in
`/home/niki/Documents/ai-projects/sitewatcher/2026-10-22-owner-public-dashboard/`:
`task10-5-screenshots/`, `task10-7-screenshots/`, `task10-settings-*.png`, browser result
JSON, reusable QA scripts and `task10-initial-release/` (logs, exact changed-file list,
portable patch/source archive and SHA-256 manifest). The worktree task report contains
exact commands and RED/GREEN outcomes. The parent refreshes final artifacts after
independent reviews; these files are initial release evidence.

This is a one-owner, one-web-process installation with one scheduler per database.
The analytics cache remains process-local, bounded to 8 entries/4 MiB/60 seconds;
serialization avoids duplicate cold work but can delay another cold report. No heavy
production-scale load claim is made. SQLite versions observed: 3.50.4 natively and
3.46.1 in the container. One idle container snapshot measured web 65.22 MiB/0.07% CPU
and worker 50.74 MiB/0.00% CPU; this is an observation, not a load benchmark. TLS fixture checks used only an isolated local container.
Browser manual checks and Telegram delivery were mocked; no real Telegram message was
sent. Synthetic accounts were never promoted to the user installation. No push,
deployment, firewall change or original-checkout integration was performed.
