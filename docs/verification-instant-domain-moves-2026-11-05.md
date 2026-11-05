# Instant domain moves — 2026-11-05

Cross-group moves now retain and move the existing domain tbody after server
confirmation. The page, charts, details and their listeners are not replaced.
The owner-only response provides canonical ordering/membership and shared rendered
group headings/empty placeholders, keeping counts and critical badges accurate
across all members under filtering. Original membership is checked atomically;
stale-tab moves return 409. A read-only JSON snapshot reconciles lost confirmations
without repeating POST. Neither endpoint exposes raw check diagnostics/metrics.

Dynamic delegated group disclosure follows moved rows. Desktop native drag uses
an explicit target outline/label, custom domain preview, delayed hover opening
and edge scrolling. The destination stays open while confirming a hovered drop.
Short FLIP/arrival feedback respects reduced motion. The same handle opens a
named native dialog for touch/keyboard, with local saving/errors and focus return.
No dialog is offered when only one group exists. Refresh is suppressed during
drag/save/dialog use and briefly after completion. Status tooltip IDs are now
unique per domain rather than repeating per group.

## Verification

- Full Python 3.12 suite: 1132 tests passed. Ruff, msgfmt, diff checks and every
  Node suite passed. New backend red/green covers authoritative escaped headings,
  counts, stale membership, owner isolation and omission of raw provider payloads.
- Node regressions cover no reload, same row identity, repeated moves, pending
  exclusion, dynamic source/target disclosure, favorites, original DOM retention,
  ambiguous response read-back, post-save/dialog refresh guards and reorder rollback.
- Chromium with isolated synthetic data: real native mouse drag/drop (CDP drag
  interception), real touch tap and keyboard Enter. Verified empty/collapsed target,
  hover opening, retained expanded details/row identity, updated counts/critical
  badges, repeated moves, filtered target creation with all-member count (9 vs 1
  matching row), no duplicate IDs/overflow/uncaught exceptions, reduced motion.
- Deliberately lost the POST response after server commit: GET reconciled the move
  with one POST only. Rejected the request before commit: row stayed in its original
  group and subsequent retry worked. With both POST/read-back unavailable, the
  dialog retained visible local feedback and a successful retry closed it.
- Independent review: no important correctness/security blockers; 91 focused
  Python tests and drag/disclosure Node suites passed. Dialog naming and local
  status feedback were included in the final implementation.

Screenshots use only synthetic domains: `docs/screenshots/domain-move-native-desktop.png`,
`domain-move-target-desktop.png`, `domain-move-complete-desktop.png`, and
`domain-move-dialog-mobile.png`, and `domain-move-dialog-dark-mobile.png`. Production verification is runtime/data/HTTP,
not an assertion that private production UI was browser-inspected.

## Release read-back

Runtime source commit `3891728`; all 1132 tests passed in GitHub CI on Python
3.12/3.13/3.14, together with container and security checks. Source archive SHA256:
`8c7244788ed59b9c7af9905761456be08525bb19636c62d9a36546534b9c19c5`.

Verified backups:

- Local: `/data/backups/before-groups-20261105T202011640113Z`.
- VPS: `/data/backups/before-groups-20261105T202203203745Z`.

Private database clone rehearsal passed before switching the VPS. All 145 runtime
files match the source in local and VPS web/worker. Immediate post-switch comparison
preserved domains, overrides, publications and prior history; integrity/FKs and the
single scheduler lock passed. All four persistent VT report timestamps/outcomes
were retained. Both VPS containers run `sitewatcher:3891728`, with no restarts or
OOM. Binding remains 127.0.0.1:8080. Public HTTPS health/login/demo return 200;
unauthenticated JSON group access correctly redirects to login. Served JS/CSS
bytes match the release, and all four changed assets use `Cache-Control: no-store`.

Rollback requires the previous retained `sitewatcher:b7e8951` image and private
compose/release snapshot in `/opt/sitewatcher/backups/groups-3891728`. No schema
changes or database rollback are needed for this iteration. Archives, patch and
revision are retained in `/opt/sitewatcher/upgrades`; database backups remain
private. No real domain memberships were changed by the deployment verification.
