# Collapsible domain groups and HTTP chart visibility — 2026-11-05

Implements the selected first proposal. See the design and implementation plan
under docs/superpowers. Main is implicit for existing/unassigned sites. Custom
owner groups use two additive monitoring tables; membership/owner foreign keys,
atomic form writes, rename preservation and default-group deletion behavior are
covered. Public DTOs do not publish group names/IDs.

UX includes group counts and warnings while collapsed, per-browser/owner disclosure
preferences, expand/collapse all, search-open behavior, explicit bulk moves,
within-group favorites/reordering, read-only mode, translated group forms and
light/dark responsive layouts. Existing snapshot/report queries remain bounded;
this is not pagination/lazy loading.

HTTP charts are hidden when HTTP is disabled or the selected period has no HTTP
observations. Failed-only observations retain the section. Owner overview/history
and public pages share the behavior.

## Validation

- Regression red/green for storage and web groups, HTTP charts, stale membership
  forms and empty-group disclosure. Last integration: 1090 tests passed on each of
  Python 3.12, 3.13 and 3.14. Ruff and translation checks passed.
- All existing Node browser-script tests passed; new group-state/selection test
  passes and is included in CI. Original empty-group selector was verified failing.
- Independent review's stale-form overwrite and empty-collapse findings were fixed;
  follow-up review passed 31 Python tests plus the Node regression with no blockers.
- Firefox on an isolated synthetic workspace: collapse/reload persistence, bulk
  transfer, edit transfer back, empty-group collapse, chart omission, zero horizontal
  overflow, and failed-reorder rollback retaining all group headers.
- Chromium headless at actual 390px viewport: content width 390px, three group
  headers, five visible shop rows, no uncaught exceptions. Light/dark screenshots
  also captured at 1366px. The synthetic workspace contains no production data.

Screenshots: screenshots/groups-dark-desktop.png, groups-light-desktop.png,
groups-dark-mobile.png and groups-light-mobile.png.

Runtime/migration/rollback evidence follows after deployment.
