# Collapsible domain groups and HTTP chart visibility — 2026-11-05

Implements the selected first proposal. See the design and implementation plan
under docs/superpowers. Main is implicit for existing/unassigned sites. Custom
owner groups use two additive monitoring tables; membership/owner foreign keys,
atomic form writes, rename preservation and default-group deletion behavior are
covered. Status-page group selections dynamically publish current members and selected
group names in HTML only. Flat public JSON never contains internal group IDs.
Unselected/private group names are not published. Migration 0008 adds public_groups
with an empty default, preserving old pages.

UX includes group counts and warnings while collapsed, per-browser/owner disclosure
preferences, search-open behavior, confirmed cross-group dragging,
within-group favorites/reordering, read-only mode, atomic inline New groups, single-group heading omission, Settings-only management,
translated group forms and
light/dark responsive layouts. Existing snapshot/report queries remain bounded;
this is not pagination/lazy loading.

HTTP charts are hidden when HTTP is disabled or the selected period has no HTTP
observations. Failed-only observations retain the section. Owner overview/history
and public pages share the behavior.

## Validation

- Regression red/green for storage and web groups, HTTP charts, stale membership
  forms and empty-group disclosure. Last integration: 1115 tests passed on each of
  Python 3.12, 3.13 and 3.14. Ruff and translation checks passed.
- All existing Node browser-script tests passed; new group-state/inline-form test
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

## Final user refinements

List selection checkboxes, global expand/collapse buttons, management toolbar and
footer link were removed. Settings is the entrypoint for group management. One
group adds no heading. Inline New creates the group only with successful domain
save. DND cross-group transfers wait for explicit saved JSON, preserve old DOM on
failure and open the destination after confirmation. Both state and failure paths
have Node regressions; old selectors/behavior were verified failing before fixes.

Status-page group checkboxes were verified in Chromium: two selected groups
published exactly 17 synthetic sites, excluded Main and exposed no internal group
IDs. Owner screenshots were recaptured without removed controls at 390/1366px in
both themes. Additional screenshots show the inline New field, single-group view
and status-page group selection/publication. All browser accounts/data are isolated
synthetic fixtures, not production acceptance.
