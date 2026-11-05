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
  forms and empty-group disclosure. Last integration: 1116 tests passed on each of
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

Runtime/migration/rollback evidence is recorded below.

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


## Runtime release and preservation

Final runtime revision: `6895d5f` (group feature `7c68192` plus the effective
status-page member count fix). All 1116 tests passed independently on Python
3.12, 3.13 and 3.14; Ruff, diff whitespace and all Node scripts passed.

Before migration 0008, rehearsals on private copies of both databases confirmed
preservation of existing domain configuration, status pages and history, empty
public-group defaults, SQLite integrity and owner foreign keys. Before the final
count-only update, new verified online backups were saved:

- Local: `/data/backups/before-groups-20261105T162917015806Z`.
- VPS: `/data/backups/before-groups-20261105T162920533685Z`.

The earlier pre-migration VPS backup is
`/data/backups/before-groups-20261105T162249393744Z`.
Archives and binary patches are retained privately under `/opt/sitewatcher/upgrades`.
The final source archive SHA256 is
`b2e82b5997f83cf609063d1fe560cdfcd9527374fccb07b6b61a03fc4dfbaf9b`.
VPS compose/config/release snapshots are in
`/opt/sitewatcher/backups/groups-6895d5f` (private permissions).

For rollback of this count-only update, restore that compose/release snapshot
and start retained image `sitewatcher:7c68192`. For rollback across migration 0008
to the pre-group image, first preserve the current database and restore the verified
pre-migration database/configuration together with the old image; changing only
the image does not undo the added non-null field. A historical database restore
would discard monitoring changes made after that backup.

Post-switch read-back passed in both environments: all 143 tracked runtime files
match the committed source in web and worker; old domains/settings/publication
and prior history match the backups; SQLite integrity/foreign keys pass and the
single scheduler lock is held. VPS web is healthy and worker running; both have
zero restarts and no OOM. Binding remains 127.0.0.1:8080. Public HTTPS health,
login and demo return 200; the protected group route redirects unauthenticated
requests with 302 as expected. Browser/visual evidence above uses synthetic data;
production verification uses HTTP and runtime/data read-back.

## Critical badge on group headings

Group headings reuse the domain's existing `badge crit` markup and translated
Critical label when any member's displayed state is critical. Aggregation includes
all group members even when search hides the affected domain; paused domains do
not raise a group critical badge. Recovery clears the badge on the next render.
Five regression cases cover CRIT/WARN/UNKNOWN/OK, pausing, recovery and filtering.
Synthetic Chromium checks at 1366/390px confirmed the badge remains visible while
collapsed, with no horizontal overflow. Screenshots:
`docs/screenshots/groups-critical-desktop.png` and `groups-critical-mobile.png`.
