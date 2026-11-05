# Status pages and compact response summary — 2026-11-05

Implemented in the local checkout and local Compose runtime. No VPS deployment performed.

- Settings → Status pages lists pages and opens native create/edit forms. Each page has its own title, enabled state, public/private access and owned domain selection. Disabling or deleting a page revokes its paths without deleting monitoring data. Titles are escaped; title edits retain the address.
- Private links are shown once, stored as hashes and can be reissued. Private pages reject public aliases and alias data/activity routes. Owner isolation, CSRF, read-only mode and stale edits are enforced; conflicts retain the submitted values. Renaming a monitored domain updates only its owner's page selections and invalidates stale editors.
- Migration 0006 copies existing publication settings. The real migrated primary page was compared with the pre-migration SQLite backup: enabled state, slug, token hash and domains all matched. Previous root and bearer URLs are also covered by migration regression tests.
- Response summary reads `среднее: … мс … мс … мс`. The three windows are 15 minutes, one hour and one day. Native popovers support hover, keyboard focus, tap, outside dismissal and Escape. Open tooltips defer refresh.
- History failures use #ff5c68 in dark mode and #d92d3a in light mode, shared with the legend. A non-scaling one-pixel stroke makes a single failed bucket visible in the compressed strip. Percentages and bucket classification are unchanged; unknown results and missing measurements remain grey.

Validation:

- Full Python suite: 1000 passed. After final translation/template adjustments: 92 presentation/language/status-page tests passed.
- All five Node test files passed; Ruff, msgfmt --check, migration drift check, git diff --check and Compose configuration passed.
- Chromium: status-page list/editor at 1440, 390 and 320 pixels with no horizontal overflow; native private-page creation and guest link access on an isolated synthetic database; no JavaScript exceptions.
- Updated real public page: Chromium at 1440 (dark/light), 390 and 320 pixels; three compact means, hover/touch popover, viewport positioning and native Escape; red failure bar and matching legend. Firefox independently confirmed the compact text and red failed bucket. A real failed strip contains red pixels after rendering.
- Backup: `/data/backups/before-status-pages-20261105T072757Z.sqlite3`, mode 0600, integrity OK. Post-migration integrity OK. Web healthy, `/healthz` OK, one worker scheduler lock held. Nine changed runtime source/assets hashes match the checkout in both web and worker. Both use local image `94b8c126b974`.

Screenshots: [page list](screenshots/status-pages-desktop.png), [mobile editor](screenshots/status-page-form-mobile.png), [public desktop](screenshots/status-averages-history-desktop.png), [public mobile](screenshots/status-averages-history-mobile.png).


Follow-up before server release: public addresses are editable in the page form,
validated against reserved routes and all page/workspace addresses. Private mode
hides and omits this field. Changing the address revokes the old alias. Domain
selection rows are 30 pixels (36 on coarse pointers), with no inter-row gap.
Regression tests cover address changes, collisions, legacy synchronization and
private-mode protection. The complete suite now passes 1004 tests; all five Node
files and Ruff pass. Chromium reconfirmed the editor at 1440/390/320 pixels and
native private-page creation. Updated editor screenshot includes the address field.
