# Domain groups implementation plan

**Goal:** Deliver the selected accordion groups and hide inapplicable HTTP charts.
**Architecture:** Owner-bound monitoring group/membership tables with implicit Main;
existing Django forms and shared table, progressively enhanced by a small JS file.
**Tech Stack:** Python 3.12+, SQLite, Django, native HTML/CSS/JS; no dependencies.
**Spec:** docs/superpowers/specs/2026-11-05-domain-groups-design.md

## Global constraints
Owner isolation, CSRF, read-only mode and public DTO boundaries remain mandatory.
Storage changes are additive. Preserve monitoring settings/history/publication.

## Review focus
Cross-owner IDs/batch moves, stale group forms, hidden rows during reorder rollback,
search and status filtering across collapsed groups, empty/failed HTTP observations.

- [x] Backend: regression-first group CRUD/membership, atomic domain writes, rename
  preservation, read-only snapshots and legacy fallback. Assigned groups_backend.
- [x] Charts: regression-first conditional presentation owner/detail/public, including
  disabled checks and failed-only observations. Assigned hide_empty_http_charts.
- [x] Owner UI: regression-first group routes/forms, owner isolation/read-only/CSRF,
  add/edit selection, cross-group dragging, inline New and Settings-only group management. Root.
- [x] Accordion UX: grouped table headers/counters, search behavior, persisted state, no list selection/global buttons,
  grouped reorder/rollback, mobile and light/dark presentation, JS behavior checks.
- [x] Integrate: full Python/JS/translation/Compose suites and independent review;
  browser acceptance and screenshots desktop/mobile/light/dark.
- [ ] Release: verified backups and clone migration rehearsal, immutable artifacts,
  runtime source/settings/history/publication read-back and rollback record.

- [x] Status-page group selection: additive migration, current/future members, flat
  public data/activity privacy, old-page compatibility and browser verification.
