# Instant domain moves

Reuse native desktop drag and the existing move POST. Keep the existing domain
tbody (charts, details and listeners) instead of replacing the table or reloading.
Only move after authoritative confirmation. Return current owner-only group
headings and canonical domain order; aggregate counts/critical state across all
members even under filters. Check the original membership atomically to reject
stale-tab moves. Read back membership after an ambiguous network response.

- [x] Regression-first response metadata, stale membership and ownership; shared
  group summary/heading/empty partials, no raw diagnostics or foreign data.
- [x] Dynamic group disclosure; move existing rows after confirmation, preserve
  favorite ordering/details/focus, update headings/placeholders without reload.
- [x] Clear drop target, delayed hover opening, native drag ghost, edge scrolling,
  short reduced-motion-aware movement/arrival feedback and visible save status.
- [x] Same move via the grip's accessible native dialog for keyboard/touch. Block
  competing moves during save; keep original DOM on failure, reconcile uncertainty.
- [x] Unit/browser regressions for repeated moves, source/target toggling, empty/
  filtered/collapsed groups, failures, favorites, reduced motion and mobile dialog.
- [x] Independent review, CI, verified backup, immutable deployment and read-back;
  update PR21 with screenshots and validation evidence. No new dependencies.
