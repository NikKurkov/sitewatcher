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
