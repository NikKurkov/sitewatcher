# Web management implementation plan

Baseline: `6524676`. Feature branch: `feat/web-management`. User authorized implementation and autonomous decisions; preserve the earlier verified branch and archive.

- [x] Actions: reuse storage/config/CSV for owner-scoped create/edit/pause/resume/reset/delete, form context and history. Regression tests first.
- [x] UI: native forms, domain action links, management pages, tri-state inherited settings, safe error redisplay, CSV controls, responsive/accessibility tests.
- [x] HTTP integration: fixed-owner routing, bounded POST parsing, CSRF and strict Origin, 303 redirects, readonly switch, manual live checks with a single nonblocking lock and cancellation/error handling.
- [ ] Verification: full suite across supported Python versions, independent review, installed-package/browser operations, docs and local commits.

Review focus: zero GET writes; no secret redisplay; no cross-owner mutation; failed validation has no partial state; manual checks cannot resurrect deleted domains; readonly remains available. Acknowledged boundary: web manual runs save results but do not send notifications; the running bot evaluates saved state on its next scheduled tick. No new periodic scheduler is introduced.

Execution record:
- User additionally requested Day/Night switching. Native cookie preference includes System mode; optional 14-line theme script prevents losing drafts and native links remain a no-JS fallback.
- HTTP/browser integration caught and corrected check-name history mapping, non-ASCII CSRF handling, stale-revision error retry, CSV mode retention and Referrer-Policy causing Chromium Origin:null. Regression tests/browser RED→GREEN recorded.
- Independent review found stale retry and CSV-mode errors; both corrected with HTTP regressions. CSV content is deliberately not echoed after errors because it may contain credentials.
- Chromium completed add/edit/pause/resume/delete, settings and export/history flows; themes and responsive forms checked at 1440/390/320. Native no-JS add/delete and theme fallback also passed.
- A final CSV concurrency regression reproduced invalid merged thresholds when another interface changed settings after validation. The shared importer now uses the same atomic revision guard; valid independent rows remain importable. Oversize-form admission test sends headers only to avoid an expected client-side broken pipe after early rejection.
