# Public status readability verification — 2026-11-05

Implemented the approved public-page review and follow-up requests:

- Separate page refresh time from saved site-check age; no displayed timezone or next-check date.
- Label the metric “Successful checks”; show distinct unavailable, unknown and unmeasured history states.
- Keep refresh enabled on monitoring pages and remove the clock toggle from owner/public headers. Preserve draft, dragging, live-map and tooltip guards.
- Group checks by availability/network, domain/certificate and security/blocking, with problems first within each group.
- Show exact means of successful HTTP samples over the last 15 minutes, 1 hour and 1 day. These are independent of the chart period; empty windows remain unknown.
- Treat saved results as stale only after three effective polling intervals. Scheduling still uses one interval; failures and missing results remain immediate.
- Improve domain emphasis, text size, dividers, icon explanations and chart keyboard/touch interaction.

## Evidence

- Full Python suite: **976 passed**.
- Ruff, gettext validation, JavaScript syntax/behavior checks and Compose validation passed.
- Regression tests cover freshness boundaries, domain-specific intervals, unchanged due times, immediate failures, exact recent-window boundaries, weighted means, ownership isolation and empty windows.
- Firefox confirmed the rendered public page and keyboard-focus icon explanations.
- Headless Chromium checked 320, 390, 768, 960 and 1440 px; dark plus desktop/mobile light themes. No horizontal overflow; all three values fit. Arrow/Home/End navigation and pointer/touch inspection passed. No JavaScript exceptions were observed.
- Local Docker web service is healthy, `/healthz` returns `ok`, worker remains running. Hashes of all **21 changed package files** match the running web import path.
- SQLite backup passed integrity checking before the first image switch: `/data/backups/before-public-ui-20261105T062652Z.sqlite3` (private, mode 0600).

## VirusTotal finding

Recent saved malware results for the published shop URL say that VirusTotal has no URL report. The private API-key sidecar exists. The public page now shows the allowlisted explanation “No report in VirusTotal”, without raw diagnostics or credentials. No URL submission was performed. Creating a report requires a separate VirusTotal analysis request; the existing check only reads reports. See [VirusTotal Scan URL](https://docs.virustotal.com/reference/scan-url).

## Screenshots

- [Desktop, dark](screenshots/public-status-readability-desktop.png)
- [Mobile, dark](screenshots/public-status-readability-mobile.png)
- [Mobile, light](screenshots/public-status-readability-mobile-light.png)

Later on 2026-11-05, the owner requested automatic submission of missing URL reports. This supersedes the passive-only behavior described above; see [automatic-submission verification](verification-virustotal-auto-submit-2026-11-05.md).

A subsequent owner review restored the Checks section to the supplied compact reference: a flat two-column list (one column on phones), no category headings or visible diagnostic paragraphs, 13 px labels and a compact common timestamp. Diagnostic notes and individual timestamps remain in native hover hints; real overdue results retain their indicator. The explanatory paragraph below the response-time graph was also removed; pointer, touch and keyboard inspection continue to work. Full suite after the compact-list restoration: 989 passed. Firefox and headless Chromium confirmed the compact desktop/mobile layout. Screenshots: [desktop](screenshots/compact-checks-desktop.png), [mobile](screenshots/compact-checks-mobile.png).

The three recent response-time means were then condensed into one inline summary: “Среднее: 15 мин: … мс, 1 час: … мс, 1 день: … мс”. It wraps naturally on narrow screens. All 100 public-page and presentation tests passed after removing the chart instruction and changing this summary.
