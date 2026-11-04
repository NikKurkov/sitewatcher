# Clearer Domain Details and Daily WHOIS Cache Plan

> Use subagent-driven-development for independent chart and WHOIS tasks; integrate and review before publishing.

Goal: implement six approved detail UI improvements and persistent daily WHOIS refresh/backoff.
Spec: ../specs/2026-11-04-check-details-and-whois-cache-design.md
Stack: existing Django/SQLite/httpx/native JS/CSS; no new dependencies.

Constraints: preserve gaps, timestamp accuracy, keyboard/pointer access, owner/public
boundaries, 24h WHOIS success cache and current HTTP/scheduler settings.

Review focus: zero/empty/large chart values, localized/timezone scales, mixed check
timestamps, neutral VT UNKNOWN, stale OK freshness, RDAP retries after process restart,
HTTP-date/seconds Retry-After and concurrent same-domain attempts.

- [ ] Chart agent: presentation.py chart_context/report_context, chart.html and chart tests only; preserve other helpers. Produce chart ticks using existing UTC window + workspace timezone and numeric levels from same plot scale; compact caption title and mean. Send new CSS hooks/msgids.
- [ ] WHOIS agent: whois_info.py and tests/test_whois.py (+storage only if needed); persist success/failure attempt cooldown and Retry-After with minimal additive state. Red/green tests for repeated attempts, restart and expired retry window.
- [ ] Main: shared detail/check presentation adapter, majority timestamp handling and CSS, neutral freshness labels and successful dot statuses; translations and UI regression coverage.
- [ ] Integrate, independent review, full Python/JS tests and synthetic Chromium both themes/mobile for axes, gaps, mixed timestamps and interactions.
- [ ] Commit, back up/rebuild local containers; immutable release to vpn-msk with verified backup, private rehearsal, source/asset/data/health/scheduler readback.
