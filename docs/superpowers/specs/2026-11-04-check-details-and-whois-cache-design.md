# Clearer details and daily WHOIS fetch policy

Approved six UI points plus follow-up WHOIS caching request on 2026-11-04.

UI: graph remains full width before a two-column check list (one column on phones).
Use Website response time + compact Average value, readable Y levels and intermediate
local-time X ticks. Preserve exact keyboard/pointer tooltips and gaps in samples.
Small normal dots, highlighted active point. Share the common check timestamp when
a majority has identical saved time; retain individual times for exceptions, stale
or missing checks. Distinguish a saved result from freshness with neutral Awaiting
update. Use dot/text for successful check statuses, fills for warnings/errors only.
Absent passive VirusTotal reports remain neutral UNKNOWN.

WHOIS: success data already have a 24h internal cache. Persist failed/in-flight
refresh attempts too, preventing 5–10 minute domain overrides from hammering the
provider. One logical refresh per configured refresh_hours (currently 24h), including
manual checks. Honor Retry-After if it asks for a longer wait. Keep last successful
snapshot and honest UNKNOWN error outcomes. State survives restart and respects
custom cache database paths. Other monitoring checks/settings remain unchanged.

Approach: extend existing chart presentation and shared detail partial, add a small
check-list presentation adapter, and persistent WHOIS backoff beside its existing
SQLite snapshot cache. No new dependency/framework. Never expose raw diagnostics in
public projections. Back up production and rehearse cache changes before release.
