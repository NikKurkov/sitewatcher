# VirusTotal daily cache — 2026-11-05

The global malware schedule was already 1440 minutes, but a domain interval
replaces per-check schedules, and manual web/forced bot checks bypass the generic
history cache. UNKNOWN results also bypass that cache by default. Production's
last-day audit found 725 malware history records across four owner/domain pairs,
with up to 243 records for one pair. These are observations, not an exact provider
request count.

A mandatory provider cache now uses an additive `virustotal_reports` table keyed
by owner and canonical HTTPS URL. SQLite reserves the lookup atomically before
network access. Successes, detections, pending analyses and provider failures
(including HTTP 429) remain cached for a rolling 86400 seconds. Repeated, forced,
short-interval, restarted and concurrent checks cannot bypass the cache. Recent
pre-upgrade provider observations seed it without another lookup. Cached outcomes
do not append duplicate monitoring history or extend the original expiry.

A local limiter refusal before any request releases the reservation. A 404 lookup
may still require one separately rate-limited submission POST; a refusal after
that lookup keeps the daily cooldown. Ambiguous/cancelled attempts retain their
claim to avoid duplicate requests; without a saved outcome, users see a neutral
no-result message until the next daily attempt. Credentials/proxy are still read
securely on each run; changing them does not force a same-day lookup.

## Validation

Seven new regression cases cover successful/429 caching across instances/event
loops, atomic concurrent reservations, owner isolation, the exact 24-hour boundary,
concurrent requests, legacy history adoption, unspent local quotas and forced
Dispatcher calls. Previous proxy/key reload and submission tests now explicitly
expire the daily cache before requiring another request. Red failures were
observed before implementation; 1123 tests passed on each of Python 3.12, 3.13
and 3.14. Ruff, msgfmt and diff checks passed. Provider responses are mocked in
these tests, avoiding real quota usage.

Runtime source commit: `362cf53`. Immutable source archive SHA256:
`0ac7eef12101bf34f96af2e96ad28eb6f7f845c280d6d68221b08ae45b17d58a`.

Verified online backups:

- Local: `/data/backups/before-groups-20261105T163707602549Z`.
- VPS: `/data/backups/before-groups-20261105T164019841220Z`.

Migration rehearsals on private copies passed in both environments: existing
rows/configuration/publication/history were identical; new cache table exists;
SQLite integrity and foreign keys passed. Local runtime matches all 143 tracked
package files in both containers; preservation and single-worker lock pass.

The first VPS backup failed because the filesystem was full; no application
switch occurred at that point. Twelve historical image archives (785852404 bytes)
were copied to `/home/niki/.local/state/sitewatcher/vpn-msk-archives`, SHA256-verified
before removal from the VPS, with local manifest `offload-20261105.json` and remote
`.offloaded` pointers. Existing tagged images and database backups were retained.
A fresh successful verified backup and clone rehearsal preceded the VPS switch.

Rollback: retain `sitewatcher:6895d5f`; restore the private compose/release snapshot
at `/opt/sitewatcher/backups/groups-362cf53` and restart web/worker. This change
only adds a table, so the preceding image can use the existing database. Preserve
the current database before any historical backup restore.

VPS post-switch checks: all 143 runtime package hashes match in web and worker;
configuration/publication/domain rows and pre-switch history match the backup;
SQLite integrity, foreign keys and the one scheduler lock pass. Both containers
run `sitewatcher:362cf53` with zero restarts and no OOM, loopback binding remains
127.0.0.1:8080. HTTPS health/demo return 200. Cache-only acceptance in the actual
web process reused four recent owner/domain reports on twelve repeats, including
provider failures, with the uncached path deliberately forbidden: zero outbound
provider requests. Filesystem available space after archive offload is 713 MB.
The same twelve-repeat acceptance also passed in the separate worker container,
confirming reuse of the database cache across processes, with no provider requests.
