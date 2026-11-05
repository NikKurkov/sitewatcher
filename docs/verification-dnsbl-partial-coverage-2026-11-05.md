# Neutral DNSBL source failures — 2026-11-05

Requested behavior supersedes the strict partial-coverage policy in the earlier
DNSBL recovery report. A source outage is not a website reputation problem.

- If at least one healthy DNSBL source completes all target IPv4 lookups and there
  are no hits, return OK. Missing coverage is a neutral diagnostic, translated as
  «Попаданий не найдено. Неполное покрытие источников DNSBL.»
- If no source completes the check, return UNKNOWN.
- Confirmed hits remain CRIT even when another source is unavailable.
- Keep source/query failures, completed-source count and partial_coverage in metrics.
- Version 3 invalidates old cached/serialized verdicts and schedules a fresh check
  without waiting for the daily interval. No sources, DNS resolvers or monitoring
  switches change; no schema migration is introduced.

Regression tests cover unavailable controls, target-query timeouts, zero completed
sources, multi-IP targets, preserved hits, old-cache invalidation, Russian wording
and owner overview/problem-filter behavior. Tests reproduced the old behavior
before implementation. Independent review found no blockers; 118 targeted tests
passed. Full Python 3.12/3.13/3.14 suites passed: 1038 tests each. Ruff, translations
and git diff checks passed.

Runtime and rollback evidence follows after deployment verification.

Runtime verification completed after the interrupted deployment turn: local image
308540aaaf23 and VPS image sitewatcher:28b30a4 are running. VPS web and worker have
zero restarts/OOM; public HTTPS health returned 200. All 137 runtime source hashes
match in each VPS container. Database integrity, domain/settings preservation and
single-worker scheduler lock passed. Backups: local
/data/backups/before-dnsbl-partial-20261105T152026390453Z/sitewatcher.sqlite3 and VPS
/data/backups/before-dnsbl-partial-20261105T152325941898Z/sitewatcher.sqlite3 (18 domains
each). Host rollback snapshot: /opt/sitewatcher/backups/dnsbl-28b30a4; previous VPS
image sitewatcher:2a6e247 retained. Built-image fault simulation verified one-source
failure => OK, all-source failure => UNKNOWN and hit+failure => CRIT. No browser
visual acceptance is claimed for the DNSBL text-only change.
