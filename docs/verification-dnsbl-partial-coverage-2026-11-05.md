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
