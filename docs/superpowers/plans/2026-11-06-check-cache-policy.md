# Check cache policy implementation

Spec: ../specs/2026-11-06-check-cache-policy.md

- [x] Shared per-check effective intervals/result deadlines for scheduler, reporting
  and alerts; no repeated VT activity while its daily observation remains valid.
- [x] Persistent cache primitive + DNSBL daily IP/source answers and source-health
  cache; resolve only needed address families, retain coverage semantics.
- [x] TLS daily facts with local expiry assessment, legacy observation adoption,
  explicit per-domain owner refresh. WHOIS explicit refresh + cached/failure facts.
- [x] Shared daily RKN registry preparation, cross-process refresh claim, failure
  backoff, local-only membership checks; no downloads per domain on source failure.
- [x] Per-run HTTP/DNS coalescing, bounded bytes/redirect metadata, cancellation
  isolation; operational ping/ports duplicate suppression across concurrent runs.
- [x] Owner UI/manual routes/CLI semantics, docs/config examples/translations.
- [x] Independent review, targeted regressions, full Python3.12/13/14 and Node,
  synthetic browser manual-refresh checks; see check-cache-validation companion.
- [ ] CI, verified backup/clone/immutable release, runtime assets/data/history/worker
  read-back and PR update (release acceptance after the implementation commit).

Ownership: root owns policy, dispatcher/scheduler/reporting/alerts/storage, TLS/WHOIS,
manual UI/CLI and integration. Provider agents own isolated RKN, DNSBL/cache primitive,
and HTTP/run-context files plus their tests. They do not edit shared orchestrators,
config.py or production state. Root integrates their interfaces sequentially.
