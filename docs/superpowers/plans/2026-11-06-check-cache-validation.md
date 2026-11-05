# Check cache policy validation

Validated on 2026-11-06 before release:

- Python 3.12, 3.13 and 3.14: 1238 tests each, all passed.
- Ruff, `git diff --check`, gettext `msgfmt --check`, CLI help, compileall,
  Django migration drift check and both Compose configurations passed.
- All `tests/*.cjs` browser-script checks passed.
- Synthetic Chromium desktop/mobile: TLS/WHOIS refresh actions, CSRF token,
  real mouse POST and honest cooldown notice; no horizontal overflow.
  Screenshot: `docs/screenshots/cache-metadata-refresh.png`.
- Independent final review: no remaining Important/Critical issues. Regression
  fixes cover retained TLS/WHOIS/RKN/VT threats and original evidence age,
  DNSBL custom resolvers and changes of IP with older shared observations,
  operational progress during RKN download, concurrent ping/ports, and interrupted
  VT reservations without false clean results or repeated activity events.

Provider traffic in regressions is mocked. Runtime release acceptance must separately
verify immutable image/source hashes, private backup/clone integrity, preservation of
existing data/history/cache, one worker lock, public HTTP/assets and effective daily
metadata intervals. No production quotas are spent for a manual acceptance test.

The VirusTotal aggregate API limiter remains process-local; durable per-owner/URL
lookup/submission guards prevent daily duplicates across processes. A global budget
across different domains/workers is a separate improvement, not provided by this release.
