# DNSBL recovery and source validation — 2026-11-05

The former example configured Spamhaus ZEN, DroneBL and EFnet RBL. Removing the
example in 2900f18 left empty built-in sources. Enabling the check in the owner UI
therefore did not make it usable. The old probe also treated every A answer as a
listing, including Spamhaus access-denied replies.

## Research and live qualification

Reviewed operator documentation for Spamhaus, DroneBL, Blocklist.de, PSBL and
SpamCop, plus GitHub implementations/data in andreasf/check-dnsbl,
sbonfert/rbl-checker and ircd-hybrid/hopm (reference.conf). Old GitHub zone lists
contain retired entries and cannot be imported without live qualification. No
third-party implementation was copied and no dependencies were added.

Queries were made from the running vpn-msk worker container, first through its
system Docker resolver and then separately through Cloudflare and Google. Both
127.0.0.2 (positive) and 127.0.0.1 (negative) controls were queried.

| Source | Observed result | Decision |
| --- | --- | --- |
| DroneBL | Positive 127.0.0.1; negative NXDOMAIN; repeated across three resolvers | Default; .1 accepted only for the positive control |
| Blocklist.de | Positive 127.0.0.2; negative NXDOMAIN; repeated across three resolvers | Default |
| PSBL | Positive 127.0.0.2; negative NXDOMAIN; repeated across three resolvers | Default |
| Spamhaus ZEN | Both controls returned 127.255.255.254 with the runtime resolver | Exclude from defaults; access denial, not a listing |
| EFnet RBL | Initial timeouts; subsequent positive and negative both NXDOMAIN | Exclude; positive control missing |
| SpamCop | Initial system controls passed, later timed out; Cloudflare passed; Google NoNameservers | Optional only; unstable in this environment |
| Barracuda | Both controls passed once | Exclude by default; resolver registration/access requirements need separate setup |
| SORBS | Positive and negative both NXDOMAIN | Exclude; positive control missing |
| SpamRATS | Controls timed out | Exclude |
| Mailspike | Positive timed out; negative NXDOMAIN | Exclude |

DroneBL, Blocklist.de and PSBL also passed controls from the local Compose worker.
The new code and built image returned OK for a.tabak-pochtoy.com with three sources,
and the live 127.0.0.2 positive target returned CRIT with three hits. Exact target
mail.tabak-pochtoy.com returned NXDOMAIN through all three tested VPS resolvers;
its reputation cannot be checked until it resolves. It was absent from both the
VPS and local monitoring databases checked in this session.

These observations establish reachability and control behavior at the time of the
probe, not future uptime or completeness/freshness of a provider's underlying data.

## Resulting behavior

- Built-in sources work without a YAML file; explicit zones: [] remains explicit.
- Default source query timeout is four seconds, per-check concurrency eight.
- Both controls must pass before a source can contribute a clean result or hit.
- Unexpected/invalid return codes and access errors are UNKNOWN, never false hits.
- Real hits remain CRIT with an incomplete-coverage note if another source fails.
- Metrics retain checked/total sources, failures, IPs, response codes and hits.
- UNKNOWN is not cached by default. Legacy results and changed source/resolver
  configurations are bypassed and scheduled again without waiting one day.
- Source failures do not cause queries through arbitrary alternative resolvers.
- IPv4 only; the existing check_ipv6 flag detects AAAA presence and is not an
  IPv6-reputation implementation. DNSBL changes do not modify monitoring switches,
  owners, groups, notifications or public-page publication settings.
- Missing configuration and clean results have Russian UI translations.

## Verification

- New regression tests reproduced the old false listings, missing defaults,
  unvalidated dead/wildcard zones, stale cache and delayed rescheduling before fixes.
- Python 3.12, 3.13 and 3.14 full suites: 1033 passed each; Ruff and git diff --check passed.
- Compose configuration validated and image sitewatcher:local built successfully.
- Installed-package smoke in a network-disabled, capability-dropped nonroot
  container passed health/authentication-boundary and Russian diagnostic checks.
- Independent read-only code review found no blockers; 43 targeted tests passed.

Deployment evidence is recorded separately after runtime verification. No database
schema change is required for this fix.

## Runtime verification

Code release: `2a6e247` (branch `fix/dnsbl-source-validation`).

Local Compose was rebuilt and restarted with image `87bd9c356c6b`. The pre-switch
SQLite backup is `/data/backups/before-dnsbl-20261105T145557547221Z/sitewatcher.sqlite3`.
All 18 domain rows and the full domain-overrides fingerprint were preserved.
Web is healthy, exactly one worker holds the scheduler lock, and all 137 tracked
runtime files in both containers match the committed source. The running worker
returned OK with all three sources for the real clean-target probe.

The VPS archive SHA-256 is
`063b8d0e74327a147bc1d19715c408f6c22c9e23ec2c176cf5f835699a300f83`.
It was verified before building `sitewatcher:2a6e247` (image `72154be00f9d`). Before
the switch, this image passed migration/preservation/integrity checks on a private
clone of the VPS database in a network-disabled nonroot container. Live probes
from that image returned OK/three checked sources for a.tabak-pochtoy.com and
CRIT/three hits for the synthetic 127.0.0.2 target. Controls were tested before
adding the default sources to the running deployment.

The final VPS pre-switch backup is
`/data/backups/before-dnsbl-20261105T150352106056Z/sitewatcher.sqlite3`, private with
integrity OK. Host configuration/release snapshots are in
`/opt/sitewatcher/backups/dnsbl-2a6e247/`; immutable source, commit ID, binary patch
and deployment script remain in `/opt/sitewatcher/upgrades/`.

Both live VPS services now use `sitewatcher:2a6e247`, with zero restarts and no OOM.
All 17 domains and domain-settings fingerprints match the final backup. SQLite
integrity is OK, the worker holds the single scheduler lock, and 137 runtime source
hashes match in each container. Public HTTPS returned 200 for health, 302 for the
protected root and 200 for login. The backup timer remained active. A live-worker
DNSBL probe after switching returned OK with three sources and zero hits/errors.

Rollback requires restoring `compose.yaml` and `release.txt` from the private host
snapshot and running `docker compose up -d --no-build --wait web worker` in
`/opt/sitewatcher`; previous image `sitewatcher:98d6977` remains available. No schema
or application-setting change was made. For local rollback, retag the preserved
`sitewatcher:before-dnsbl-20261105` as `sitewatcher:local`, then recreate web/worker.
No browser visual acceptance is claimed; UI diagnostic translations were verified
through Django and the installed-package checks.
