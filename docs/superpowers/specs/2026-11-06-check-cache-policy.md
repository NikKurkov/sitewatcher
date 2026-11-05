# Agreed check/network cache policy

The user's ten-item policy is approved for implementation. Slow metadata/reputation
must not inherit a shorter domain HTTP interval. TLS facts and DNSBL IP/source
results are persistent daily observations; WHOIS and VT keep their existing daily
protection. Explicit owner-only refresh may bypass TLS/WHOIS success TTL for a
single owned domain, never provider retry deadlines or VT's daily limit.

Network facts, local assessment time, next allowed network attempt and stale
coverage are distinct. Scheduler, reporting and alert recovery must use the same
check policy. Cache hits do not refresh evidence age or produce duplicate history;
a locally recomputed severity transition remains observable/alertable. Known expiry
or threats are not erased by a failed provider update. TLS verification of ordinary
HTTPS availability requests stays enabled.

RKN uses one shared daily registry refresh with cross-process claim and persistent
failure cooldown; membership checks read the local index. IP/DNS snapshots remain
operational, with per-cycle coalescing. HTTP/keywords/deface share one bounded fetch
per equivalent owner/URL/routing context in a run, retaining redirect/timing facts.
Ping/ports remain operational, with concurrent duplicate suppression. Route queue
and its hourly persisted cache remain separate and unchanged.

No dependencies or general job queue. Owner boundaries, CSRF, read-only controls,
public DTO allowlists, cancellation cleanup and bounded bytes/time remain required.
Back up and rehearse additive state changes before deployment. User has already
authorized server deployment/PR publication after checks in this conversation.
