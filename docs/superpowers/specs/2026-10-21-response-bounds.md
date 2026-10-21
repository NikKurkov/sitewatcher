# Bounded page responses

## Decision

Keep the existing HTTPX clients and retry helper. Bound page downloads so a single large response cannot accumulate arbitrary body data in the monitor. The user authorized autonomous product and reliability improvements; no approval pause is required.

- Add `http.max_response_bytes`, a positive operator setting defaulting to 8 MiB. Apply it to HTTP status, keyword and defacement checks only. Large registry downloads and external API behavior remain unchanged.
- Use public HTTPX streaming and redirect APIs. Bound both wire and decoded bytes across each GET's redirect chain. Request gzip/deflate; decode with bounded standard-library zlib operations. Do not use HTTPX private attributes or its unbounded automatic body decoder on this path.
- Preserve complete-body latency, redirect history, client/proxy ownership, ordinary retry behavior and cancellation cleanup. Size/codec failures are non-transient and must not repeatedly download the same oversized body.
- Incomplete inspection returns UNKNOWN. HTTP basic and keyword checks retain CRIT for known HTTP errors; defacement retains its inspection-coverage policy. Never label a truncated page clean.
- Test plain/compressed limits, intermediate redirects, normal decoding, unsupported/truncated encodings, HTTP failures, cancellation, and installed-package execution. Use small synthetic streams and no external services.

## Complexity boundary

One bounded helper and a small decoder, no custom transport, dependency, background service or generic codec framework. Reject unsupported encodings visibly. Do not add per-domain budget overrides or download persistence.
