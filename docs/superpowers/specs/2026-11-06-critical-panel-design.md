# Persistent critical problems in Signal room

Approved direction: compact bottom-right panel, only inside Signal room (including its fullscreen dialog). No panel on other pages or public status pages. Existing dark instrument-panel palette, restrained red edge and slow pulse, readable static text, keyboard links, reduced-motion override.

Each owned domain has one expandable row listing its unresolved critical checks and start time. Latest CRIT opens/updates an incident; only OK of that same check clears it. WARN/UNKNOWN and paused monitoring keep the incident and show the last known state. Unrelated successful checks, bounded event history, animation pause/replay, connection loss and page reload cannot clear it. Removal/rename removes old-host incidents; disabled checks are omitted until re-enabled. No dismiss/acknowledge button.

Store minimal incident state transactionally alongside saved results, not in the browser. Seed existing unresolved CRIT history on initialization; no raw diagnostics/metrics in API or HTML. Reuse authenticated activity polling and snapshot resolution. Transport errors retain rendered rows and show stale connection. Owner-scoped read-only GET; public API unchanged. Group domains, fixed-height scrolling list, visible count; no animation of text. On narrow screens position below scene in normal flow, with compact native disclosure. Keep map, route controls and console usable.

Approaches: chosen local corner panel preserves the existing scene width; a permanent column narrows it and a bottom strip hides too much on desktop. No new dependency or independent polling loop. Worker owns durable incident updates; additive monitoring schema, no Django migration.
