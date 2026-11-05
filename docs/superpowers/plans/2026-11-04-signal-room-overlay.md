# Signal room overlay

Approved visual concept: /tmp/sitewatcher-signal-concept/index.html. Console blends into
left side of the map, hub at center, domain cards right. Turquoise restrained glow.
Persistent fullscreen display; actual timestamp/check/domain/result/duration, no fake data.

1. Move shared console into activity-stage. Preserve all JS hooks and accessible log.
2. Render structured fields using textContent, retain public privacy and owner links.
3. Desktop stage overlays left console and reserves map space; fullscreen fills remaining
   viewport. Mobile puts readable console above map. Preserve route inspector controls.
4. Browser checks: owner/public, desktop/mobile/fullscreen, fields, follow/scroll, pause,
   replay, keyboard and no overflow. Run existing activity Python and JS checks.
5. Update changelog/screenshots, commit/push PR. Deploy immutable image with backup,
   private migration rehearsal, data/source/asset/health/scheduler and browser readback.
