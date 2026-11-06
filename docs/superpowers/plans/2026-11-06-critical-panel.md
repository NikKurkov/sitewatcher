# Critical panel implementation plan

> Execute inline using superpowers:executing-plans; user delegated design choices.

**Goal:** unresolved critical problems stay visible within Signal room until recovery.
**Architecture:** minimal durable incident rows updated atomically with monitoring history; owner activity API projects enabled checks into grouped UI. Existing polling, native disclosures and CSS pulse.
**Tech Stack:** Python/SQLite/Django, native JS/CSS.
**Spec:** docs/superpowers/specs/2026-11-06-critical-panel-design.md

## Constraints and review focus
Owner isolation and read-only GET; public output unchanged; no provider requests, no extra poller or dependencies. UNKNOWN/paused/replay/network failure must never imply recovery. History cleanup must not erase active incidents. Old renamed host evidence must not reopen. API diagnostics never exposed. Existing source/cache/auth behaviors retained.

## Tasks
- [x] Write failing persistence tests for CRIT repeat/duration, unrelated OK, WARN/UNKNOWN, same-check recovery, cleanup/restart, old history seed, rename/delete and owner isolation. Implement critical_incidents.py record/seed/read and storage transaction hook.
- [x] Add owner API tests: grouped enabled checks, no private diagnostics, no auth/query/method bypass or GET writes; public unchanged. Extend existing activity payload with critical_incidents.
- [x] Add shipped-JS regressions for retained rows on transport failure, pause/replay, fresh snapshot removal and grouped updates. Build semantic panel only in owner activity partial, reconcile keyed DOM via existing poll, reduced-motion responsive CSS, English/Russian strings.
- [x] Run focused/full Python matrix, Node/Ruff/gettext/CLI/Compose/package checks. Review final diff and synthetic browser desktop/mobile/fullscreen/connection behavior with screenshot. Fix any regressions.
- [ ] Commit/push focused PR stacked on PR24; verified pre-upgrade backup and network-isolated clone, immutable image deployment locally/VPS, source/data/health/worker/HTTP/browser read-back. Preserve rollback and report scope.

Ruling: the user's explicit 'только в центре сигналов' supersedes the initial all-admin suggestion. Existing 1315-test green baseline from c47c536 retained; no unrelated changes.

Validation: 1323 tests passed on each Python3.12/13/14; shipped Node suites, Ruff, gettext, CLI, migration drift and Compose checks passed. Real Chromium confirmed grouped API data, full screen, mobile, reduced motion and selected-map-detail bounds above the panel. Independent review reproduced an old-host opening-time backfill error; fixed with a red/green regression and re-reviewed. Release acceptance follows the implementation commit.
