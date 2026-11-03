# Local Dashboard Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans for integration and dispatching-parallel-agents for disjoint components.

**Goal:** View saved monitoring results in a safe, clear local dashboard.
**Architecture:** Read-only snapshot -> stdlib loopback HTTP server -> packaged HTML/CSS, no JavaScript framework.
**Tech Stack:** Python >=3.12, sqlite3, http.server, string.Template, pytest.
**Spec:** `docs/superpowers/specs/2026-10-21-local-dashboard-design.md`

## Global Constraints

- No new runtime dependencies, no remote bind/publish, explicit positive owner.
- Read-only database access; no config or secret values in HTML/JSON.
- Existing bot/CLI behavior preserved; tests offline except loopback sockets.

## Review Focus

- Owner isolation despite query/path manipulation.
- DNS rebinding Host headers and external Origin values.
- Stored HTML, quotes, Unicode and long messages.
- Missing/stale/paused results and incompatible databases.
- Installed-package assets and shutdown behavior.

## Tasks

- [x] **1. Owner-scoped snapshots** — `reporting.py`, `tests/test_reporting.py`; implement exact spec contract with read-only consistent SQL queries and freshness tests.
- [x] **2. Local HTTP boundary** — `web.py`, `tests/test_web.py`; real loopback tests, safe headers, fixed owner, readonly endpoints and clean lifecycle.
- [x] **3. Dashboard and CLI** — `dashboard.py`, packaged HTML/CSS, `main.py`, packaging metadata, UI/CLI tests; keyboard/no-JS functionality, responsive layout, safe escaping.
- [x] **4. Product verification** — wheel/container/browser smoke, measured scheduler/storage workloads, full tests on Python 3.12–3.14, independent review, docs and local commits.

## Execution Record

- User explicitly authorized autonomous design/implementation without review pauses; no approval requested.
- Reliability checkpoint `b469df7`: 190 tests pass on Python 3.12/3.13, Ruff clean.

- Phase2 implemented: owner-scoped consistent snapshots, loopback HTTP/JSON, native HTML/CSS and explicit-owner CLI. Auto-refresh can be paused while reading.
- Real Chromium verification: 1440/390/320px, no horizontal page overflow; expansion, search/filter, accessible names and refresh pause passed.
- Native HTTPX integration: two local CONNECT proxies and TLS origin verified target/global routing and cancellation cleanup.
- Fresh full verification: 332 tests on Python 3.12, 3.13 and 3.14; Ruff/diff clean before final review corrections.
- Installed wheel assets and local socket smoke passed outside source checkout. Docker synthetic private-config/cache canaries excluded; installed dashboard/config assets present.
- Read performance: added latest-ID index and native seeks, with read-only legacy fallback. Three bounded reads (including index metadata), no per-domain queries. Synthetic 4.36M histories: snapshot median 346.59 -> 25.34ms, index +151MiB/+14.4% storage, writes +7-8%/~20-24us per 3-result batch in warm temporary storage.
- Ten-minute synthetic concurrency run: six readers, background writer, 500 visible domains/240k starting history rows; no errors, final integrity OK. First 573s recorded 9,366 reads/5,114 writes, read p50 234.8ms/p95 274.4ms. One-hour indexed run in progress.
- Final review found explicit empty port CSV overrides were lost in merge imports; reproduced and fixed with JSON list cells, preserving legacy comma input and blank-cell behavior.

- Final runtime checkpoint `23c9a11`: 473 tests on all three Python versions and in both installed-package environments. Wheel, image source and installed image copies match byte for byte across all 55 application/resource files.
- Final storage evidence includes a backup under six-reader load, restored owner snapshots and SIGKILL rollback experiments. Native Compose volume persistence and clean SIGTERM shutdown passed twice.
- Measured final reporting study: 4,365,002 histories, complete snapshot median 349.50 -> 22.17 ms; index and write overhead are documented with the result, without claiming production latency.
- Final user-facing verification and operational limits are collected in `docs/verification-2026-10-21.md` and `docs/operations.md`.

- Final one-hour six-reader/writer soak completed 57,924 reads and 32,075 writes in 3,600.98 seconds, with zero errors and integrity `ok`; recorded source checkpoint `baa014f`. Later isolated command/diagnostic corrections have separate final regression coverage.
