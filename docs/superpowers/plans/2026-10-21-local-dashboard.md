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

- [ ] **1. Owner-scoped snapshots** — `reporting.py`, `tests/test_reporting.py`; implement exact spec contract with read-only consistent SQL queries and freshness tests.
- [ ] **2. Local HTTP boundary** — `web.py`, `tests/test_web.py`; real loopback tests, safe headers, fixed owner, readonly endpoints and clean lifecycle.
- [ ] **3. Dashboard and CLI** — `dashboard.py`, packaged HTML/CSS, `main.py`, packaging metadata, UI/CLI tests; keyboard/no-JS functionality, responsive layout, safe escaping.
- [ ] **4. Product verification** — wheel/container/browser smoke, measured scheduler/storage workloads, full tests on both Python versions, independent review, docs and local commits.

## Execution Record

- User explicitly authorized autonomous design/implementation without review pauses; no approval requested.
- Reliability checkpoint `b469df7`: 190 tests pass on Python 3.12/3.13, Ruff clean.
