# SiteWatcher Reliability Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans for integration and dispatching-parallel-agents for independent owned components. Track completion below.

**Goal:** Deliver dependable monitoring, persistent settings, recoverable notifications, and verifiable local operation.
**Architecture:** Retain the current dispatcher/checks/bot/storage boundaries. Apply narrow fixes at shared entry points, with temporary-database and mocked-I/O tests. No new runtime dependency.
**Tech Stack:** Python >=3.12, SQLite, httpx, Pydantic, python-telegram-bot, pytest, Ruff.
**Spec:** `docs/superpowers/specs/2026-10-21-reliability-design.md`

## Global Constraints

- Python 3.12+, one Telegram monitoring process, no external database.
- No production operations or real notification sends; secrets never printed.
- User authorized autonomous decisions and explicitly cannot answer approvals.
- Every task runs its regression tests RED then GREEN, followed by the full suite.

## Review Focus

- Concurrent updates and partial SQL failures must preserve data and owner isolation.
- Missing chat destination and transient send failures must not consume an alert transition.
- Malformed overrides and explicit zero values must not break scheduled monitoring.
- Network/certificate failures must not be reported as healthy.
- Long/escaped HTML and Unicode input must remain valid and readable.

## Tasks and ownership

- [x] **1. Atomic owner-scoped storage** — `storage.py`, storage tests. Reproduce unset failure and rollback/concurrent-patch behavior; use real SQLite tests; implement atomic writes and genuine deletion without resurrecting removed domains.
- [x] **2. Reliable Telegram boundaries** — `bot/utils.py`, `bot/app.py`, `bot/router.py`, optional bounded HTML helper, dedicated tests. Test remembered chat, denied-user/no-write, busy release, oversized escaped replies. Implement without changing alerts.py/config.py.
- [x] **3. Trustworthy network checks** — `checks/tls_cert.py`, `checks/whois_info.py`, `checks/ip_change.py`, dedicated tests. Pin wildcard one-label behavior, configured WHOIS database/fallback, persistent default DNS cache. Preserve cancellation and fail visibly.
- [x] **4. Valid configuration and recoverable scheduling/alerts** — coordinator owns `config.py`, `dispatcher.py`, `bot/alerts.py`, `bot/jobs.py`, cfg/CSV handlers and tests. Trace end-to-end override and notification flows; regression tests first for each confirmed failure; centralize boundary validation and durable transition retries.
- [ ] **5. Operational completion** — CLI diagnostics and docs, installed wheel/container smoke, both supported Python versions, full fresh-context review. Apply review fixes with regression tests; commit verified results and document exact commands/limitations.

## Execution record

- Baseline: 44 tests pass on Python 3.12 and 3.13; Ruff clean; wheel CLI/SQLite smoke passes.
- Checkpoints: `fd4b6b4` contributor guide; `594437d` completed Ponytail refactor.
- Confirmed before changes: unsetting `checks.ping` leaves it stored, because deletion is followed by merge against the original JSON.

- Core integration: atomic storage, Telegram boundaries, network failure classification, strict domain overrides, durable alert delivery, validated atomic CSV replacements.
- New operational command: `sitewatcher doctor --json`, read-only configuration/schema/integrity/permission checks with secret presence only.
- Core review: four reproduced findings (CSV zero export, invalid boolean flags, invalid inherited thresholds after unset, YAML recovery intervals) fixed with RED-to-GREEN tests. Also normalized unset names and checked existing database file permissions.
- Validation before core checkpoint: 190 tests on both Python versions, Ruff and diff whitespace checks (fresh run recorded in following commit). No live API calls or notification sends.
- Design decision: SQLite mode=ro may update existing WAL reader metadata, but never application database rows/journal content. Missing WAL metadata fails safely.
- DNS default cache migration: old standalone `ipchange_cache.sqlite` remains untouched. Set `ipchange.db_path` explicitly to retain its baseline; otherwise first run establishes a fresh baseline in the persistent application database.
