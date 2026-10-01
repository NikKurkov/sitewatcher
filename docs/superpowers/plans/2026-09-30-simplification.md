# SiteWatcher Simplification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Keep all monitoring capabilities while making defaults, checks, scheduling, and delivery reliable and easier to understand.

**Architecture:** Retain the existing check classes and SQLite schema. Centralize owner-specific settings in the dispatcher, use per-check history to decide scheduled work, and share dispatch between CLI and bot.

**Tech Stack:** Python 3.12+, pytest, Ruff, httpx, python-telegram-bot, SQLite, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-09-30-simplification-design.md`

## Global Constraints

- Preserve every check and multi-user separation.
- English bot copy, simple user workflow.
- No database or YAML compatibility requirement.
- CI only; no deployment.

## Review Focus

- No YAML file: default configuration loads and validates.
- One owner's override cannot affect another owner's settings.
- Empty or unknown check selection returns a clear result.
- A periodic tick skips recent checks and disabled domains.
- A failed check or network error does not prevent other checks completing.

---

### Task 1: Configuration and dispatcher correctness

**Files:** `sitewatcher/config.py`, `sitewatcher/dispatcher.py`, `sitewatcher/main.py`, `tests/test_dispatcher.py`, `tests/test_config.py`

**Interfaces:** `load_config(path=None) -> AppConfig`; `Dispatcher.run_for(owner_id, domain, only_checks=None, use_cache=False, run_id=None) -> list[CheckOutcome]`.

- [ ] Write and run failing tests for default config, owner isolation, empty selection, CLI scan and per-domain proxy.
- [ ] Fix configuration resolution and dispatcher entry points with minimal code.
- [ ] Run focused and full tests; commit.

### Task 2: Scheduled due checks and efficient persistence

**Files:** `sitewatcher/bot/jobs.py`, `sitewatcher/bot/app.py`, `sitewatcher/storage.py`, `tests/test_jobs.py`, `tests/test_storage.py`

**Interfaces:** `due_checks(cfg, owner_id, domain, *, warmup=False) -> list[str]`; `storage.last_check_ages(owner_id, domain) -> dict[str, float]`.

- [ ] Write and run failing tests for interval boundaries, disabled schedule, owner isolation and database initialization.
- [ ] Implement due selection and batch history lookup; respect scheduler flags.
- [ ] Run focused and full tests; commit.

### Task 3: Simplify bot and request flow

**Files:** `sitewatcher/bot/handlers/checks.py`, `sitewatcher/utils/http_retry.py`, `sitewatcher/bot/handlers/help.py`, `tests/test_http_retry.py`, `tests/test_bot_checks.py`

**Interfaces:** Keep user commands; run ad-hoc checks through the dispatcher without persistence or alerts.

- [ ] Write and run failing tests for ephemeral checks and HTTP request handling.
- [ ] Remove duplicate run path and obsolete request arguments; simplify help and copy.
- [ ] Run focused and full tests; commit.

### Task 4: CI, docs, cleanup and final review

**Files:** `.github/workflows/ci.yml`, `README.md`, `CHANGELOG.md`, `pyproject.toml`, plus import cleanup.

- [ ] Add GitHub Actions test and lint workflow, update English documentation and changelog.
- [ ] Run Ruff, tests, build, and CLI smoke checks; fix issues found.
- [ ] Review the diff, commit, push branch, and create PR against `main`.
