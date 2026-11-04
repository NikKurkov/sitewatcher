# Unified Domain Disclosures Implementation Plan

> **For agentic workers:** Use superpowers:subagent-driven-development for independent tasks, followed by integrated review.

**Goal:** Implement six approved public/owner UX improvements.
**Architecture:** Keep owner table semantics with one tbody per domain pair; keep public native details. Share domain_details.html. State-preserving native refresh avoids new DOM initialization infrastructure.
**Tech Stack:** Django, native details/buttons, CSS grid, existing JavaScript, pytest and Chromium.
**Spec:** ../specs/2026-11-04-unified-domain-disclosures-design.md

## Global constraints

Preserve owner isolation, HTTP metric semantics, no-report VT neutrality, all current
owner controls, 44px targets, keyboard access, native fallback and both themes.
Do not deploy. Keep current feature branch and preserve other work.

## Review focus

Public messages/metrics must never leak; paused/stale/missing data remain honest;
reorder moves complete summary/detail groups; refresh cannot discard input or close
rows; multiple open charts must have unique accessible IDs and fit mobile widths.

## Tasks

- [x] Public agent: safe per-check attention flags/counts; compact header and period in list header; move checks and chart under same native details; tests for privacy and neutral VT.
- [x] Refresh agent: owner toggle/row click handlers and state-preserving refresh/navigation; keep filter behaviors and add meaningful JS/browser checks. Markers: data-domain-key groups; data-domain-toggle button with aria-controls; target hidden panel; public details[data-domain-disclosure]. data-disclosure-scope on list root.
- [x] Main: shared domain_details.html using checks/report/owner_detail variables; owner paired tbody controls; adapt reorder selectors to grouped tbody; scoped styling; rendering/regression tests.
- [x] Integrate and review changed tasks, run full Python/JS checks; synthetic browser acceptance light/dark 320–1440px including toggles, period/filter retention, reorder, refresh state, focus and scroll.
- [x] Update docs/screenshots, commit and refresh local containers with backup; verify actual served code and owner/public routes.

Validation: full pytest suite, Ruff, Node controls and JS syntax checks passed. Synthetic Chromium owner/public both themes 320/390/768/900/960/1024/1440px passed. Real Django fixture navigation verified multiple/nested open state, scroll/focus, period/filter/favorite navigation, atomic reorder and failure rollback, minute timer via virtual clock, input deferral and no-JS fallback. Independent code/UX/graphic reviews found no blockers. Local containers rebuilt successfully; live owner/public rendering, HTTP health and changed asset hashes verified. Backup integrity and pre-existing domains, overrides and history preservation verified; web/worker running with zero restarts and no OOM. Production is unchanged.
