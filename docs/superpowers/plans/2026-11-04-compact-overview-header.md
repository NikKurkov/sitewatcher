# Compact Overview Header Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans to implement this task.

**Goal:** Give the domain table more vertical space by moving the overview status beside the logo.
**Architecture:** Add an empty base-template header block; populate it only in the overview. Retain period links and timestamp in a compact results toolbar. Scope responsive CSS to the overview header.
**Tech Stack:** Django templates, existing CSS, pytest, Chromium.
**Spec:** ../specs/2026-11-04-compact-overview-header-design.md

## Global Constraints

- Preserve all states, counts, translations, native controls and existing palette.
- Preserve unrelated pending changes; do not deploy.
- Keep 44px action targets; wrap long Russian labels rather than truncate them.

## Review Focus

- Empty overview must not show an empty status block.
- Settings and public pages must not acquire the owner status.
- Warning, waiting, paused and healthy states must retain their text.
- Period links must retain current filters.
- Narrow screens and dark mode must remain readable without horizontal overflow.

## Task: Move and verify the summary

- [x] Add a rendering assertion for summary placement inside the header and toolbar inside main; run it and confirm failure.
- [x] Add `header_summary` block after the brand in base.html; move the overview summary there and place its controls above the table.
- [x] Add scoped responsive CSS for two-line status, compact symbol and results toolbar. Use a neutral symbol for waiting/paused.
- [x] Run presentation/public/domain tests and Ruff, then render synthetic Russian fixtures for Chromium checks at 320, 390, 768, 1024 and 1440px in both themes. Save review screenshots.
- [x] Review with the UX and graphic designers, fix material issues, record verification and leave changes ready for review.

## Execution notes

Use the existing checkout on a new feature branch to preserve the pending approved
changes that touch the same base template. No worktree copy or production data is needed.

Verification: 130 presentation/public/domain tests passed; Ruff and diff whitespace checks passed. Chromium verified both themes at 320, 390, 768, 900, 1024 and 1440px: no horizontal overflow and all measured action targets at least 44px. The synthetic table starts 86px earlier at 1440px and 57px earlier at 390px. Both designers reviewed the screenshots without blocking findings. Existing mobile domain-name wrapping is outside this change. No production deployment.
