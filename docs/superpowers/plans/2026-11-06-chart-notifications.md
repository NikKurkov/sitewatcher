# Compact chart averages and domain notification channels

User scope: integer chart values; compact 15min/hour/day/month averages with period tooltips; per-domain email/Telegram subscriptions using account-level channels; propose a simpler add/edit card without applying the full redesign.

- [x] Preserve analytics classification/owner boundaries; calculate rolling30-day averages independently of selected1/7/30-day chart window. Keep SQL aggregation bounded and no raw provider diagnostics public.
- [x] Render integer values/axis/tooltips; compact four averages separated by slashes, units and periods in accessible hover/focus/touch tooltip; no-data dash.
- [x] General email settings: recipient scoped to Workspace; private installation SMTP config using existing0600 atomic secret storage. No password disclosure, CSRF-protected save/test, standard SMTP/TLS transport, bounded timeouts. Legacy installations remain functional without email configured.
- [x] Domain add/edit: independent Email/Telegram subscription controls. Existing Telegram behavior preserved; unconfigured email cannot silently appear subscribed. Old forms/API saves preserve channel settings. Owner isolation, rename/reset and public DTO boundaries retained.
- [x] Alert delivery: eligible configured channels only; status changes/recovery follow current policies. Separate durable delivery state per channel so one channel's success cannot discard another's failure; no duplicate retries for a delivered channel. Existing Telegram compatibility retained; no real messages during verification.
- [x] Regression tests, independent review, full Python matrix/Node/gettext/CLI/migrations/Compose checks, synthetic browser validation. Verified backup/clone before migration; PR and deployment/read-back per standing authorization.
- [x] Present add/edit UX proposal: four sections, progressive disclosure, presets, contextual options, validation and persistent save action. Final redesigned form remains a proposal pending user choice.

Technical choices: month means rolling30days; global SMTP transport configured once in Settings, domain selects channels only. New email delivery is opt-in and needs valid recipient+SMTP. No new dependencies.

## Pre-release validation

Baseline1281tests passed. Final full suites passed1313tests each on Python3.12/13/14;
an additional public-notification privacy regression passed on all three, giving
1314collected tests. A CI cold-start SQLite race was then reproduced with a
deterministic regression and fixed by serializing first-time initialization.
All1315tests passed again on Python3.12/13/14 after this fix. Node behavior, Ruff, gettext, CLI, migration drift and Compose
checks passed. Two independent reviews found and verified fixes for YAML-inherited
subscription preservation during rename and false asynchronous SMTP deadlines.

Real Chromium saves with synthetic settings verified hidden SMTP passwords,
recipient configuration, domain channel persistence, compact four-window values,
month hover and mobile layout. SMTP/Telegram delivery in tests is mocked; no real
messages were sent. Actual SMTP delivery requires the owner to configure and test
the connection in Settings.

The form proposal is docs/design/domain-form-proposal.html with an accompanying
screenshot. Profiles and full form restructuring remain a proposal. Release
acceptance (backup/clone/migration/runtime/CI) follows the implementation commit.
