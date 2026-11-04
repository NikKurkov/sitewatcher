# Unified domain disclosures

All six recommendations approved in conversation on 2026-11-04.

Owner and public pages use compact closed domain rows. Each domain has one
expandable area containing current checks and the HTTP chart. The graph comes first across the full width. Checks follow below in two desktop
columns and one mobile column, per the approved follow-up. Keep owner favorites, reorder,
edit, manual check, pause and full history links outside the expandable area.
Multiple domains may be open. Interactive controls must not toggle the row.

Public header follows the owner header (logo, separated summary, relative latest
result time, appropriate read-only actions and theme). Period stays in the list
header. Public availability explicitly means HTTP; independent check warnings
remain visible when the HTTP badge is green. No-report VirusTotal is informational.
Public DTOs expose only safe statuses/times/attention flags, never messages,
credentials, private domains or owner IDs. Counts are publication-scoped.

Remove the About these figures panel and repeated portfolio HTTP statistics from the public page, per the approved follow-up. Sort real problems
first in the detail list. Preserve empty, paused, stale and unavailable states.
Refresh keeps open rows, period, filters, scroll and keyboard focus, and continues
while merely reading details. It must not interrupt active input or dragging.
Refresh state is scoped to account/page and public publication URL. Invalid/deleted
saved rows are ignored. Native no-JS navigation/history remains usable.

Approach: preserve the owner table and group each summary/detail pair in one tbody
so drag and keyboard reorder move the pair atomically. Public uses existing native
details with both checks and graph inside it. Share the inner detail partial and
visual layout; reuse native HTTP navigation with saved UI state for refresh rather
than adding a frontend framework or replacing DOM with uninitialized scripts.
No production deployment is included in implementation; update local containers.
