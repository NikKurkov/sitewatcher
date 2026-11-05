# SiteWatcher domain groups

The owner selected proposal 1: collapsible groups inside the existing monitoring
table, following the supplied dark-theme mockup. Goal: reduce scrolling while
keeping problems visible across groups. Tabs hide the wider overview; a selector
is compact but offers less visibility. The approved choice retains one shared
set of table columns and independently expandable group headers.

Each owner has a permanent Main group (Russian: Основная). Existing and unassigned
sites belong to Main. A domain belongs to one group; names/groups never change
check settings, scheduling, alerts or public-page publication. New groups can be
created, renamed and deleted; deletion returns members to Main. Add/edit forms
select a group; batch-add applies one group to all addresses. A bulk move action
organizes existing sites. Group membership survives renaming a domain.

Headers show site count and problem count, including when collapsed. Existing
search/status filters apply across groups; searches open matching groups. Group
open state is saved per owner/browser; filtered views do not overwrite it. Main
opens by default; a newly created group also opens on first display. Buttons
expand/collapse all. Favorites and manual order operate within each group. Failed
reorder restores the exact previous DOM ordering. Empty groups remain manageable;
empty filter results are explicit. Keyboard focus, native buttons and aria-expanded
must work; collapsed rows are removed from keyboard navigation. Mobile headers
and bulk actions wrap without horizontal page overflow. Light/dark themes reuse
existing tokens; no new fonts, illustration assets or dependencies are needed.

Implementation choices: Main has implicit ID 0 and memberships are absent for it;
two additive monitoring tables enforce owner-bound foreign keys for custom groups
and membership. No external infrastructure is added. Group names are private owner
metadata and are not included in public DTOs/pages. Public grouping can be considered
separately. Current snapshot/report architecture remains; collapsing reduces DOM
visibility, not total query cost. Do not claim this is pagination or lazy loading.

Additional approved fix: hide HTTP response charts where HTTP checks are disabled
or no HTTP observations exist in the selected period; keep meaningful failed-only
HTTP histories visible. Apply consistently to owner/public shared presentation.

Before any runtime schema initialization, take verified backups, rehearse on a
private clone and verify owner/domain/settings/history preservation. Full suites,
JS behavior checks, installed-container checks, browser desktop/mobile/theme and
keyboard checks are required before acceptance.
