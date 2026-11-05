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
select a group; batch-add applies one group to all addresses. Dragging sites onto another group header or domain row organizes existing sites.
Group creation is also available inline via New and is atomic with domain saving. Group membership survives renaming a domain.

Headers show site count and problem count, including when collapsed. Existing
search/status filters apply across groups; searches open matching groups. Group
open state is saved per owner/browser; filtered views do not overwrite it. Main
opens by default; a newly created group also opens on first display. With a single group, no group header is shown. The user removed global
expand/collapse controls, management toolbar buttons and all list selection checkboxes.
Group management is linked only from Settings. Favorites and manual order operate within each group. Failed
reorder restores the exact previous DOM ordering. Empty groups remain manageable;
empty filter results are explicit. Keyboard focus, native buttons and aria-expanded
must work; collapsed rows are removed from keyboard navigation. Mobile headers
and group headers wrap without horizontal page overflow. Light/dark themes reuse
existing tokens; no new fonts, illustration assets or dependencies are needed.

Implementation choices: Main has implicit ID 0 and memberships are absent for it;
two additive monitoring tables enforce owner-bound foreign keys for custom groups
and membership. No external infrastructure is added. Group names stay private unless explicitly selected for a status page. Status-page
editors offer group checkboxes; selection dynamically publishes current members and
adds future members, unioned with individually selected sites. Only selected group
names may appear in public HTML; public JSON/activity stay scoped to effective
published domains and retain their minimal DTO contract. A single published group
does not add an extra header. Existing pages default to no selected groups. Current snapshot/report architecture remains; collapsing reduces DOM
visibility, not total query cost. Do not claim this is pagination or lazy loading.

Additional approved fix: hide HTTP response charts where HTTP checks are disabled
or no HTTP observations exist in the selected period; keep meaningful failed-only
HTTP histories visible. Apply consistently to owner/public shared presentation.

Before any runtime schema initialization, take verified backups, rehearse on a
private clone and verify owner/domain/settings/history preservation. Full suites,
JS behavior checks, installed-container checks, browser desktop/mobile/theme and
keyboard checks are required before acceptance.
