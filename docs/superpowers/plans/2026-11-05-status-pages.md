# Multiple status pages

**Goal:** Add a Status pages section in Settings with a list and create/edit forms for title, public/private access and selected owned domains.

## Design

- Store each page in a Django StatusPage model linked to its Workspace; owner language/timezone remain shared.
- Migrate the existing page with its address, selected domains, enabled state and token hash intact. Keep the previous publication POST endpoint as a compatibility bridge.
- Public pages have stable root addresses; private pages are accessible only through a random bearer URL. Raw private tokens are shown only after creation/rotation; only hashes are stored.
- Reuse the existing safe report and activity projections and the early public boundary. Public GET/HEAD must not create sessions, perform checks or write data.
- Native owner-only forms provide title, access, enabled state and domain checkboxes. Private links can be reissued; pages can be disabled/deleted independently of monitoring.
- Protect edits against stale submissions, bound form input and validate every domain against current ownership.
- Display a custom title on the status page; preserve the existing compact monitoring layout.

## Tasks

- [x] Regression tests for multiple pages, title escaping, private/public transitions, token revocation, owner isolation, CSRF/read-only, stale edits and migration compatibility.
- [x] Model/migration and public read routing, retaining previous URLs.
- [x] Settings list/editor and safe native actions; update domain rename handling.
- [x] Translations, documentation, full suite, backup/migration/deployment read-back and browser acceptance.

The compact response metrics and HTTP-history colours are independent visual subtasks delegated to the requested UX/web designers.
