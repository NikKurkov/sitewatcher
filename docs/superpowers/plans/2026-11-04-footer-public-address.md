# Compact footer and persistent public address

Approved in conversation: remove the footer rule and large gaps, center the project
link, and put the public-page link next to it. Store an editable public address in
the database, defaulting to /status. Deploy all approved pending panel changes to
vpn-msk after verification, with a data backup and rollback package.

Implementation: add a unique workspace slug through an additive migration; first
workspace gets status and other workspaces get independent random paths. Reuse the
existing early public boundary, HTTP report projection and selected-domain checks.
Preserve old bearer links; their rotation remains independent of the named address.
Reserve application routes, reject collisions and invalid paths, require owner auth
and CSRF for settings edits, and disable both addresses when publication is off.

Checks: named-page rendering/data/activity, path edits and invalid/reserved paths,
owner isolation, disabled publication, anonymous read-only access, full suite, Ruff,
translations and browser checks. Deploy a committed release; verify archive hash,
backup integrity, migration rehearsal, data preservation, web/worker health,
scheduler lock, served assets and production /status. Retain the prior image.
