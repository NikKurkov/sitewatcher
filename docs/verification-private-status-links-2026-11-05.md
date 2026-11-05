# Recoverable private status links — 2026-11-05

Owner-only Status pages now displays new private links with Open and Copy controls;
the editor also displays their current address. Tokens are derived with Django's
SHA-256 salted HMAC from a per-link random nonce, workspace identity and the server
secret. The database retains the nonce and token hash, without the raw bearer token.
A hash match is required before revealing a derived URL. Disabling, rotating or
switching to public access revokes and clears the old nonce/token as appropriate.

Migration 0007 adds a blank nonce; old private links keep working. Their raw address
cannot be recovered from the old hash, so the owner sees a one-time reissue hint.
No existing links are automatically rotated. Preserve the server secret alongside
backups to recover new links after restoring the database.

Validation: owner-only visibility, independent workspaces, secret mismatch,
legacy link compatibility, reissue, public-mode transitions and existing security
regressions passed. Chromium at 1440/390/320 pixels verified displayed URL,
Open destination, actual clipboard contents after clicking Copy, anonymous access
to the private page, no horizontal overflow and no JS exceptions. Screenshots use
only an isolated synthetic database: [desktop](screenshots/status-private-links-desktop.png),
[mobile](screenshots/status-private-links-mobile.png).

Full Python suite: 1010 passed. All five Node test files, Ruff, msgfmt and migration-drift checks passed.
