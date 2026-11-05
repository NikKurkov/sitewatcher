# Remembered sign-in — 2026-11-05

The login form has an unchecked-by-default “Remember me for 30 days” checkbox.
Successful sign-in sets a 30-day expiry only when selected; ordinary sign-in stays
at the configured 12 hours. Native Django sessions, session rotation, CSRF,
HttpOnly/SameSite/Secure cookies, sign-out and password revocation are retained.
Existing sessions keep their previous expiry until the next sign-in.

Validation: 1008 Python tests passed, all five Node test files passed, Ruff,
msgfmt and diff checks passed. Regression cases cover cookie age/persistence,
browser reopen, ordinary sign-in, expiry, logout, password revocation, failed
login and HTTPS cookie flags. Chromium checked the native checkbox and layout at
1440 and 320 pixels, dark/light themes, with no overflow or JS exceptions.

[Desktop](screenshots/login-remember-me-desktop.png) · [Mobile](screenshots/login-remember-me-mobile.png).
