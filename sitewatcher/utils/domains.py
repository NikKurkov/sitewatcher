# Shared domain normalization; independent of Telegram application imports.
from __future__ import annotations

import re
from typing import List, Optional
from urllib.parse import urlsplit, urlunsplit

__all__ = [
    "DOMAIN_RE",
    "normalize_domain",
    "normalize_site_url",
    "parse_domains",
]

# -----------------------------------------------------------------------------
# Domain regexes
# -----------------------------------------------------------------------------
# RFC 1035-ish label: starts/ends with alnum, allows hyphens inside, 1..63 chars.
# Allows punycode labels (xn--...), ASCII only after normalization.
_LABEL = r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)"

# Strict domain: at least two labels (e.g., example.com). ASCII only.
DOMAIN_RE = re.compile(rf"^(?:{_LABEL}\.)+{_LABEL}$", re.IGNORECASE)


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
def normalize_domain(raw: str) -> Optional[str]:
    """
    Normalize user input into an ASCII domain (IDNA) or return None if empty/invalid form.

    Steps:
      - Strip URL scheme (e.g., https://).
      - Cut off path/query/fragment after the first '/'|'?'|'#'.
      - Strip trailing dot (FQDN) and surrounding commas/semicolons/spaces.
      - Lowercase and convert Unicode domains to IDNA using the built-in 'idna' codec.
    """
    if not raw:
        return None
    s = str(raw).strip().lower()

    # Remove a scheme like 'http://', 'https://', 'ftp://', etc.
    s = re.sub(r"^[a-z][a-z0-9+\-.]*://", "", s)

    # Drop userinfo@host if pasted (rare but possible)
    if "@" in s:
        s = s.split("@", 1)[1]

    # Drop path / query / fragment if user pasted a URL
    s = s.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]

    # Tidy punctuation & FQDN dot
    s = s.strip(" ,;").rstrip(".")

    if not s:
        return None

    # Convert Unicode to ASCII (punycode). Built-in codec; no external deps.
    try:
        s = s.encode("idna").decode("ascii")
    except Exception:
        # Keep as-is if conversion fails; regex below will reject if not domain-like
        pass

    return s if len(s) <= 253 and DOMAIN_RE.fullmatch(s) else None


def parse_domains(args: List[str]) -> List[str]:
    """
    Extract domain names from arguments:
      - Skips flags (tokens starting with '--')
      - Accepts comma/space-separated lists inside a single arg: "a.com,b.com c.com"
      - Normalizes tokens (scheme/path/IDN/ending dot)
      - Deduplicates while preserving order
    """
    out: list[str] = []

    for a in args:
        if not a or a.startswith("--"):
            continue

        # Allow comma-separated list in a single arg: "a.com,b.com"
        for token in re.split(r"[,\s]+", a):
            d = normalize_domain(token)
            if not d:
                continue
            out.append(d)

    # De-duplicate while preserving order
    return list(dict.fromkeys(out))


def normalize_site_url(raw: str) -> Optional[str]:
    """Validate an HTTP target, retaining its path/query and defaulting to HTTPS."""
    value = str(raw or '').strip()
    if not value or len(value) > 4096 or "\\" in value or any(
        char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value
    ):
        return None
    try:
        parsed = urlsplit(value if re.match(r'^[a-z][a-z0-9+.-]*://', value, re.I)
                          else 'https://' + value)
        if parsed.scheme.lower() not in {'http', 'https'} or parsed.username is not None:
            return None
        host = normalize_domain(parsed.hostname or '')
        port = parsed.port
        if not host or parsed.netloc.endswith(':') or (port is not None and not 1 <= port <= 65535):
            return None
        authority = host + (f':{port}' if port is not None else '')
        return urlunsplit((parsed.scheme.lower(), authority, parsed.path or '/', parsed.query, ''))
    except (ValueError, UnicodeError):
        return None
