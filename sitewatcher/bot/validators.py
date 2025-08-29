# sitewatcher/bot/validators.py
from __future__ import annotations

import re
from typing import List

# Permissive domain validator (kept for input parsing)
_PERMISSIVE_DOMAIN_RE = re.compile(r"^[a-z0-9.-]+\.[a-z]{2,}$", re.IGNORECASE)

# Strict domain validator used for add_domain
DOMAIN_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$")


def parse_domains(args: List[str]) -> List[str]:
    """Extract domain names from arguments, skipping flags, deduping and preserving order."""
    out: list[str] = []
    for a in args:
        if a.startswith("--"):
            continue
        d = a.strip().lower()
        if d and _PERMISSIVE_DOMAIN_RE.match(d):
            out.append(d)
    # de-duplicate while preserving order
    seen: set[str] = set()
    uniq: list[str] = []
    for d in out:
        if d not in seen:
            uniq.append(d)
            seen.add(d)
    return uniq
