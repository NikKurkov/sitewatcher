# sitewatcher/checks/deface.py
from __future__ import annotations

import html
import time
from typing import Iterable, List, Tuple

import httpx

from .base import BaseCheck, CheckOutcome, Status
from ..utils.http_retry import get_with_retries


# Minimal built-in fallback markers; primary source can be a text file (one phrase per line).
_DEFAULT_MARKERS: Tuple[str, ...] = (
    "defaced by",
    "hacked by",
    "owned by",
    "pwned by",
    "was here",
    "сайт взломан",
    "сайт хакнут",
    "greetz",
    "0wned",
    "security breached",
    "this site has been hacked",
)


def _normalize_markers(markers: Iterable[str]) -> List[str]:
    """Normalize dictionary phrases: strip, lower, drop empties and duplicates."""
    seen = set()
    out: List[str] = []
    for m in markers:
        mm = (m or "").strip().lower()
        if mm and mm not in seen:
            out.append(mm)
            seen.add(mm)
    return out


class DefaceCheck(BaseCheck):
    """Scan the main page HTML for common defacement markers."""
    name = "deface"

    def __init__(self, domain: str, client: httpx.AsyncClient, *, timeout_s: float = 10.0, markers: Iterable[str] | None = None) -> None:
        super().__init__(domain)
        self.client = client
        self.timeout_s = float(timeout_s or 10.0)
        self.markers = _normalize_markers(markers or _DEFAULT_MARKERS)

    async def run(self) -> CheckOutcome:
        """Fetch '/' and look for defacement phrases (case-insensitive)."""
        # Try HTTPS, then HTTP as a fallback if HTTPS fails to connect.
        tried_urls: List[str] = []
        for scheme in ("https", "http"):
            url = f"{scheme}://{self.domain}/"
            tried_urls.append(url)
            try:
                start = time.perf_counter()
                r = await get_with_retries(
                    self.client,
                    url,
                    timeout_s=self.timeout_s,
                    retries=2,
                    backoff_s=0.25,
                    follow_redirects=True,
                    headers={"User-Agent": "sitewatcher/0.1 (+https://github.com/NikKurkov/sitewatcher)"},
                )
                elapsed_ms = int((time.perf_counter() - start) * 1000)
                redirects = len(r.history)
                code = r.status_code
                
                # We still inspect the body even for non-2xx in case the hacked page returns 403/503 but shows text.
                text = (r.text or "").lower()
                for phrase in self.markers:
                    if phrase in text:
                        # Report CRIT with the matched phrase highlighted.
                        return CheckOutcome(
                            self.name,
                            Status.CRIT,
                            f"'{phrase}' found on main page",
                            {"url": str(r.url), "matched": phrase, "status_code": code, "redirects": redirects, "latency_ms": elapsed_ms}
                        )
                # No markers found on a successfully fetched page: OK.
                return CheckOutcome(
                    self.name,
                    Status.OK,
                    "no deface markers",
                    {"url": str(r.url), "status_code": code, "redirects": redirects, "latency_ms": elapsed_ms}
                )
            except httpx.RequestError:
                # Try next scheme (HTTP) if HTTPS request failed to connect.
                continue
            except Exception as e:
                # Unexpected errors: UNKNOWN.
                return CheckOutcome(self.name, Status.UNKNOWN, f"deface check error: {e.__class__.__name__}", {})

        # Both HTTPS and HTTP failed to connect: UNKNOWN.
        return CheckOutcome(self.name, Status.UNKNOWN, "unable to fetch main page", {"tried": tried_urls})
