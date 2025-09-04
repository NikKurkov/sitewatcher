# sitewatcher/checks/deface.py
from __future__ import annotations

import logging
import time
from typing import List, Optional

import httpx

from .base import BaseCheck, CheckOutcome, Status
from ..utils.http_retry import get_with_retries

# Module-level logger for structured events
log = logging.getLogger(__name__)


class DefaceCheck(BaseCheck):
    """Detect common website defacement markers on the main page."""

    name = "deface"

    def __init__(
        self,
        domain: str,
        *,
        client: httpx.AsyncClient,
        timeout_s: int = 5,
        markers: Optional[List[str]] = None,
    ) -> None:
        """
        Args:
            domain: Domain name to request (scheme tried in order: https, http).
            client: Shared httpx.AsyncClient instance.
            timeout_s: Request timeout (seconds).
            markers: Case-insensitive phrases to search for; if None, a built-in set is used.
        """
        super().__init__(domain)
        self.client = client
        self.timeout_s = int(timeout_s)
        # Normalize markers: keep a lowercased list for O(n) substring matches
        provided = markers if markers else self._default_markers()
        self.markers: List[str] = [m.strip().lower() for m in provided if isinstance(m, str) and m.strip()]

    async def run(self) -> CheckOutcome:
        """Fetch '/' and look for defacement phrases (case-insensitive)."""
        # Try HTTPS, then HTTP as a fallback if HTTPS fails to connect.
        tried_urls: List[str] = []

        # Emit a start event with basic context
        log.debug(
            "deface.start",
            extra={
                "event": "deface.start",
                "domain": self.domain,
                "timeout_s": self.timeout_s,
                "markers_count": len(self.markers),
            },
        )

        for scheme in ("https", "http"):
            url = f"{scheme}://{self.domain}/"
            tried_urls.append(url)
            try:
                log.debug(
                    "deface.fetch.try",
                    extra={"event": "deface.fetch.try", "domain": self.domain, "url": url, "scheme": scheme},
                )
                start = time.perf_counter()
                r = await get_with_retries(
                    self.client,
                    url,
                    timeout_s=self.timeout_s,
                    retries=2,
                    backoff_s=0.25,
                    follow_redirects=True,
                    headers={"User-Agent": "sitewatcher/0.1 (+https://github.com/NikKurkov/sitewatcher)"},
                    log_extra={"domain": self.domain, "check": self.name},  # pass context for retry logs
                )
                elapsed_ms = int((time.perf_counter() - start) * 1000)
                redirects = len(r.history)
                code = r.status_code

                log.info(
                    "deface.fetch",
                    extra={
                        "event": "deface.fetch",
                        "domain": self.domain,
                        "final_url": str(r.url),
                        "status_code": code,
                        "latency_ms": elapsed_ms,
                        "redirects": redirects,
                        "bytes": len(r.content or b""),
                    },
                )

                # Search markers in body (case-insensitive)
                body_lower = (r.text or "").lower()
                for phrase in self.markers:
                    if phrase in body_lower:
                        # Report CRIT with the matched phrase highlighted.
                        log.warning(
                            "deface.matched",
                            extra={
                                "event": "deface.matched",
                                "domain": self.domain,
                                "final_url": str(r.url),
                                "matched": phrase,
                                "status_code": code,
                                "latency_ms": elapsed_ms,
                            },
                        )
                        return CheckOutcome(
                            self.name,
                            Status.CRIT,
                            f"'{phrase}' found on main page",
                            {
                                "url": str(r.url),
                                "matched": phrase,
                                "status_code": code,
                                "redirects": redirects,
                                "latency_ms": elapsed_ms,
                                "markers_checked": len(self.markers),
                            },
                        )

                # No markers found on this scheme: return OK immediately
                return CheckOutcome(
                    self.name,
                    Status.OK,
                    "no defacement markers found",
                    {
                        "url": str(r.url),
                        "status_code": code,
                        "redirects": redirects,
                        "latency_ms": elapsed_ms,
                        "markers_checked": len(self.markers),
                    },
                )

            except httpx.RequestError as e:
                # Try next scheme (HTTP) if HTTPS request failed to connect.
                log.info(
                    "deface.scheme_error",
                    extra={"event": "deface.scheme_error", "domain": self.domain, "url": url, "error": e.__class__.__name__},
                )
                continue
            except Exception:
                # Unexpected errors: UNKNOWN.
                log.exception(
                    "deface.unexpected_error",
                    extra={"event": "deface.unexpected_error", "domain": self.domain, "url": url},
                )
                return CheckOutcome(self.name, Status.UNKNOWN, "deface check error", {})

        # Both HTTPS and HTTP failed to connect: UNKNOWN.
        log.warning(
            "deface.unreachable",
            extra={"event": "deface.unreachable", "domain": self.domain, "tried": tried_urls},
        )
        return CheckOutcome(self.name, Status.UNKNOWN, "unable to fetch main page", {"tried": tried_urls})

    # ----------------------------- internals -----------------------------

    @staticmethod
    def _default_markers() -> List[str]:
        """Built-in list of common defacement phrases (kept short & generic)."""
        return [
            "hacked by",
            "defaced by",
            "you have been hacked",
            "security breach",
            "owned by",
            "pwned by",
        ]
