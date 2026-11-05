from __future__ import annotations

import logging
import time
from typing import List, Optional

import httpx

from ..check_context import CheckContext
from .base import BaseCheck, CheckOutcome, Status
from ..utils.http_retry import get_with_retries
from ..utils.http_body import BodyReadError, DEFAULT_MAX_RESPONSE_BYTES

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
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        http_url: str | None = None,
        cycle_context: CheckContext | None = None,
        owner_id: int | None = None,
    ) -> None:
        """
        Args:
            domain: Domain name to request (scheme tried in order: https, http).
            client: Shared httpx.AsyncClient instance.
            timeout_s: Request timeout (seconds).
            markers: Case-insensitive phrases to search for; if None, a built-in set is used.
        """
        super().__init__(domain)
        self.cycle_context = cycle_context
        self.owner_id = owner_id
        self.http_url = http_url
        self.client = client
        self.max_response_bytes = max_response_bytes
        self.timeout_s = int(timeout_s)
        # Normalize markers: keep a lowercased list for O(n) substring matches
        provided = markers if markers else self._default_markers()
        self.markers: List[str] = [m.strip().lower() for m in provided if isinstance(m, str) and m.strip()]

    async def run(self) -> CheckOutcome:
        """Fetch the configured page and look for defacement phrases."""
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

        for url in ([self.http_url] if self.http_url else
                    [f"https://{self.domain}/", f"http://{self.domain}/"]):
            scheme = url.split(":", 1)[0]
            tried_urls.append(url)
            try:
                log.debug(
                    "deface.fetch.try",
                    extra={"event": "deface.fetch.try", "domain": self.domain, "url": url, "scheme": scheme},
                )
                start = time.perf_counter()
                if self.cycle_context is not None:
                    observation = await self.cycle_context.fetch_page(
                        self.client, url, timeout_s=self.timeout_s,
                        max_response_bytes=self.max_response_bytes,
                        owner_id=self.owner_id, domain=self.domain,
                    )
                    r = observation.content_response()
                else:
                    r = await get_with_retries(
                        self.client,
                        url,
                        timeout_s=self.timeout_s,
                        max_response_bytes=self.max_response_bytes,
                        retries=2,
                        backoff_s=0.25,
                        follow_redirects=True,
                        headers={"User-Agent": "sitewatcher/0.2 (+https://github.com/NikKurkov/sitewatcher)"},
                        log_extra={"domain": self.domain, "check": self.name},  # pass context for retry logs
                    )
                elapsed_ms = r.extensions.get(
                    "cycle_latency_ms", int((time.perf_counter() - start) * 1000),
                )
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

                if not 200 <= code < 300:
                    return CheckOutcome(
                        self.name, Status.UNKNOWN, f"unable to inspect main page: HTTP {code}",
                        {"url": str(r.url), "status_code": code, "redirects": redirects,
                         "latency_ms": elapsed_ms, "markers_checked": len(self.markers)},
                    )

                # No markers found in a successful response.
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

            except BodyReadError as e:
                return CheckOutcome(
                    self.name, Status.UNKNOWN, str(e),
                    {"status_code": e.status_code, "max_response_bytes": self.max_response_bytes},
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
