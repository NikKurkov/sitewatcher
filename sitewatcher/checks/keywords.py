from __future__ import annotations

import logging
import time
from typing import List

import httpx

from ..check_context import CheckContext
from .base import BaseCheck, CheckOutcome, Status
from ..utils.http_retry import get_with_retries
from ..utils.http_body import BodyReadError, DEFAULT_MAX_RESPONSE_BYTES

# Module-level logger
log = logging.getLogger(__name__)


class KeywordsCheck(BaseCheck):
    """Verify that landing page contains all configured keywords."""

    name = "keywords"

    def __init__(
        self,
        domain: str,
        *,
        client: httpx.AsyncClient,
        timeout_s: int = 5,
        keywords: List[str] | None = None,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        http_url: str | None = None,
        cycle_context: CheckContext | None = None,
        owner_id: int | None = None,
    ) -> None:
        """Create a keywords presence check.

        Args:
            domain: Hostname used to identify this check.
            client: Shared httpx.AsyncClient instance.
            timeout_s: Request timeout in seconds.
            keywords: List of phrases to find on the page.
        """
        super().__init__(domain)
        self.cycle_context = cycle_context
        self.owner_id = owner_id
        self.http_url = http_url
        self.client = client
        self.max_response_bytes = max_response_bytes
        self.timeout_s = int(timeout_s)
        self._kw_list = [keyword.strip() for keyword in (keywords or []) if keyword.strip()]
        # Precompute a lowercased version for fast search
        self._kw_lower: List[str] = [k.lower() for k in self._kw_list]

    async def run(self) -> CheckOutcome:
        """Fetch the landing page and verify that all keywords are present."""
        if not self._kw_list:
            log.warning(
                "keywords.no_config",
                extra={"event": "keywords.no_config", "domain": self.domain},
            )
            return CheckOutcome(self.name, Status.UNKNOWN, "no keywords configured", {"found": []})

        url = self.http_url or f"https://{self.domain}/"
        try:
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
                    backoff_s=0.3,
                    follow_redirects=True,
                    headers={"User-Agent": "sitewatcher/0.2 (+https://github.com/NikKurkov/sitewatcher)"},
                    log_extra={"domain": self.domain, "check": self.name},
                )
            elapsed_ms = r.extensions.get(
                "cycle_latency_ms", int((time.perf_counter() - start) * 1000),
            )
            redirects = len(r.history)

            log.info(
                "keywords.fetch",
                extra={
                    "event": "keywords.fetch",
                    "domain": self.domain,
                    "final_url": str(r.url),
                    "status_code": r.status_code,
                    "latency_ms": elapsed_ms,
                    "redirects": redirects,
                    "bytes": len(r.content or b""),
                },
            )
        except BodyReadError as e:
            return CheckOutcome(
                self.name, Status.CRIT if e.status_code >= 400 else Status.UNKNOWN, str(e),
                {"status_code": e.status_code, "max_response_bytes": self.max_response_bytes},
            )
        except httpx.RequestError as e:
            elapsed_ms = int((time.perf_counter() - start) * 1000) if "start" in locals() else None
            log.error(
                "keywords.error",
                extra={
                    "event": "keywords.error",
                    "domain": self.domain,
                    "url": url,
                    "error": e.__class__.__name__,
                    "latency_ms": elapsed_ms,
                },
            )
            return CheckOutcome(
                self.name,
                Status.CRIT,
                f"request error: {e.__class__.__name__}",
                {"url": url, "latency_ms": elapsed_ms},
            )

        code = r.status_code
        content = r.text or ""
        body_lower = content.lower()

        # Evaluate presence
        total = len(self._kw_list)
        missing: List[str] = [self._kw_list[i] for i, k in enumerate(self._kw_lower) if k not in body_lower]
        missing_cnt = len(missing)
        metrics = {
            "url": str(r.url),
            "status_code": code,
            "bytes": len(r.content or b""),
            "keywords_total": total,
            "keywords_missing": missing_cnt,
            "final_url": str(r.url),
            "redirects": redirects,
            "latency_ms": elapsed_ms,
        }

        if code >= 400:
            log.warning(
                "keywords.http_error",
                extra={
                    "event": "keywords.http_error",
                    "domain": self.domain,
                    "final_url": str(r.url),
                    "status_code": code,
                    "latency_ms": elapsed_ms,
                    "redirects": redirects,
                },
            )
            return CheckOutcome(
                self.name,
                Status.CRIT,
                f"HTTP {code}",
                {**metrics, "missing": missing},
            )

        if missing_cnt:
            log.info(
                "keywords.missing",
                extra={
                    "event": "keywords.missing",
                    "domain": self.domain,
                    "missing_cnt": missing_cnt,
                    "keywords_total": total,
                },
            )
            return CheckOutcome(
                self.name,
                Status.WARN,
                f"missing: {', '.join(missing)}",
                {**metrics, "missing": missing},
            )

        # All good
        base_status = Status.OK
        log.info(
            "keywords.done",
            extra={
                "event": "keywords.done",
                "domain": self.domain,
                "status": base_status.name,
                "keywords_total": total,
                "redirects": redirects,
                "latency_ms": elapsed_ms,
                "status_code": code,
            },
        )
        return CheckOutcome(
            self.name,
            base_status,
            "all keywords present",
            {**metrics, "found_count": total},
        )
