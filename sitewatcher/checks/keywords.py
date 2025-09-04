# sitewatcher/checks/keywords.py
from __future__ import annotations

import logging
import time
from typing import Any, Iterable, List, Tuple

import httpx

from .base import BaseCheck, CheckOutcome, Status
from ..utils.http_retry import get_with_retries

# Module-level logger
log = logging.getLogger(__name__)


def _normalize_keywords(src: Any) -> List[str]:
    """Normalize keywords setting into a flat list of non-empty strings.

    Accepts:
      - list/tuple of strings
      - list/tuple of dicts with 'text' key
      - list/tuple of (key, value) where value is the text
      - a single string (comma-separated)
    """
    if not src:
        return []
    out: List[str] = []

    def _add(val: Any) -> None:
        if isinstance(val, str):
            s = val.strip()
            if s:
                out.append(s)

    if isinstance(src, str):
        # allow comma/semicolon separated formats
        parts = [p.strip() for p in src.replace(";", ",").split(",")]
        for p in parts:
            _add(p)
        return out

    if isinstance(src, (list, tuple, set)):
        for it in src:
            if isinstance(it, str):
                _add(it)
            elif isinstance(it, dict):
                _add(it.get("text"))
            elif isinstance(it, (list, tuple)) and len(it) >= 2:
                _add(it[1])
            else:
                # ignore unknown shapes
                pass
        return out

    # Fallback: one value
    _add(src)
    return out


class KeywordsCheck(BaseCheck):
    """Verify that landing page contains all configured keywords."""

    name = "keywords"

    def __init__(
        self,
        domain: str,
        *,
        client: httpx.AsyncClient,
        timeout_s: int = 5,
        keywords: Any = None,
    ) -> None:
        """Create a keywords presence check.

        Args:
            domain: Domain name to request (https://<domain>/).
            client: Shared httpx.AsyncClient instance.
            timeout_s: Request timeout in seconds.
            keywords: Iterable of strings (or flexible structure; see _normalize_keywords).
        """
        super().__init__(domain)
        self.client = client
        self.timeout_s = int(timeout_s)
        self._kw_list: List[str] = _normalize_keywords(keywords)
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

        url = f"https://{self.domain}/"
        try:
            start = time.perf_counter()
            r = await get_with_retries(
                self.client,
                url,
                timeout_s=self.timeout_s,
                retries=2,
                backoff_s=0.3,
                follow_redirects=True,
                headers={"User-Agent": "sitewatcher/0.1 (+https://github.com/NikKurkov/sitewatcher)"},
                log_extra={"domain": self.domain, "check": self.name},
            )
            elapsed_ms = int((time.perf_counter() - start) * 1000)
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
                {
                    "url": str(r.url),
                    "status_code": code,
                    "bytes": len(r.content or b""),
                    "keywords_total": total,
                    "keywords_missing": missing_cnt,
                    "missing": missing,
                    "final_url": str(r.url),
                    "redirects": redirects,
                    "latency_ms": elapsed_ms,
                },
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
                {
                    "url": str(r.url),
                    "status_code": code,
                    "bytes": len(r.content or b""),
                    "keywords_total": total,
                    "keywords_missing": missing_cnt,
                    "missing": missing,
                    "final_url": str(r.url),
                    "redirects": redirects,
                    "latency_ms": elapsed_ms,
                },
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
            {
                "url": str(r.url),
                "status_code": code,
                "bytes": len(r.content or b""),
                "keywords_total": total,
                "keywords_missing": 0,
                "found_count": total,
                "final_url": str(r.url),
                "redirects": redirects,
                "latency_ms": elapsed_ms,
            },
        )
