# /checks/keywords.py
from __future__ import annotations

from typing import List, Tuple
import time
import httpx

from .base import BaseCheck, CheckOutcome, Status
from ..utils.http_retry import get_with_retries


def _unique_preserve_order(items: List[str]) -> List[str]:
    """Return a list with duplicates removed while preserving order."""
    seen = set()
    out: List[str] = []
    for it in items:
        if it not in seen:
            seen.add(it)
            out.append(it)
    return out


class KeywordsCheck(BaseCheck):
    """Fetches the homepage and verifies that all configured keywords are present (case-insensitive)."""

    name = "keywords"

    def __init__(self, domain: str, client: httpx.AsyncClient, timeout_s: int, keywords: List[str]) -> None:
        super().__init__(domain)
        self.client = client
        self.timeout_s = timeout_s

        # Normalize once: drop blanks, deduplicate, keep order, and precompute lower-case variants.
        base = [k for k in (keywords or []) if isinstance(k, str) and k.strip()]
        base = _unique_preserve_order(base)
        self._kw_pairs: List[Tuple[str, str]] = [(k, k.lower()) for k in base]

    @property
    def keywords(self) -> List[str]:
        """Expose original keywords (read-only) for metrics/tests."""
        return [k for (k, _) in self._kw_pairs]

    async def run(self) -> CheckOutcome:
        if not self._kw_pairs:
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
            )
            elapsed_ms = int((time.perf_counter() - start) * 1000)
            redirects = len(r.history)
        except httpx.RequestError as e:
            return CheckOutcome(
                self.name,
                Status.CRIT,
                f"request error: {e.__class__.__name__}",
                {"url": url},
            )

        code = r.status_code
        text = r.text or ""
        lower_text = text.lower()

        # Compute missing by original label, using precomputed lower-cased tokens.
        missing = [orig for (orig, low) in self._kw_pairs if low not in lower_text]
        total = len(self._kw_pairs)
        missing_cnt = len(missing)

        if code >= 400:
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

        base_status = Status.WARN if 300 <= code < 400 else Status.OK

        if missing_cnt:
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
