# sitewatcher/checks/http_basic.py
from __future__ import annotations

import time
from typing import Optional

import httpx

from .base import BaseCheck, CheckOutcome, Status
from ..utils.http_retry import get_with_retries


class HttpBasicCheck(BaseCheck):
    """Minimal HTTP health check: status code and latency on the landing page.

    Strategy:
      1) Request https://<domain>/ without following redirects; measure initial latency.
      2) If 3xx with Location, follow redirects once (letting httpx handle the full chain)
         to obtain final URL/code and add the extra time.
      3) Status:
         - CRIT: initial HTTP >= 400, or initial latency >= latency_crit_ms, or request error.
         - WARN: initial HTTP is 3xx, or initial latency >= latency_warn_ms.
         - OK: otherwise.
    """

    name = "http_basic"

    def __init__(
        self,
        domain: str,
        client: httpx.AsyncClient,
        timeout_s: int = 5,
        latency_warn_ms: int = 1000,
        latency_crit_ms: int = 3000,
        proxy: Optional[str] = None,
    ) -> None:
        super().__init__(domain)
        self.client = client
        self.timeout_s = timeout_s
        self.latency_warn_ms = latency_warn_ms
        self.latency_crit_ms = latency_crit_ms
        # Optional per-domain proxy (httpx supports per-request proxies)
        self.proxy = proxy

    async def run(self) -> CheckOutcome:
        origin_url = f"https://{self.domain}/"

        # --- 1) First hop (no redirects) ---
        start1 = time.perf_counter()
        try:
            kw = {"proxies": self.proxy} if self.proxy else {}
            r1 = await get_with_retries(
                self.client,
                origin_url,
                timeout_s=self.timeout_s,
                retries=2,
                backoff_s=0.3,
                retry_on_status=(502, 503, 504),
                follow_redirects=False,
                **kw,
            )
        except httpx.RequestError as e:
            elapsed_ms = int((time.perf_counter() - start1) * 1000)
            return CheckOutcome(
                check=self.name,
                status=Status.CRIT,
                message=f"request error: {e.__class__.__name__}",
                metrics={"latency_ms_initial": elapsed_ms, "url": origin_url},
            )

        elapsed1_ms = int((time.perf_counter() - start1) * 1000)
        code1 = r1.status_code

        # Defaults for the final hop
        final_url = str(r1.url)
        final_code = code1
        redirects = 0
        total_ms = elapsed1_ms

        # --- 2) Follow redirects (if any) to report the final target & total latency ---
        if 300 <= code1 < 400 and "location" in r1.headers:
            try:
                start2 = time.perf_counter()
                kw = {"proxies": self.proxy} if self.proxy else {}
                r2 = await get_with_retries(
                    self.client,
                    final_url,
                    timeout_s=self.timeout_s,
                    retries=2,
                    backoff_s=0.3,
                    retry_on_status=(502, 503, 504),
                    follow_redirects=True,
                    **kw,
                )
                elapsed2_ms = int((time.perf_counter() - start2) * 1000)
                redirects = len(r2.history) + 1  # include the initial 3xx
                final_url = str(r2.url)
                final_code = r2.status_code
                total_ms = elapsed1_ms + elapsed2_ms
            except httpx.RequestError:
                # If redirect chain failed, keep the initial result/latency.
                pass

        # --- 3) Derive status from initial code and initial latency thresholds ---
        status = self._status_from_initial(code1, elapsed1_ms)

        # --- 4) Compose a compact message & metrics ---
        if redirects:
            msg = (
                f"HTTP {code1} -> {final_code} @ {final_url}, "
                f"latency {total_ms} ms (first {elapsed1_ms} ms)"
            )
        else:
            msg = f"HTTP {code1}, latency {elapsed1_ms} ms"

        return CheckOutcome(
            check=self.name,
            status=status,
            message=msg,
            metrics={
                "code_initial": code1,
                "latency_ms_initial": elapsed1_ms,
                "redirects": redirects,
                "final_url": final_url,
                "final_code": final_code,
                "latency_ms_total": total_ms,
                "origin_url": origin_url,
            },
        )

    # ---- helpers ----
    def _status_from_initial(self, code1: int, elapsed1_ms: int) -> Status:
        """Map the first response code and latency to a status."""
        if code1 >= 400:
            return Status.CRIT
        if 300 <= code1 < 400:
            return Status.WARN
        # 2xx:
        if elapsed1_ms >= self.latency_crit_ms:
            return Status.CRIT
        if elapsed1_ms >= self.latency_warn_ms:
            return Status.WARN
        return Status.OK
