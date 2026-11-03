from __future__ import annotations

import logging
import time
from typing import Optional

import httpx

from .base import BaseCheck, CheckOutcome, Status
from ..utils.http_retry import get_with_retries
from ..utils.http_body import BodyReadError, DEFAULT_MAX_RESPONSE_BYTES

# Module-level logger for structured events
log = logging.getLogger(__name__)


class HttpBasicCheck(BaseCheck):
    """Minimal HTTP health check: status code and latency on the landing page.

    Strategy:
      1) Request the configured HTTP(S) address without following redirects; measure initial latency.
      2) If 3xx with Location, follow redirects once (letting httpx handle the full chain)
         to obtain final URL/code and add the extra time.
      3) Status:
         - CRIT: initial/final HTTP >= 400, critical initial latency, or request error.
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
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        http_url: str | None = None,
    ) -> None:
        super().__init__(domain)
        self.http_url = http_url
        self.client = client
        self.max_response_bytes = max_response_bytes
        self.timeout_s = timeout_s
        self.latency_warn_ms = latency_warn_ms
        self.latency_crit_ms = latency_crit_ms
        self.proxy = proxy

    async def run(self) -> CheckOutcome:
        if self.proxy:
            async with httpx.AsyncClient(proxy=self.proxy) as client:
                return await self._run(client)
        return await self._run(self.client)

    async def _run(self, client: httpx.AsyncClient) -> CheckOutcome:
        origin_url = self.http_url or f"https://{self.domain}/"

        # Emit a start event (useful in DEBUG traces)
        log.debug(
            "http_basic.start",
            extra={
                "event": "http_basic.start",
                "domain": self.domain,
                "origin_url": origin_url,
                "timeout_s": self.timeout_s,
                "proxy_set": bool(self.proxy),
            },
        )

        # --- 1) First hop (no redirects) ---
        start1 = time.perf_counter()
        try:
            r1 = await get_with_retries(
                client,
                origin_url,
                timeout_s=self.timeout_s,
                max_response_bytes=self.max_response_bytes,
                retries=2,
                backoff_s=0.3,
                follow_redirects=False,
                headers={"User-Agent": "sitewatcher/0.2 (+https://github.com/NikKurkov/sitewatcher)"},
            )
        except BodyReadError as e:
            return CheckOutcome(
                self.name, Status.CRIT if e.status_code >= 400 else Status.UNKNOWN, str(e),
                {"status_code": e.status_code, "max_response_bytes": self.max_response_bytes,
                 "availability": "unavailable" if e.status_code >= 400 else "unknown"},
            )
        except httpx.RequestError as e:
            elapsed_ms = int((time.perf_counter() - start1) * 1000)
            # Log request error with initial latency measured
            log.error(
                "http_basic.error",
                extra={
                    "event": "http_basic.error",
                    "domain": self.domain,
                    "url": origin_url,
                    "latency_ms_initial": elapsed_ms,
                    "error": e.__class__.__name__,
                },
            )
            return CheckOutcome(
                check=self.name,
                status=Status.CRIT,
                message=f"request error: {e.__class__.__name__}",
                metrics={"latency_ms_initial": elapsed_ms, "url": origin_url,
                         "availability": "unavailable"},
            )

        elapsed1_ms = int((time.perf_counter() - start1) * 1000)
        code1 = r1.status_code

        # Log initial response hop
        log.info(
            "http_basic.initial",
            extra={
                "event": "http_basic.initial",
                "domain": self.domain,
                "url": str(r1.url),
                "code_initial": code1,
                "latency_ms_initial": elapsed1_ms,
            },
        )

        # Defaults for the final hop
        final_url = str(r1.url)
        final_code = code1
        redirects = 0
        redirect_error: Optional[str] = None
        total_ms = elapsed1_ms

        # --- 2) Follow redirects (if any) to report the final target & total latency ---
        if 300 <= code1 < 400 and "location" in r1.headers:
            try:
                start2 = time.perf_counter()
                # Follow from the advertised Location to avoid repeating the 1st hop
                loc = r1.headers["location"]
                base = httpx.URL(str(r1.url))
                target = str(base.join(loc))
                r2 = await get_with_retries(
                    client,
                    target,
                    timeout_s=self.timeout_s,
                    max_response_bytes=self.max_response_bytes,
                    prior_body_bytes=r1.extensions.get("body_bytes", (0, 0)),
                    retries=2,
                    backoff_s=0.3,
                    follow_redirects=True,
                    headers={"User-Agent": "sitewatcher/0.2 (+https://github.com/NikKurkov/sitewatcher)"},
                )
                elapsed2_ms = int((time.perf_counter() - start2) * 1000)
                redirects = len(r2.history) or 1  # at least one redirect happened
                final_url = str(r2.url)
                final_code = r2.status_code
                total_ms = elapsed1_ms + elapsed2_ms

                log.info(
                    "http_basic.redirect_chain",
                    extra={
                        "event": "http_basic.redirect_chain",
                        "domain": self.domain,
                        "origin_url": origin_url,
                        "final_url": final_url,
                        "redirects": redirects,
                        "final_code": final_code,
                        "latency_ms_total": total_ms,
                        "latency_ms_initial": elapsed1_ms,
                    },
                )
            except BodyReadError as e:
                return CheckOutcome(
                    self.name, Status.CRIT if e.status_code >= 400 else Status.UNKNOWN, str(e),
                    {"status_code": e.status_code, "max_response_bytes": self.max_response_bytes,
                     "availability": "unavailable" if e.status_code >= 400 else "unknown"},
                )
            except httpx.RequestError as e:
                redirect_error = e.__class__.__name__
                # Keep initial hop data; log that following redirects failed
                log.warning(
                    "http_basic.redirect_follow_error",
                    extra={
                        "event": "http_basic.redirect_follow_error",
                        "domain": self.domain,
                        "from_url": str(r1.url),
                        "error": e.__class__.__name__,
                    },
                )

        # --- 3) Derive status from initial code and initial latency thresholds ---
        status = self._status_from_initial(code1, elapsed1_ms)
        if final_code >= 400 or redirect_error:
            status = Status.CRIT

        # --- 4) Compose a compact message & metrics ---
        if redirects:
            msg = (
                f"HTTP {code1} -> {final_code} @ {final_url}, "
                f"latency {total_ms} ms (first {elapsed1_ms} ms)"
            )
        else:
            msg = f"HTTP {code1}, latency {elapsed1_ms} ms"

        if redirect_error:
            msg += f"; redirect request error: {redirect_error}"

        # Final event (compact, with derived status)
        log.info(
            "http_basic.done",
            extra={
                "event": "http_basic.done",
                "domain": self.domain,
                "status": getattr(status, "name", str(status)),
                "code_initial": code1,
                "latency_ms_initial": elapsed1_ms,
                "redirects": redirects,
                "final_url": final_url,
                "final_code": final_code,
                "latency_ms_total": total_ms,
            },
        )

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
                "redirect_error": redirect_error,
                "availability": (
                    "unavailable" if final_code >= 400 or redirect_error else "available"
                ),
                **({"response_latency_ms": total_ms}
                   if final_code < 400 and not redirect_error else {}),
            },
        )

    # ---- helpers ----
    def _status_from_initial(self, code1: int, elapsed1_ms: int) -> Status:
        """Map the first response code and latency to a status."""
        if code1 >= 400 or elapsed1_ms >= self.latency_crit_ms:
            return Status.CRIT
        if 300 <= code1 < 400:
            return Status.WARN
        # 2xx:
        if elapsed1_ms >= self.latency_warn_ms:
            return Status.WARN
        return Status.OK
