# sitewatcher/checks/ping.py
from __future__ import annotations

import asyncio
import logging
import time
from typing import Optional

from .base import BaseCheck, CheckOutcome, Status

# Optional ICMP support via icmplib (used when available)
try:  # pragma: no cover - optional dependency
    from icmplib import async_ping as icmp_async_ping  # type: ignore
    HAVE_ICMP = True
except Exception:  # pragma: no cover
    icmp_async_ping = None  # type: ignore[assignment]
    HAVE_ICMP = False

# Module-level logger for structured events
log = logging.getLogger(__name__)


class PingCheck(BaseCheck):
    """Measure host reachability via ICMP (if available) or TCP connect RTT."""

    name = "ping"

    def __init__(
        self,
        domain: str,
        *,
        tcp_port: int = 443,
        tcp_timeout_s: float = 2.0,
        icmp_count: int = 2,
        icmp_interval_s: float = 0.2,
        icmp_timeout_s: float = 2.0,
    ) -> None:
        """
        Args:
            domain: Target host to ping.
            tcp_port: TCP port for fallback connect RTT (default: 443).
            tcp_timeout_s: Timeout for TCP connect attempt (seconds).
            icmp_count: Number of ICMP packets for average RTT.
            icmp_interval_s: Interval between ICMP packets (seconds).
            icmp_timeout_s: Per-ICMP operation timeout (seconds).
        """
        super().__init__(domain)
        self.tcp_port = int(tcp_port)
        self.tcp_timeout_s = float(tcp_timeout_s)
        self.icmp_count = int(icmp_count)
        self.icmp_interval_s = float(icmp_interval_s)
        self.icmp_timeout_s = float(icmp_timeout_s)

    async def run(self) -> CheckOutcome:
        """
        Prefer ICMP RTT (when icmplib is available and permitted).
        Otherwise use a TCP connect RTT as a reasonable approximation.
        """
        log.debug("ping.start", extra={"event": "ping.start", "domain": self.domain, "have_icmp": HAVE_ICMP})

        # ICMP path (if library is present and permitted by environment)
        if HAVE_ICMP and icmp_async_ping is not None:
            try:
                log.debug(
                    "ping.icmp.try",
                    extra={
                        "event": "ping.icmp.try",
                        "domain": self.domain,
                        "count": self.icmp_count,
                        "interval_s": self.icmp_interval_s,
                        "timeout_s": self.icmp_timeout_s,
                    },
                )
                host = await icmp_async_ping(
                    self.domain,
                    count=self.icmp_count,
                    interval=self.icmp_interval_s,
                    timeout=self.icmp_timeout_s,
                )
                if getattr(host, "is_alive", False):
                    avg = float(getattr(host, "avg_rtt", 0.0))
                    log.info(
                        "ping.done",
                        extra={
                            "event": "ping.done",
                            "domain": self.domain,
                            "method": "icmp",
                            "status": "OK",
                            "avg_rtt_ms": round(avg, 2),
                        },
                    )
                    return CheckOutcome(
                        self.name,
                        Status.OK,
                        f"icmp avg {avg:.0f} ms",
                        {"method": "icmp", "avg_rtt_ms": round(avg, 2)},
                    )
                log.warning(
                    "ping.done",
                    extra={"event": "ping.done", "domain": self.domain, "method": "icmp", "status": "CRIT", "reason": "no_reply"},
                )
                return CheckOutcome(self.name, Status.CRIT, "icmp no reply", {"method": "icmp"})
            except Exception as e:
                # Fall back to TCP below.
                log.info(
                    "ping.icmp.error",
                    extra={
                        "event": "ping.icmp.error",
                        "domain": self.domain,
                        "error": e.__class__.__name__,
                        "fallback": True,
                    },
                )

        # TCP fallback path
        rtt = await self._tcp_ping(port=self.tcp_port, timeout=self.tcp_timeout_s)
        if rtt >= 0:
            log.info(
                "ping.done",
                extra={"event": "ping.done", "domain": self.domain, "method": "tcp", "status": "OK", "rtt_ms": round(rtt, 2)},
            )
            return CheckOutcome(
                self.name,
                Status.OK,
                f"tcp {rtt:.0f} ms",
                {"method": "tcp", "port": self.tcp_port, "rtt_ms": round(rtt, 2)},
            )
        log.warning(
            "ping.done",
            extra={"event": "ping.done", "domain": self.domain, "method": "tcp", "status": "CRIT", "error": "connect_failed"},
        )
        return CheckOutcome(self.name, Status.CRIT, "tcp connect failed", {"method": "tcp", "port": self.tcp_port})

    async def _tcp_ping(self, *, port: int = 443, timeout: float = 2.0) -> float:
        """
        Measure TCP connect round-trip time to (domain, port).
        Returns RTT in milliseconds or -1.0 on failure.
        """
        log.debug(
            "ping.tcp.try",
            extra={"event": "ping.tcp.try", "domain": self.domain, "port": port, "timeout_s": timeout},
        )
        start = time.perf_counter()
        writer: Optional[asyncio.StreamWriter] = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.domain, port),
                timeout=timeout,
            )
            rtt_ms = (time.perf_counter() - start) * 1000.0
            # Cleanly close the socket; ignore close-time exceptions.
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            log.info(
                "ping.tcp.ok",
                extra={"event": "ping.tcp.ok", "domain": self.domain, "port": port, "rtt_ms": round(rtt_ms, 2)},
            )
            return rtt_ms
        except Exception as e:
            log.warning(
                "ping.tcp.error",
                extra={"event": "ping.tcp.error", "domain": self.domain, "port": port, "error": e.__class__.__name__},
            )
            return -1.0
        finally:
            # Ensure writer is closed if open_connection partially succeeded.
            if writer is not None:
                try:
                    writer.close()
                except Exception:
                    pass
