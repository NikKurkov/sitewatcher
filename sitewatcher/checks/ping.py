# /checks/ping.py
from __future__ import annotations

import asyncio
import time

from .base import BaseCheck, CheckOutcome, Status

# Try ICMP first; fall back to TCP if the library/privileges are unavailable.
try:
    from icmplib import async_ping as icmp_async_ping  # type: ignore
    HAVE_ICMP = True
except Exception:
    HAVE_ICMP = False


class PingCheck(BaseCheck):
    """Ping a host using ICMP if possible, otherwise fall back to a TCP connect RTT."""

    name = "ping"

    def __init__(self, domain: str) -> None:
        super().__init__(domain)

    async def _tcp_ping(self, port: int = 443, timeout: float = 2.0) -> float:
        """
        Measure TCP connect round-trip time to (domain, port).
        Returns RTT in milliseconds or -1.0 on failure.
        """
        start = time.perf_counter()
        writer = None
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
            return rtt_ms
        except Exception:
            return -1.0
        finally:
            # Ensure writer is closed if open_connection partially succeeded.
            if writer is not None:
                try:
                    writer.close()
                except Exception:
                    pass

    async def run(self) -> CheckOutcome:
        """
        Prefer ICMP RTT (when icmplib is available and permitted).
        Otherwise use a TCP connect RTT as a reasonable approximation.
        """
        if HAVE_ICMP:
            try:
                host = await icmp_async_ping(self.domain, count=2, interval=0.2, timeout=2)
                if host.is_alive:
                    return CheckOutcome(
                        self.name,
                        Status.OK,
                        f"icmp avg {host.avg_rtt:.0f} ms",
                        {"method": "icmp", "avg_rtt_ms": round(host.avg_rtt, 2)},
                    )
                return CheckOutcome(self.name, Status.CRIT, "icmp no reply", {"method": "icmp"})
            except Exception:
                # Fall back to TCP below.
                pass

        rtt = await self._tcp_ping()
        if rtt >= 0:
            return CheckOutcome(
                self.name,
                Status.OK,
                f"tcp {rtt:.0f} ms",
                {"method": "tcp", "port": 443, "rtt_ms": round(rtt, 2)},
            )
        return CheckOutcome(self.name, Status.CRIT, "tcp connect failed", {"method": "tcp", "port": 443})
