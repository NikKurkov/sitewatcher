# sitewatcher/checks/ip_blacklist.py
from __future__ import annotations

import asyncio
import logging
import socket
from dataclasses import dataclass
from typing import List, Optional, Tuple

import dns.asyncresolver
import dns.exception
import dns.resolver

from .base import BaseCheck, CheckOutcome, Status

# Module-level logger for structured events
log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Hit:
    """A single DNSBL listing hit for an IP within a zone."""
    ip: str
    zone: str
    a: List[str]
    txt: List[str]


class IpBlacklistCheck(BaseCheck):
    """Check whether resolved IPs are listed in DNSBL/blacklist zones."""

    name = "ip_blacklist"

    def __init__(
        self,
        domain: str,
        *,
        zones: List[str],
        dns_servers: Optional[List[str]] = None,
        timeout_s: float = 2.5,
        concurrency: int = 20,
        check_ipv6: bool = False,
    ) -> None:
        """
        Args:
            domain: Domain whose IPs will be tested against DNSBL zones.
            zones: List of DNSBL zones (e.g., "zen.spamhaus.org").
            dns_servers: Optional list of resolver IPs. Defaults to system resolvers.
            timeout_s: Per-DNS query timeout.
            concurrency: Max in-flight DNS queries across IPs×zones.
            check_ipv6: If True, consider AAAA presence for "no records" logic (most DNSBLs are IPv4-only).
        """
        super().__init__(domain)
        self.zones = [z.strip().strip(".") for z in (zones or []) if isinstance(z, str) and z.strip()]
        self.timeout_s = float(timeout_s)
        self.concurrency = max(1, int(concurrency))
        self.check_ipv6 = bool(check_ipv6)

        # Async resolver instance (dnspython)
        self.resolver = dns.asyncresolver.Resolver()
        if dns_servers:
            # Accept only raw IPs; ignore malformed entries
            good = [ip for ip in dns_servers if _is_ip(ip)]
            if good:
                self.resolver.nameservers = good

    async def run(self) -> CheckOutcome:
        # Start event
        log.debug(
            "ipbl.start",
            extra={
                "event": "ipbl.start",
                "domain": self.domain,
                "zones_count": len(self.zones),
                "concurrency": self.concurrency,
                "timeout_s": self.timeout_s,
                "check_ipv6": self.check_ipv6,
                "nameservers": list(getattr(self.resolver, "nameservers", []) or []),
            },
        )

        # Defensive: no zones configured → nothing to check
        if not self.zones:
            log.warning(
                "ipbl.no_zones",
                extra={"event": "ipbl.no_zones", "domain": self.domain},
            )
            return CheckOutcome(self.name, Status.UNKNOWN, "no zones configured", {})

        # Resolve A/AAAA for the domain
        try:
            ips_v4, ips_v6 = await self._resolve_ips()
            log.info(
                "ipbl.resolved",
                extra={
                    "event": "ipbl.resolved",
                    "domain": self.domain,
                    "ips_v4_count": len(ips_v4),
                    "ips_v6_count": len(ips_v6),
                },
            )
        except Exception as e:
            log.error(
                "ipbl.resolve_error",
                extra={"event": "ipbl.resolve_error", "domain": self.domain, "error": e.__class__.__name__},
            )
            return CheckOutcome(self.name, Status.UNKNOWN, f"dns error: {e.__class__.__name__}", {})

        # If the domain resolves to nothing (A and, if requested, AAAA), flag as WARN
        if not ips_v4 and not (self.check_ipv6 and ips_v6):
            log.info(
                "ipbl.no_records",
                extra={"event": "ipbl.no_records", "domain": self.domain},
            )
            return CheckOutcome(
                self.name,
                Status.WARN,
                "no A/AAAA records",
                {"ips_v4": [], "ips_v6": []},
            )

        # Most DNSBLs are IPv4-only; we probe only IPv4 addresses against zones.
        ips = ips_v4

        # Prepare concurrent probes
        sem = asyncio.Semaphore(self.concurrency)
        tasks = [self._probe_ip_zone(sem, ip, zone) for ip in ips for zone in self.zones]

        results = await asyncio.gather(*tasks, return_exceptions=True)
        hits: List[Hit] = [r for r in results if isinstance(r, Hit)]
        errors_count = sum(1 for r in results if isinstance(r, Exception))
        queries_total = len(ips) * len(self.zones)

        log.info(
            "ipbl.summary",
            extra={
                "event": "ipbl.summary",
                "domain": self.domain,
                "queries_total": queries_total,
                "hits_count": len(hits),
                "errors_count": errors_count,
            },
        )

        if hits:
            # Compact message like "IP@zone (reason...); ..."
            parts: List[str] = []
            for h in hits:
                label = f"{h.ip}@{h.zone}"
                if h.txt:
                    label += f" ({'; '.join(h.txt)[:120]})"
                parts.append(label)

            log.warning(
                "ipbl.listed",
                extra={
                    "event": "ipbl.listed",
                    "domain": self.domain,
                    "hits_count": len(hits),
                    "examples": parts[:5],
                },
            )

            message = f"listed: {', '.join(parts)}"
            metrics = {
                "hits": [{"ip": h.ip, "zone": h.zone, "a": h.a, "txt": h.txt} for h in hits],
                "ips_v4": ips_v4,
                "ips_v6": ips_v6,
                "queries_total": queries_total,
                "hits_count": len(hits),
                "errors_count": errors_count,
            }
            return CheckOutcome(self.name, Status.CRIT, message, metrics)

        return CheckOutcome(
            self.name,
            Status.OK,
            "not listed",
            {
                "ips_v4": ips_v4,
                "ips_v6": ips_v6,
                "queries_total": queries_total,
                "hits_count": 0,
                "errors_count": errors_count,
            },
        )

    # ----------------------------- internals -----------------------------

    async def _resolve_ips(self) -> Tuple[List[str], List[str]]:
        """Resolve A/AAAA records using the configured async resolver."""
        v4: List[str] = []
        v6: List[str] = []

        try:
            ans_a = await self.resolver.resolve(self.domain, "A", lifetime=self.timeout_s)
            v4 = [rr.address for rr in ans_a]
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.Timeout,
            dns.exception.DNSException,
        ):
            v4 = []

        try:
            ans_aaaa = await self.resolver.resolve(self.domain, "AAAA", lifetime=self.timeout_s)
            v6 = [rr.address for rr in ans_aaaa]
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.Timeout,
            dns.exception.DNSException,
        ):
            v6 = []

        # Deduplicate preserving order
        v4 = _uniq_preserve(v4)
        v6 = _uniq_preserve(v6)
        return v4, v6

    async def _probe_ip_zone(self, sem: asyncio.Semaphore, ip: str, zone: str) -> Optional[Hit]:
        """Query DNSBL zone for given IPv4: return Hit on listing, otherwise None."""
        # Reverse IPv4: 1.2.3.4 -> 4.3.2.1.zone
        try:
            rev = ".".join(ip.split(".")[::-1])
        except Exception:
            return None
        qname = f"{rev}.{zone}."

        async with sem:
            try:
                # A record signifies a listing
                ans_a = await self.resolver.resolve(qname, "A", lifetime=self.timeout_s)
                a_values = [rr.address for rr in ans_a]
                # If we got here, the IP is listed in zone — log at WARNING level
                log.warning(
                    "ipbl.hit",
                    extra={"event": "ipbl.hit", "domain": self.domain, "ip": ip, "zone": zone, "a_count": len(a_values)},
                )
            except (
                dns.resolver.NXDOMAIN,
                dns.resolver.NoAnswer,
                dns.resolver.Timeout,
                dns.exception.DNSException,
            ):
                return None

            # TXT is optional; useful for human-readable reason/category
            txt_values: List[str] = []
            try:
                ans_txt = await self.resolver.resolve(qname, "TXT", lifetime=self.timeout_s)
                for rr in ans_txt:
                    try:
                        # rr.to_text() may return quoted; strip quotes for readability
                        txt = rr.to_text().strip('"')
                        if txt:
                            txt_values.append(txt)
                    except Exception:
                        pass
            except (
                dns.resolver.NXDOMAIN,
                dns.resolver.NoAnswer,
                dns.resolver.Timeout,
                dns.exception.DNSException,
            ):
                pass

        return Hit(ip=ip, zone=zone, a=a_values, txt=txt_values)


# ----------------------------- helpers -----------------------------

def _uniq_preserve(items: List[str]) -> List[str]:
    """Deduplicate a list while preserving the first occurrence order."""
    seen = set()
    out: List[str] = []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _is_ip(s: str) -> bool:
    """Return True if the string is a valid IPv4/IPv6 address."""
    try:
        socket.inet_pton(socket.AF_INET, s)
        return True
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, s)
        return True
    except OSError:
        return False
