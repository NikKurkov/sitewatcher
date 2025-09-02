# /checks/ip_blacklist.py
from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass
from typing import List, Optional, Tuple

import dns.asyncresolver
import dns.exception
import dns.resolver

from .base import BaseCheck, CheckOutcome, Status


@dataclass
class Hit:
    ip: str
    zone: str
    a: List[str]
    txt: List[str]


class IpBlacklistCheck(BaseCheck):
    """
    Checks if a domain's IPv4 addresses are listed in configured DNSBL zones.

    Logic:
      1) Resolve A/AAAA for the domain (AAAA is optional and not used for DNSBL queries).
      2) For each IPv4 address and each zone, query A/TXT for reversed_ip.zone.
      3) If an A record is returned, consider it a listing; TXT carries reason/category if present.
      4) Status: CRIT (any hits), WARN (no A/AAAA for the domain), OK (clean), UNKNOWN (resolver error).
    """

    name = "ip_blacklist"

    def __init__(
        self,
        domain: str,
        zones: List[str],
        dns_servers: Optional[List[str]] = None,
        timeout_s: int = 3,
        concurrency: int = 8,
        check_ipv6: bool = False,
    ) -> None:
        super().__init__(domain)
        self.zones = [z.strip().strip(".") for z in zones if z.strip()]
        self.timeout_s = float(timeout_s)
        self.concurrency = int(concurrency)
        self.check_ipv6 = bool(check_ipv6)

        # Configure dnspython async resolver
        self.resolver = dns.asyncresolver.Resolver(configure=True)
        self.resolver.lifetime = self.timeout_s
        self.resolver.timeout = self.timeout_s
        if dns_servers:
            self.resolver.nameservers = dns_servers

    # ---------- public ----------

    async def run(self) -> CheckOutcome:
        # Defensive: no zones configured → nothing to check
        if not self.zones:
            return CheckOutcome(self.name, Status.UNKNOWN, "no zones configured", {})

        try:
            ips_v4, ips_v6 = await self._resolve_ips()
        except Exception as e:
            return CheckOutcome(self.name, Status.UNKNOWN, f"dns error: {e.__class__.__name__}", {})

        # If the domain resolves to nothing (A and, if requested, AAAA), flag as WARN
        if not ips_v4 and not (self.check_ipv6 and ips_v6):
            return CheckOutcome(
                self.name,
                Status.WARN,
                "no A/AAAA records",
                {"ips_v4": [], "ips_v6": []},
            )

        # DNSBLs generally operate on IPv4 only
        ips = ips_v4

        sem = asyncio.Semaphore(self.concurrency)
        tasks = [self._probe_ip_zone(sem, ip, zone) for ip in ips for zone in self.zones]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        hits: List[Hit] = [r for r in results if isinstance(r, Hit)]
        errors_count = sum(1 for r in results if isinstance(r, Exception))
        queries_total = len(ips) * len(self.zones)

        if hits:
            # Compact message like "IP@zone (reason...); ..."
            parts: List[str] = []
            for h in hits:
                label = f"{h.ip}@{h.zone}"
                if h.txt:
                    label += f" ({'; '.join(h.txt)[:120]})"
                parts.append(label)
            message = f"listed: {', '.join(parts)}"
            metrics = {
                "hits": [{"ip": h.ip, "zone": h.zone, "a": h.a, "txt": h.txt} for h in hits],
                "ips_v4": ips_v4,
                "ips_v6": ips_v6,
            }
            metrics |= {
                "queries_total": queries_total,
                "hits_count": len(hits),
                "errors_count": errors_count,
            }
            return CheckOutcome(self.name, Status.CRIT, message, metrics)

        return CheckOutcome(
            self.name,
            Status.OK,
            "not listed",
            {"ips_v4": ips_v4, "ips_v6": ips_v6, "queries_total": queries_total, "hits_count": 0, "errors_count": errors_count},
        )
    # ---------- internals ----------

    async def _resolve_ips(self) -> Tuple[List[str], List[str]]:
        """Resolve domain with system resolver and split by address family."""
        loop = asyncio.get_running_loop()
        try:
            infos = await loop.getaddrinfo(self.domain, 80, type=socket.SOCK_STREAM)
        except Exception:
            infos = []

        v4: set[str] = set()
        v6: set[str] = set()
        for family, *_rest, sockaddr in infos:
            host = sockaddr[0]
            if family == socket.AF_INET:
                v4.add(host)
            elif family == socket.AF_INET6:
                v6.add(host)

        return sorted(v4), sorted(v6)

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
