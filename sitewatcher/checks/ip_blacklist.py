from __future__ import annotations

import asyncio
import json
import logging
import socket
from ipaddress import IPv4Address
from dataclasses import dataclass
from typing import List, Optional, Tuple

import dns.asyncresolver
import dns.exception
import dns.resolver

from .base import BaseCheck, CheckOutcome, Status

# Module-level logger for structured events
log = logging.getLogger(__name__)

# Documented IP-listing codes; unknown providers must still use 127.0.0.x.
_RETURN_CODES = {
    'bl.spamcop.net': {2},
    'psbl.surriel.com': {2},
    'bl.blocklist.de': set(range(2, 23)),
    'dnsbl.dronebl.org': {2, 3, *range(5, 20), 255},
    'zen.spamhaus.org': {2, 3, 4, 5, 6, 7, 9, 10, 11, 30},
    'rbl.efnetrbl.org': {1, 2, 3, 4, 5},
}


def _normalize_zones(zones: list[str]) -> list[str]:
    return list(dict.fromkeys(z.strip().strip('.').lower() for z in zones
                              if isinstance(z, str) and z.strip().strip('.')))


def current_ipbl_result(metrics: dict | str | None, config) -> bool:
    """Reject old verdicts or results collected with different source settings."""
    if isinstance(metrics, str):
        try:
            metrics = json.loads(metrics)
        except (ValueError, TypeError):
            return False
    return (isinstance(metrics, dict) and metrics.get('dnsbl_version') == 2
            and metrics.get('zones') == _normalize_zones(config.zones)
            and metrics.get('dns_servers') == config.dns_servers
            and metrics.get('check_ipv6') == config.check_ipv6)


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
        self.zones = _normalize_zones(zones or [])
        self.timeout_s = float(timeout_s)
        self.concurrency = max(1, int(concurrency))
        self.check_ipv6 = bool(check_ipv6)
        self.dns_servers = dns_servers

        # Async resolver instance (dnspython)
        self.resolver = dns.asyncresolver.Resolver()
        if dns_servers:
            # Accept only raw IPs; ignore malformed entries
            good = [ip for ip in dns_servers if _is_ip(ip)]
            if good:
                self.resolver.nameservers = good

    async def run(self) -> CheckOutcome:
        metrics = {
            'dnsbl_version': 2,
            'zones': self.zones,
            'dns_servers': self.dns_servers,
            'check_ipv6': self.check_ipv6,
            'zones_total': len(self.zones),
            'zones_checked': 0,
            'zone_errors': [],
            'query_errors': [],
            'queries_total': 0,
            'hits_count': 0,
            'errors_count': 0,
            'hits': [],
        }
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
            return CheckOutcome(self.name, Status.UNKNOWN, "IP blocklists are not configured", metrics)

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
            return CheckOutcome(self.name, Status.UNKNOWN, f"dns error: {e.__class__.__name__}", metrics)

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
                {**metrics, 'ips_v4': [], 'ips_v6': []},
            )

        # Most DNSBLs are IPv4-only; we probe only IPv4 addresses against zones.
        ips = ips_v4

        # Validate both control records before trusting a zone. An offline/retired
        # DNSBL may return NXDOMAIN for everything or list the entire Internet.
        sem = asyncio.Semaphore(self.concurrency)
        health = await asyncio.gather(*(self._zone_health(sem, zone) for zone in self.zones))
        healthy_zones = [zone for zone, error in zip(self.zones, health, strict=True)
                         if error is None]
        zone_errors = [{'zone': zone, 'error': error}
                       for zone, error in zip(self.zones, health, strict=True) if error is not None]
        pairs = [(ip, zone) for ip in ips for zone in healthy_zones]
        tasks = [self._probe_ip_zone(sem, ip, zone) for ip, zone in pairs]

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, asyncio.CancelledError):
                raise result
        hits: List[Hit] = [r for r in results if isinstance(r, Hit)]
        query_errors = [{'ip': ip, 'zone': zone,
                         'error': str(result) if isinstance(result, ValueError)
                         else type(result).__name__}
                        for (ip, zone), result in zip(pairs, results, strict=True)
                        if isinstance(result, Exception)]
        errors_count = len(query_errors) + len(zone_errors)
        queries_total = len(pairs)
        metrics.update({
            'zones_checked': len(healthy_zones),
            'zone_errors': zone_errors,
            'query_errors': query_errors,
            'ips_v4': ips_v4,
            'ips_v6': ips_v6,
            'queries_total': queries_total,
            'hits_count': len(hits),
            'errors_count': errors_count,
            'hits': [{'ip': h.ip, 'zone': h.zone, 'a': h.a, 'txt': h.txt} for h in hits],
        })

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
            if errors_count:
                message += f'; incomplete coverage ({errors_count} errors)'
            return CheckOutcome(self.name, Status.CRIT, message, metrics)

        message = 'not listed'
        if errors_count or not queries_total:
            message = 'DNSBL queries incomplete'
            if not ips:
                message = 'IP blocklists require an IPv4 address'
            elif errors_count:
                details = [f"{e['zone']}: {e['error']}" for e in zone_errors + query_errors]
                message += ': ' + '; '.join(details)[:500]
        return CheckOutcome(
            self.name,
            Status.UNKNOWN if errors_count or not queries_total else Status.OK,
            message,
            metrics,
        )

    # ----------------------------- internals -----------------------------

    async def _zone_health(self, sem: asyncio.Semaphore, zone: str) -> str | None:
        try:
            async with sem:
                positive = await self._lookup('127.0.0.2', zone)
                if not positive:
                    return 'positive test record is missing'
                negative = await self._lookup('127.0.0.1', zone)
                if negative:
                    return 'negative test record is listed'
        except Exception as error:
            return str(error) if isinstance(error, ValueError) else type(error).__name__
        return None

    async def _lookup(self, ip: str, zone: str) -> list[str]:
        qname = '.'.join(reversed(ip.split('.'))) + '.' + zone + '.'
        try:
            answer = await self.resolver.resolve(qname, 'A', lifetime=self.timeout_s)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        values = [record.address for record in answer]
        if not values:
            raise ValueError('empty DNSBL answer')
        for value in values:
            # IP DNSBLs use 127.0.0.x. In particular, Spamhaus 127.255.255.x
            # codes are access/quota errors, never reputation listings.
            try:
                address = IPv4Address(value)
            except ValueError:
                raise ValueError(f'invalid DNSBL response: {value}') from None
            if str(address).rsplit('.', 1)[0] != '127.0.0' or int(address) % 256 == 0:
                raise ValueError(f'DNSBL service error: {value}')
            code = int(address) % 256
            allowed = _RETURN_CODES.get(zone)
            # DroneBL currently returns .1 for its RFC 5782 positive control.
            if (allowed is not None and code not in allowed
                    and not (zone == 'dnsbl.dronebl.org' and ip == '127.0.0.2' and code == 1)):
                raise ValueError(f'unrecognized DNSBL response: {value}')
        return values

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
        ):
            v4 = []

        try:
            ans_aaaa = await self.resolver.resolve(self.domain, "AAAA", lifetime=self.timeout_s)
            v6 = [rr.address for rr in ans_aaaa]
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
        ):
            v6 = []

        # Deduplicate preserving order
        v4 = list(dict.fromkeys(v4))
        v6 = list(dict.fromkeys(v6))
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
                a_values = await self._lookup(ip, zone)
                if not a_values:
                    return None
                # If we got here, the IP is listed in zone — log at WARNING level
                log.warning(
                    "ipbl.hit",
                    extra={"event": "ipbl.hit", "domain": self.domain, "ip": ip, "zone": zone, "a_count": len(a_values)},
                )
            except (
                dns.resolver.NXDOMAIN,
                dns.resolver.NoAnswer,
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
