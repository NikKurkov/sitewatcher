"""Bounded, unprivileged UDP route observations from the worker host."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import ipaddress
import re
import shutil
import time

import dns.asyncresolver
import dns.exception
import dns.reversename

from .base import BaseCheck, CheckOutcome, Status

MAX_HOPS = 24
MAX_OUTPUT_BYTES = 64 * 1024
TOTAL_TIMEOUT = 29.0  # Leave time inside the 30-second contract for kill/reap.
DNS_TIMEOUT = 2.0
PTR_TIMEOUT = 1.0


def _parse_hops(output: str) -> list[dict]:
    hops = []
    for line in output.splitlines():
        match = re.match(r"^\s*(\d+)\s+(.+)$", line)
        if not match or not 1 <= int(match[1]) <= MAX_HOPS:
            continue
        ttl, tail = int(match[1]), match[2]
        address = None
        rtt = None
        for token in tail.split():
            try:
                address = str(ipaddress.ip_address(token))
                break
            except ValueError:
                continue
        if address:
            timing = re.search(r"(\d+(?:\.\d+)?)\s*ms\b", tail)
            if timing:
                rtt = float(timing[1])
        elif "*" not in tail:
            continue
        # -q 1 emits one observation per TTL; keep malformed duplicate lines out.
        if any(hop["ttl"] == ttl for hop in hops):
            continue
        hops.append({"ttl": ttl, "ip": address, "hostname": None, "rtt_ms": rtt})
    return sorted(hops, key=lambda hop: hop["ttl"])


async def _resolve_destination(domain: str) -> str:
    try:
        return str(ipaddress.ip_address(domain))
    except ValueError:
        pass
    for family in ("A", "AAAA"):
        try:
            answer = await dns.asyncresolver.resolve(domain, family, lifetime=DNS_TIMEOUT)
            for record in answer:
                address = ipaddress.ip_address(record.address)
                if address.version == (4 if family == "A" else 6):
                    return str(address)
        except (dns.exception.DNSException, OSError, ValueError):
            continue
    raise ValueError("No destination address")


async def _resolve_hostname(hop: dict) -> None:
    if not hop["ip"]:
        return
    try:
        async with asyncio.timeout(PTR_TIMEOUT):
            answer = await dns.asyncresolver.resolve(
                dns.reversename.from_address(hop["ip"]), "PTR", lifetime=PTR_TIMEOUT
            )
            if answer:
                # DNS labels are data, never commands; discard control characters.
                hostname = str(answer[0].target).rstrip(".")
                if hostname and len(hostname) <= 253 and not any(
                    ord(char) < 32 or ord(char) == 127 for char in hostname
                ):
                    hop["hostname"] = hostname
    except (dns.exception.DNSException, OSError, ValueError, TimeoutError):
        pass


class TracerouteCheck(BaseCheck):
    name = "traceroute"

    async def run(self) -> CheckOutcome:
        started = time.monotonic()
        output = bytearray()
        destination = None
        hops: list[dict] = []
        truncated = False
        error = None
        process = None
        executable = shutil.which("traceroute")

        async def collect_stdout() -> None:
            nonlocal truncated
            while chunk := await process.stdout.read(4096):
                remaining = MAX_OUTPUT_BYTES - len(output)
                output.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    truncated = True
                    if process.returncode is None:
                        try:
                            process.kill()
                        except ProcessLookupError:
                            pass
                    break

        try:
            if not executable:
                error = "tool_unavailable"
            else:
                async with asyncio.timeout(TOTAL_TIMEOUT):
                    destination = await _resolve_destination(self.domain)
                    family = "-6" if ipaddress.ip_address(destination).version == 6 else "-4"
                    # Shield process creation so cancellation cannot orphan a spawned child.
                    spawning = asyncio.create_task(asyncio.create_subprocess_exec(
                        executable, family, "-n", "-q", "1", "-m", str(MAX_HOPS),
                        "-w", "1", "-N", "4", "--", destination,
                        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
                        limit=MAX_OUTPUT_BYTES,
                    ))
                    try:
                        process = await asyncio.shield(spawning)
                    except asyncio.CancelledError:
                        process = await spawning
                        raise
                    await asyncio.gather(collect_stdout(), process.wait())
                    hops = _parse_hops(output.decode("utf-8", errors="replace"))
                    if process.returncode:
                        error = "process_failed"
                    await asyncio.gather(*(_resolve_hostname(hop) for hop in hops))
        except TimeoutError:
            truncated = True
            error = "timeout"
        except (dns.exception.DNSException, ValueError):
            error = "dns_failed"
        except OSError:
            error = "process_unavailable"
        finally:
            if process is not None and process.returncode is None:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
                await asyncio.shield(process.wait())

        if not hops:
            hops = _parse_hops(output.decode("utf-8", errors="replace"))
        responsive = any(hop["ip"] for hop in hops)
        reached = bool(destination and any(hop["ip"] == destination for hop in hops))
        truncated = truncated or (not reached and any(hop["ttl"] == MAX_HOPS for hop in hops))
        metrics = {
            "destination_ip": destination, "method": "udp", "hops": hops,
            "reached": reached, "truncated": truncated,
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "duration_ms": int((time.monotonic() - started) * 1000),
        }
        if error:
            metrics["error"] = error
        elif not responsive:
            metrics["error"] = "no_responses"
        return CheckOutcome(
            self.name, Status.OK if responsive else Status.UNKNOWN,
            "Route observed" if reached else "Partial route observed" if responsive
            else "Route unavailable", metrics,
        )
