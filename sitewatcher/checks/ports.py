# sitewatcher/checks/ports.py
from __future__ import annotations

import asyncio
import logging
import re
import ssl
import time
from dataclasses import dataclass
from typing import Any, List, Optional, Mapping

from .base import BaseCheck, CheckOutcome, Status

# Module-level logger for structured events
log = logging.getLogger(__name__)


@dataclass(frozen=True)
class PortSpec:
    """Desired port probe specification.

    Attributes:
        port: TCP port number.
        host: Optional override host; defaults to the check's domain.
        tls: If True, wrap the TCP connection with TLS.
        send: Optional preamble to send after connect (e.g., "HEAD / HTTP/1.0\r\n\r\n").
        expect: Optional regex to check in the received banner.
        timeout_s: Optional per-probe connect timeout (seconds). If None, use defaults.
    """
    port: int
    host: Optional[str] = None
    tls: bool = False
    send: Optional[str] = None
    expect: Optional[str] = None
    timeout_s: Optional[float] = None


@dataclass
class _PortResult:
    """Result of a single port probe."""
    port: int
    host: str
    ok: bool
    latency_ms: int
    banner: str
    matched: Optional[bool]
    error: Optional[str]
    tls: bool


class PortsCheck(BaseCheck):
    """Probe a set of TCP/TLS ports and optionally verify response banners."""

    name = "ports"

    def __init__(
        self,
        domain: str,
        *,
        targets: List[PortSpec],
        defaults,
    ) -> None:
        """
        Args:
            domain: Primary host used when a PortSpec doesn't override host.
            targets: List of PortSpec describing which ports to probe.
            defaults: Config-like object providing:
                - connect_timeout_s: float
                - read_timeout_s: float
                - read_bytes: int
        """
        super().__init__(domain)
        self.defaults = defaults
        self.targets: List[PortSpec] = self._normalize_targets(targets)

    def _normalize_targets(self, targets: Any) -> List[PortSpec]:
        """Coerce heterogeneous targets (ints, dicts, PortSpec) into List[PortSpec]."""
        out: List[PortSpec] = []
        if not targets:
            return out

        # Accept a single value or an iterable
        items = targets if isinstance(targets, (list, tuple, set)) else [targets]

        for it in items:
            try:
                if isinstance(it, PortSpec):
                    out.append(it)
                    continue
                if isinstance(it, int):
                    out.append(PortSpec(port=int(it)))
                    continue
                if isinstance(it, Mapping):
                    # Expected keys: port (required), host/tls/send/expect/timeout_s (optional)
                    if "port" not in it:
                        log.warning("ports.target_ignored", extra={"event": "ports.target_ignored", "reason": "no_port_key", "item": dict(it)})
                        continue
                    out.append(
                        PortSpec(
                            port=int(it.get("port")),
                            host=str(it.get("host")) if it.get("host") is not None else None,
                            tls=bool(it.get("tls", False)),
                            send=str(it.get("send")) if it.get("send") is not None else None,
                            expect=str(it.get("expect")) if it.get("expect") is not None else None,
                            timeout_s=float(it.get("timeout_s")) if it.get("timeout_s") is not None else None,
                        )
                    )
                    continue
                # Unknown shape — try to coerce simple strings like "443"
                if isinstance(it, str) and it.isdigit():
                    out.append(PortSpec(port=int(it)))
                    continue

                log.warning("ports.target_ignored", extra={"event": "ports.target_ignored", "reason": "unsupported_type", "item": repr(it)})
            except Exception as e:
                log.warning("ports.target_ignored", extra={"event": "ports.target_ignored", "reason": e.__class__.__name__})
        return out

    async def run(self) -> CheckOutcome:
        # Emit a start event: how many targets/which ports we are about to probe
        log.debug(
            "ports.start",
            extra={
                "event": "ports.start",
                "domain": self.domain,
                "targets": [{"host": (t.host or self.domain), "port": int(t.port), "tls": bool(t.tls)} for t in self.targets],
            },
        )

        # Run all probes concurrently
        tasks = [self._probe(spec) for spec in self.targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Normalize exceptions into failed _PortResult
        flat: List[_PortResult] = []
        for spec, res in zip(self.targets, results):
            host = spec.host or self.domain
            if isinstance(res, Exception):
                # Defensive default on unexpected crash per probe
                flat.append(
                    _PortResult(
                        port=spec.port,
                        host=host,
                        ok=False,
                        latency_ms=0,
                        banner="",
                        matched=None,
                        error=res.__class__.__name__,
                        tls=bool(spec.tls),
                    )
                )
            else:
                flat.append(res)

        # Decide status
        total = sum(1 for pr in flat if pr.port != -1)
        failures = sum(1 for pr in flat if pr.port != -1 and not pr.ok)
        mismatches = sum(1 for pr in flat if pr.port != -1 and pr.ok and pr.matched is False)
        opens = sum(1 for pr in flat if pr.port != -1 and pr.ok)
        closed = failures

        if failures > 0:
            status = Status.CRIT
        elif mismatches > 0:
            status = Status.WARN
        else:
            status = Status.OK

        # Human-friendly message
        parts = [f"open {opens}/{total}"]
        if mismatches:
            parts.append(f"mismatch {mismatches}")
        if failures:
            parts.append(f"fail {failures}")
        message = ", ".join(parts)

        # Metrics (compact per-probe list)
        metrics = {
            "total": total,
            "open_count": opens,
            "closed_count": closed,
            "mismatch_count": mismatches,
            "results": [
                {
                    "host": r.host,
                    "port": r.port,
                    "tls": r.tls,
                    "ok": r.ok,
                    "latency_ms": r.latency_ms,
                    "matched": r.matched,
                    "error": r.error,
                    "banner_preview": (r.banner[:120] if r.banner else ""),
                }
                for r in flat
            ],
        }

        # Final summary log for dashboards
        log.info(
            "ports.done",
            extra={
                "event": "ports.done",
                "domain": self.domain,
                "status": status.name if hasattr(status, "name") else str(status),
                "open_count": opens,
                "closed_count": closed,
                "warn_mismatch": mismatches,
                "total": total,
            },
        )

        return CheckOutcome(
            check=self.name,
            status=status,
            message=message,
            metrics=metrics,
        )

    async def _probe(self, spec: PortSpec) -> _PortResult:
        host = spec.host or self.domain
        port = int(spec.port)
        tls = bool(spec.tls)
        connect_timeout = float(getattr(spec, "timeout_s", None) or getattr(self.defaults, "connect_timeout_s", 2.0))
        read_timeout = float(getattr(self.defaults, "read_timeout_s", 1.0))
        read_bytes = int(getattr(self.defaults, "read_bytes", 512))

        # Attempt-start event
        log.debug(
            "ports.probe.start",
            extra={
                "event": "ports.probe.start",
                "domain": self.domain,
                "host": host,
                "port": port,
                "tls": tls,
                "connect_timeout_s": connect_timeout,
                "read_timeout_s": read_timeout,
                "read_bytes": read_bytes,
            },
        )

        start = time.perf_counter()
        reader: Optional[asyncio.StreamReader]
        writer: Optional[asyncio.StreamWriter]
        reader = writer = None
        banner_text = ""
        try:
            ssl_ctx = None
            server_hostname = None
            if tls:
                ssl_ctx = ssl.create_default_context()
                server_hostname = host

            # connect TCP/TLS
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ssl_ctx, server_hostname=server_hostname),
                timeout=connect_timeout,
            )
            latency_ms = int((time.perf_counter() - start) * 1000)
            log.info(
                "ports.probe.connected",
                extra={
                    "event": "ports.probe.connected",
                    "domain": self.domain,
                    "host": host,
                    "port": port,
                    "tls": tls,
                    "latency_ms": latency_ms,
                },
            )

            # send request/preamble if configured
            if spec.send:
                try:
                    payload = spec.send.encode("utf-8")
                    writer.write(payload)
                    await writer.drain()
                    log.debug(
                        "ports.probe.sent",
                        extra={
                            "event": "ports.probe.sent",
                            "domain": self.domain,
                            "host": host,
                            "port": port,
                            "bytes": len(payload),
                        },
                    )
                except Exception:
                    # sending is best-effort; continue to read banner
                    pass

            # read the banner (useful)
            try:
                data = await asyncio.wait_for(reader.read(read_bytes), timeout=read_timeout)
                banner_text = (data or b"").decode("utf-8", errors="ignore").strip()
                log.debug(
                    "ports.probe.banner",
                    extra={
                        "event": "ports.probe.banner",
                        "domain": self.domain,
                        "host": host,
                        "port": port,
                        "bytes": len(data or b""),
                    },
                )
            except asyncio.TimeoutError:
                banner_text = ""  # no banner - it's normal too
            except Exception:
                banner_text = ""

            matched: Optional[bool] = None
            if spec.expect:
                try:
                    matched = bool(re.search(spec.expect, banner_text or "", flags=re.IGNORECASE | re.MULTILINE))
                    log.info(
                        "ports.probe.expect",
                        extra={
                            "event": "ports.probe.expect",
                            "domain": self.domain,
                            "host": host,
                            "port": port,
                            "matched": matched,
                        },
                    )
                except re.error:
                    matched = None  # invalid regex — ignore

            return _PortResult(
                port=port,
                host=host,
                ok=True,
                latency_ms=latency_ms,
                banner=banner_text,
                matched=matched,
                error=None,
                tls=tls,
            )

        except Exception as e:
            latency_ms = int((time.perf_counter() - start) * 1000)
            log.warning(
                "ports.probe.error",
                extra={
                    "event": "ports.probe.error",
                    "domain": self.domain,
                    "host": host,
                    "port": port,
                    "tls": tls,
                    "latency_ms": latency_ms,
                    "error": e.__class__.__name__,
                },
            )
            return _PortResult(
                port=port,
                host=host,
                ok=False,
                latency_ms=latency_ms,
                banner=banner_text,
                matched=None,
                error=e.__class__.__name__,
                tls=tls,
            )
        finally:
            if writer is not None:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    # best-effort close; do not mask earlier outcomes
                    pass