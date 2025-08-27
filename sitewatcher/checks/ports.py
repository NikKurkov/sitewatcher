# /checks/ports.py
from __future__ import annotations

import asyncio
import re
import ssl
import time
from dataclasses import dataclass
from typing import List, Optional, Tuple

from .base import BaseCheck, CheckOutcome, Status
from ..config import PortSpec, PortsConfig


@dataclass
class _PortResult:
    port: int
    host: str
    ok: bool
    latency_ms: int
    banner: str
    matched: Optional[bool]
    error: Optional[str]
    tls: bool


class PortsCheck(BaseCheck):
    name = "ports"

    def __init__(
        self,
        domain: str,
        targets: List[PortSpec],
        defaults: PortsConfig,
    ) -> None:
        super().__init__(domain)
        self.targets = targets
        self.defaults = defaults

    async def run(self) -> CheckOutcome:
        # parallel
        tasks = [self._probe(spec) for spec in self.targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        flat: List[_PortResult] = []
        for r in results:
            if isinstance(r, Exception):
                flat.append(_PortResult(
                    port=-1, host=self.domain, ok=False, latency_ms=0,
                    banner="", matched=None, error=f"{r.__class__.__name__}: {r}", tls=False
                ))
            else:
                flat.append(r)

        # aggregate status: if have CRIT (closed/erro) -> CRIT, otherwise if have WARN (expect not eq) -> WARN, else Ok
        has_crit = any((not pr.ok) and pr.port != -1 for pr in flat)
        has_warn = any(pr.ok and pr.matched is False for pr in flat)

        if has_crit:
            status = Status.CRIT
        elif has_warn:
            status = Status.WARN
        else:
            status = Status.OK

        # short message
        parts = []
        for pr in flat:
            if pr.port == -1:
                parts.append(f"internal error ({pr.error})")
                continue
            state = "open" if pr.ok else "closed"
            extra = []
            if pr.tls:
                extra.append("TLS")
            if pr.matched is False:
                extra.append("expect_miss")
            elif pr.matched is True:
                extra.append("expect_ok")
            tag = f" [{', '.join(extra)}]" if extra else ""
            parts.append(f"{pr.port}:{state}{tag} ({pr.latency_ms} ms)")

        message = "; ".join(parts)

        # metrics in pretty view
        metrics = {
            "results": [
                {
                    "port": pr.port,
                    "host": pr.host,
                    "open": pr.ok,
                    "latency_ms": pr.latency_ms,
                    "banner": pr.banner,
                    "matched": pr.matched,
                    "error": pr.error,
                    "tls": pr.tls,
                }
                for pr in flat if pr.port != -1
            ]
        }

        return CheckOutcome(
            check=self.name,
            status=status,
            message=message,
            metrics=metrics,
        )

    async def _probe(self, spec: PortSpec) -> _PortResult:
        host = spec.host or self.domain
        port = spec.port
        tls = bool(spec.tls)
        connect_timeout = float(spec.timeout_s or self.defaults.connect_timeout_s)
        read_timeout = float(self.defaults.read_timeout_s)
        read_bytes = int(self.defaults.read_bytes)

        start = time.perf_counter()
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

            # send spec
            if spec.send:
                try:
                    writer.write(spec.send.encode("utf-8"))
                    await writer.drain()
                except Exception:
                    pass

            # read the banner (usefull)
            try:
                data = await asyncio.wait_for(reader.read(read_bytes), timeout=read_timeout)
                banner_text = data.decode("utf-8", errors="ignore").strip()
            except asyncio.TimeoutError:
                banner_text = ""  # no banner - its normal too
            except Exception:
                banner_text = ""

            matched: Optional[bool] = None
            if spec.expect:
                try:
                    matched = bool(re.search(spec.expect, banner_text or "", flags=re.IGNORECASE | re.MULTILINE))
                except re.error:
                    matched = None  # not correct regex — ignore

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
                    pass
