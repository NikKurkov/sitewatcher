# sitewatcher/dispatcher.py
from __future__ import annotations

import asyncio
import json
import re
from typing import Dict, Iterable, List, Optional, Sequence, Tuple
from pathlib import Path
import logging

import httpx

from . import storage
from .checks.base import CheckOutcome, Status
from .checks.http_basic import HttpBasicCheck
from .checks.ip_blacklist import IpBlacklistCheck
from .checks.ip_change import IpChangeCheck
from .checks.keywords import KeywordsCheck
from .checks.ping import PingCheck
from .checks.ports import PortsCheck
from .checks.tls_cert import TlsCertCheck
from .checks.whois_info import WhoisInfoCheck
from .checks.deface import DefaceCheck
from .config import AppConfig, ResolvedSettings, resolve_settings


logger = logging.getLogger("sitewatcher.dispatcher")

# Optional RKN plugin (kept soft to avoid import-time failures)
try:  # pragma: no cover
    from .checks.rkn_block_sqlite import RknBlockCheck  # type: ignore
except Exception:  # pragma: no cover
    RknBlockCheck = None  # type: ignore


class Dispatcher:
    """
    Orchestrates checks for a domain:
      - manages a shared httpx.AsyncClient (HTTP/2 if available, otherwise HTTP/1.1),
      - limits per-domain concurrency with a semaphore,
      - builds and runs the active checks concurrently,
      - optionally serves cached results by per-check TTL.

    Мульти-тенант: все операции требуют owner_id.
    """

    def __init__(self, cfg: AppConfig, max_concurrency: int = 10) -> None:
        self.cfg = cfg
        self._client: Optional[httpx.AsyncClient] = None
        self._default_per_domain_concurrency = max(1, int(max_concurrency))

    # ---------- lifecycle ----------

    async def __aenter__(self) -> "Dispatcher":
        http_cfg = getattr(self.cfg, "http", None)

        connect = float(getattr(http_cfg, "connect_timeout", 5.0)) if http_cfg else 5.0
        read = float(getattr(http_cfg, "read_timeout", 10.0)) if http_cfg else 10.0
        write = float(getattr(http_cfg, "write_timeout", 10.0)) if http_cfg else 10.0
        pool = float(getattr(http_cfg, "pool_timeout", 5.0)) if http_cfg else 5.0
        max_conn = int(getattr(http_cfg, "max_connections", 100)) if http_cfg else 100
        max_keep = int(getattr(http_cfg, "max_keepalive_connections", 20)) if http_cfg else 20

        timeout = httpx.Timeout(connect=connect, read=read, write=write, pool=pool)
        limits = httpx.Limits(max_connections=max_conn, max_keepalive_connections=max_keep)

        # Respect proxies from config (if any) and environment (trust_env=True)
        proxy_kw: dict[str, object] = {}
        if http_cfg:
            proxy_val = getattr(http_cfg, "proxy", None) or getattr(http_cfg, "proxies", None)
            if isinstance(proxy_val, str):
                proxy_kw = {"proxy": proxy_val}
            elif isinstance(proxy_val, dict):
                # Map scheme => transport using AsyncHTTPTransport
                mounts: dict[str, httpx.AsyncHTTPTransport] = {}
                for scheme, url in proxy_val.items():
                    key = scheme if scheme.endswith("://") else f"{scheme}://"
                    mounts[key] = httpx.AsyncHTTPTransport(proxy=url)
                proxy_kw = {"mounts": mounts}

        try:
            self._client = httpx.AsyncClient(
                http2=True,
                timeout=timeout,
                limits=limits,
                trust_env=True,
                headers={"User-Agent": "sitewatcher/0.1 (+https://github.com/NikKurkov/sitewatcher)"},
                **proxy_kw,
            )
        except Exception:
            self._client = httpx.AsyncClient(
                http2=False,
                timeout=timeout,
                limits=limits,
                trust_env=True,
                headers={"User-Agent": "sitewatcher/0.1 (+https://github.com/NikKurkov/sitewatcher)"},
                **proxy_kw,
            )

        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    # ---------- public API ----------

    async def run_for(
        self,
        owner_id: int,
        domain: str,
        only_checks: Optional[Iterable[str]] = None,
        use_cache: bool = False,
    ) -> List[CheckOutcome]:
        """
        Run checks for a single domain (owner-aware).
        """
        settings = self._resolve(owner_id, domain)
        checks = self._filter_checks(self._build_checks(settings), only_checks)

        def _ttl_minutes(check_name: str) -> int:
            sc = getattr(self.cfg.schedules, check_name, None)
            try:
                return int(getattr(sc, "cache_ttl_minutes", 0) or 0) if sc is not None else 0
            except Exception:
                return 0

        per_domain_limit = self._get_scheduler_value("per_domain_concurrency", self._default_per_domain_concurrency)
        sem = asyncio.Semaphore(per_domain_limit)

        results_ordered: List[Optional[CheckOutcome]] = [None] * len(checks)
        tasks: List[asyncio.Task[Tuple[int, CheckOutcome]]] = []
        idx_map: List[int] = []

        async def _run_one(idx: int, chk) -> Tuple[int, CheckOutcome]:
            async with sem:
                try:
                    res = await chk.run()
                except Exception as e:
                    name = getattr(chk, "name", "")
                    res = CheckOutcome(name, Status.UNKNOWN, f"error: {e.__class__.__name__}: {e}", {})
                return idx, res

        for i, chk in enumerate(checks):
            name = getattr(chk, "name", "")
            if use_cache:
                cached = self._maybe_cached_result(owner_id, domain, name, _ttl_minutes)
                if cached is not None:
                    results_ordered[i] = cached
                    continue

            tasks.append(asyncio.create_task(_run_one(i, chk)))
            idx_map.append(i)

        if tasks:
            domain_timeout = self._get_scheduler_value("domain_timeout_s", None)

            if isinstance(domain_timeout, (int, float)) and domain_timeout > 0:
                try:
                    done_results = await asyncio.wait_for(
                        asyncio.gather(*tasks, return_exceptions=False),
                        timeout=float(domain_timeout),
                    )
                    for idx, res in done_results:
                        results_ordered[idx] = res
                except asyncio.TimeoutError:
                    for t in tasks:
                        if not t.done():
                            t.cancel()

                    gathered = await asyncio.gather(*tasks, return_exceptions=True)
                    for pos, outcome in enumerate(gathered):
                        chk_idx = idx_map[pos]
                        name = getattr(checks[chk_idx], "name", "")
                        if isinstance(outcome, tuple):
                            i_idx, res = outcome
                            results_ordered[i_idx] = res
                        elif isinstance(outcome, asyncio.CancelledError):
                            results_ordered[chk_idx] = CheckOutcome(name, Status.UNKNOWN, "timeout", {})
                        elif isinstance(outcome, Exception):
                            results_ordered[chk_idx] = CheckOutcome(
                                name, Status.UNKNOWN, f"error: {outcome.__class__.__name__}: {outcome}", {}
                            )
                        else:
                            results_ordered[chk_idx] = CheckOutcome(name, Status.UNKNOWN, "unknown", {})
            else:
                done_results = await asyncio.gather(*tasks, return_exceptions=False)
                for idx, res in done_results:
                    results_ordered[idx] = res

        return [r for r in results_ordered if r is not None]

    async def run_many(self, owner_id: int, domains: Sequence[str]) -> Dict[str, List[CheckOutcome]]:
        """
        Convenience helper: run checks for multiple domains (same owner).
        """
        assert self._client is not None, "Use 'async with Dispatcher(cfg) as d:'"

        domains_concurrency = self._get_scheduler_value("domains_concurrency", 5)
        sem = asyncio.Semaphore(domains_concurrency)

        async def _run(name: str) -> Tuple[str, List[CheckOutcome]]:
            return name, await self.run_for(owner_id, name)

        async def _guarded(name: str) -> Tuple[str, List[CheckOutcome]]:
            async with sem:
                return await _run(name)

        pairs = await asyncio.gather(*(_guarded(d) for d in domains))
        return {name: outcomes for name, outcomes in pairs}

    # ---------- internals ----------

    def _resolve(self, owner_id: int, domain: str) -> ResolvedSettings:
        """
        Resolve base settings and apply per-domain overrides from storage (owner-aware).
        """
        base = resolve_settings(self.cfg, domain)
        try:
            patch = storage.get_domain_override(owner_id, domain)
        except Exception:
            patch = {}

        if not patch:
            return base

        checks_patch = patch.get("checks")
        if isinstance(checks_patch, dict) and getattr(base, "checks", None) is not None:
            for k, v in checks_patch.items():
                if hasattr(base.checks, k):
                    setattr(base.checks, k, bool(v))

        for f in (
            "http_timeout_s",
            "latency_warn_ms",
            "latency_crit_ms",
            "tls_warn_days",
            "proxy",
            "keywords",
            "ports",
        ):
            if f in patch:
                setattr(base, f, patch[f])

        return base

    def _build_checks(self, settings: ResolvedSettings) -> List:
        """Instantiate enabled checks based on resolved settings."""
        assert self._client is not None

        out: List = []

        if getattr(settings.checks, "http_basic", False):
            out.append(
                HttpBasicCheck(
                    settings.name,
                    client=self._client,
                    timeout_s=settings.http_timeout_s,
                    latency_warn_ms=settings.latency_warn_ms,
                    latency_crit_ms=settings.latency_crit_ms,
                    proxy=settings.proxy,
                )
            )

        if getattr(settings.checks, "tls_cert", False):
            out.append(TlsCertCheck(settings.name, warn_days=settings.tls_warn_days))

        if getattr(settings.checks, "keywords", False):
            out.append(
                KeywordsCheck(
                    settings.name,
                    client=self._client,
                    timeout_s=settings.http_timeout_s,
                    keywords=settings.keywords,
                )
            )

        if getattr(settings.checks, "deface", False):
            # Use HTTP timeout from settings for consistency with other HTTP checks.
            timeout_s = float(getattr(settings, "http_timeout_s", 10) or 10)

            # Load phrases from cfg.deface.phrases_path if provided; fallback to built-ins.
            markers = None
            phrases_path = getattr(getattr(self.cfg, "deface", None), "phrases_path", None)
            if phrases_path:
                try:
                    with open(phrases_path, "r", encoding="utf-8") as fh:
                        markers = [ln.strip() for ln in fh if ln.strip()]
                    logger.debug("DefaceCheck: loaded %d markers from %s", len(markers), phrases_path)
                except Exception as e:
                    logger.warning("DefaceCheck: failed to read markers file %r: %s (fallback to built-in)", phrases_path, e)
                    markers = None
            else:
                logger.debug("DefaceCheck: no phrases_path configured; using built-in defaults")

            out.append(DefaceCheck(settings.name, client=self._client, timeout_s=timeout_s, markers=markers))
        else:
            logger.debug("DefaceCheck: disabled for %s", settings.name)

        # В самом конце метода _build_checks добавьте единый лог:
        logger.debug("Build checks for %s: %s", settings.name, [getattr(c, 'name', '?') for c in out])

        if getattr(settings.checks, "ping", False):
            out.append(PingCheck(settings.name))

        if getattr(settings.checks, "rkn_block", False) and RknBlockCheck is not None:
            out.append(RknBlockCheck(settings.name, client=self._client, rkn_cfg=self.cfg.rkn))

        if getattr(settings.checks, "ports", False):
            targets = getattr(settings, "ports", None) or self.cfg.ports.targets
            out.append(PortsCheck(settings.name, targets=targets if targets else self.cfg.ports.targets, defaults=self.cfg.ports))

        if getattr(settings.checks, "whois", False):
            out.append(WhoisInfoCheck(settings.name, client=self._client, cfg=self.cfg.whois))

        if getattr(settings.checks, "ip_blacklist", False):
            out.append(
                IpBlacklistCheck(
                    settings.name,
                    zones=self.cfg.ipbl.zones,
                    dns_servers=self.cfg.ipbl.dns_servers,
                    timeout_s=self.cfg.ipbl.timeout_s,
                    concurrency=self.cfg.ipbl.concurrency,
                    check_ipv6=self.cfg.ipbl.check_ipv6,
                )
            )

        if getattr(settings.checks, "ip_change", False):
            out.append(IpChangeCheck(settings.name, cfg=self.cfg.ipchange))

        return out

    @staticmethod
    def _normalize_results(results: Iterable[object]) -> List[CheckOutcome]:
        out: List[CheckOutcome] = []
        for r in results:
            if isinstance(r, Exception):
                out.append(CheckOutcome(check="internal", status=Status.CRIT, message=f"{r.__class__.__name__}: {r}", metrics={}))
            else:
                out.append(r)  # type: ignore[arg-type]
        return out

    # ---------- small helpers ----------

    def _get_scheduler_value(self, name: str, default):
        sched = getattr(self.cfg, "scheduler", object())
        val = getattr(sched, name, None)
        return val if isinstance(val, (int, float)) and val > 0 else default

    @staticmethod
    def _strip_cached_suffix(msg: str) -> str:
        return re.sub(r"(?:\s*\[cached\s+\d+m\])+$", "", msg or "", flags=re.I)

    def _maybe_cached_result(
        self,
        owner_id: int,
        domain: str,
        check_name: str,
        ttl_fn,
    ) -> Optional[CheckOutcome]:
        """
        Return cached CheckOutcome if fresh enough, otherwise None. (owner-aware)
        """
        ttl = ttl_fn(check_name)
        if ttl <= 0:
            return None

        row = storage.last_history_for_check(owner_id, domain, check_name)
        if not row:
            return None

        mins = storage.minutes_since_last(owner_id, domain, check_name)
        if mins is None or mins > ttl:
            return None

        try:
            metrics = json.loads(row["metrics_json"] or "{}")
        except Exception:
            metrics = {}

        base_msg = self._strip_cached_suffix(row["message"] or "")
        return CheckOutcome(
            check=check_name,
            status=row["status"],
            message=f"{base_msg} [cached {mins}m]",
            metrics=metrics,
        )

    @staticmethod
    def _filter_checks(checks: List, only_checks: Optional[Iterable[str]]) -> List:
        if not only_checks:
            return checks
        allowed = {str(x) for x in only_checks}
        return [c for c in checks if getattr(c, "name", "") in allowed]
