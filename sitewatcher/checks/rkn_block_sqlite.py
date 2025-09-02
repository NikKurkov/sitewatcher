# sitewatcher/checks/rkn_block_sqlite.py
from __future__ import annotations

import asyncio
import io
import logging
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

import httpx

from .base import BaseCheck, CheckOutcome, Status
from ..config import RknConfig
from ..utils.http_retry import get_with_retries

logger = logging.getLogger("sitewatcher.rkn")

# Single-writer guard for index refresh (process-wide)
_REFRESH_LOCK = asyncio.Lock()

# Default upstream: zapret-info/z-i public dataset
_ZI_DEFAULT_URL = "https://raw.githubusercontent.com/zapret-info/z-i/master/dump.csv.gz"


@dataclass
class _DbMeta:
    fetched_at: Optional[datetime] = None


class RknBlockCheck(BaseCheck):
    """Check presence of a domain (and optionally its IPs) in RKN (zapret-info) lists.

    Design goals:
      - Keep a tiny local SQLite index (domains + IPv4) for fast lookups.
      - Refresh the index on demand by TTL.
      - Treat source/network failures as UNKNOWN (not CRIT).
    """

    name = "rkn_block"

    def __init__(
        self,
        domain: str,
        *,
        client: httpx.AsyncClient,
        rkn_cfg: RknConfig,
    ) -> None:
        super().__init__(domain)
        self.client = client
        self.cfg = rkn_cfg

        # Resolve DB path; default to package data directory.
        data_dir = Path(__file__).resolve().parent.parent / "data"
        self.db_path = (
            Path(self.cfg.index_db_path)
            if self.cfg.index_db_path
            else (data_dir / "z_i_index.db")
        )

        # Behavior toggles (explicit defaults come from RknConfig)
        self._dump_url = self.cfg.z_i_url or _ZI_DEFAULT_URL
        self._ttl_hours = int(self.cfg.cache_ttl_hours)
        self._match_subdomains = bool(self.cfg.match_subdomains)
        self._check_ip = bool(self.cfg.check_ip)

    # ------------------------------- Public API -------------------------------

    async def run(self) -> CheckOutcome:
        """Ensure index is fresh, then check domain/IP presence."""
        try:
            await self._ensure_index_up_to_date()
        except Exception as e:
            logger.exception("RKN: index refresh failed for %s", self.domain)
            return CheckOutcome(
                self.name, Status.UNKNOWN, f"source error: {e.__class__.__name__}: {e}", {}
            )

        dom = self.domain.lower().rstrip(".")
        try:
            listed_by_domain = self._query_domain_match(dom, self._match_subdomains)
        except Exception as e:
            logger.exception("RKN: domain query failed for %s", dom)
            return CheckOutcome(
                self.name, Status.UNKNOWN, f"query error: {e.__class__.__name__}: {e}", {}
            )

        ips: list[str] = []
        listed_by_ip = False
        if self._check_ip and not listed_by_domain:
            try:
                ips = await self._resolve_ips(dom)
                if ips:
                    listed_by_ip = self._query_ip_match(ips)
            except Exception:
                # DNS/OS issues are not fatal for this check
                ips = []
                listed_by_ip = False

        meta = self._get_meta()
        fetched_iso = meta.fetched_at.isoformat() if meta.fetched_at else None

        if listed_by_domain or listed_by_ip:
            msg = "listed" + (" (by IP)" if listed_by_ip and not listed_by_domain else "")
            # If the domain itself is listed → CRIT; if only IP is listed → keep WARN.
            severity = Status.CRIT if listed_by_domain else Status.WARN
            return CheckOutcome(
                self.name,
                severity,
                msg,
                {
                    "source": "z-i",
                    "fetched_at": fetched_iso,
                    "domain": dom,
                    "ips": ips,
                    "matched_domain": bool(listed_by_domain),
                    "matched_ip": bool(listed_by_ip),
                },
            )

        return CheckOutcome(
            self.name,
            Status.OK,
            "not listed",
            {"source": "z-i", "fetched_at": fetched_iso, "domain": dom, "ips": ips},
        )

    # ------------------------------ Index refresh -----------------------------

    async def _ensure_index_up_to_date(self) -> None:
        """Create DB if missing and refresh content if stale by TTL (single-writer)."""
        self._init_schema_if_needed()
        meta = self._get_meta()
        now = datetime.now(timezone.utc)

        # Fast path: already fresh
        if meta.fetched_at is not None and (now - meta.fetched_at) < timedelta(hours=self._ttl_hours):
            return

        # Only one task may rebuild the index at a time
        async with _REFRESH_LOCK:
            # Re-check freshness after acquiring the lock (herd protection)
            meta2 = self._get_meta()
            now2 = datetime.now(timezone.utc)
            if meta2.fetched_at is not None and (now2 - meta2.fetched_at) < timedelta(hours=self._ttl_hours):
                return

            logger.info("RKN: refreshing index (TTL %dh)", self._ttl_hours)
            csv_text = await self._download_dump(self._dump_url)
            self._rebuild_index(csv_text, fetched_at=now2)

    async def _download_dump(self, url: str) -> str:
        """Download upstream dump (CSV or gzipped CSV) and return UTF-8 text."""
        resp = await get_with_retries(
            self.client,
            url,
            timeout_s=30.0,
            retries=2,
            backoff_s=0.3,
            follow_redirects=True,
            headers={"User-Agent": "sitewatcher/0.1 (+https://github.com/NikKurkov/sitewatcher)"},
        )
        resp.raise_for_status()
        content = resp.content

        # GZIP magic header 1F 8B
        if len(content) >= 2 and content[0] == 0x1F and content[1] == 0x8B:
            import gzip

            with gzip.GzipFile(fileobj=io.BytesIO(content)) as gz:
                return gz.read().decode("utf-8", "ignore")
        return content.decode("utf-8", "ignore")

    # ------------------------------- SQLite layer -----------------------------

    def _connect(self) -> sqlite3.Connection:
        """Open SQLite with WAL + timeouts to play well with concurrency."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path), timeout=5.0)
        # Performance/robustness pragmas
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA temp_store=MEMORY;")
        conn.execute("PRAGMA busy_timeout=3000;")
        return conn

    def _init_schema_if_needed(self) -> None:
        """Create a clean schema (no legacy columns)."""
        conn = self._connect()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS meta (
                    key   TEXT PRIMARY KEY,
                    value TEXT
                );

                CREATE TABLE IF NOT EXISTS domains (
                    domain TEXT PRIMARY KEY
                );

                CREATE TABLE IF NOT EXISTS ips (
                    ip TEXT PRIMARY KEY
                );
                """
            )
            conn.commit()
        finally:
            conn.close()

    def _get_meta(self) -> _DbMeta:
        conn = self._connect()
        try:
            row = conn.execute("SELECT value FROM meta WHERE key='fetched_at'").fetchone()
            if not row or not row[0]:
                return _DbMeta(None)
            try:
                dt = datetime.fromisoformat(row[0])
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
            except Exception:
                dt = None
            return _DbMeta(dt)
        finally:
            conn.close()

    def _rebuild_index(self, csv_text: str, *, fetched_at: datetime) -> None:
        """Parse upstream dump and rebuild the local index in a single transaction."""
        domain_rx = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.I)
        ipv4_rx = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

        conn = self._connect()
        try:
            cur = conn.cursor()
            cur.execute("BEGIN IMMEDIATE")  # exclusive writer
            cur.execute("DELETE FROM domains")
            cur.execute("DELETE FROM ips")

            dom_seen: set[str] = set()
            ip_seen: set[str] = set()

            for line in csv_text.splitlines():
                if not line:
                    continue
                for d in domain_rx.findall(line):
                    d = d.lower().rstrip(".")
                    if d not in dom_seen:
                        dom_seen.add(d)
                        cur.execute("INSERT OR IGNORE INTO domains(domain) VALUES(?)", (d,))
                for ip in ipv4_rx.findall(line):
                    if ip not in ip_seen:
                        ip_seen.add(ip)
                        cur.execute("INSERT OR IGNORE INTO ips(ip) VALUES(?)", (ip,))

            # Write meta in the same transaction/connection (avoids cross-connection lock)
            cur.execute(
                "INSERT INTO meta(key,value) VALUES('fetched_at', ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (fetched_at.isoformat(),),
            )

            conn.commit()
            logger.info("RKN: index rebuilt: %d domains, %d ips", len(dom_seen), len(ip_seen))
        finally:
            conn.close()

    # ---------------------------- Query primitives ----------------------------

    def _query_domain_match(self, domain: str, match_subdomains: bool) -> bool:
        """Return True if the domain (or its parent suffix) is listed."""
        conn = self._connect()
        try:
            # Exact match first
            row = conn.execute(
                "SELECT 1 FROM domains WHERE domain = ? LIMIT 1", (domain,)
            ).fetchone()
            if row:
                return True

            if not match_subdomains:
                return False

            # Walk up suffixes: a.b.c -> b.c -> c
            parts = domain.split(".")
            for i in range(1, len(parts) - 1):
                suffix = ".".join(parts[i:])
                row = conn.execute(
                    "SELECT 1 FROM domains WHERE domain = ? LIMIT 1", (suffix,)
                ).fetchone()
                if row:
                    return True
            return False
        finally:
            conn.close()

    def _query_ip_match(self, ips: list[str]) -> bool:
        """Return True if any of the IPv4 addresses is listed."""
        if not ips:
            return False
        conn = self._connect()
        try:
            q = "SELECT 1 FROM ips WHERE ip = ? LIMIT 1"
            for ip in ips:
                row = conn.execute(q, (ip,)).fetchone()
                if row:
                    return True
            return False
        finally:
            conn.close()

    async def _resolve_ips(self, domain: str) -> list[str]:
        """Resolve A-records for the domain (best-effort)."""
        loop = asyncio.get_running_loop()
        try:
            infos = await loop.getaddrinfo(domain, None, family=0, type=0, proto=0, flags=0)
        except Exception:
            return []
        out: list[str] = []
        for _, _, _, _, sockaddr in infos:
            if isinstance(sockaddr, tuple) and len(sockaddr) >= 1:
                ip = sockaddr[0]
                # Keep IPv4 only (schema stores IPv4)
                if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
                    out.append(ip)
        # Deduplicate preserving order
        seen: set[str] = set()
        uniq: list[str] = []
        for ip in out:
            if ip not in seen:
                uniq.append(ip)
                seen.add(ip)
        return uniq
