# /checks/rkn_block_sqlite.py
from __future__ import annotations

import asyncio
import gzip
import ipaddress
import re
import socket
import sqlite3
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path
from typing import Optional, Sequence, Iterable

import httpx

from .base import BaseCheck, CheckOutcome, Status
from ..config import RknConfig
from ..utils.http_retry import get_with_retries

# --- SSOT: constants & regexes ---
_ZI_BASE_URL = "https://raw.githubusercontent.com/zapret-info/z-i/master/"
_ZI_PARTS_COUNT = 20            # dump-00..19.csv
_BATCH_SIZE = 10_000            # insert batch size

_DOMAIN_RE = re.compile(r"\b([a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# SQLite schema (kept minimal and tuned for fast inserts / lookups)
SCHEMA_SQL = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA temp_store=MEMORY;

CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS domains (
  domain TEXT PRIMARY KEY
);
CREATE INDEX IF NOT EXISTS idx_domains_domain ON domains(domain);

CREATE TABLE IF NOT EXISTS ips (
  ip TEXT PRIMARY KEY
);
CREATE INDEX IF NOT EXISTS idx_ips_ip ON ips(ip);
"""


class RknBlockCheck(BaseCheck):
    """
    SQLite-backed RKN (zapret-info) checker.

    - Maintains a compact local index with two sets: domains and IPv4 addresses.
    - Rebuilds the index when stale using the official dump with resilient fallbacks.
    - Queries are simple equality lookups; subdomain matching is done in Python.
    """
    name = "rkn_block"

    # Process-wide lock to avoid concurrent rebuilds.
    _lock = asyncio.Lock()

    def __init__(self, domain: str, client: httpx.AsyncClient, rkn_cfg: RknConfig) -> None:
        super().__init__(domain)
        self.client = client
        self.cfg = rkn_cfg

        data_dir = Path(__file__).resolve().parent.parent / "data"
        # Align with bot's clear-cache routine
        self.db_path = Path(self.cfg.index_db_path) if self.cfg.index_db_path else (data_dir / "z_i_index.db")

    # ---------------- public ----------------

    async def run(self) -> CheckOutcome:
        """Check domain/IP presence in local SQLite index; refresh index if stale."""
        try:
            await self._ensure_index_up_to_date()
        except Exception as e:
            return CheckOutcome(self.name, Status.UNKNOWN, f"source error: {e.__class__.__name__}", {})

        dom = self.domain.lower().rstrip(".")

        # 1) domain & parent labels (if enabled)
        matched = self._query_domain_match(dom, self.cfg.match_subdomains)
        if matched:
            return CheckOutcome(
                check=self.name,
                status=Status.CRIT,
                message=f"listed (domain match: {matched})",
                metrics={"type": "domain", "matched": matched, "source": "z-i", "fetched_at": self._get_meta("fetched_at")},
            )

        # 2) IPv4
        if self.cfg.check_ip:
            ips = await self._resolve_ips(dom)
            hit = self._query_ip_match(ips)
            if hit:
                return CheckOutcome(
                    check=self.name,
                    status=Status.CRIT,
                    message=f"listed (ip match: {', '.join(hit)})",
                    metrics={"type": "ip", "matched": hit, "source": "z-i", "fetched_at": self._get_meta("fetched_at")},
                )

        return CheckOutcome(
            self.name,
            Status.OK,
            "not listed",
            {"source": "z-i", "fetched_at": self._get_meta("fetched_at")},
        )

    # ---------------- indexing / TTL ----------------

    async def _ensure_index_up_to_date(self) -> None:
        """Create schema if needed and refresh index when older than TTL."""
        self._ensure_schema()

        async with self._lock:
            fetched_at = self._get_meta("fetched_at")
            if fetched_at and not self._expired_iso(fetched_at):
                return

            text = await self._download_dump(self.cfg.z_i_url)
            # Heavy work moved to a thread to keep the loop responsive
            await asyncio.to_thread(self._rebuild_index, text)
            await asyncio.to_thread(self._set_meta, "fetched_at", datetime.now(timezone.utc).isoformat())

    def _ensure_schema(self) -> None:
        conn = sqlite3.connect(self.db_path)
        try:
            conn.executescript(SCHEMA_SQL)
            conn.commit()
        finally:
            conn.close()

    def _expired_iso(self, fetched_at_iso: str) -> bool:
        try:
            dt = datetime.fromisoformat(fetched_at_iso)
        except Exception:
            return True
        ttl = timedelta(hours=int(self.cfg.cache_ttl_hours or 12))
        return datetime.now(timezone.utc) - dt >= ttl

    # ---------------- DB helpers ----------------

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA temp_store=MEMORY;")
        return conn

    def _get_meta(self, key: str) -> Optional[str]:
        conn = self._connect()
        try:
            cur = conn.execute("SELECT value FROM meta WHERE key = ?", (key,))
            row = cur.fetchone()
            return row[0] if row else None
        finally:
            conn.close()

    def _set_meta(self, key: str, value: str) -> None:
        conn = self._connect()
        try:
            conn.execute(
                "INSERT INTO meta(key,value) VALUES(?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )
            conn.commit()
        finally:
            conn.close()

    def _rebuild_index(self, text: str) -> None:
        """Rebuild tables in a single immediate transaction, batched inserts for speed."""
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("DELETE FROM domains")
            conn.execute("DELETE FROM ips")

            dom_batch: list[str] = []
            ip_batch: list[str] = []

            def flush() -> None:
                if dom_batch:
                    conn.executemany(
                        "INSERT OR IGNORE INTO domains(domain) VALUES(?)",
                        ((d,) for d in dom_batch),
                    )
                    dom_batch.clear()
                if ip_batch:
                    conn.executemany(
                        "INSERT OR IGNORE INTO ips(ip) VALUES(?)",
                        ((i,) for i in ip_batch),
                    )
                    ip_batch.clear()

            for line in text.splitlines():
                for m in _DOMAIN_RE.finditer(line.lower()):
                    d = m.group(0).rstrip(".")
                    if self._looks_like_domain(d):
                        dom_batch.append(d)
                        if len(dom_batch) >= _BATCH_SIZE:
                            flush()
                for m in _IP_RE.finditer(line):
                    ip = m.group(0)
                    if self._valid_ipv4(ip):
                        ip_batch.append(ip)
                        if len(ip_batch) >= _BATCH_SIZE:
                            flush()

            flush()
            conn.commit()
        finally:
            conn.close()

    # ---------------- queries ----------------

    def _query_domain_match(self, domain: str, subdomains: bool) -> Optional[str]:
        """Return the first match for domain or its parents (if enabled)."""
        candidates = [domain]
        if subdomains:
            labels = domain.split(".")
            for i in range(1, len(labels)):
                candidates.append(".".join(labels[i:]))

        placeholders = ",".join("?" for _ in candidates)
        sql = f"SELECT domain FROM domains WHERE domain IN ({placeholders}) LIMIT 1"
        conn = self._connect()
        try:
            cur = conn.execute(sql, candidates)
            row = cur.fetchone()
            return row[0] if row else None
        finally:
            conn.close()

    def _query_ip_match(self, ips: Sequence[str]) -> list[str]:
        """Return all hits among provided IPv4 strings."""
        if not ips:
            return []
        placeholders = ",".join("?" for _ in ips)
        sql = f"SELECT ip FROM ips WHERE ip IN ({placeholders})"
        conn = self._connect()
        try:
            cur = conn.execute(sql, list(ips))
            return [r[0] for r in cur.fetchall()]
        finally:
            conn.close()

    # ---------------- downloading (with fallbacks) ----------------

    async def _download_dump(self, url: str) -> str:
        """
        1) Try dump.csv.gz (decompress if needed).
        2) Fallback to dump-00..19.csv concatenation.
        3) Fallback to mirrors.txt (gz/plain).
        All HTTP calls use retry logic and modest timeouts.
        """
        # 1) gz (or plain csv)
        try:
            r = await get_with_retries(self.client, url, timeout_s=45.0, retries=3, backoff_s=0.5, retry_on_status=(502, 503, 504), follow_redirects=True)
            r.raise_for_status()
            content = r.content
            if self._looks_like_gzip(content):
                with gzip.GzipFile(fileobj=BytesIO(content)) as gz:
                    data = gz.read()
                return self._decode_bytes(data)
            try:
                return r.text
            except UnicodeDecodeError:
                return content.decode("cp1251", errors="ignore")
        except Exception:
            pass

        # 2) parts
        parts: list[str] = []
        for i in range(_ZI_PARTS_COUNT):
            try:
                u = f"{_ZI_BASE_URL}dump-{i:02d}.csv"
                rr = await get_with_retries(self.client, u, timeout_s=30.0, retries=2, backoff_s=0.3, retry_on_status=(502, 503, 504), follow_redirects=True)
                if rr.status_code == 200 and rr.content:
                    try:
                        parts.append(rr.text)
                    except UnicodeDecodeError:
                        parts.append(rr.content.decode("cp1251", errors="ignore"))
            except Exception:
                continue
        if parts:
            return "\n".join(parts)

        # 3) mirrors
        try:
            mirrors_txt = await get_with_retries(self.client, f"{_ZI_BASE_URL}mirrors.txt", timeout_s=15.0, retries=2, backoff_s=0.3, retry_on_status=(502, 503, 504), follow_redirects=True)
            if mirrors_txt.status_code == 200:
                mirrors = [
                    ln.strip() for ln in mirrors_txt.text.splitlines()
                    if ln.strip() and not ln.strip().startswith("#")
                ]
                for m in mirrors:
                    for cand in (f"{m.rstrip('/')}/dump.csv.gz", f"{m.rstrip('/')}/dump.csv"):
                        try:
                            mr = await get_with_retries(self.client, cand, timeout_s=30.0, retries=3, backoff_s=0.5, retry_on_status=(502, 503, 504), follow_redirects=True)
                            if mr.status_code == 200:
                                data = mr.content
                                if self._looks_like_gzip(data):
                                    with gzip.GzipFile(fileobj=BytesIO(data)) as gz:
                                        raw = gz.read()
                                    return self._decode_bytes(raw)
                                try:
                                    return mr.text
                                except UnicodeDecodeError:
                                    return data.decode("cp1251", errors="ignore")
                        except Exception:
                            continue
        except Exception:
            pass

        raise RuntimeError("z-i dump not available via primary or mirrors")

    # ---------------- utilities ----------------

    @staticmethod
    def _looks_like_gzip(content: bytes) -> bool:
        return len(content) >= 2 and content[0] == 0x1F and content[1] == 0x8B

    @staticmethod
    def _decode_bytes(data: bytes) -> str:
        """Prefer UTF-8; fallback to CP1251 (common on mirrors)."""
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return data.decode("cp1251", errors="ignore")

    @staticmethod
    def _looks_like_domain(d: str) -> bool:
        """Reject IP tokens; require ≥2 labels and TLD len ≥2."""
        try:
            ipaddress.ip_address(d)
            return False
        except Exception:
            pass
        parts = d.split(".")
        return len(parts) >= 2 and all(parts) and len(parts[-1]) >= 2

    @staticmethod
    def _valid_ipv4(ip: str) -> bool:
        try:
            ipaddress.IPv4Address(ip)
            return True
        except Exception:
            return False

    async def _resolve_ips(self, domain: str) -> list[str]:
        """Resolve IPv4 addresses via getaddrinfo; return unique list."""
        loop = asyncio.get_running_loop()
        try:
            infos = await loop.getaddrinfo(domain, 80, type=socket.SOCK_STREAM)
        except Exception:
            return []
        out: list[str] = []
        for family, _, _, _, sockaddr in infos:
            if family == socket.AF_INET:
                out.append(sockaddr[0])
        return sorted(set(out))
