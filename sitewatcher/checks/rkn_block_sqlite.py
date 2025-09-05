# sitewatcher/checks/rkn_block_sqlite.py
from __future__ import annotations

import asyncio
import gzip
import ipaddress
import json
import re
import socket
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path
from typing import Iterable, Optional, Sequence, Set, Tuple

import httpx

from .base import BaseCheck, CheckOutcome, Status
from ..config import RknConfig
from ..utils.http_retry import get_with_retries  # импорт оставлен как есть

# ---- Constants & regexes (source of truth) ----
_ZI_BASE_URL = "https://raw.githubusercontent.com/zapret-info/z-i/master/"
_ZI_PARTS_COUNT = 20  # dump-00..19.csv

_DOMAIN_RE = re.compile(r"\b([a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@dataclass
class _CacheMeta:
    fetched_at: datetime
    db_path: Path


class RknBlockCheck(BaseCheck):
    """
    RKN/Zapret-Info blocklist check using an on-disk SQLite index (domains + IPv4).

    Strategy
    --------
    - Keep a small SQLite DB with 3 tables:
        meta(key TEXT PRIMARY KEY, value TEXT)
        domains(domain TEXT PRIMARY KEY)
        ips(ip TEXT PRIMARY KEY)
      plus appropriate indexes (PRIMARY KEY is enough).
    - Refresh DB if stale (by cfg.cache_ttl_hours) using upstream dump:
        1) try dump.csv.gz (or plain dump.csv),
        2) fallback to segmented dump-00..19.csv,
        3) fallback to mirrors.txt list.
    - To decide listing:
        * direct domain hit (optionally check parent labels when match_subdomains=True),
        * resolve IPv4 A-records and check IP hits (if cfg.check_ip=True).
    """
    name = "rkn_block"  # keep the same logical name

    # Process-wide refresh lock (avoid concurrent rebuilds)
    _refresh_lock = asyncio.Lock()

    def __init__(self, domain: str, client: httpx.AsyncClient, rkn_cfg: RknConfig) -> None:
        super().__init__(domain)
        self.client = client
        self.cfg = rkn_cfg

        # Default DB path unless overridden via config
        data_dir = Path(__file__).resolve().parent.parent / "data"
        idx_from_cfg = getattr(rkn_cfg, "index_db_path", None)
        self.db_path: Path = Path(idx_from_cfg) if idx_from_cfg else (data_dir / "z_i_index.db")

        # Cache TTL (hours)
        self._ttl_hours: int = int(getattr(rkn_cfg, "cache_ttl_hours", 12) or 12)

        # Primary dump URL (can be overridden in config)
        self._dump_url: str = getattr(rkn_cfg, "z_i_url", f"{_ZI_BASE_URL}dump.csv.gz")

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    async def run(self) -> CheckOutcome:
        """Return CRIT if listed, OK if not, UNKNOWN on source/IO errors."""
        try:
            await self._ensure_index_fresh()
        except Exception as e:
            self.log.exception(
                "rkn.index.refresh_failed",
                extra={"event": "rkn.index.refresh_failed", "domain": self.domain},
            )
            return CheckOutcome(self.name, Status.UNKNOWN, f"source error: {e.__class__.__name__}: {e}", {})

        dom = self.domain.lower().rstrip(".")
        try:
            # 1) Domain match (with optional parent walk)
            hit_domain = await asyncio.to_thread(self._query_domain_match, dom, self.cfg.match_subdomains)
            if hit_domain:
                return CheckOutcome(
                    check=self.name,
                    status=Status.CRIT,
                    message=f"listed (domain match: {hit_domain})",
                    metrics={"type": "domain", "matched": hit_domain, "source": "z-i", "db_path": str(self.db_path)},
                )

            # 2) IP matches (IPv4 only)
            if self.cfg.check_ip:
                ips = await self._resolve_ipv4(dom)
                if ips:
                    hits = await asyncio.to_thread(self._query_ip_matches, ips)
                    if hits:
                        return CheckOutcome(
                            check=self.name,
                            status=Status.CRIT,
                            message=f"listed (ip match: {', '.join(hits)})",
                            metrics={"type": "ip", "matched": hits, "source": "z-i", "db_path": str(self.db_path)},
                        )
        except Exception as e:
            self.log.exception(
                "rkn.domain.query_failed",
                extra={"event": "rkn.domain.query_failed", "domain": dom},
            )
            return CheckOutcome(self.name, Status.UNKNOWN, f"query error: {e.__class__.__name__}: {e}", {})

        return CheckOutcome(self.name, Status.OK, "not listed", {"source": "z-i", "db_path": str(self.db_path)})

    # ------------------------------------------------------------------ #
    # Index lifecycle
    # ------------------------------------------------------------------ #

    async def _ensure_index_fresh(self) -> None:
        """Ensure SQLite index exists and is within TTL; rebuild if stale/missing."""
        async with self._refresh_lock:
            # If no DB — build from scratch
            if not self.db_path.exists():
                self.log.info(
                    "rkn.index.bootstrap",
                    extra={"event": "rkn.index.bootstrap", "db_path": str(self.db_path)},
                )
                csv_text = await self._download_dump_with_fallbacks()
                await asyncio.to_thread(self._rebuild_index, csv_text, datetime.now(timezone.utc))
                return

            # If DB exists — check TTL from meta
            try:
                fetched_at = await asyncio.to_thread(self._read_meta_fetched_at)
            except Exception:
                fetched_at = None

            if fetched_at is None or datetime.now(timezone.utc) - fetched_at >= timedelta(hours=self._ttl_hours):
                self.log.info(
                    "rkn.index.refresh_start",
                    extra={
                        "event": "rkn.index.refresh_start",
                        "db_path": str(self.db_path),
                        "ttl_h": self._ttl_hours,
                        "url": self._dump_url,
                    },
                )
                try:
                    csv_text = await self._download_dump_with_fallbacks()
                    await asyncio.to_thread(self._rebuild_index, csv_text, datetime.now(timezone.utc))
                except Exception as e:
                    # Soft-fail: keep existing DB for queries, only log the refresh error.
                    self.log.exception(
                        "rkn.index.refresh_error",
                        extra={"event": "rkn.index.refresh_error", "error": f"{e.__class__.__name__}: {e}"},
                    )

    # ------------------------------------------------------------------ #
    # Download & parse
    # ------------------------------------------------------------------ #

    async def _download_dump_with_fallbacks(self) -> str:
        """
        Primary: dump.csv.gz (or plain csv).
        Fallbacks: dump-00..19.csv concatenated, then mirrors.txt (gz/plain).
        """
        # 1) Direct gz/plain
        try:
            r = await get_with_retries(self.client, self._dump_url, timeout_s=45.0, retries=2, follow_redirects=True)
            r.raise_for_status()
            content = r.content
            if self._looks_like_gzip(content):
                with gzip.GzipFile(fileobj=BytesIO(content)) as gz:
                    raw = gz.read()
                return self._decode_bytes(raw)
            try:
                return r.text
            except UnicodeDecodeError:
                return content.decode("cp1251", errors="ignore")
        except Exception:
            pass

        # 2) Parts
        parts: list[str] = []
        for i in range(_ZI_PARTS_COUNT):
            try:
                u = f"{_ZI_BASE_URL}dump-{i:02d}.csv"
                rr = await get_with_retries(self.client, u, timeout_s=30.0, retries=1, follow_redirects=True)
                if rr.status_code == 200 and rr.content:
                    try:
                        parts.append(rr.text)
                    except UnicodeDecodeError:
                        parts.append(rr.content.decode("cp1251", errors="ignore"))
            except Exception:
                continue
        if parts:
            return "\n".join(parts)

        # 3) Mirrors
        try:
            mirrors_txt = await get_with_retries(
                self.client, f"{_ZI_BASE_URL}mirrors.txt", timeout_s=15.0, retries=1, follow_redirects=True
            )
            if mirrors_txt.status_code == 200:
                mirrors = [
                    ln.strip()
                    for ln in mirrors_txt.text.splitlines()
                    if ln.strip() and not ln.strip().startswith("#")
                ]
                for m in mirrors:
                    for cand in (f"{m.rstrip('/')}/dump.csv.gz", f"{m.rstrip('/')}/dump.csv"):
                        try:
                            mr = await get_with_retries(self.client, cand, timeout_s=30.0, retries=1, follow_redirects=True)
                            if mr.status_code == 200 and mr.content:
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

    @staticmethod
    def _looks_like_gzip(content: bytes) -> bool:
        return len(content) >= 2 and content[0] == 0x1F and content[1] == 0x8B

    @staticmethod
    def _decode_bytes(data: bytes) -> str:
        """Try UTF-8, then CP1251 as a fallback (z-i mirrors often use CP1251)."""
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return data.decode("cp1251", errors="ignore")

    @staticmethod
    def _parse_dump(text: str) -> Tuple[Set[str], Set[str]]:
        """Extract domains and IPv4s from CSV text using regexes with simple validation."""
        doms: Set[str] = set()
        ips: Set[str] = set()
        for line in text.splitlines():
            # domains
            for m in _DOMAIN_RE.finditer(line.lower()):
                d = m.group(0).rstrip(".")
                if RknBlockCheck._looks_like_domain(d):
                    doms.add(d)
            # IPv4
            for m in _IP_RE.finditer(line):
                ip = m.group(0)
                if RknBlockCheck._valid_ipv4(ip):
                    ips.add(ip)
        return doms, ips

    @staticmethod
    def _looks_like_domain(d: str) -> bool:
        """Reject IP-like tokens; require at least 2 labels and TLD length >= 2."""
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

    # ------------------------------------------------------------------ #
    # SQLite index
    # ------------------------------------------------------------------ #

    def _read_meta_fetched_at(self) -> Optional[datetime]:
        if not self.db_path.exists():
            return None
        con = sqlite3.connect(self.db_path.as_posix())
        try:
            cur = con.cursor()
            cur.execute("SELECT value FROM meta WHERE key='fetched_at'")
            row = cur.fetchone()
            if not row:
                return None
            try:
                return datetime.fromisoformat(row[0])
            except Exception:
                return None
        finally:
            con.close()

    def _rebuild_index(self, csv_text: str, fetched_at: datetime) -> None:
        """Create/replace SQLite DB from parsed dump text."""
        dom_seen, ip_seen = self._parse_dump(csv_text)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        con = sqlite3.connect(self.db_path.as_posix())
        try:
            cur = con.cursor()
            # Schema
            cur.executescript(
                """
                PRAGMA journal_mode=WAL;
                PRAGMA synchronous=NORMAL;

                DROP TABLE IF EXISTS meta;
                DROP TABLE IF EXISTS domains;
                DROP TABLE IF EXISTS ips;

                CREATE TABLE meta (
                    key   TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE domains (
                    domain TEXT PRIMARY KEY
                );

                CREATE TABLE ips (
                    ip TEXT PRIMARY KEY
                );
                """
            )

            # Bulk insert
            if dom_seen:
                cur.executemany("INSERT OR IGNORE INTO domains(domain) VALUES (?)", ((d,) for d in dom_seen))
            if ip_seen:
                cur.executemany("INSERT OR IGNORE INTO ips(ip) VALUES (?)", ((ip,) for ip in ip_seen))

            # Meta
            cur.execute("INSERT OR REPLACE INTO meta(key, value) VALUES ('fetched_at', ?)", (fetched_at.isoformat(),))
            con.commit()
        finally:
            con.close()

        self.log.info(
            "rkn.index.refresh_done",
            extra={
                "event": "rkn.index.refresh_done",
                "domains": len(dom_seen),
                "ips": len(ip_seen),
                "fetched_at": fetched_at.isoformat(),
                "db_path": str(self.db_path),
            },
        )

    # ------------------------------------------------------------------ #
    # Queries (domain/IP)
    # ------------------------------------------------------------------ #

    def _query_domain_match(self, domain: str, match_parents: bool) -> Optional[str]:
        """
        Return exact or parent match from domains table if present.
        """
        con = sqlite3.connect(self.db_path.as_posix())
        try:
            cur = con.cursor()
            # Exact
            cur.execute("SELECT 1 FROM domains WHERE domain = ? LIMIT 1", (domain,))
            if cur.fetchone():
                return domain
            # Parents
            if match_parents:
                labels = domain.split(".")
                for i in range(1, len(labels)):
                    parent = ".".join(labels[i:])
                    cur.execute("SELECT 1 FROM domains WHERE domain = ? LIMIT 1", (parent,))
                    if cur.fetchone():
                        return parent
            return None
        finally:
            con.close()

    def _query_ip_matches(self, ips: Sequence[str]) -> list[str]:
        """
        Return list of IPs that are present in the index.
        Use batched IN-queries to avoid too long parameter lists.
        """
        if not ips:
            return []
        con = sqlite3.connect(self.db_path.as_posix())
        try:
            cur = con.cursor()
            hits: list[str] = []
            batch_size = 500
            for i in range(0, len(ips), batch_size):
                chunk = ips[i : i + batch_size]
                qmarks = ",".join("?" for _ in chunk)
                cur.execute(f"SELECT ip FROM ips WHERE ip IN ({qmarks})", chunk)
                hits.extend([row[0] for row in cur.fetchall()])
            # Preserve input order, unique
            hit_set = set(hits)
            return [ip for ip in ips if ip in hit_set]
        finally:
            con.close()

    # ------------------------------------------------------------------ #
    # DNS (IPv4 only)
    # ------------------------------------------------------------------ #

    async def _resolve_ipv4(self, domain: str) -> list[str]:
        """
        Resolve A-records (IPv4) for domain; preserve order & deduplicate.
        """
        loop = asyncio.get_running_loop()
        try:
            infos = await loop.getaddrinfo(
                domain,
                80,
                family=socket.AF_INET,            # IPv4 only: our index stores IPv4
                type=socket.SOCK_STREAM,
                proto=socket.IPPROTO_TCP,
                flags=socket.AI_ADDRCONFIG,       # skip unsupported families on this host
            )
        except Exception:
            return []
        out: list[str] = []
        for _, _, _, _, sockaddr in infos:
            if isinstance(sockaddr, tuple) and len(sockaddr) >= 1:
                out.append(sockaddr[0])
        # Deduplicate preserving order
        seen: Set[str] = set()
        uniq: list[str] = []
        for ip in out:
            if ip not in seen:
                uniq.append(ip)
                seen.add(ip)
        return uniq
