# /checks/rkn_block.py
from __future__ import annotations

import asyncio
import gzip
import ipaddress
import json
import re
import socket
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path
from typing import Optional, Set, Tuple, Iterable

import httpx

from .base import BaseCheck, CheckOutcome, Status
from ..config import RknConfig
from ..utils.http_retry import get_with_retries

# --- SSOT: constants & regexes ---
_ZI_BASE_URL = "https://raw.githubusercontent.com/zapret-info/z-i/master/"
_ZI_PARTS_COUNT = 20  # dump-00..19.csv

_DOMAIN_RE = re.compile(r"\b([a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@dataclass
class _Cache:
    """In-memory parsed index cache."""
    fetched_at: datetime
    domains: Set[str]
    ips: Set[str]


class RknBlockCheck(BaseCheck):
    """
    Checks if a domain or its resolved IPv4 addresses appear in the zapret-info (RKN) lists.
    Uses a small on-disk gz-json index + in-process memory cache.
    """
    name = "rkn_block"

    # process-wide cache & lock
    _cache: Optional[_Cache] = None
    _lock = asyncio.Lock()

    def __init__(self, domain: str, client: httpx.AsyncClient, rkn_cfg: RknConfig) -> None:
        super().__init__(domain)
        self.client = client
        self.cfg = rkn_cfg

        # Persist index under sitewatcher/data, same paths as bot clear-cache expects.
        data_dir = Path(__file__).resolve().parent.parent / "data"
        self._raw_path = data_dir / "z_i_dump.csv.gz"
        self._idx_path = data_dir / "z_i_index.json.gz"

    # ---------------- public ----------------

    async def run(self) -> CheckOutcome:
        try:
            cache = await self._ensure_cache()
        except Exception as e:
            return CheckOutcome(self.name, Status.UNKNOWN, f"source error: {e.__class__.__name__}", {})

        domain = self.domain.lower().rstrip(".")

        # 1) Domain (optionally walk parents for subdomain matches)
        matched_domain = self._match_domain(domain, cache.domains, self.cfg.match_subdomains)
        if matched_domain:
            return CheckOutcome(
                check=self.name,
                status=Status.CRIT,
                message=f"listed (domain match: {matched_domain})",
                metrics={"type": "domain", "matched": matched_domain, "source": "z-i", "fetched_at": cache.fetched_at.isoformat()},
            )

        # 2) IP match (IPv4 only)
        matched_ips: list[str] = []
        if self.cfg.check_ip:
            ips = await self._resolve_ips(domain)
            for ip in ips:
                if ip in cache.ips:
                    matched_ips.append(ip)

        if matched_ips:
            return CheckOutcome(
                check=self.name,
                status=Status.CRIT,
                message=f"listed (ip match: {', '.join(matched_ips)})",
                metrics={"type": "ip", "matched": matched_ips, "source": "z-i", "fetched_at": cache.fetched_at.isoformat()},
            )

        return CheckOutcome(
            check=self.name,
            status=Status.OK,
            message="not listed",
            metrics={"source": "z-i", "fetched_at": cache.fetched_at.isoformat()},
        )

    # ---------------- cache & index ----------------

    async def _ensure_cache(self) -> _Cache:
        """
        Return a fresh parsed index. Use in-process cache when valid; otherwise try
        on-disk gz-json first; rebuild from CSV when needed.
        """
        async with self._lock:
            # memory cache fresh?
            if self._cache and not self._expired(self._cache.fetched_at):
                return self._cache

            # 1) try on-disk gz-json index
            idx = self._load_index_gz_json()
            if idx is not None and not self._expired(idx["fetched_at"]):
                self._cache = _Cache(
                    fetched_at=idx["fetched_at"],
                    domains=set(idx.get("domains", [])),
                    ips=set(idx.get("ips", [])),
                )
                return self._cache

            # 2) rebuild index from CSV text (local raw if fresh; else re-download)
            text = await self._obtain_dump_text(self.cfg.z_i_url)
            domains, ips = self._parse_dump(text)
            fetched_at = datetime.now(timezone.utc)

            # 3) save gz-json index
            self._save_index_gz_json(fetched_at, domains, ips)

            self._cache = _Cache(fetched_at=fetched_at, domains=domains, ips=ips)
            return self._cache

    def _expired(self, fetched_at: datetime) -> bool:
        ttl = timedelta(hours=int(self.cfg.cache_ttl_hours or 12))
        return datetime.now(timezone.utc) - fetched_at >= ttl

    # ---------------- download path ----------------

    async def _obtain_dump_text(self, url: str) -> str:
        """
        Get CSV text: prefer local raw gz if fresh; otherwise download (with fallbacks).
        """
        # local raw (fresh enough)?
        if self._raw_path.exists():
            age = datetime.now(timezone.utc) - datetime.fromtimestamp(self._raw_path.stat().st_mtime, tz=timezone.utc)
            if age < timedelta(hours=int(self.cfg.cache_ttl_hours or 12)):
                try:
                    with gzip.open(self._raw_path, "rb") as f:
                        data = f.read()
                    return self._decode_bytes(data)
                except Exception:
                    pass  # fall through to download

        # download & store
        text = await self._download_dump(url)
        try:
            self._raw_path.parent.mkdir(parents=True, exist_ok=True)
            with gzip.open(self._raw_path, "wb") as f:
                f.write(text.encode("utf-8", errors="ignore"))
        except Exception:
            pass
        return text

    async def _download_dump(self, url: str) -> str:
        """
        Primary: dump.csv.gz (decompress if needed).
        Fallbacks: dump-00..19.csv (concatenate), then mirrors.txt (gz/plain).
        """
        # 1) direct gz (or plain csv)
        try:
            r = await get_with_retries(self.client, url, timeout_s=45.0, retries=2, follow_redirects=True)
            r.raise_for_status()
            content = r.content
            if self._looks_like_gzip(content):
                with gzip.GzipFile(fileobj=BytesIO(content)) as gz:
                    raw = gz.read()
                return self._decode_bytes(raw)
            # plain text
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

        # 3) mirrors
        try:
            mirrors_txt = await get_with_retries(self.client, f"{_ZI_BASE_URL}mirrors.txt", timeout_s=15.0, retries=1, follow_redirects=True)
            if mirrors_txt.status_code == 200:
                mirrors = [
                    ln.strip() for ln in mirrors_txt.text.splitlines()
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

    # ---------------- parsing & matching ----------------

    def _parse_dump(self, text: str) -> Tuple[Set[str], Set[str]]:
        """Extract domains and IPv4s from CSV text using regexes with simple validation."""
        doms: Set[str] = set()
        ips: Set[str] = set()
        for line in text.splitlines():
            # domains
            for m in _DOMAIN_RE.finditer(line.lower()):
                d = m.group(0).rstrip(".")
                if self._looks_like_domain(d):
                    doms.add(d)
            # ipv4
            for m in _IP_RE.finditer(line):
                ip = m.group(0)
                if self._valid_ipv4(ip):
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

    @staticmethod
    def _match_domain(domain: str, blocked: Set[str], subdomains: bool) -> Optional[str]:
        """Return match for domain or any parent if subdomains=True."""
        if domain in blocked:
            return domain
        if subdomains:
            labels = domain.split(".")
            for i in range(1, len(labels)):
                cand = ".".join(labels[i:])
                if cand in blocked:
                    return cand
        return None

    async def _resolve_ips(self, domain: str) -> Set[str]:
        """Resolve IPv4 addresses via getaddrinfo; ignore IPv6 here."""
        loop = asyncio.get_running_loop()
        try:
            infos = await loop.getaddrinfo(domain, 80, type=socket.SOCK_STREAM)
        except Exception:
            return set()
        out: Set[str] = set()
        for family, _, _, _, sockaddr in infos:
            if family == socket.AF_INET:
                out.add(sockaddr[0])
        return out

    # ---------------- helpers ----------------

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

    def _load_index_gz_json(self) -> Optional[dict]:
        if not self._idx_path.exists():
            return None
        try:
            with gzip.open(self._idx_path, "rb") as f:
                payload = json.loads(f.read().decode("utf-8"))
            fetched_at = datetime.fromisoformat(payload["fetched_at"])
            return {
                "fetched_at": fetched_at,
                "domains": payload.get("domains", []),
                "ips": payload.get("ips", []),
            }
        except Exception:
            return None

    def _save_index_gz_json(self, fetched_at: datetime, domains: Iterable[str], ips: Iterable[str]) -> None:
        try:
            self._idx_path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "fetched_at": fetched_at.isoformat(),
                "domains": sorted(set(domains)),
                "ips": sorted(set(ips)),
            }
            with gzip.open(self._idx_path, "wb") as f:
                f.write(json.dumps(payload).encode("utf-8"))
        except Exception:
            # Best-effort: in-memory cache still works even if disk write fails.
            pass
