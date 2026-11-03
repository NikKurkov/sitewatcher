"""Independent RKN domain/IP checks over complete, dated provider snapshots."""
from __future__ import annotations

import asyncio
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
import ipaddress
from pathlib import Path
import socket
import sqlite3
from weakref import WeakValueDictionary

import httpx

from .base import BaseCheck, CheckOutcome, Status
from .. import storage
from ..config import RknConfig
from ..utils.domains import normalize_domain
from ..utils.http_retry import get_with_retries

_PARSER_VERSION = '3'
_MIN_DOMAINS = 1000
_MIN_IPS = 1000
_MAX_DOWNLOAD_BYTES = 96 * 1024 * 1024
_PROVIDERS = {
    'antifilter': (
        ('domains', 'https://antifilter.download/list/domains.lst'),
        ('ips', 'https://antifilter.download/list/ip.lst'),
        ('ips', 'https://antifilter.download/list/subnet.lst'),
    ),
    'bol-van': (
        ('domains', 'https://raw.githubusercontent.com/bol-van/rulist/main/reestr_hostname.txt'),
        ('ips', 'https://raw.githubusercontent.com/bol-van/rulist/main/reestr_ipban4.txt'),
        ('ips', 'https://raw.githubusercontent.com/bol-van/rulist/main/reestr_resolved_ip4.txt'),
    ),
}
_GITHUB_COMMIT_URL = 'https://api.github.com/repos/bol-van/rulist/commits?per_page=1'


@dataclass(frozen=True)
class RegistryData:
    domains: set[str]
    networks: set[ipaddress.IPv4Network]
    source: str
    updated_at: datetime
    revision: str = ''


def rkn_index_path(cfg: RknConfig) -> Path:
    # Retain the old filename so existing installations replace their cache automatically.
    path = Path(cfg.index_db_path) if cfg.index_db_path else storage.DEFAULT_DB.with_name('z_i_index.db')
    if path.resolve() == storage.DEFAULT_DB.resolve():
        raise ValueError('RKN index must be separate from the monitoring database')
    return path


def _timestamp(value: str) -> datetime:
    stamp = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if stamp.tzinfo is None:
        raise ValueError('Source timestamp has no timezone')
    return stamp.astimezone(timezone.utc)


def _parse_lines(text: str, kind: str) -> set:
    """Parse one value per line; never extract hostnames from an HTML error page."""
    values = set()
    invalid = total = 0
    for line in text.splitlines():
        line = line.strip().lstrip('\ufeff')
        if not line or line.startswith('#'):
            continue
        total += 1
        if kind == 'domains':
            raw = line.removeprefix('*.').rstrip('.')
            domain = normalize_domain(raw) if not any(c in raw for c in '/:;<>"@') else None
            if domain and (domain.split('.')[-1].isalpha()
                           or domain.split('.')[-1].startswith('xn--')):
                values.add(domain)
                continue
        else:
            try:
                values.add(ipaddress.IPv4Network(line, strict=False))
                continue
            except ValueError:
                pass
        invalid += 1
    if not values or invalid > max(0, total // 20):
        raise ValueError('Source list is empty or malformed')
    return values


class RknBlockCheck(BaseCheck):
    """Domain/parent matches are CRIT; RknIpCheck reuses this shared index for WARN."""

    name = 'rkn_domain'
    _refresh_locks = WeakValueDictionary()

    def __init__(self, domain: str, client: httpx.AsyncClient, rkn_cfg: RknConfig) -> None:
        super().__init__(domain)
        self.client, self.cfg = client, rkn_cfg
        self.db_path = rkn_index_path(rkn_cfg).resolve()

    async def run(self) -> CheckOutcome:
        try:
            await self._ensure_index_fresh()
            domain = self.domain.rstrip('.').encode('idna').decode('ascii').lower()
            return await self._lookup(domain)
        except Exception as error:
            self.log.warning('RKN check unavailable (%s)', type(error).__name__)
            return CheckOutcome(self.name, Status.UNKNOWN,
                                'RKN data unavailable or stale; no clean result confirmed',
                                {'registry_version': _PARSER_VERSION})

    async def _lookup(self, domain: str) -> CheckOutcome:
        hit, metrics = await asyncio.to_thread(self._query, domain=domain)
        return CheckOutcome(self.name, Status.CRIT if hit else Status.OK,
                            f'Domain listed: {hit}' if hit else 'Domain not listed',
                            {**metrics, 'type': 'domain', 'matched': hit})

    def _read_meta(self) -> dict[str, str]:
        if not self.db_path.exists():
            return {}
        with closing(sqlite3.connect(self.db_path.as_uri() + '?mode=ro', uri=True)) as con:
            return dict(con.execute('SELECT key,value FROM meta'))

    def _check_source_age(self, updated_at: datetime) -> None:
        age = datetime.now(timezone.utc) - updated_at
        if age < -timedelta(minutes=5) or age > timedelta(hours=self.cfg.max_source_age_hours):
            raise ValueError('Source snapshot timestamp is stale or in the future')

    def _meta_is_fresh(self, meta: dict[str, str]) -> bool:
        try:
            self._check_source_age(_timestamp(meta['source_updated_at']))
            return (meta['parser_version'] == _PARSER_VERSION
                    and meta['source'] in _PROVIDERS
                    and timedelta(0) <= datetime.now(timezone.utc) - _timestamp(meta['fetched_at'])
                    < timedelta(hours=self.cfg.cache_ttl_hours))
        except (ValueError, KeyError, TypeError):
            return False

    async def _ensure_index_fresh(self) -> None:
        loop = asyncio.get_running_loop()
        lock = self._refresh_locks.get(loop)
        if lock is None:
            lock = asyncio.Lock()
            self._refresh_locks[loop] = lock
        async with lock:
            try:
                meta = await asyncio.to_thread(self._read_meta)
            except sqlite3.Error:
                meta = {}
            if not self._meta_is_fresh(meta):
                data = await self._download_with_fallback()
                await asyncio.to_thread(self._rebuild_index, data, datetime.now(timezone.utc))

    async def _download_with_fallback(self) -> RegistryData:
        order = (self.cfg.source, 'bol-van' if self.cfg.source == 'antifilter' else 'antifilter')
        for source in order:
            try:
                async with asyncio.timeout(50):
                    data = await self._download_source(source)
                    await asyncio.to_thread(self._check_reduction, data)
                    return data
            except Exception as error:
                self.log.warning('RKN source %s rejected (%s)', source, type(error).__name__)
        raise RuntimeError('Both RKN sources are unavailable, incomplete or stale')

    async def _get(self, url: str) -> httpx.Response:
        response = await get_with_retries(
            self.client, url, timeout_s=30, retries=0, follow_redirects=True,
            max_response_bytes=_MAX_DOWNLOAD_BYTES,
        )
        response.raise_for_status()
        return response

    async def _get_many(self, urls) -> list[httpx.Response]:
        responses = await asyncio.gather(*(self._get(url) for url in urls), return_exceptions=True)
        for response in responses:
            if isinstance(response, BaseException):
                raise response
        return responses

    async def _download_source(self, source: str) -> RegistryData:
        revision = ''
        feeds = _PROVIDERS[source]
        if source == 'bol-van':
            response = await self._get(_GITHUB_COMMIT_URL)
            commit = response.json()[0]
            revision = commit['sha']
            feeds = tuple((kind, url.replace('/main/', f'/{revision}/')) for kind, url in feeds)
            dates = await self._get_many(
                f'https://api.github.com/repos/bol-van/rulist/commits?sha={revision}'
                f'&path={url.rsplit("/", 1)[1]}&per_page=1' for _, url in feeds)
            timestamps = [_timestamp(item.json()[0]['commit']['committer']['date']) for item in dates]
            for stamp in timestamps:
                self._check_source_age(stamp)
            updated = min(timestamps)
        # Await every request, including failures, before trying the next provider.
        responses = await self._get_many(url for _, url in feeds)
        if source == 'antifilter':
            timestamps = [parsedate_to_datetime(response.headers['Last-Modified'])
                          for response in responses]
            for stamp in timestamps:
                self._check_source_age(stamp)
            updated = min(timestamps)
        self._check_source_age(updated)
        def parse():
            domains, networks = set(), set()
            for (kind, _), response in zip(_PROVIDERS[source], responses, strict=True):
                values = _parse_lines(response.content.decode('utf-8-sig'), kind)
                (domains if kind == 'domains' else networks).update(values)
            if len(domains) < _MIN_DOMAINS or len(networks) < _MIN_IPS:
                raise ValueError('Source bundle is suspiciously small')
            return RegistryData(domains, networks, source, updated, revision)
        return await asyncio.to_thread(parse)

    def _check_reduction(self, data: RegistryData) -> None:
        try:
            meta = self._read_meta()
        except sqlite3.Error:
            return
        if meta.get('parser_version') == _PARSER_VERSION and meta.get('source') == data.source:
            if (len(data.domains) < int(meta['domain_count']) // 2
                    or len(data.networks) < int(meta['network_count']) // 2):
                raise ValueError('Source bundle unexpectedly lost over half its entries')

    def _rebuild_index(self, data: RegistryData, fetched_at: datetime) -> None:
        if not data.domains or not data.networks or data.source not in _PROVIDERS:
            raise ValueError('Incomplete registry bundle')
        self._check_source_age(data.updated_at)
        ranges = [(int(net.network_address), int(net.broadcast_address))
                  for net in ipaddress.collapse_addresses(data.networks)]
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        # A complete index write exceeds SQLite's default five-second busy timeout.
        with closing(sqlite3.connect(self.db_path, timeout=60)) as con, con:
            con.execute('PRAGMA journal_mode=WAL')
            con.execute('BEGIN IMMEDIATE')
            has_meta = con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='meta'").fetchone()
            meta = dict(con.execute('SELECT key,value FROM meta')) if has_meta else {}
            # Another web/worker process may have published while we downloaded or waited.
            if (self._meta_is_fresh(meta)
                    and _timestamp(meta['source_updated_at']) >= data.updated_at):
                return
            for table in ('meta', 'domains', 'ips', 'networks'):
                con.execute(f'DROP TABLE IF EXISTS {table}')
            con.execute('CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)')
            con.execute('CREATE TABLE domains(domain TEXT PRIMARY KEY)')
            con.execute('CREATE TABLE networks(start INTEGER,end INTEGER,PRIMARY KEY(start,end))')
            con.executemany('INSERT INTO domains VALUES (?)', ((name,) for name in data.domains))
            con.executemany('INSERT INTO networks VALUES (?,?)', ranges)
            con.executemany('INSERT INTO meta VALUES (?,?)', {
                'parser_version': _PARSER_VERSION, 'source': data.source,
                'source_revision': data.revision,
                'source_updated_at': data.updated_at.isoformat(), 'fetched_at': fetched_at.isoformat(),
                'domain_count': str(len(data.domains)), 'network_count': str(len(data.networks)),
            }.items())

    def _query(self, *, domain: str | None = None, ips: list[str] | None = None):
        # The result and provenance must come from the same SQLite snapshot.
        with closing(sqlite3.connect(self.db_path.as_uri() + '?mode=ro', uri=True)) as con:
            con.execute('BEGIN')
            meta = dict(con.execute('SELECT key,value FROM meta'))
            metrics = {key: meta[key] for key in ('source', 'source_updated_at', 'fetched_at')}
            metrics['registry_version'] = _PARSER_VERSION
            if meta.get('source_revision'):
                metrics['source_revision'] = meta['source_revision']
            metrics['db_path'] = str(self.db_path)
            if domain is not None:
                labels = domain.split('.')
                names = ['.'.join(labels[i:]) for i in range(len(labels) - 1)]
                if not self.cfg.match_subdomains:
                    names = names[:1]
                hit = next((name for name in names if con.execute(
                    'SELECT 1 FROM domains WHERE domain=?', (name,)).fetchone()), None)
            else:
                hit = []
                for ip in dict.fromkeys(ips or []):
                    number = int(ipaddress.IPv4Address(ip))
                    row = con.execute('SELECT end FROM networks WHERE start<=? '
                                      'ORDER BY start DESC LIMIT 1', (number,)).fetchone()
                    if row and number <= row[0]:
                        hit.append(ip)
            return hit, metrics

    async def _resolve_ipv4(self, domain: str) -> list[str]:
        infos = await asyncio.get_running_loop().getaddrinfo(
            domain, 80, family=socket.AF_INET, type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP, flags=socket.AI_ADDRCONFIG,
        )
        return list(dict.fromkeys(sockaddr[0] for _, _, _, _, sockaddr in infos))


class RknIpCheck(RknBlockCheck):
    name = 'rkn_ip'

    async def _lookup(self, domain: str) -> CheckOutcome:
        ips = await self._resolve_ipv4(domain)
        if not ips:
            return CheckOutcome(self.name, Status.UNKNOWN, 'No IPv4 addresses resolved',
                                {'registry_version': _PARSER_VERSION})
        hits, metrics = await asyncio.to_thread(self._query, ips=ips)
        return CheckOutcome(
            self.name, Status.WARN if hits else Status.OK,
            (f"IP listed: {', '.join(hits)}. May affect another domain on shared hosting."
             if hits else 'IPv4 addresses not listed'),
            {**metrics, 'type': 'ip', 'matched': hits},
        )
