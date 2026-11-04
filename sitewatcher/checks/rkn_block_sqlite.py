"""Independent RKN domain/IP checks over complete, dated provider snapshots."""
from __future__ import annotations

import asyncio
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
import ipaddress
import io
from pathlib import Path
import socket
import sqlite3
import tempfile
from weakref import WeakValueDictionary

import httpx

from .base import BaseCheck, CheckOutcome, Status
from .. import storage
from ..config import RknConfig
from ..utils.domains import DOMAIN_RE, normalize_domain
from ..utils.http_retry import get_with_retries
from ..utils.http_body import _read_body

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
    path: Path
    source: str
    updated_at: datetime
    domain_count: int
    network_count: int
    revision: str = ''


async def _in_thread(function, *args):
    # Cancellation must finish the disk operation before deleting its temporary directory.
    task = asyncio.create_task(asyncio.to_thread(function, *args))
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError as cancelled:
        while not task.done():
            try:
                await asyncio.shield(task)
            except asyncio.CancelledError:
                continue
            except Exception:
                break
        if not task.cancelled():
            task.exception()  # Consume a disk failure without replacing cancellation.
        raise cancelled


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


def _parse_values(lines, kind: str):
    """Validate a bounded line at a time; incomplete/malformed files never publish."""
    invalid = total = valid = 0
    for line in lines:
        if len(line) > 4096:
            raise ValueError('Source line is too long')
        line = line.strip().lstrip('\ufeff')
        if not line or line.startswith('#'):
            continue
        total += 1
        if kind == 'domains':
            raw = line.removeprefix('*.').rstrip('.').lower()
            domain = (raw if len(raw) <= 253 and DOMAIN_RE.fullmatch(raw) else None) \
                if raw.isascii() else normalize_domain(raw)
            if (domain and not any(c in raw for c in '/:;<>"@')
                    and (domain.split('.')[-1].isalpha()
                         or domain.split('.')[-1].startswith('xn--'))):
                valid += 1
                yield domain
                continue
        else:
            try:
                network = ipaddress.IPv4Network(line, strict=False)
                valid += 1
                yield network
                continue
            except ValueError:
                pass
        invalid += 1
    if not valid or invalid > total // 20:
        raise ValueError('Source list is empty or malformed')


def _parse_lines(text: str, kind: str) -> set:
    return set(_parse_values(io.StringIO(text), kind))


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
                await self._download_with_fallback()

    async def _download_with_fallback(self) -> None:
        order = (self.cfg.source, 'bol-van' if self.cfg.source == 'antifilter' else 'antifilter')
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        for source in order:
            try:
                with tempfile.TemporaryDirectory(prefix='.rkn-', dir=self.db_path.parent) as folder:
                    data = await self._download_source(source, Path(folder))
                    await _in_thread(self._check_reduction, data)
                    await _in_thread(self._rebuild_index, data, datetime.now(timezone.utc))
                    return
            except Exception as error:
                self.log.warning('RKN source %s rejected (%s)', source, type(error).__name__)
        raise RuntimeError('Both RKN sources are unavailable, incomplete or stale')

    async def _download_file(self, url: str, path: Path, source: str):
        async with self.client.stream('GET', url, timeout=30, follow_redirects=False,
                                      headers={'Accept-Encoding': 'gzip, deflate'}) as response:
            response.raise_for_status()
            stamp = None
            if source == 'antifilter':
                stamp = parsedate_to_datetime(response.headers['Last-Modified'])
                self._check_source_age(stamp)
            with path.open('wb') as target:
                await _read_body(response, _MAX_DOWNLOAD_BYTES, _MAX_DOWNLOAD_BYTES, sink=target)
            return stamp

    @staticmethod
    def _import_file(index: Path, path: Path, kind: str):
        with closing(sqlite3.connect(index)) as con, con:
            con.execute('PRAGMA cache_size=-2048')
            con.execute('PRAGMA synchronous=OFF')  # Disposable staging index only.
            con.execute('CREATE TABLE IF NOT EXISTS domains(domain TEXT PRIMARY KEY)')
            con.execute('CREATE TABLE IF NOT EXISTS networks(start INTEGER,end INTEGER, '
                        'PRIMARY KEY(start,end))')
            with path.open(encoding='utf-8-sig') as stream:
                lines = iter(lambda: stream.readline(4097), '')
                values = _parse_values(lines, kind)
                if kind == 'domains':
                    con.executemany('INSERT OR IGNORE INTO domains VALUES (?)',
                                    ((value,) for value in values))
                else:
                    con.executemany('INSERT OR IGNORE INTO networks VALUES (?,?)',
                                    ((int(net.network_address), int(net.broadcast_address))
                                     for net in values))

    @staticmethod
    def _finish_index(index: Path):
        with closing(sqlite3.connect(index)) as con, con:
            con.execute('PRAGMA cache_size=-2048')
            domains = con.execute('SELECT COUNT(*) FROM domains').fetchone()[0]
            networks = con.execute('SELECT COUNT(*) FROM networks').fetchone()[0]
            if domains < _MIN_DOMAINS or networks < _MIN_IPS:
                raise ValueError('Source bundle is suspiciously small')
            con.execute('CREATE TABLE merged(start INTEGER,end INTEGER,PRIMARY KEY(start,end))')
            def merged():
                start = end = None
                for first, last in con.execute('SELECT start,end FROM networks ORDER BY start,end'):
                    if start is not None and first > end + 1:
                        yield start, end
                        start = None
                    if start is None:
                        start, end = first, last
                    else:
                        end = max(end, last)
                if start is not None:
                    yield start, end
            con.executemany('INSERT INTO merged VALUES (?,?)', merged())
            con.execute('DROP TABLE networks')
            con.execute('ALTER TABLE merged RENAME TO networks')
            return domains, networks

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

    async def _download_source(self, source: str, folder: Path) -> RegistryData:
        revision = ''
        feeds = _PROVIDERS[source]
        timestamps = []
        # Network deadlines do not cancel a still-running parser thread and start another.
        async with asyncio.timeout(150):
            if source == 'bol-van':
                response = await self._get(_GITHUB_COMMIT_URL)
                revision = response.json()[0]['sha']
                feeds = tuple((kind, url.replace('/main/', f'/{revision}/')) for kind, url in feeds)
                dates = await self._get_many(
                    f'https://api.github.com/repos/bol-van/rulist/commits?sha={revision}'
                    f'&path={url.rsplit("/", 1)[1]}&per_page=1' for _, url in feeds)
                timestamps = [_timestamp(item.json()[0]['commit']['committer']['date'])
                              for item in dates]
                for stamp in timestamps:
                    self._check_source_age(stamp)
            for i, (_, url) in enumerate(feeds):
                stamp = await self._download_file(url, folder / f'{i}.txt', source)
                if stamp is not None:
                    timestamps.append(stamp)
        index = folder / 'index.db'
        for i, (kind, _) in enumerate(feeds):
            path = folder / f'{i}.txt'
            await _in_thread(self._import_file, index, path, kind)
            path.unlink()
        domains, networks = await _in_thread(self._finish_index, index)
        return RegistryData(index, source, min(timestamps), domains, networks, revision)

    def _check_reduction(self, data: RegistryData) -> None:
        try:
            meta = self._read_meta()
        except sqlite3.Error:
            return
        if meta.get('parser_version') == _PARSER_VERSION and meta.get('source') == data.source:
            if (data.domain_count < int(meta['domain_count']) // 2
                    or data.network_count < int(meta['network_count']) // 2):
                raise ValueError('Source bundle unexpectedly lost over half its entries')

    def _rebuild_index(self, data: RegistryData, fetched_at: datetime) -> None:
        if not data.domain_count or not data.network_count or data.source not in _PROVIDERS:
            raise ValueError('Incomplete registry bundle')
        self._check_source_age(data.updated_at)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        # A complete index write exceeds SQLite's default five-second busy timeout.
        with closing(sqlite3.connect(self.db_path, timeout=60, uri=True)) as con, con:
            con.execute('PRAGMA journal_mode=WAL')
            con.execute('PRAGMA cache_size=-2048')
            con.execute('ATTACH DATABASE ? AS staged', (data.path.resolve().as_uri() + '?mode=ro',))
            con.execute('BEGIN IMMEDIATE')
            has_meta = con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='meta'").fetchone()
            meta = dict(con.execute('SELECT key,value FROM meta')) if has_meta else {}
            # Another web/worker process may have published while we downloaded or waited.
            if (self._meta_is_fresh(meta)
                    and _timestamp(meta['source_updated_at']) >= data.updated_at):
                return
            for table in ('meta', 'domains', 'ips', 'networks'):
                con.execute(f'DROP TABLE IF EXISTS main.{table}')
            con.execute('CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)')
            con.execute('CREATE TABLE domains(domain TEXT PRIMARY KEY)')
            con.execute('CREATE TABLE networks(start INTEGER,end INTEGER,PRIMARY KEY(start,end))')
            con.execute('INSERT INTO domains SELECT domain FROM staged.domains')
            con.execute('INSERT INTO networks SELECT start,end FROM staged.networks')
            con.executemany('INSERT INTO meta VALUES (?,?)', {
                'parser_version': _PARSER_VERSION, 'source': data.source,
                'source_revision': data.revision,
                'source_updated_at': data.updated_at.isoformat(), 'fetched_at': fetched_at.isoformat(),
                'domain_count': str(data.domain_count), 'network_count': str(data.network_count),
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
