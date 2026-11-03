"""Owner-scoped route diagnostic queue, independent of monitoring and alerts."""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager, closing
from datetime import datetime, timedelta, timezone
import json
import logging
import sqlite3
from time import monotonic

from . import check_activity, storage
from .config import AppConfig, resolve_settings

log = logging.getLogger(__name__)
POLL_SECONDS = 1
REFRESH_SECONDS = 3600
LEASE_SECONDS = 60


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connect(mode: str = 'rw') -> sqlite3.Connection:
    conn = sqlite3.connect(storage.DEFAULT_DB.resolve().as_uri() + '?mode=' + mode,
                           uri=True, timeout=1, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys=ON')
    return conn


def request_trace(owner_id: int, domain: str, enabled: bool = True) -> None:
    """Queue a selected owned domain, or disable it while retaining its last result."""
    domain = (domain or '').strip().lower()
    storage._ensure_initialized()
    with closing(_connect()) as conn, conn:
        conn.execute('BEGIN IMMEDIATE')
        if not conn.execute('SELECT 1 FROM domains WHERE owner_id=? AND name=?',
                            (owner_id, domain)).fetchone():
            raise ValueError('Unknown domain')
        row = conn.execute('SELECT state FROM domain_routes WHERE owner_id=? AND domain=?',
                           (owner_id, domain)).fetchone()
        if enabled and row and row['state'] in ('queued', 'running'):
            raise RuntimeError('Route diagnostic already queued or running')
        conn.execute(
            'INSERT INTO domain_routes(owner_id,domain,enabled,state,updated_at) '
            'VALUES(?,?,?,?,?) ON CONFLICT(owner_id,domain) DO UPDATE SET '
            'enabled=excluded.enabled,state=excluded.state,updated_at=excluded.updated_at',
            (owner_id, domain, int(enabled), 'queued' if enabled else 'disabled', _now()),
        )


def read_owner(owner_id: int) -> dict[str, dict]:
    """Read existing cache only; reading a fresh/older installation creates nothing."""
    try:
        with closing(_connect('ro')) as conn:
            if not conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' "
                                "AND name='domain_routes'").fetchone():
                return {}
            rows = conn.execute('SELECT * FROM domain_routes WHERE owner_id=?',
                                (owner_id,)).fetchall()
    except sqlite3.OperationalError:
        if not storage.DEFAULT_DB.exists():
            return {}
        raise
    result = {}
    for row in rows:
        try:
            cached = json.loads(row['result_json']) if row['result_json'] else None
        except (ValueError, TypeError):
            cached = None
        result[row['domain']] = {'enabled': bool(row['enabled']), 'state': row['state'],
                                 'updated_at': row['updated_at'], 'result': cached}
    return result


def _candidates(cfg: AppConfig) -> list[tuple[int, str]]:
    now = datetime.now(timezone.utc)
    stale = (now - timedelta(seconds=LEASE_SECONDS)).isoformat()
    due = (now - timedelta(seconds=REFRESH_SECONDS)).isoformat()
    with closing(_connect()) as conn, conn:
        conn.execute('BEGIN IMMEDIATE')
        conn.execute("UPDATE domain_routes SET state='queued',updated_at=? "
                     "WHERE enabled=1 AND state='running' AND updated_at<?", (_now(), stale))
        rows = conn.execute(
            'SELECT r.*,o.data_json FROM domain_routes r LEFT JOIN domain_overrides o '
            'ON o.owner_id=r.owner_id AND o.domain=r.domain WHERE r.enabled=1 '
            "AND (r.state='queued' OR (r.state IN ('ready','partial','error') "
            'AND r.updated_at<=?)) ORDER BY r.updated_at', (due,),
        ).fetchall()
        selected = []
        for row in rows:
            if row['state'] != 'queued':
                if not cfg.scheduler.enabled:
                    continue
                try:
                    override = json.loads(row['data_json']) if row['data_json'] else None
                    interval = resolve_settings(cfg, row['domain'], override).interval_minutes
                except (ValueError, TypeError):
                    continue
                if interval is not None and interval <= 0:
                    continue
            selected.append((row['owner_id'], row['domain']))
        return selected


def _claim(owner: int, domain: str, lease: str, cfg: AppConfig | None = None) -> str | None:
    with closing(_connect()) as conn, conn:
        conn.execute('BEGIN IMMEDIATE')
        row = conn.execute(
            'SELECT r.*,o.data_json FROM domain_routes r LEFT JOIN domain_overrides o '
            'ON o.owner_id=r.owner_id AND o.domain=r.domain '
            'WHERE r.owner_id=? AND r.domain=? AND r.enabled=1', (owner, domain),
        ).fetchone()
        if row is None or row['state'] == 'running' or row['state'] == 'disabled':
            return None
        if row['state'] != 'queued':
            if cfg is None or not cfg.scheduler.enabled:
                return None
            due = (datetime.now(timezone.utc) - timedelta(seconds=REFRESH_SECONDS)).isoformat()
            if row['updated_at'] > due:
                return None
            try:
                override = json.loads(row['data_json']) if row['data_json'] else None
                interval = resolve_settings(cfg, domain, override).interval_minutes
            except (ValueError, TypeError):
                return None
            if interval is not None and interval <= 0:
                return None
        changed = conn.execute(
            "UPDATE domain_routes SET state='running',updated_at=? "
            'WHERE owner_id=? AND domain=? AND enabled=1 AND state=? AND updated_at=?',
            (lease, owner, domain, row['state'], row['updated_at']),
        ).rowcount
        return row['state'] if changed else None


def _persist(owner: int, domain: str, lease: str, state: str, result: dict | None) -> None:
    with closing(_connect()) as conn:
        conn.execute(
            'UPDATE domain_routes SET state=?,updated_at=?,result_json=COALESCE(?,result_json) '
            "WHERE owner_id=? AND domain=? AND enabled=1 AND state='running' AND updated_at=?",
            (state, _now(), json.dumps(result) if result is not None else None, owner, domain, lease),
        )


async def _drain(task):
    """Finish cleanup despite repeated cancellation, retaining the original cancellation."""
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            pass
    return task.result()


async def _db(function, *args):
    task = asyncio.create_task(asyncio.to_thread(function, *args))
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        try:
            await _drain(task)
        except Exception:
            pass
        raise


async def _execute(owner: int, domain: str, cfg: AppConfig | None = None) -> None:
    # Lease equality protects disable/refresh and delete/recreate races.
    lease = _now()
    started = monotonic()
    activity = None
    status = 'UNKNOWN'
    state = 'queued'
    result = None
    claim = asyncio.create_task(asyncio.to_thread(_claim, owner, domain, lease, cfg))
    try:
        if not await asyncio.shield(claim):
            return
        activity = asyncio.create_task(asyncio.to_thread(check_activity.start,
                                                        owner, domain, 'traceroute'))
        event_id = await asyncio.shield(activity)
        if event_id is None:
            state = 'error'
            return
        from .checks.traceroute import TracerouteCheck
        outcome = await TracerouteCheck(domain).run()
        status = outcome.status.value
        result = outcome.metrics or None
        if result and result.get('destination_ip'):
            state = 'ready' if result.get('reached') else 'partial'
        else:
            state = 'error'
    except asyncio.CancelledError:
        raise
    except Exception as error:
        state = 'error'
        log.warning('route.probe.failed', extra={'etype': type(error).__name__})
    finally:
        async def cleanup():
            try:
                previous_state = await _drain(claim)
            except (sqlite3.Error, OSError):
                return
            if not previous_state:
                return
            if activity is not None:
                event_id = await _drain(activity)
                await _db(check_activity.finish, event_id, status,
                          int((monotonic() - started) * 1000))
            try:
                await _db(_persist, owner, domain, lease,
                          previous_state if state == 'queued' else state, result)
            except (sqlite3.Error, OSError) as error:
                log.warning('route.cache.unavailable', extra={'etype': type(error).__name__})
        await _drain(asyncio.create_task(cleanup()))


async def _loop(cfg: AppConfig) -> None:
    active: dict[tuple[int, str], asyncio.Task] = {}
    try:
        while True:
            for key, task in list(active.items()):
                if task.done():
                    try:
                        task.result()
                    except Exception as error:
                        log.warning('route.job.failed', extra={'etype': type(error).__name__})
                    del active[key]
            try:
                candidates = await _db(_candidates, cfg)
                for key in candidates:
                    if key not in active and len(active) < 2:
                        active[key] = asyncio.create_task(_execute(*key, cfg))
            except (sqlite3.Error, OSError) as error:
                log.warning('route.queue.unavailable', extra={'etype': type(error).__name__})
            await asyncio.sleep(POLL_SECONDS)
    finally:
        for task in active.values():
            if not task.done():
                task.cancel()
        await _drain(asyncio.gather(*active.values(), return_exceptions=True))


@asynccontextmanager
async def runner(cfg: AppConfig):
    """Worker-only diagnostics loop; caller holds the existing scheduler lock."""
    task = asyncio.create_task(_loop(cfg))
    try:
        yield
    finally:
        task.cancel()
        drain = asyncio.gather(task, return_exceptions=True)
        await _drain(drain)
