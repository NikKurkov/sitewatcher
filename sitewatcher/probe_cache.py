"""Persistent public network observations with bounded cross-process fetch claims.

Only public facts belong here. Keys must include the provider/resolver context;
owner credentials and private page content must never enter this shared cache.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import time
from typing import Awaitable, Callable
from uuid import uuid4

from . import storage

_LEASE_S = 120.0
_FETCH_TIMEOUT_S = 110.0
_WAIT_TIMEOUT_S = 245.0
_POLL_S = 0.05


@dataclass(frozen=True)
class Observation:
    value: dict
    fetched_at: datetime
    expires_at: datetime
    cached: bool


def _initialize() -> None:
    storage._ensure_initialized()
    with storage._write_connection() as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS probe_cache (
            namespace TEXT NOT NULL,
            cache_key TEXT NOT NULL,
            value_json TEXT,
            fetched_at REAL,
            expires_at REAL,
            claim_token TEXT,
            claim_until REAL,
            PRIMARY KEY(namespace, cache_key)
        )''')


def _observation(row, *, cached: bool = True) -> Observation | None:
    if row is None or row['value_json'] is None:
        return None
    return Observation(
        json.loads(row['value_json']),
        datetime.fromtimestamp(row['fetched_at'], timezone.utc),
        datetime.fromtimestamp(row['expires_at'], timezone.utc),
        cached,
    )


def read(namespace: str, key: str) -> Observation | None:
    """Read the last observation, including stale facts, without fetching."""
    _initialize()
    with storage._write_connection() as conn:
        return _observation(conn.execute(
            'SELECT * FROM probe_cache WHERE namespace=? AND cache_key=?',
            (namespace, key),
        ).fetchone())


def seed(namespace: str, key: str, value: dict, *, fetched_at: datetime, ttl_s: float) -> None:
    """Adopt legacy evidence once without replacing an observation or active claim."""
    if fetched_at.tzinfo is None:
        raise ValueError('fetched_at must be timezone-aware')
    _initialize()
    stamp = fetched_at.timestamp()
    with storage._write_connection() as conn:
        conn.execute('''INSERT OR IGNORE INTO probe_cache
            (namespace, cache_key, value_json, fetched_at, expires_at)
            VALUES (?, ?, ?, ?, ?)''',
                     (namespace, key, json.dumps(value), stamp, stamp + max(0, ttl_s)))


def _failure(value: dict) -> bool:
    return bool(value.get('error')) or str(value.get('status', '')).lower() in {
        'error', 'unknown', 'failed',
    }


async def get_or_fetch(
    namespace: str,
    key: str,
    fetch: Callable[[], Awaitable[dict]],
    *,
    ttl_s: float | Callable[[dict], float] = 86400,
    force: bool = False,
) -> Observation:
    """Coalesce refreshes across event loops/processes without holding a DB lock.

    Failed payloads retain their retry deadline under force. Successful explicit
    refreshes are debounced for 60 seconds and never bypass another caller's claim.
    Fetch exceptions/cancellation release the claim and preserve old evidence.
    """
    _initialize()
    token = uuid4().hex
    deadline = time.monotonic() + _WAIT_TIMEOUT_S
    while True:
        now = time.time()
        with storage._write_connection() as conn:
            row = conn.execute(
                'SELECT * FROM probe_cache WHERE namespace=? AND cache_key=?',
                (namespace, key),
            ).fetchone()
            observation = _observation(row)
            if observation and observation.expires_at.timestamp() > now:
                if (not force or _failure(observation.value)
                        or observation.fetched_at.timestamp() + 60 > now):
                    return observation
            if row is None or not row['claim_until'] or row['claim_until'] <= now:
                conn.execute('''INSERT INTO probe_cache
                    (namespace, cache_key, claim_token, claim_until) VALUES (?, ?, ?, ?)
                    ON CONFLICT(namespace, cache_key) DO UPDATE SET
                    claim_token=excluded.claim_token, claim_until=excluded.claim_until''',
                             (namespace, key, token, now + _LEASE_S))
                break
        if time.monotonic() >= deadline:
            raise TimeoutError('network observation refresh is busy')
        await asyncio.sleep(_POLL_S)

    try:
        value = await asyncio.wait_for(fetch(), timeout=_FETCH_TIMEOUT_S)
        if not isinstance(value, dict):
            raise TypeError('network observation must be a dictionary')
        fetched_at = datetime.now(timezone.utc)
        lifetime = max(0, float(ttl_s(value) if callable(ttl_s) else ttl_s))
        expires_at = datetime.fromtimestamp(fetched_at.timestamp() + lifetime, timezone.utc)
        encoded = json.dumps(value)
        with storage._write_connection() as conn:
            updated = conn.execute('''UPDATE probe_cache SET value_json=?, fetched_at=?,
                expires_at=?, claim_token=NULL, claim_until=NULL
                WHERE namespace=? AND cache_key=? AND claim_token=?''',
                                   (encoded, fetched_at.timestamp(), expires_at.timestamp(),
                                    namespace, key, token)).rowcount
        if not updated:
            raise TimeoutError('network observation lease expired')
        return Observation(value, fetched_at, expires_at, False)
    finally:
        with storage._write_connection() as conn:
            conn.execute('''UPDATE probe_cache SET claim_token=NULL, claim_until=NULL
                WHERE namespace=? AND cache_key=? AND claim_token=?''',
                         (namespace, key, token))
