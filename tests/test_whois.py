from sitewatcher import storage
from sitewatcher.checks.whois_info import WhoisInfoCheck
from sitewatcher.config import WhoisConfig


def test_whois_check_can_start_with_empty_database(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DEFAULT_DB", tmp_path / "sitewatcher.db")
    check = WhoisInfoCheck("example.com", client=None, cfg=WhoisConfig())
    assert check._db_get() is None

import asyncio
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from sitewatcher.checks.base import Status


@pytest.mark.parametrize('failure', ['429', '500', '503', 'transport'])
def test_failed_refresh_is_persistent_and_daily(tmp_path, failure):
    calls = []

    def respond(request):
        calls.append(request)
        if failure == 'transport':
            raise httpx.ConnectError('private diagnostic', request=request)
        return httpx.Response(int(failure), headers={'Retry-After': '172800'})

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            cfg = WhoisConfig(db_path=str(tmp_path / 'cache.db'))
            first = await WhoisInfoCheck('WWW.Example.COM.', client, cfg).run()
            second = await WhoisInfoCheck('example.com', client, cfg).run()
            assert first.status == Status.UNKNOWN
            assert second.status == Status.UNKNOWN
            if failure != 'transport':
                assert first.metrics['status_code'] == int(failure)
                assert second.metrics['status_code'] == int(failure)
            assert second.metrics['next_retry_at']
            assert len(calls) == 1
            if failure == '429':
                retry = datetime.fromisoformat(second.metrics['next_retry_at'])
                assert retry > datetime.now(timezone.utc) + timedelta(hours=47)
    asyncio.run(run())


def test_success_cached_and_failed_refresh_retains_old_snapshot(tmp_path):
    calls = []

    def respond(request):
        calls.append(request)
        if len(calls) > 1:
            return httpx.Response(429)
        return httpx.Response(200, json={'events': [
            {'eventAction': 'expiration', 'eventDate': '2099-01-01T00:00:00Z'},
        ]})

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            cfg = WhoisConfig(db_path=str(tmp_path / 'cache.db'))
            check = WhoisInfoCheck('example.com', client, cfg)
            first = await check.run()
            second = await WhoisInfoCheck('www.example.com', client, cfg).run()
            assert first.status == second.status == Status.OK
            assert len(calls) == 1
            old = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
            with check._connect() as conn:
                conn.execute('UPDATE whois_state SET fetched_at=?', (old,))
                conn.execute('UPDATE whois_attempts SET next_retry_at=?', (old,))
            failed = await check.run()
            cached_failure = await check.run()
            assert failed.status == cached_failure.status == Status.UNKNOWN
            assert cached_failure.metrics['fetched_at'] == old
            assert check._db_get().fetched_at.isoformat() == old
            assert len(calls) == 2
    asyncio.run(run())


@pytest.mark.parametrize('header', ['garbage', '-10', '9' * 100, 'NaN'])
def test_invalid_retry_after_uses_daily_deadline(tmp_path, header):
    check = WhoisInfoCheck('example.com', None, WhoisConfig(db_path=str(tmp_path / 'cache.db')))
    now = datetime.now(timezone.utc)
    check._claim_refresh(now)
    assert check._finish_attempt(Status.UNKNOWN, 'failed', now, header) == now + timedelta(hours=24)


def test_http_date_retry_after_and_atomic_inflight_claim(tmp_path):
    from email.utils import format_datetime

    cfg = WhoisConfig(db_path=str(tmp_path / 'cache.db'))
    check = WhoisInfoCheck('www.example.com', None, cfg)
    other = WhoisInfoCheck('example.com', None, cfg)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    assert check._claim_refresh(now) is None
    assert other._claim_refresh(now).status == Status.UNKNOWN
    later = now + timedelta(days=3)
    assert check._finish_attempt(Status.UNKNOWN, 'rate limited', now, format_datetime(later)) == later
    assert other._claim_refresh(now).metrics['next_retry_at'] == later.isoformat()


@pytest.mark.parametrize('age_days', [0, 2])
def test_legacy_subdomain_snapshot_is_reused(tmp_path, age_days):
    import json

    calls = []

    def respond(request):
        calls.append(request)
        return httpx.Response(200, json={'events': [
            {'eventAction': 'expiration', 'eventDate': '2099-01-01T00:00:00Z'},
        ]})

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            cfg = WhoisConfig(db_path=str(tmp_path / 'cache.db'))
            check = WhoisInfoCheck('a.example.com', client, cfg)
            stamp = (datetime.now(timezone.utc) - timedelta(days=age_days)).isoformat()
            with check._connect() as conn:
                conn.execute(
                    'INSERT INTO whois_state(domain,snapshot_json,fetched_at) VALUES(?,?,?)',
                    ('a.example.com', json.dumps({'expires_at': '2099-01-01T00:00:00+00:00'}),
                     stamp),
                )
            assert (await check.run()).status in (Status.OK, Status.WARN)
            assert (await check.run()).status == Status.OK
            assert len(calls) == (1 if age_days else 0)
            with check._connect() as conn:
                assert conn.execute('SELECT COUNT(*) FROM whois_state').fetchone()[0] == 2
    asyncio.run(run())


def test_concurrent_instances_make_one_network_request(tmp_path):
    async def run():
        entered = asyncio.Event()
        release = asyncio.Event()
        calls = []

        async def respond(request):
            calls.append(request)
            entered.set()
            await release.wait()
            return httpx.Response(429)

        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            cfg = WhoisConfig(db_path=str(tmp_path / 'cache.db'))
            first = asyncio.create_task(WhoisInfoCheck('www.example.com', client, cfg).run())
            await entered.wait()
            second = await WhoisInfoCheck('example.com', client, cfg).run()
            assert second.status == Status.UNKNOWN
            assert len(calls) == 1
            release.set()
            assert (await first).status == Status.UNKNOWN
            assert len(calls) == 1
    asyncio.run(run())


def test_legacy_snapshot_does_not_replace_newer_canonical(tmp_path):
    import json

    check = WhoisInfoCheck('a.example.com', None, WhoisConfig(db_path=str(tmp_path / 'cache.db')))
    now = datetime.now(timezone.utc)
    with check._connect() as conn:
        conn.executemany(
            'INSERT INTO whois_state(domain,snapshot_json,fetched_at) VALUES(?,?,?)',
            [('a.example.com', json.dumps({'registrar': 'old'}),
              (now - timedelta(days=1)).isoformat()),
             ('example.com', json.dumps({'registrar': 'new'}), now.isoformat())],
        )
    assert json.loads(check._db_get().snapshot_json)['registrar'] == 'new'


@pytest.mark.parametrize('timestamp', ['2000-01-01T00:00:00', 'malformed'])
def test_legacy_canonical_timestamp_can_refresh(tmp_path, timestamp):
    calls = []

    def respond(request):
        calls.append(request)
        return httpx.Response(200, json={'events': [
            {'eventAction': 'expiration', 'eventDate': '2099-01-01T00:00:00Z'},
        ]})

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            check = WhoisInfoCheck(
                'example.com', client, WhoisConfig(db_path=str(tmp_path / 'cache.db')),
            )
            with check._connect() as conn:
                conn.execute(
                    'INSERT INTO whois_state(domain,snapshot_json,fetched_at) VALUES(?,?,?)',
                    ('example.com', '{}', timestamp),
                )
            assert (await check.run()).status in (Status.OK, Status.WARN)
            assert (await check.run()).status == Status.OK
            assert len(calls) == 1
    asyncio.run(run())


def test_cached_snapshot_has_stable_observation_and_recomputes_expiry(tmp_path):
    check = WhoisInfoCheck('example.com', None, WhoisConfig(db_path=str(tmp_path / 'cache.db')))
    fetched = datetime.now(timezone.utc) - timedelta(hours=1)
    check._db_upsert({'expires_at': '2000-01-01T00:00:00+00:00'}, fetched)
    result = asyncio.run(check.run())
    assert result.status == Status.CRIT
    assert result.cached
    assert result.metrics['observed_at'] == fetched.isoformat()
    assert result.metrics['next_refresh_at'] == (fetched + timedelta(hours=24)).isoformat()


def test_force_refresh_bypasses_success_ttl_after_debounce(tmp_path):
    calls = []

    def respond(request):
        calls.append(request)
        return httpx.Response(200, json={'events': [
            {'eventAction': 'expiration', 'eventDate': '2099-01-01T00:00:00Z'},
        ]})

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            cfg = WhoisConfig(db_path=str(tmp_path / 'cache.db'))
            check = WhoisInfoCheck('example.com', client, cfg)
            first = await check.run()
            force = WhoisInfoCheck('www.example.com', client, cfg, force_refresh=True)
            assert (await force.run()).cached
            old = datetime.now(timezone.utc) - timedelta(seconds=61)
            with check._connect() as conn:
                conn.execute('UPDATE whois_state SET fetched_at=?', (old.isoformat(),))
                conn.execute('UPDATE whois_attempts SET attempted_at=?', (old.isoformat(),))
            updated = await force.run()
            assert len(calls) == 2
            assert not updated.cached
            assert updated.metrics['observed_at'] != first.metrics['observed_at']
    asyncio.run(run())


@pytest.mark.parametrize('expiry, expected', [
    ('2000-01-01T00:00:00+00:00', Status.CRIT),
    ((datetime.now(timezone.utc) + timedelta(days=20)).isoformat(), Status.WARN),
    ('2099-01-01T00:00:00+00:00', Status.UNKNOWN),
])
def test_force_failure_preserves_expiry_and_retry_observation(tmp_path, expiry, expected):
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(
            lambda request: httpx.Response(429, headers={'Retry-After': '172800'}),
        )) as client:
            cfg = WhoisConfig(db_path=str(tmp_path / 'cache.db'))
            check = WhoisInfoCheck('example.com', client, cfg, force_refresh=True)
            fetched = datetime.now(timezone.utc) - timedelta(hours=1)
            check._db_upsert({'expires_at': expiry, 'registrar': 'known'}, fetched)
            failed = await check.run()
            blocked = await check.run()
            regular = await WhoisInfoCheck('example.com', None, cfg).run()
            assert failed.status == blocked.status == regular.status == expected
            assert not failed.cached
            assert blocked.cached and regular.cached
            assert failed.metrics['registrar'] == blocked.metrics['registrar'] == 'known'
            assert failed.metrics['observed_at'] == blocked.metrics['observed_at']
            assert blocked.metrics['observed_at'] == fetched.isoformat()
            assert blocked.metrics['attempted_at'] == failed.metrics['attempted_at']
            assert blocked.metrics['attempted_at'] != fetched.isoformat()
            assert blocked.metrics['next_refresh_at'] == failed.metrics['next_retry_at']
            assert blocked.metrics['cache_state'] == 'stale'
    asyncio.run(run())


def test_force_refresh_cannot_bypass_active_claim_with_fresh_snapshot(tmp_path):
    cfg = WhoisConfig(db_path=str(tmp_path / 'cache.db'))
    check = WhoisInfoCheck('example.com', None, cfg, force_refresh=True)
    now = datetime.now(timezone.utc)
    check._db_upsert({'expires_at': '2099-01-01T00:00:00+00:00'}, now - timedelta(hours=1))
    assert check._claim_refresh(now) is None
    blocked = asyncio.run(WhoisInfoCheck('www.example.com', None, cfg, force_refresh=True).run())
    assert blocked.cached
    assert blocked.status == Status.UNKNOWN
    assert 'pending' in blocked.message


def test_cached_snapshot_reassesses_expiry_as_clock_advances(tmp_path, monkeypatch):
    import sitewatcher.checks.whois_info as whois_module

    start = datetime(2030, 1, 1, tzinfo=timezone.utc)

    class Clock(datetime):
        current = start

        @classmethod
        def now(cls, tz=None):
            return cls.current

    monkeypatch.setattr(whois_module, 'datetime', Clock)
    check = WhoisInfoCheck('example.com', None, WhoisConfig(db_path=str(tmp_path / 'cache.db')))
    check._db_upsert({'expires_at': (start + timedelta(days=31)).isoformat()}, start)
    first = asyncio.run(check.run())
    Clock.current += timedelta(hours=12)
    second = asyncio.run(check.run())
    assert first.status == Status.OK
    assert second.status == Status.WARN
    assert first.cached and second.cached
    assert first.metrics['observed_at'] == second.metrics['observed_at'] == start.isoformat()
    assert first.metrics['next_refresh_at'] == second.metrics['next_refresh_at']


def test_failed_cached_snapshot_reassesses_critical_expiry_without_network(tmp_path, monkeypatch):
    import sitewatcher.checks.whois_info as whois_module

    start = datetime(2030, 1, 1, tzinfo=timezone.utc)

    class Clock(datetime):
        current = start

        @classmethod
        def now(cls, tz=None):
            return cls.current

    monkeypatch.setattr(whois_module, 'datetime', Clock)
    cfg = WhoisConfig(db_path=str(tmp_path / 'cache.db'))
    check = WhoisInfoCheck('example.com', None, cfg)
    fetched = start - timedelta(days=1)
    check._db_upsert({'expires_at': (start + timedelta(days=8)).isoformat()}, fetched)
    assert check._claim_refresh(start) is None
    check._finish_attempt(Status.UNKNOWN, 'RDAP rate-limited', start, '172800')
    first = asyncio.run(check.run())
    Clock.current += timedelta(hours=12)
    second = asyncio.run(check.run())
    assert first.status == Status.WARN
    assert second.status == Status.CRIT
    assert first.cached and second.cached
    assert first.metrics['observed_at'] == second.metrics['observed_at'] == fetched.isoformat()
    assert first.metrics['attempted_at'] == second.metrics['attempted_at'] == start.isoformat()
    assert first.metrics['next_retry_at'] == second.metrics['next_retry_at']
