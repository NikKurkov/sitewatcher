import asyncio
from contextlib import closing
from datetime import datetime, timedelta, timezone
import json
import sqlite3
from unittest.mock import AsyncMock

import pytest

from sitewatcher.checks.base import Status
from sitewatcher.checks.ip_change import IpChangeCheck
from sitewatcher.config import AppConfig, ChecksModel, IpChangeConfig
from sitewatcher.dispatcher import Dispatcher


@pytest.fixture(params=[False, True], ids=['main-cache', 'custom-cache'])
def dns_config(tmp_path, request):
    return IpChangeConfig(db_path=str(tmp_path / 'custom-dns.db') if request.param else None)


def seed(config, ips=('192.0.2.1',), fetched=None):
    check = IpChangeCheck('example.com', cfg=config)
    check._maybe_upsert(list(ips), [], fetched or datetime.now(timezone.utc), None, True)
    return check


def stored(check, table, owner=None):
    with closing(sqlite3.connect(check._db_path)) as conn:
        query = f'SELECT snapshot_json,fetched_at FROM {table} WHERE domain=?'
        params = ('example.com',)
        if owner is not None:
            query += ' AND owner_id=?'
            params += (owner,)
        return conn.execute(query, params).fetchone()


def test_owners_and_ephemeral_scan_detect_changes_independently(dns_config, monkeypatch):
    legacy = seed(dns_config)
    before = stored(legacy, 'dns_state')
    monkeypatch.setattr(IpChangeCheck, '_resolve_ips', AsyncMock(return_value=(['192.0.2.2'], [])))

    async def scenario():
        results = []
        for owner in (0, 1, 2):  # An ad hoc scan must not consume either owner's legacy baseline.
            check = IpChangeCheck('example.com', cfg=dns_config, owner_id=owner)
            results.append((await check.run()).status)
        assert results == [Status.WARN, Status.WARN, Status.WARN]
        for owner in (0, 1, 2):
            check = IpChangeCheck('example.com', cfg=dns_config, owner_id=owner)
            assert (await check.run()).status is Status.OK
            assert json.loads(stored(check, 'owner_dns_state', owner)[0])['ips_v4'] == ['192.0.2.2']

    asyncio.run(scenario())
    assert stored(legacy, 'dns_state') == before


def test_unchanged_legacy_bootstrap_is_materialized_without_extending_ttl(dns_config, monkeypatch):
    fetched = datetime.now(timezone.utc) - timedelta(hours=2)
    legacy = seed(dns_config, fetched=fetched)
    monkeypatch.setattr(IpChangeCheck, '_resolve_ips', AsyncMock(return_value=(['192.0.2.1'], [])))
    check = IpChangeCheck('example.com', cfg=dns_config, owner_id=1)
    assert asyncio.run(check.run()).status is Status.OK
    assert stored(check, 'owner_dns_state', 1) == stored(legacy, 'dns_state')

    # Later legacy activity must not alter the materialized owner baseline.
    seed(dns_config, ips=('192.0.2.2',))
    monkeypatch.setattr(IpChangeCheck, '_resolve_ips', AsyncMock(return_value=(['192.0.2.2'], [])))
    assert asyncio.run(check.run()).status is Status.WARN


def test_owner_ttl_refresh_updates_only_that_owner(dns_config, monkeypatch):
    fetched = datetime.now(timezone.utc) - timedelta(hours=25)
    legacy = seed(dns_config, fetched=fetched)
    before = stored(legacy, 'dns_state')
    monkeypatch.setattr(IpChangeCheck, '_resolve_ips', AsyncMock(return_value=(['192.0.2.1'], [])))
    check = IpChangeCheck('example.com', cfg=dns_config, owner_id=1)
    assert asyncio.run(check.run()).status is Status.OK
    assert datetime.fromisoformat(stored(check, 'owner_dns_state', 1)[1]) > fetched
    assert stored(legacy, 'dns_state') == before


def test_dns_lookup_failure_preserves_scoped_baseline(dns_config, monkeypatch):
    legacy = seed(dns_config)
    check = IpChangeCheck('example.com', cfg=dns_config, owner_id=1)
    initial = check._db_get()  # Bootstrap before the transient resolution error.
    monkeypatch.setattr(check, '_resolve_ips', AsyncMock(side_effect=OSError('offline')))
    result = asyncio.run(check.run())
    assert result.status is Status.UNKNOWN and result.metrics['baseline_preserved']
    assert check._db_get() == initial
    assert stored(legacy, 'dns_state') == stored(check, 'owner_dns_state', 1)


def test_failed_scoped_write_does_not_consume_change(dns_config, monkeypatch):
    seed(dns_config)
    check = IpChangeCheck('example.com', cfg=dns_config, owner_id=1)
    before = check._db_get()
    with closing(sqlite3.connect(check._db_path)) as conn:
        conn.execute("""CREATE TRIGGER reject_dns BEFORE INSERT ON owner_dns_state
                     BEGIN SELECT RAISE(ABORT,'synthetic write failure'); END""")
    monkeypatch.setattr(check, '_resolve_ips', AsyncMock(return_value=(['192.0.2.2'], [])))
    with pytest.raises(sqlite3.IntegrityError):
        asyncio.run(check.run())
    assert check._db_get() == before
    with closing(sqlite3.connect(check._db_path)) as conn:
        conn.execute('DROP TRIGGER reject_dns')
    assert asyncio.run(check.run()).status is Status.WARN


def test_scoped_read_failure_stops_before_dns_lookup(dns_config, monkeypatch):
    seed(dns_config)
    check = IpChangeCheck('example.com', cfg=dns_config, owner_id=1)
    check._db_get()
    with closing(sqlite3.connect(check._db_path)) as conn:
        conn.execute('DROP TABLE owner_dns_state')
    resolver = AsyncMock(return_value=(['192.0.2.2'], []))
    monkeypatch.setattr(check, '_resolve_ips', resolver)
    with pytest.raises(sqlite3.OperationalError):
        asyncio.run(check.run())
    assert resolver.await_count == 0


def test_legacy_standalone_checker_preserves_existing_cache_contract(dns_config, monkeypatch):
    seed(dns_config)
    monkeypatch.setattr(IpChangeCheck, '_resolve_ips', AsyncMock(return_value=(['192.0.2.2'], [])))
    first = IpChangeCheck('example.com', cfg=dns_config)
    assert asyncio.run(first.run()).status is Status.WARN
    following = IpChangeCheck('example.com', cfg=dns_config)
    assert asyncio.run(following.run()).status is Status.OK
    assert json.loads(stored(following, 'dns_state')[0])['ips_v4'] == ['192.0.2.2']


def test_dispatcher_passes_monitor_owner_and_separate_ephemeral_scope(dns_config, monkeypatch):
    seed(dns_config)
    cfg = AppConfig.model_validate({
        'defaults': {'checks': {name: name == 'ip_change' for name in ChecksModel.model_fields}},
        'ipchange': dns_config,
    })
    monkeypatch.setattr(IpChangeCheck, '_resolve_ips', AsyncMock(return_value=(['192.0.2.2'], [])))

    async def scenario():
        async with Dispatcher(cfg) as dispatcher:
            for owner in (0, 1, 2):
                result = await dispatcher.run_for(owner, 'example.com', ephemeral=(owner == 0))
                assert result[0].status is Status.WARN

    asyncio.run(scenario())


@pytest.mark.parametrize('owner', [-1, True, '1'])
def test_invalid_owner_scope_is_rejected(owner):
    with pytest.raises(ValueError, match='owner_id'):
        IpChangeCheck('example.com', cfg=IpChangeConfig(), owner_id=owner)
