"""The shared registry refresh has a durable claim and failure backoff."""
import asyncio
from datetime import datetime, timedelta, timezone
import subprocess
import sys

import pytest
from unittest.mock import AsyncMock

from rkn_helpers import registry_data
from sitewatcher.checks import rkn_block_sqlite as rkn
from sitewatcher.checks.base import Status
from sitewatcher.config import RknConfig


def config(tmp_path):
    return RknConfig(index_db_path=str(tmp_path / 'index.db'), cache_ttl_hours=24)


def test_four_failed_domains_and_new_event_loop_share_one_attempt(tmp_path, monkeypatch):
    download = AsyncMock(side_effect=RuntimeError('offline'))
    monkeypatch.setattr(rkn.RknBlockCheck, '_download_with_fallback', download)
    cfg = config(tmp_path)
    async def batch():
        return await asyncio.gather(*(rkn.RknBlockCheck(f'd{i}.example', None, cfg).run()
                                      for i in range(4)))
    assert all(result.status is Status.UNKNOWN for result in asyncio.run(batch()))
    assert asyncio.run(rkn.RknBlockCheck('other.example', None, cfg).run()).status is Status.UNKNOWN
    assert download.await_count == 1


def test_daily_preparation_followed_by_fresh_local_membership(tmp_path, monkeypatch):
    cfg = config(tmp_path)
    data = registry_data(tmp_path, {'blocked.example'})
    download = AsyncMock(return_value=data)
    monkeypatch.setattr(rkn.RknBlockCheck, '_download_source', download)
    asyncio.run(rkn.prepare_registry(None, cfg))
    generation = rkn.current_registry_generation(cfg)
    asyncio.run(rkn.prepare_registry(None, cfg))
    first = asyncio.run(rkn.RknBlockCheck('blocked.example', None, cfg, auto_prepare=False).run())
    second = asyncio.run(rkn.RknBlockCheck('clean.example', None, cfg, auto_prepare=False).run())
    assert first.status is Status.CRIT and second.status is Status.OK
    assert download.await_count == 1 and generation
    assert first.metrics['observed_at'] != second.metrics['observed_at']
    assert first.metrics['fetched_at'] == second.metrics['fetched_at']
    assert first.metrics['next_refresh_at']


def test_local_only_missing_or_stale_index_never_downloads_or_confirms_clean(tmp_path, monkeypatch):
    cfg = config(tmp_path)
    check = rkn.RknBlockCheck('clean.example', None, cfg, auto_prepare=False)
    download = AsyncMock()
    monkeypatch.setattr(check, '_download_with_fallback', download)
    assert asyncio.run(check.run()).status is Status.UNKNOWN
    check._rebuild_index(registry_data(tmp_path, {'old.example'}),
                         datetime.now(timezone.utc) - timedelta(days=2))
    assert asyncio.run(check.run()).status is Status.UNKNOWN
    download.assert_not_awaited()


def test_cancelled_claim_records_cooldown_and_does_not_publish(tmp_path, monkeypatch):
    cfg = config(tmp_path)
    download = AsyncMock(side_effect=asyncio.CancelledError)
    monkeypatch.setattr(rkn.RknBlockCheck, '_download_with_fallback', download)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(rkn.prepare_registry(None, cfg))
    asyncio.run(rkn.prepare_registry(None, cfg))
    assert download.await_count == 1
    assert not rkn.rkn_index_path(cfg).exists()


def test_ip_lookup_uses_shared_dns_context(tmp_path):
    cfg = config(tmp_path)
    check = rkn.RknIpCheck('example.com', None, cfg, auto_prepare=False,
                         cycle_context=type('Context', (), {'resolve': AsyncMock(return_value=[
                             (2, 1, 6, '', ('192.0.2.1', 0))])})())
    check._rebuild_index(registry_data(tmp_path, {'example.com'}), datetime.now(timezone.utc))
    result = asyncio.run(check.run())
    assert result.status is Status.WARN
    assert result.metrics['ips_v4'] == ['192.0.2.1']
    check.cycle_context.resolve.assert_awaited_once_with('example.com', family=2)


def test_failed_refresh_in_separate_process_keeps_durable_cooldown(tmp_path, monkeypatch):
    cfg = config(tmp_path)
    script = """
import asyncio
import sys
from sitewatcher.checks import rkn_block_sqlite as rkn
from sitewatcher.config import RknConfig
async def fail(self):
    raise RuntimeError('offline')
rkn.RknBlockCheck._download_with_fallback = fail
asyncio.run(rkn.prepare_registry(None, RknConfig(index_db_path=sys.argv[1])))
"""
    subprocess.run([sys.executable, '-c', script, cfg.index_db_path], check=True,
                   capture_output=True, text=True)
    download = AsyncMock(side_effect=RuntimeError('must remain deferred'))
    monkeypatch.setattr(rkn.RknBlockCheck, '_download_with_fallback', download)
    result = asyncio.run(rkn.RknBlockCheck('example.com', None, cfg).run())
    assert result.status is Status.UNKNOWN
    assert datetime.fromisoformat(result.metrics['next_refresh_at']) > datetime.now(timezone.utc)
    download.assert_not_awaited()


def test_expired_or_replaced_claim_cannot_publish_or_release_new_claim(tmp_path):
    cfg = config(tmp_path)
    check = rkn.RknBlockCheck('example.com', None, cfg)
    old = check.refresh_state.claim()
    check._refresh_token = old
    with check.refresh_state.transaction() as con:
        con.execute('UPDATE refresh SET lease=0')
    current = check.refresh_state.claim()
    assert current != old
    with pytest.raises(RuntimeError, match='lease expired'):
        check._publish_index(registry_data(tmp_path, {'example.com'}), datetime.now(timezone.utc))
    check.refresh_state.finish(old, False)
    assert check.refresh_state.claim() is None
    assert not check.db_path.exists()


def test_failure_backoff_doubles_and_is_bounded(tmp_path, monkeypatch):
    from sitewatcher.checks import rkn_refresh_state as state
    now = 1_000_000
    monkeypatch.setattr(state.time, 'time', lambda: now)
    refresh = state.RefreshState(rkn.rkn_index_path(config(tmp_path)))
    for attempt in range(10):
        token = refresh.claim()
        assert token is not None
        refresh.finish(token, False)
        delay = refresh.deadline() - now
        assert delay == min(1800 * 2 ** attempt, 86400)
        now += delay + 1


def test_cancellation_during_claim_releases_the_committed_lease(tmp_path, monkeypatch):
    import threading
    check = rkn.RknBlockCheck('example.com', None, config(tmp_path))
    original = check.refresh_state.claim
    committed, release = threading.Event(), threading.Event()

    def paused_claim():
        token = original()
        committed.set()
        assert release.wait(5)
        return token

    monkeypatch.setattr(check.refresh_state, 'claim', paused_claim)

    async def run():
        task = asyncio.create_task(check._ensure_index_fresh())
        assert await asyncio.to_thread(committed.wait, 5)
        task.cancel()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(run())
    with check.refresh_state.transaction() as con:
        token, lease, failures, retry = con.execute(
            'SELECT token,lease,failures,retry_at FROM refresh').fetchone()
    assert token is None and lease == 0 and failures == 1 and retry > 0


def test_clean_ip_lookup_records_sorted_current_dns_snapshot(tmp_path):
    cfg = config(tmp_path)
    context = type('Context', (), {'resolve': AsyncMock(return_value=[
        (2, 1, 6, '', ('203.0.113.2', 0)),
        (2, 1, 6, '', ('198.51.100.1', 0)),
        (2, 1, 6, '', ('203.0.113.2', 0)),
    ])})()
    check = rkn.RknIpCheck('example.com', None, cfg, auto_prepare=False, cycle_context=context)
    check._rebuild_index(registry_data(tmp_path, {'example.com'}), datetime.now(timezone.utc))
    result = asyncio.run(check.run())
    assert result.status is Status.OK
    assert result.metrics['ips_v4'] == ['198.51.100.1', '203.0.113.2']


@pytest.mark.parametrize('check_class', [rkn.RknBlockCheck, rkn.RknIpCheck])
@pytest.mark.parametrize('listed', [True, False])
def test_failed_refresh_preserves_stale_hits_without_confirming_clean(
        tmp_path, monkeypatch, check_class, listed):
    import sqlite3
    cfg = config(tmp_path)
    check = check_class('example.com', None, cfg)
    check._rebuild_index(registry_data(tmp_path, {'example.com' if listed else 'other.example'}),
                         datetime.now(timezone.utc) - timedelta(days=2))
    with sqlite3.connect(check.db_path) as con:
        con.execute("UPDATE meta SET value=? WHERE key='source_updated_at'",
                    ((datetime.now(timezone.utc) - timedelta(days=10)).isoformat(),))
    monkeypatch.setattr(check, '_download_with_fallback',
                        AsyncMock(side_effect=RuntimeError('offline')))
    monkeypatch.setattr(check, '_resolve_ipv4', AsyncMock(return_value=[
        '192.0.2.1' if listed else '203.0.113.1']))
    first = asyncio.run(check.run())
    second = asyncio.run(check.run())
    expected = (Status.CRIT if check_class is rkn.RknBlockCheck else Status.WARN)
    assert first.status is (expected if listed else Status.UNKNOWN)
    assert second.status is first.status
    assert first.metrics['source_stale'] is True
    assert first.metrics['source_updated_at'] and first.metrics['fetched_at']
    assert datetime.fromisoformat(first.metrics['next_refresh_at']) > datetime.now(timezone.utc)
    assert check._download_with_fallback.await_count == 1
