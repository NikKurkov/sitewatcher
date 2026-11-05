import asyncio
import socket
from types import SimpleNamespace
from unittest.mock import AsyncMock

import dns.exception
import dns.resolver
import pytest

from sitewatcher.checks.base import Status
from sitewatcher.checks.ip_blacklist import IpBlacklistCheck
from sitewatcher import storage


def make_check(monkeypatch, *, ip='192.0.2.1', server='1.1.1.1', target=None):
    check = IpBlacklistCheck('example.test', zones=['bl.example'], dns_servers=[server])
    monkeypatch.setattr(check, '_resolve_ips', AsyncMock(return_value=([ip], [])))
    calls = []

    async def resolve(name, record, **kwargs):
        calls.append((name, record))
        if record == 'TXT' or name.startswith('1.0.0.127.'):
            raise dns.resolver.NXDOMAIN
        if name.startswith('2.0.0.127.'):
            return [SimpleNamespace(address='127.0.0.2')]
        if isinstance(target, Exception):
            raise target
        if target:
            return [SimpleNamespace(address=target)]
        raise dns.resolver.NXDOMAIN

    monkeypatch.setattr(check.resolver, 'resolve', resolve)
    return check, calls


def test_dnsbl_daily_cache_persists_across_instances_and_keys_by_ip_and_resolver(monkeypatch):
    first, calls = make_check(monkeypatch)
    result = asyncio.run(first.run())
    assert result.status is Status.OK
    assert not result.cached
    second, again = make_check(monkeypatch)
    cached = asyncio.run(second.run())
    assert cached.cached
    assert not again
    assert cached.metrics['observed_at'] == result.metrics['observed_at']
    assert cached.metrics['next_refresh_at'] == result.metrics['next_refresh_at']
    third, different_ip = make_check(monkeypatch, ip='192.0.2.2')
    assert not asyncio.run(third.run()).cached
    assert len(different_ip) == 1  # Shared healthy source controls, different IP answer.
    fourth, different_resolver = make_check(monkeypatch, server='8.8.8.8')
    assert not asyncio.run(fourth.run()).cached
    assert len(different_resolver) == len(calls)


def test_dnsbl_failed_queries_cool_down_and_cached_hits_survive_failed_health(monkeypatch):
    check, _ = make_check(monkeypatch, target=dns.exception.Timeout())
    failure = asyncio.run(check.run())
    assert failure.status is Status.UNKNOWN
    retry, calls = make_check(monkeypatch)
    assert asyncio.run(retry.run()).cached
    assert not calls


@pytest.mark.parametrize('ipv6', [False, True])
def test_ipv6_timeout_does_not_poison_available_ipv4(monkeypatch, ipv6):
    check = IpBlacklistCheck('example.test', zones=['bl.example'], check_ipv6=ipv6)
    calls = []

    async def resolve(name, record, **kwargs):
        calls.append(record)
        if record == 'AAAA':
            raise dns.exception.Timeout()
        return [SimpleNamespace(address='192.0.2.1')]

    monkeypatch.setattr(check.resolver, 'resolve', resolve)
    assert asyncio.run(check._resolve_ips()) == (['192.0.2.1'], [])
    assert ('AAAA' in calls) is ipv6


def test_dnsbl_cycle_context_resolves_ipv4_only(monkeypatch):
    context = SimpleNamespace(resolve=AsyncMock(return_value=[
        (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.0.2.1', 0)),
    ]))
    check = IpBlacklistCheck('example.test', zones=['bl.example'], cycle_context=context)
    assert asyncio.run(check._resolve_ips()) == (['192.0.2.1'], [])
    context.resolve.assert_awaited_once_with('example.test', family=socket.AF_INET)


def test_known_hit_is_retained_if_provider_refresh_fails(monkeypatch):
    check, _ = make_check(monkeypatch, target='127.0.0.2')
    assert asyncio.run(check.run()).status is Status.CRIT
    with storage._write_connection() as conn:
        conn.execute('UPDATE probe_cache SET expires_at=0')
    check, _ = make_check(monkeypatch, target=dns.exception.Timeout())
    result = asyncio.run(check.run())
    assert result.status is Status.CRIT
    assert result.metrics['partial_coverage']
    assert result.metrics['query_errors']


def test_stale_hit_with_failed_source_uses_future_retry_deadline(monkeypatch):
    from datetime import datetime, timezone

    check, _ = make_check(monkeypatch, target='127.0.0.2')
    asyncio.run(check.run())
    from sitewatcher import probe_cache
    observed = probe_cache.read('dnsbl-answer', check._cache_key(
        'bl.example', '192.0.2.1')).fetched_at.isoformat()
    with storage._write_connection() as conn:
        conn.execute('UPDATE probe_cache SET expires_at=0')
    check, _ = make_check(monkeypatch)
    monkeypatch.setattr(check, '_zone_health', AsyncMock(return_value='Timeout'))
    failed = asyncio.run(check.run())
    assert failed.status is Status.CRIT
    assert failed.metrics['observed_at'] == observed
    assert datetime.fromisoformat(failed.metrics['next_refresh_at']) > datetime.now(timezone.utc)
    check, calls = make_check(monkeypatch)
    cached = asyncio.run(check.run())
    assert cached.status is Status.CRIT
    assert cached.cached
    assert not calls


def test_successful_control_refresh_keeps_daily_answer_deadline_and_evidence_age(monkeypatch):
    from datetime import datetime, timedelta, timezone

    check, _ = make_check(monkeypatch)
    first = asyncio.run(check.run())
    assert datetime.fromisoformat(first.metrics['next_refresh_at']) > (
        datetime.now(timezone.utc) + timedelta(hours=23))
    with storage._write_connection() as conn:
        conn.execute("UPDATE probe_cache SET expires_at=0 WHERE namespace='dnsbl-health'")
    check, calls = make_check(monkeypatch)
    refreshed_controls = asyncio.run(check.run())
    assert len(calls) == 2
    assert refreshed_controls.status is Status.OK
    assert refreshed_controls.metrics['observed_at'] == first.metrics['observed_at']
    assert refreshed_controls.metrics['next_refresh_at'] == first.metrics['next_refresh_at']


def test_dnsbl_custom_resolver_does_not_reuse_system_cycle_dns(monkeypatch):
    context = SimpleNamespace(resolve=AsyncMock(return_value=[
        (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.0.2.99', 0)),
    ]))
    check = IpBlacklistCheck('example.test', zones=['bl.example'], dns_servers=['1.1.1.1'],
                             cycle_context=context)
    resolve = AsyncMock(return_value=[SimpleNamespace(address='192.0.2.1')])
    monkeypatch.setattr(check.resolver, 'resolve', resolve)
    assert asyncio.run(check._resolve_ips()) == (['192.0.2.1'], [])
    context.resolve.assert_not_awaited()
    resolve.assert_awaited_once_with('example.test', 'A', lifetime=check.timeout_s)
