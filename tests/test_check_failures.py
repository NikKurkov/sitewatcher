import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import dns.exception
import dns.resolver
import httpx
import pytest

from sitewatcher.checks.base import Status
from sitewatcher.checks.deface import DefaceCheck
from sitewatcher.checks.http_basic import HttpBasicCheck
from sitewatcher.checks.ip_blacklist import IpBlacklistCheck
from sitewatcher.checks.ports import PortsCheck
from sitewatcher.config import PortSpec


@pytest.fixture(autouse=True)
def no_retry_delays(monkeypatch):
    monkeypatch.setattr(asyncio, 'sleep', AsyncMock())


@pytest.mark.parametrize(('final_code', 'status'), [(200, Status.WARN), (503, Status.CRIT)])
def test_http_redirect_classifies_final_failure(final_code, status):
    async def scenario():
        def handler(request):
            if request.url.path == '/':
                return httpx.Response(302, headers={'Location': '/landing'})
            return httpx.Response(final_code)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            result = await HttpBasicCheck('example.test', client).run()
            assert result.status is status
            assert result.metrics['final_code'] == final_code
    asyncio.run(scenario())


def test_http_redirect_connection_failure_is_critical():
    async def scenario():
        def handler(request):
            if request.url.path == '/':
                return httpx.Response(302, headers={'Location': '/landing'})
            raise httpx.ConnectError('unreachable', request=request)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            result = await HttpBasicCheck('example.test', client).run()
            assert result.status is Status.CRIT
            assert 'ConnectError' in result.message
    asyncio.run(scenario())


@pytest.mark.parametrize(('code', 'body', 'status'), [
    (503, 'maintenance', Status.UNKNOWN),
    (403, 'blocked', Status.UNKNOWN),
    (503, 'hacked by somebody', Status.CRIT),
    (200, 'normal page', Status.OK),
])
def test_deface_requires_successful_page_for_clean_result(code, body, status):
    async def scenario():
        async with httpx.AsyncClient(transport=httpx.MockTransport(
            lambda request: httpx.Response(code, text=body),
        )) as client:
            result = await DefaceCheck('example.test', client=client).run()
            assert result.status is status
            assert result.metrics['status_code'] == code
    asyncio.run(scenario())


def dnsbl(monkeypatch, *, zones=None, query_effect=None):
    check = IpBlacklistCheck('example.test', zones=zones or ['bl.example'])
    monkeypatch.setattr(check, '_resolve_ips', AsyncMock(return_value=(['192.0.2.1'], [])))
    async def resolve(name, record, **kwargs):
        if name.startswith('2.0.0.127.'):
            return [SimpleNamespace(address='127.0.0.2')]
        if name.startswith('1.0.0.127.'):
            raise dns.resolver.NXDOMAIN
        return await target_resolve(name, record, **kwargs)
    target_resolve = AsyncMock(side_effect=query_effect)
    monkeypatch.setattr(check.resolver, 'resolve', resolve)
    return check


@pytest.mark.parametrize('error', [dns.resolver.NXDOMAIN, dns.resolver.NoAnswer])
def test_dnsbl_confirmed_negative_is_clean(monkeypatch, error):
    result = asyncio.run(dnsbl(monkeypatch, query_effect=error).run())
    assert result.status is Status.OK
    assert result.metrics['errors_count'] == 0


@pytest.mark.parametrize(('errors', 'status'), [
    ([dns.exception.Timeout], Status.UNKNOWN),
    ([dns.resolver.NXDOMAIN, dns.exception.Timeout], Status.OK),
])
def test_dnsbl_failed_queries_preserve_successful_source_results(monkeypatch, errors, status):
    check = dnsbl(monkeypatch, zones=['bl%d.example' % n for n in range(len(errors))],
                  query_effect=errors)
    result = asyncio.run(check.run())
    assert result.status is status
    assert result.metrics['errors_count'] == 1


def test_dnsbl_hit_remains_critical_when_another_zone_fails(monkeypatch):
    check = dnsbl(monkeypatch, zones=['good.example', 'bad.example'])
    async def resolve(name, record, **kwargs):
        if name.startswith('2.0.0.127.'):
            return [SimpleNamespace(address='127.0.0.2')]
        if name.startswith('1.0.0.127.'):
            raise dns.resolver.NXDOMAIN
        if name.endswith('.bad.example.'):
            raise dns.exception.Timeout
        if record == 'A':
            return [SimpleNamespace(address='127.0.0.2')]
        raise dns.exception.Timeout
    monkeypatch.setattr(check.resolver, 'resolve', resolve)
    result = asyncio.run(check.run())
    assert result.status is Status.CRIT
    assert result.metrics['hits_count'] == 1
    assert result.metrics['errors_count'] == 1


def test_dnsbl_address_lookup_failure_is_unknown(monkeypatch):
    check = IpBlacklistCheck('example.test', zones=['bl.example'])
    monkeypatch.setattr(check.resolver, 'resolve', AsyncMock(side_effect=dns.exception.Timeout))
    assert asyncio.run(check.run()).status is Status.UNKNOWN


def test_dnsbl_ipv6_only_target_is_unknown(monkeypatch):
    check = dnsbl(monkeypatch)
    check.check_ipv6 = True
    monkeypatch.setattr(check, '_resolve_ips', AsyncMock(return_value=([], ['2001:db8::1'])))
    assert asyncio.run(check.run()).status is Status.UNKNOWN


def test_dnsbl_child_cancellation_propagates(monkeypatch):
    check = dnsbl(monkeypatch, query_effect=asyncio.CancelledError)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(check.run())


def port_defaults():
    return SimpleNamespace(connect_timeout_s=1, read_timeout_s=1, read_bytes=3)


def test_ports_empty_targets_is_unknown():
    result = asyncio.run(PortsCheck('example.test', targets=[], defaults=port_defaults()).run())
    assert result.status is Status.UNKNOWN


@pytest.mark.parametrize('as_mapping', [False, True])
def test_ports_honors_target_read_bytes(monkeypatch, as_mapping):
    target = {'port': 1234, 'read_bytes': 32, 'expect': 'READY'}
    if not as_mapping:
        target = PortSpec(**target)
    async def read(limit):
        return b'hello READY'[:limit]
    reader = SimpleNamespace(read=read)
    writer = SimpleNamespace(close=lambda: None, wait_closed=AsyncMock())
    monkeypatch.setattr(asyncio, 'open_connection', AsyncMock(return_value=(reader, writer)))
    check = PortsCheck('example.test', targets=[target], defaults=port_defaults())
    result = asyncio.run(check.run())
    assert result.status is Status.OK
    assert result.metrics['results'][0]['matched'] is True


def test_ports_child_cancellation_propagates(monkeypatch):
    check = PortsCheck('example.test', targets=[PortSpec(port=80)], defaults=port_defaults())
    monkeypatch.setattr(check, '_probe', AsyncMock(side_effect=asyncio.CancelledError))
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(check.run())


def test_http_slow_redirect_retains_critical_latency(monkeypatch):
    from sitewatcher import check_context
    times = iter([0.0, 4.0, 4.0])
    monkeypatch.setattr(check_context, 'time', SimpleNamespace(perf_counter=lambda: next(times)))
    async def scenario():
        def handler(request):
            if request.url.path == '/':
                return httpx.Response(302, headers={'Location': '/landing'})
            return httpx.Response(200)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            result = await HttpBasicCheck('example.test', client).run()
            assert result.status is Status.CRIT
            assert result.metrics['latency_ms_initial'] == 4000
    asyncio.run(scenario())
