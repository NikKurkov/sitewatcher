import asyncio
import socket
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

from sitewatcher.checks.base import Status
from sitewatcher.checks.ip_change import IpChangeCheck
from sitewatcher.checks.malware_scan import MalwareScanCheck, _VTConfig


@pytest.mark.parametrize('failure', [
    TimeoutError(), socket.gaierror(socket.EAI_AGAIN, 'temporary failure'), OSError('resolver failed'),
])
def test_dns_lookup_failure_preserves_baseline_and_recovery(tmp_path, monkeypatch, failure):
    check = IpChangeCheck('example.test', cfg=SimpleNamespace(db_path=str(tmp_path / 'dns.db')))
    check._maybe_upsert(['192.0.2.1'], [], datetime.now(timezone.utc), None, True)
    before = check._db_get()
    address = (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.0.2.1', 80))
    async def scenario():
        loop = asyncio.get_running_loop()
        monkeypatch.setattr(loop, 'getaddrinfo', AsyncMock(side_effect=[failure, [address]]))
        failed = await check.run()
        assert failed.status is Status.UNKNOWN
        after = check._db_get()
        assert after == before
        recovered = await check.run()
        assert recovered.status is Status.OK
        assert 'ip changed' not in recovered.message
    asyncio.run(scenario())


def test_dns_failure_without_baseline_does_not_store_empty_result(tmp_path, monkeypatch):
    check = IpChangeCheck('example.test', cfg=SimpleNamespace(db_path=str(tmp_path / 'dns.db')))
    async def scenario():
        monkeypatch.setattr(asyncio.get_running_loop(), 'getaddrinfo', AsyncMock(
            side_effect=TimeoutError,
        ))
        assert (await check.run()).status is Status.UNKNOWN
        assert check._db_get() is None
    asyncio.run(scenario())


@pytest.mark.parametrize('answer', [[], socket.gaierror(socket.EAI_NONAME, 'not found')])
def test_dns_confirmed_no_addresses_is_critical(tmp_path, monkeypatch, answer):
    check = IpChangeCheck('example.test', cfg=SimpleNamespace(db_path=str(tmp_path / 'dns.db')))
    async def scenario():
        query = AsyncMock(return_value=answer)
        if isinstance(answer, Exception):
            query.side_effect = answer
        monkeypatch.setattr(asyncio.get_running_loop(), 'getaddrinfo', query)
        assert (await check.run()).status is Status.CRIT
    asyncio.run(scenario())


def test_dns_cancellation_preserves_baseline(tmp_path, monkeypatch):
    check = IpChangeCheck('example.test', cfg=SimpleNamespace(db_path=str(tmp_path / 'dns.db')))
    check._maybe_upsert(['192.0.2.1'], [], datetime.now(timezone.utc), None, True)
    before = check._db_get()
    async def scenario():
        monkeypatch.setattr(asyncio.get_running_loop(), 'getaddrinfo', AsyncMock(
            side_effect=asyncio.CancelledError,
        ))
        with pytest.raises(asyncio.CancelledError):
            await check.run()
    asyncio.run(scenario())
    assert check._db_get() == before


@pytest.mark.parametrize(('stats', 'expected'), [
    ({}, Status.UNKNOWN),
    (None, Status.UNKNOWN),
    ([], Status.UNKNOWN),
    ({'timeout': 20}, Status.UNKNOWN),
    ({'harmless': 0, 'undetected': 0}, Status.UNKNOWN),
    ({'harmless': 1}, Status.UNKNOWN),
    ({'undetected': 1}, Status.UNKNOWN),
    ({'malicious': 0, 'suspicious': 0, 'harmless': 1}, Status.OK),
    ({'malicious': 0, 'suspicious': 0, 'undetected': 1}, Status.OK),
    ({'malicious': 0, 'harmless': 1}, Status.UNKNOWN),
    ({'suspicious': 0, 'undetected': 1}, Status.UNKNOWN),
    ({'malicious': 1}, Status.CRIT),
    ({'suspicious': 1}, Status.WARN),
    ({'harmless': 1, 'malicious': -1}, Status.UNKNOWN),
    ({'harmless': 1, 'suspicious': 'invalid'}, Status.UNKNOWN),
    ({'harmless': True}, Status.UNKNOWN),
    ({'harmless': 1.5}, Status.UNKNOWN),
    ({'harmless': '12'}, Status.UNKNOWN),
    ({'malicious': 1, 'harmless': 'invalid'}, Status.CRIT),
    ({'suspicious': 1, 'undetected': -1}, Status.WARN),
])
def test_virustotal_requires_valid_completed_observations(stats, expected):
    async def scenario():
        requests = []
        def handler(request):
            requests.append(request)
            return httpx.Response(200, json={'data': {'attributes': {'last_analysis_stats': stats}}})
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            check = MalwareScanCheck('example.test', client=client, vt_cfg=_VTConfig(api_key='test'))
            result = await check.run()
        assert result.status is expected
        assert len(requests) == 1
        assert requests[0].method == 'GET'
        assert requests[0].url.host == 'www.virustotal.com'
    asyncio.run(scenario())


@pytest.mark.parametrize('payload', [{}, {'data': {}}, {'data': {'attributes': {}}}])
def test_virustotal_missing_statistics_are_unknown(payload):
    async def scenario():
        async with httpx.AsyncClient(transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json=payload),
        )) as client:
            result = await MalwareScanCheck('example.test', client=client,
                                           vt_cfg=_VTConfig(api_key='test')).run()
            assert result.status is Status.UNKNOWN
    asyncio.run(scenario())


@pytest.mark.parametrize('api_key', [None, 'test'])
def test_virustotal_unavailable_or_missing_report_stays_unknown(api_key):
    async def scenario():
        requests = []
        def handler(request):
            requests.append(request)
            return (httpx.Response(404) if request.method == 'GET' else
                    httpx.Response(200, json={'data': {'id': 'queued'}}))
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            result = await MalwareScanCheck('example.test', client=client,
                                           vt_cfg=_VTConfig(api_key=api_key)).run()
        assert result.status is Status.UNKNOWN
        assert result.message == (
            'VirusTotal analysis is pending' if api_key else
            'VirusTotal is not configured: API key is missing')
        assert [request.method for request in requests] == (['GET', 'POST'] if api_key else [])
    asyncio.run(scenario())


def test_virustotal_quota_denial_does_not_request_provider():
    async def scenario():
        def unexpected(request):
            pytest.fail('quota denial must not contact the provider')
        async with httpx.AsyncClient(transport=httpx.MockTransport(unexpected)) as client:
            limiter = SimpleNamespace(try_acquire=AsyncMock(return_value=(False, 10)))
            result = await MalwareScanCheck('example.test', client=client,
                                           vt_cfg=_VTConfig(api_key='test'),
                                           vt_limiter=limiter).run()
            assert result.status is Status.UNKNOWN
    asyncio.run(scenario())


def test_virustotal_cancellation_propagates():
    async def scenario():
        def canceled(request):
            raise asyncio.CancelledError
        async with httpx.AsyncClient(transport=httpx.MockTransport(canceled)) as client:
            check = MalwareScanCheck('example.test', client=client, vt_cfg=_VTConfig(api_key='test'))
            with pytest.raises(asyncio.CancelledError):
                await check.run()
    asyncio.run(scenario())
