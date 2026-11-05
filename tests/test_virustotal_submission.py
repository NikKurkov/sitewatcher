"""Missing URL reports are queued once, never confused with a clean verdict."""
import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

from sitewatcher import storage
from sitewatcher.checks.base import Status
from sitewatcher.checks.malware_scan import MalwareScanCheck, _VTConfig


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch):
    monkeypatch.delenv('VIRUSTOTAL_API_KEY', raising=False)
    monkeypatch.delenv('VIRUSTOTAL_PROXY', raising=False)


def test_missing_report_submits_once_across_new_checks_then_recovers():
    requests = []
    ready = False

    def handler(request):
        requests.append(request)
        assert request.headers['x-apikey'] == 'private-key'
        if request.method == 'POST':
            assert str(request.url) == 'https://www.virustotal.com/api/v3/urls'
            assert request.content == b'url=https%3A%2F%2Fexample.test%2F'
            return httpx.Response(200, json={'data': {'id': 'analysis-private-id'}})
        return httpx.Response(200, json={'data': {'attributes': {'last_analysis_stats': {
            'malicious': 0, 'suspicious': 0, 'harmless': 5, 'undetected': 2}}}}) if ready else httpx.Response(404)

    async def scenario():
        nonlocal ready
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            async def probe():
                return await MalwareScanCheck('Example.Test.', client=client,
                    vt_cfg=_VTConfig(api_key='private-key'), owner_id=41).run()
            first = await probe()
            assert first.status is Status.UNKNOWN
            assert first.message == 'VirusTotal analysis is pending'
            assert first.metrics['vt_analysis_id'] == 'analysis-private-id'
            assert (await probe()).message == first.message
            ready = True
            assert (await probe()).status is Status.OK
    asyncio.run(scenario())
    assert [r.method for r in requests] == ['GET', 'POST', 'GET', 'GET']


def test_submission_consumes_a_second_quota_slot_and_releases_unattempted_claim():
    methods = []
    def handler(request):
        methods.append(request.method)
        return httpx.Response(404) if request.method == 'GET' else httpx.Response(
            200, json={'data': {'id': 'queued'}})

    async def scenario():
        limiter = SimpleNamespace(try_acquire=AsyncMock(side_effect=[
            (True, 0), (False, 60), (True, 0), (True, 0)]))
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            check = MalwareScanCheck('example.test', client=client,
                vt_cfg=_VTConfig(api_key='key'), vt_limiter=limiter, owner_id=41)
            assert (await check.run()).message.startswith('VT rate limited')
            assert (await check.run()).message == 'VirusTotal analysis is pending'
        assert limiter.try_acquire.await_count == 4
    asyncio.run(scenario())
    assert methods == ['GET', 'GET', 'POST']


@pytest.mark.parametrize('failure', [401, 403, 429, 503])
def test_lookup_failures_never_submit(failure):
    def handler(request):
        assert request.method == 'GET'
        return httpx.Response(failure)
    async def scenario():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            result = await MalwareScanCheck('example.test', client=client,
                vt_cfg=_VTConfig(api_key='key'), owner_id=41).run()
            assert result.status is Status.UNKNOWN
            assert 'pending' not in result.message
    asyncio.run(scenario())


def test_submission_claim_is_atomic_durable_and_owner_scoped(monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from datetime import datetime, timedelta, timezone
    now = datetime(2026, 11, 5, tzinfo=timezone.utc)
    storage._ensure_initialized()
    def claim():
        return storage.claim_virustotal_submission(41, 'https://example.test/', now=now)[0]
    with ThreadPoolExecutor(max_workers=4) as pool:
        claims = list(pool.map(lambda _: claim(), range(4)))
    assert sum(value is not None for value in claims) == 1
    storage._INITIALIZED_PATHS.discard(storage.DEFAULT_DB)
    assert claim() is None
    assert storage.claim_virustotal_submission(42, 'https://example.test/', now=now)[0] is not None
    assert storage.claim_virustotal_submission(41, 'https://example.test/',
        now=now + timedelta(hours=24))[0] is not None


@pytest.mark.parametrize('failure', ['rejected', 'timeout', 'invalid'])
def test_rejected_submissions_retry_but_ambiguous_attempts_keep_the_claim(failure, caplog):
    posts = 0
    def handler(request):
        nonlocal posts
        if request.method == 'GET':
            return httpx.Response(404)
        posts += 1
        if posts == 1:
            if failure == 'rejected':
                return httpx.Response(429, text='private-provider-payload')
            if failure == 'timeout':
                raise httpx.ReadTimeout('private-provider-payload', request=request)
            return httpx.Response(200, json={'private-provider-payload': True})
        return httpx.Response(200, json={'data': {'id': 'queued'}})
    async def scenario():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            probe = MalwareScanCheck('example.test', client=client,
                vt_cfg=_VTConfig(api_key='private-key'), owner_id=41)
            first, second = await probe.run(), await probe.run()
            assert first.status is second.status is Status.UNKNOWN
            assert 'private-provider-payload' not in str(first) + str(second) + caplog.text
            if failure == 'rejected':
                assert second.message == 'VirusTotal analysis is pending'
            else:
                assert 'could not be confirmed' in second.message
    asyncio.run(scenario())
    assert posts == (2 if failure == 'rejected' else 1)


def test_concurrent_probes_submit_only_once():
    methods = []
    async def handler(request):
        methods.append(request.method)
        if request.method == 'POST':
            await asyncio.sleep(.01)
            return httpx.Response(200, json={'data': {'id': 'queued'}})
        return httpx.Response(404)
    async def scenario():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            await asyncio.gather(*[MalwareScanCheck('example.test', client=client,
                vt_cfg=_VTConfig(api_key='key'), owner_id=41).run() for _ in range(3)])
    asyncio.run(scenario())
    assert methods.count('POST') == 1


def test_new_url_object_without_completed_statistics_remains_pending():
    submitted = False
    def handler(request):
        nonlocal submitted
        if request.method == 'POST':
            submitted = True
            return httpx.Response(200, json={'data': {'id': 'queued'}})
        if not submitted:
            return httpx.Response(404)
        return httpx.Response(200, json={'data': {'attributes': {'last_analysis_stats': {
            'malicious': 0, 'suspicious': 0, 'harmless': 0, 'undetected': 0}}}})
    async def scenario():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            probe = MalwareScanCheck('example.test', client=client,
                vt_cfg=_VTConfig(api_key='key'), owner_id=41)
            assert (await probe.run()).message == 'VirusTotal analysis is pending'
            assert (await probe.run()).message == 'VirusTotal analysis is pending'
    asyncio.run(scenario())


def test_pending_unknown_cache_is_bypassed_unless_explicitly_allowed():
    from sitewatcher.config import AppConfig
    from sitewatcher.dispatcher import Dispatcher
    storage.save_history(41, 'example.test', 'malware', 'UNKNOWN',
                         'VirusTotal analysis is pending', {})
    cfg = AppConfig()
    dispatcher = Dispatcher(cfg)
    assert dispatcher._maybe_cached_result(41, 'example.test', 'malware', lambda _: 1440) is None
    cfg.schedules.malware.cache_unknown = True
    assert dispatcher._maybe_cached_result(41, 'example.test', 'malware', lambda _: 1440) is not None
