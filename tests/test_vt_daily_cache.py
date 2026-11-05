import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from sitewatcher import storage
from sitewatcher.checks.base import Status
from sitewatcher.checks.malware_scan import MalwareScanCheck, _VTConfig


@pytest.mark.parametrize('status_code', [200, 429])
def test_report_is_cached_across_instances_and_event_loops(status_code):
    requests = []

    def respond(request):
        requests.append(request)
        return httpx.Response(status_code, json={'data': {'attributes': {
            'last_analysis_stats': {'malicious': 0, 'suspicious': 0, 'harmless': 5}}}})

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            return await MalwareScanCheck('example.test', owner_id=7, client=client,
                                         vt_cfg=_VTConfig(api_key='test')).run()

    first, second = asyncio.run(run()), asyncio.run(run())
    assert first.status is (Status.OK if status_code == 200 else Status.UNKNOWN)
    assert second.status is first.status
    assert second.cached
    assert second.message == first.message
    assert len(requests) == 1


def test_cache_claim_is_atomic_owner_isolated_and_expires_at_24_hours():
    stamp = datetime.now(timezone.utc)
    url = 'https://example.test/'
    storage._ensure_initialized()
    with ThreadPoolExecutor(max_workers=4) as pool:
        claims = list(pool.map(lambda _: storage.claim_virustotal_report(7, url, now=stamp),
                               range(4)))
    assert sum(claim is not None for claim, _ in claims) == 1
    storage.save_virustotal_report(7, url, stamp.timestamp(),
                                  {'status': 'OK', 'message': 'clean', 'metrics': {}})
    claim, result = storage.claim_virustotal_report(7, url, now=stamp + timedelta(seconds=86399))
    assert claim is None and result['status'] == 'OK'
    assert storage.claim_virustotal_report(8, url, now=stamp)[0] is not None
    assert storage.claim_virustotal_report(7, url, now=stamp + timedelta(days=1))[0] is not None


def test_simultaneous_checks_send_one_request():
    requests = []

    async def respond(request):
        requests.append(request)
        await asyncio.sleep(0.05)
        return httpx.Response(200, json={'data': {'attributes': {'last_analysis_stats': {
            'malicious': 0, 'suspicious': 0, 'harmless': 5}}}})

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            checks = [MalwareScanCheck('example.test', owner_id=7, client=client,
                                      vt_cfg=_VTConfig(api_key='test')) for _ in range(4)]
            return await asyncio.gather(*(check.run() for check in checks))
    results = asyncio.run(run())
    assert len(requests) == 1
    assert sum(result.cached for result in results) == 3


def test_recent_existing_history_is_reused_without_spending_request():
    storage.save_history(7, 'example.test', 'malware', Status.UNKNOWN, 'quota',
                         {'url': 'https://example.test/', 'vt_error': {'kind': 'quota'}})

    async def run():
        def unexpected(request):
            pytest.fail('existing recent provider result must seed the daily cache')
        async with httpx.AsyncClient(transport=httpx.MockTransport(unexpected)) as client:
            return await MalwareScanCheck('example.test', owner_id=7, client=client,
                                         vt_cfg=_VTConfig(api_key='test')).run()
    result = asyncio.run(run())
    assert result.cached and result.message == 'quota'


def test_local_rate_limit_denial_allows_retry_without_consuming_daily_request():
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    async def run():
        requests = []
        def respond(request):
            requests.append(request)
            return httpx.Response(429)
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            limiter = SimpleNamespace(try_acquire=AsyncMock(side_effect=[(False, 10), (True, 0)]))
            check = MalwareScanCheck('example.test', client=client,
                                     vt_cfg=_VTConfig(api_key='test'), vt_limiter=limiter)
            await check.run()
            assert not requests
            await check.run()
            assert len(requests) == 1
    asyncio.run(run())


def test_manual_dispatch_bypassing_general_cache_still_uses_daily_provider_cache(monkeypatch):
    from sitewatcher.config import AppConfig
    from sitewatcher.dispatcher import Dispatcher

    requests = []
    def respond(request):
        requests.append(request)
        return httpx.Response(429)

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            dispatcher = Dispatcher(AppConfig())
            dispatcher._client = client
            monkeypatch.setattr(dispatcher, '_build_checks', lambda settings, **kwargs: [
                MalwareScanCheck(settings.name, owner_id=7, client=client,
                                 vt_cfg=_VTConfig(api_key='test'))])
            await dispatcher.run_for(7, 'example.test', only_checks=['malware'], use_cache=False)
            result = await dispatcher.run_for(7, 'example.test', only_checks=['malware'],
                                              use_cache=False)
            assert result[0].cached
    asyncio.run(run())
    assert len(requests) == 1


@pytest.mark.parametrize('later_local_refusal', [False, True])
def test_legacy_pending_reports_and_provider_results_hidden_by_local_limits_are_reused(
        later_local_refusal):
    metrics = {'url': 'https://example.test/', 'providers': {}, 'vt_analysis_id': 'queued'}
    storage.save_history(7, 'example.test', 'malware', Status.UNKNOWN,
                         'VirusTotal analysis is pending', metrics)
    if later_local_refusal:
        storage.save_history(7, 'example.test', 'malware', Status.UNKNOWN, 'VT rate limited',
                             {'url': 'https://example.test/', 'providers': {},
                              'vt_rate_limit': {'acquired': False}})
    claim, result = storage.claim_virustotal_report(7, 'https://example.test/')
    assert claim is None
    assert result['metrics'] == metrics


@pytest.mark.parametrize('prior_status', [Status.WARN, Status.CRIT])
@pytest.mark.parametrize('response_code', [200, 429])
def test_failed_daily_refresh_preserves_known_threat_and_observation(prior_status, response_code):
    url = 'https://example.test/'
    old = datetime.now(timezone.utc) - timedelta(days=2)
    claim, _ = storage.claim_virustotal_report(7, url, now=old)
    providers = {'virustotal': {'stats': {'malicious': 2}, 'analysis_date': 123}}
    storage.save_virustotal_report(7, url, claim, {
        'status': prior_status.value, 'message': 'known threat',
        'metrics': {'url': url, 'providers': providers, 'observed_at': old.isoformat()},
    })
    requests = []

    def respond(request):
        requests.append(request)
        return httpx.Response(response_code, json={'data': {'attributes': {}}})

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            return await MalwareScanCheck('example.test', owner_id=7, client=client,
                                         vt_cfg=_VTConfig(api_key='test')).run()

    first = asyncio.run(run())
    second = asyncio.run(run())
    assert first.status is second.status is prior_status
    assert first.metrics['providers'] == second.metrics['providers'] == providers
    assert first.metrics['observed_at'] == second.metrics['observed_at'] == old.isoformat()
    assert first.metrics['attempted_at'] == second.metrics['attempted_at']
    assert first.metrics['attempted_at'] != old.isoformat()
    assert first.metrics['next_refresh_at'] == second.metrics['next_refresh_at']
    assert first.metrics['cache_state'] == second.metrics['cache_state'] == 'stale'
    assert second.cached
    assert len(requests) == 1


def test_unspent_refresh_retains_standalone_threat_without_consuming_daily_budget():
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    old = datetime.now(timezone.utc) - timedelta(days=2)
    url = 'https://example.test/'
    claim, _ = storage.claim_virustotal_report(7, url, now=old)
    storage.save_virustotal_report(7, url, claim, {
        'status': 'CRIT', 'message': 'known threat',
        'metrics': {'url': url, 'providers': {'virustotal': {'stats': {'malicious': 1}}},
                    'observed_at': old.isoformat()},
    })
    requests = []

    def respond(request):
        requests.append(request)
        return httpx.Response(429)

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            limiter = SimpleNamespace(try_acquire=AsyncMock(side_effect=[(False, 10), (True, 0)]))
            check = MalwareScanCheck('example.test', owner_id=7, client=client,
                                     vt_cfg=_VTConfig(api_key='test'), vt_limiter=limiter)
            denied = await check.run()
            assert denied.status is Status.CRIT
            assert denied.metrics['observed_at'] == old.isoformat()
            assert not requests
            failed = await check.run()
            assert failed.status is Status.CRIT
            assert failed.metrics['observed_at'] == old.isoformat()
            assert len(requests) == 1
    asyncio.run(run())


@pytest.mark.parametrize('prior_status', [Status.OK, Status.WARN, Status.CRIT])
def test_inflight_and_cancelled_refresh_never_reuses_old_clean_verdict(prior_status):
    from types import SimpleNamespace

    old = datetime.now(timezone.utc) - timedelta(hours=25)
    url = 'https://example.test/'
    claim, _ = storage.claim_virustotal_report(7, url, now=old)
    providers = {'virustotal': {'stats': {'malicious': int(prior_status is Status.CRIT)}}}
    storage.save_virustotal_report(7, url, claim, {
        'status': prior_status.value, 'message': 'old observation',
        'metrics': {'url': url, 'providers': providers, 'observed_at': old.isoformat()},
    })
    requests = []

    def respond(request):
        requests.append(request)
        return httpx.Response(200)

    async def run():
        entered = asyncio.Event()
        release = asyncio.Event()

        async def blocked_quota(**kwargs):
            entered.set()
            await release.wait()
            return True, 0

        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            leader = asyncio.create_task(MalwareScanCheck('example.test', owner_id=7,
                client=client, vt_cfg=_VTConfig(api_key='test'),
                vt_limiter=SimpleNamespace(try_acquire=blocked_quota)).run())
            await entered.wait()
            pending = await MalwareScanCheck('example.test', owner_id=7, client=client,
                                             vt_cfg=_VTConfig(api_key='test')).run()
            leader.cancel()
            with pytest.raises(asyncio.CancelledError):
                await leader
            cancelled = await MalwareScanCheck('example.test', owner_id=7, client=client,
                                               vt_cfg=_VTConfig(api_key='test')).run()
            for result in (pending, cancelled):
                assert result.status is (Status.UNKNOWN if prior_status is Status.OK else prior_status)
                assert result.cached and result.metrics['cache_inflight']
                assert result.metrics['cache_state'] == 'stale'
                assert result.metrics['observed_at'] == old.isoformat()
                assert result.metrics['providers'] == providers
                assert result.metrics['attempted_at'] != old.isoformat()
            assert pending.metrics['next_refresh_at'] == cancelled.metrics['next_refresh_at']
            assert not requests
    asyncio.run(run())


def test_completed_refresh_removes_inflight_marker():
    url = 'https://example.test/'
    old = datetime.now(timezone.utc) - timedelta(hours=25)
    claim, _ = storage.claim_virustotal_report(7, url, now=old)
    storage.save_virustotal_report(7, url, claim,
        {'status': 'OK', 'message': 'old clean', 'metrics': {'url': url}})

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request:
            httpx.Response(200, json={'data': {'attributes': {'last_analysis_stats': {
                'malicious': 0, 'suspicious': 0, 'harmless': 1}}}}))) as client:
            first = await MalwareScanCheck('example.test', owner_id=7, client=client,
                                          vt_cfg=_VTConfig(api_key='test')).run()
            cached = await MalwareScanCheck('example.test', owner_id=7, client=client,
                                           vt_cfg=_VTConfig(api_key='test')).run()
            assert first.status is cached.status is Status.OK
            assert cached.cached
            assert not cached.metrics.get('cache_inflight')
            assert cached.metrics['observed_at'] == first.metrics['observed_at']
    asyncio.run(run())
