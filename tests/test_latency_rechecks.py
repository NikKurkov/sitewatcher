import asyncio
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest

from sitewatcher import latency_rechecks, scheduler, storage
from sitewatcher.checks.base import CheckOutcome, Status
from sitewatcher.config import AppConfig
from sitewatcher.webapp.analytics import domain_report


OWNER = 17
DOMAIN = 'example.test'
TARGET = f'https://{DOMAIN}/'


def http(latency, *, target=TARGET, status=Status.OK, code=200, available=True):
    metrics = {'http_target': target, 'final_code': code,
               'availability': 'available' if available else 'unavailable'}
    if latency is not None:
        metrics['response_latency_ms'] = latency
    return CheckOutcome('http_basic', status, f'HTTP {code}', metrics)


def seed(values):
    for value in values:
        result = http(value)
        storage.save_history(OWNER, DOMAIN, result.check, result.status, result.message,
                             result.metrics, source='scheduled')


def report():
    return domain_report(OWNER, DOMAIN, days=1, timezone='UTC')['totals']


def latest_http():
    return storage.last_history_for_check(OWNER, DOMAIN, 'http_basic')


@pytest.mark.parametrize(('initial', 'repeats', 'median'), [
    (8607, [900, 1100, 5000], 1100),
    (8607, [4200, 4800, 5100], 4800),
])
def test_scheduled_spike_updates_one_chart_point_without_blocking_tick(
    monkeypatch, initial, repeats, median,
):
    seed([1000] * 7)
    cfg = AppConfig()
    cfg.defaults.checks.ping = False
    cfg.defaults.checks.tls_cert = False
    cfg.defaults.checks.whois = False
    cfg.defaults.checks.ip_change = False
    monkeypatch.setattr(scheduler, 'due_checks', lambda *_args, **_kwargs: ['http_basic'])
    outcomes = iter([http(initial, status=Status.CRIT), *(http(n) for n in repeats)])
    requests = []
    release = asyncio.Event()
    delays = []

    class Dispatcher:
        def __init__(self, cfg):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            pass

        async def run_for(self, owner, domain, **kwargs):
            assert (owner, domain) == (OWNER, DOMAIN)
            assert kwargs['only_checks'] == ['http_basic']
            assert kwargs['use_cache'] is False
            requests.append(domain)
            return [next(outcomes)]

    clock = 0

    async def delay(seconds):
        nonlocal clock
        delays.append(seconds)
        await release.wait()
        clock += seconds

    monkeypatch.setattr(scheduler, 'Dispatcher', Dispatcher)
    monkeypatch.setattr(latency_rechecks, 'Dispatcher', Dispatcher)
    monkeypatch.setattr(latency_rechecks, 'sleep', delay)
    monkeypatch.setattr(latency_rechecks, 'monotonic', lambda: clock)
    on_results = AsyncMock()

    async def run():
        async with latency_rechecks.LatencyRechecks(cfg) as rechecks:
            await scheduler.run_tick(cfg, warmup=False, on_results=on_results, rechecks=rechecks)
            assert len(requests) == 1
            assert on_results.await_count == 1
            original = latest_http()
            assert original['status'] == 'CRIT'
            assert report()['sample_count'] == 8
            assert report()['latency_sample_count'] == 7
            release.set()
            await asyncio.gather(*rechecks.tasks.values())
            final = latest_http()
            metrics = json.loads(final['metrics_json'])
            assert final['id'] == original['id']
            assert final['created_at'] == original['created_at']
            assert metrics['response_latency_ms'] == initial
            assert metrics['chart_response_latency_ms'] == median
            assert [sample['latency_ms'] for sample in metrics['latency_recheck']['samples']] == repeats
            assert report()['sample_count'] == 8
            assert report()['latency_ms'] == pytest.approx((7000 + median) / 8, abs=1)
            assert on_results.await_count == 1

    asyncio.run(run())
    assert delays == [20, 20, 20]


@pytest.mark.parametrize('value', [1800, 2900])
def test_requires_a_threefold_increase_and_at_least_one_second(value):
    seed([1000] * 7)
    assert latency_rechecks.LatencyRechecks(AppConfig()).prepare(OWNER, DOMAIN, [http(value)]) is None


def test_tiny_baseline_still_needs_an_absolute_increase_and_is_owner_target_scoped():
    seed([100] * 7)
    service = latency_rechecks.LatencyRechecks(AppConfig())
    assert service.prepare(OWNER, DOMAIN, [http(800)]) is None
    assert service.prepare(OWNER + 1, DOMAIN, [http(2000)]) is None
    assert service.prepare(OWNER, DOMAIN, [http(2000, target=TARGET + 'new')]) is None
    assert service.prepare(OWNER, DOMAIN, [http(1100)]) is not None


def test_baseline_looks_past_recent_errors_and_respects_slow_probe_timeout():
    seed([1000] * 7)
    for _ in range(41):
        storage.save_history(OWNER, DOMAIN, 'http_basic', 'CRIT', 'HTTP 503',
                             {'availability': 'unavailable', 'final_code': 503}, source='scheduled')
    cfg = AppConfig()
    cfg.defaults.http_timeout_s = 40
    before = datetime.now(timezone.utc)
    detail, _ = latency_rechecks.LatencyRechecks(cfg).prepare(OWNER, DOMAIN, [http(4000)])
    assert datetime.fromisoformat(detail['expires_at']) > before + timedelta(seconds=180)


def save_spike(service):
    seed([1000] * 7)
    spike = http(8000)
    prepared = service.prepare(OWNER, DOMAIN, [spike])
    storage.save_histories(OWNER, DOMAIN, [spike], source='scheduled')
    return prepared


@pytest.mark.parametrize(('outcome', 'classification'), [
    (http(None, status=Status.CRIT, code=503, available=False), 'failed'),
    (CheckOutcome('http_basic', Status.UNKNOWN, 'timeout', {}), 'unknown'),
    (CheckOutcome('http_basic', Status.UNKNOWN, 'unexpected end of response',
                  {'availability': 'unknown', 'status_code': 200}), 'unknown'),
])
def test_failed_follow_up_is_reported_immediately_and_stops_the_series(
    monkeypatch, outcome, classification,
):
    probes = AsyncMock(side_effect=[[http(950)], [outcome]])

    class Dispatcher:
        def __init__(self, *_):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            pass

        run_for = probes

    monkeypatch.setattr(latency_rechecks, 'Dispatcher', Dispatcher)
    monkeypatch.setattr(latency_rechecks, 'sleep', AsyncMock())
    on_results = AsyncMock()

    async def run():
        async with latency_rechecks.LatencyRechecks(AppConfig()) as service:
            prepared = save_spike(service)
            row_id = latest_http()['id']
            service.start(OWNER, DOMAIN, prepared, on_results)
            await asyncio.gather(*service.tasks.values())
            row = latest_http()
            details = json.loads(row['metrics_json'])['latency_recheck']
            assert row['id'] == row_id
            assert row['status'] == outcome.status.value
            assert details['initial_ms'] == 8000
            assert details['state'] == 'failed'
            assert [sample['http_code'] for sample in details['samples']] == [
                200, outcome.metrics.get('final_code', outcome.metrics.get('status_code')),
            ]
            assert report()['sample_count'] == 8
            assert report()[classification] == 1
            assert report()['latency_sample_count'] == 7
            on_results.assert_awaited_once_with(OWNER, DOMAIN, [outcome], warmup=False)

    asyncio.run(run())
    assert probes.await_count == 2


@pytest.mark.parametrize('superseded', [False, True])
def test_shutdown_does_not_overwrite_a_newer_observation(monkeypatch, superseded):
    sleeping = asyncio.Event()

    async def pause(_):
        sleeping.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(latency_rechecks, 'sleep', pause)

    async def run():
        async with latency_rechecks.LatencyRechecks(AppConfig()) as service:
            prepared = save_spike(service)
            service.start(OWNER, DOMAIN, prepared, AsyncMock())
            await sleeping.wait()
            assert report()['latency_sample_count'] == 7
            if superseded:
                storage.save_histories(OWNER, DOMAIN, [http(1500)], source='manual')
        metrics = json.loads(latest_http()['metrics_json'])
        if superseded:
            assert metrics['response_latency_ms'] == 1500
            assert 'latency_recheck' not in metrics
        else:
            assert metrics['latency_recheck']['state'] == 'interrupted'
        assert report()['latency_sample_count'] == (9 if superseded else 8)

    asyncio.run(run())


def test_an_expired_pending_result_falls_back_to_the_original_measurement(monkeypatch):
    from sitewatcher.webapp import analytics

    service = latency_rechecks.LatencyRechecks(AppConfig())
    save_spike(service)
    assert report()['latency_sample_count'] == 7
    later = datetime.now(timezone.utc) + timedelta(minutes=3)
    monkeypatch.setattr(analytics, '_now', lambda: later)
    assert report()['latency_sample_count'] == 8
    assert report()['latency_ms'] == pytest.approx(1875)


def test_follow_up_writes_only_for_the_settings_used_to_start_it():
    service = latency_rechecks.LatencyRechecks(AppConfig())
    detail, revision = save_spike(service)
    storage.set_domain_override(OWNER, DOMAIN, {'http_url': f'{TARGET}other'})
    outcome = http(None, status=Status.CRIT, code=503, available=False)
    assert not storage.update_latency_recheck(
        OWNER, DOMAIN, {**detail, 'state': 'failed'}, expected_revision=revision, failure=outcome,
    )
    assert latest_http()['status'] == 'OK'
    assert report()['successful'] == 8


def test_scheduled_results_survive_latency_preparation_failure(monkeypatch):
    from sqlite3 import OperationalError

    storage.add_domain(OWNER, DOMAIN)
    result = http(8000)

    class Dispatcher:
        def __init__(self, _):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            pass

        async def run_for(self, *_args, **_kwargs):
            return [result]

    cfg = AppConfig()
    service = latency_rechecks.LatencyRechecks(cfg)

    def prepare(*_):
        raise OperationalError('simulated baseline read failure')

    monkeypatch.setattr(scheduler, 'Dispatcher', Dispatcher)
    monkeypatch.setattr(service, 'prepare', prepare)
    on_results = AsyncMock()
    asyncio.run(scheduler.run_tick(cfg, warmup=False, on_results=on_results, rechecks=service))
    assert latest_http()['source'] == 'scheduled'
    assert report()['latency_ms'] == pytest.approx(8000)
    on_results.assert_awaited_once_with(OWNER, DOMAIN, [result], warmup=False)
