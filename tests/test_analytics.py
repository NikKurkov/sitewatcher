import asyncio
import json
import sqlite3
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from sitewatcher import storage
from sitewatcher.checks.base import CheckOutcome, Status
from sitewatcher.checks.http_basic import HttpBasicCheck


@pytest.fixture
def database(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, 'DEFAULT_DB', tmp_path / 'history.db')
    storage.add_domain(1, 'example.com')
    return storage.DEFAULT_DB


def report(*, days=1, zone='UTC'):
    from sitewatcher.webapp.analytics import domain_report
    return domain_report(1, 'example.com', days=days, timezone=zone)


def observation(metrics, *, source='legacy', check='http_basic', status='CRIT', at=None):
    storage.save_histories(1, 'example.com', [
        CheckOutcome(check, Status(status), 'SECRET message', metrics),
    ], source=source)
    if at:
        with storage._connect() as conn:
            conn.execute('UPDATE history SET created_at=? WHERE id=(SELECT MAX(id) FROM history)',
                         (at,))


def test_empty_report_is_unknown_and_validates_period_zone_and_ownership(database):
    from sitewatcher.webapp.analytics import domain_report
    result = report()
    assert result['totals']['success_percent'] is None
    assert result['totals']['sample_count'] == 0
    assert result['buckets'] == []
    assert result['metric_label'] == 'Successful checks'
    for days in [0, 2, 31, True, 1.0]:
        with pytest.raises(ValueError):
            report(days=days)
    with pytest.raises(ValueError):
        report(zone='Mars/Olympus')
    with pytest.raises(ValueError):
        domain_report(2, 'example.com', days=1, timezone='UTC')


def test_classification_uses_http_evidence_never_check_status_or_messages(database):
    samples = [
        ({'code_initial': 200, 'latency_ms_total': 20}, 'CRIT'),
        ({'code_initial': 302, 'final_code': 200, 'latency_ms_total': 30}, 'WARN'),
        ({'final_code': 503, 'latency_ms_total': 10000}, 'CRIT'),
        ({'availability': 'unavailable', 'latency_ms_initial': 9000}, 'CRIT'),
        ({'code_initial': 200, 'latency_ms_total': 9000}, 'CRIT'),
        ({'code_initial': 302, 'final_code': 302, 'redirect_error': 'ConnectError'}, 'CRIT'),
        ({'status_code': 200}, 'UNKNOWN'),
        ({'status_code': 503}, 'CRIT'),
        ({'latency_ms_initial': 5000}, 'CRIT'),
        ({'final_code': '200', 'latency_ms_total': '12'}, 'OK'),
    ]
    for metrics, status in samples:
        observation(metrics, status=status)
    observation({}, check='tls_cert', status='CRIT')
    with storage._connect() as conn:
        conn.execute("INSERT INTO history(owner_id,domain,check_name,status,message,metrics_json) "
                     "VALUES(1,'example.com','http_basic','CRIT','request error','broken JSON')")
        conn.execute("INSERT INTO history(owner_id,domain,check_name,status,message,metrics_json) "
                     "VALUES(1,'example.com','http_basic','CRIT','request error','[]')")
    result = report()
    assert result['totals']['successful'] == 3
    assert result['totals']['failed'] == 4
    assert result['totals']['unknown'] == 5
    assert result['totals']['success_percent'] == pytest.approx(3 / 7 * 100)
    assert result['totals']['latency_sample_count'] == 3
    assert result['totals']['latency_ms'] == pytest.approx(9050 / 3)
    assert 'SECRET' not in json.dumps(result)
    assert 'metrics_json' not in json.dumps(result)


def test_sources_cached_skip_and_numeric_latency_allowlist(database):
    observation({'final_code': 200, 'latency_ms_total': True}, source='manual')
    observation({'final_code': 200, 'latency_ms_total': float('inf')}, source='scheduled')
    observation({'final_code': 200, 'latency_ms_total': -1})
    observation({'final_code': 200, 'other_latency': 10})
    storage.save_histories(1, 'example.com', [
        CheckOutcome('http_basic', Status.OK, 'cached', {'final_code': 200}, cached=True),
    ], source='scheduled')
    result = report()
    assert result['totals']['sources'] == {'legacy': 2, 'manual': 1, 'scheduled': 1}
    assert result['totals']['sample_count'] == 4
    assert result['totals']['latency_sample_count'] == 0
    assert result['totals']['latency_ms'] is None
    with pytest.raises(ValueError):
        storage.save_histories(1, 'example.com', [], source='invented')


def test_migration_adds_default_without_losing_old_rows_and_is_idempotent(tmp_path, monkeypatch):
    db = tmp_path / 'old.db'
    monkeypatch.setattr(storage, 'DEFAULT_DB', db)
    with sqlite3.connect(db) as conn:
        conn.executescript(storage.SCHEMA_SQL.replace("  source TEXT NOT NULL DEFAULT 'legacy',\n", ''))
        conn.execute('INSERT INTO users(telegram_id) VALUES(1)')
        conn.execute("INSERT INTO domains(owner_id,name) VALUES(1,'example.com')")
        conn.execute("INSERT INTO history(owner_id,domain,check_name,status,message) "
                     "VALUES(1,'example.com','http_basic','CRIT','old')")
    for _ in range(2):
        storage._INITIALIZED_PATHS.discard(db)
        storage._ensure_initialized()
    assert storage.last_results(1, 'example.com')[0]['source'] == 'legacy'
    storage.save_history(1, 'example.com', 'http_basic', 'OK', 'manual', {}, source='manual')
    assert storage.last_results(1, 'example.com')[0]['source'] == 'manual'


def test_period_boundaries_buckets_owner_isolation_and_settings_do_not_rewrite_history(
    database, monkeypatch,
):
    from sitewatcher.webapp import analytics
    now = datetime(2026, 10, 22, 12, tzinfo=timezone.utc)
    monkeypatch.setattr(analytics, '_now', lambda: now)
    observation({'final_code': 200}, at='2026-10-21 12:00:00')
    observation({'final_code': 503}, at='2026-10-21 11:59:59')
    observation({'final_code': 503}, at='2026-10-22 12:00:01')
    observation({'final_code': 200}, at='2026-10-22 11:59:59')
    storage.save_history(2, 'example.com', 'http_basic', 'CRIT', 'PRIVATE', {'final_code': 503})
    storage.set_domain_override(1, 'example.com', {'checks': {'http_basic': False}})
    result = report(zone='Europe/Moscow')
    assert result['totals']['sample_count'] == 2
    assert result['totals']['success_percent'] == 100
    assert len(result['buckets']) == 2  # No interpolated samples across the gap.
    assert result['buckets'][0]['start_at'].endswith('Z')
    assert '15:00' in result['buckets'][0]['label']
    assert report(days=7)['totals']['sample_count'] == 3
    assert report(days=30)['totals']['sample_count'] == 3
    assert analytics.overview_report(2, days=1, timezone='UTC')['totals']['sample_count'] == 1
    assert analytics.overview_report(3, days=1, timezone='UTC')['domains'] == []


def test_large_history_is_bounded_and_overview_aggregates_owners_domains(database):
    from sitewatcher.webapp.analytics import overview_report
    storage.add_domain(1, 'empty.example')
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    with storage._connect() as conn:
        conn.executemany(
            'INSERT INTO history(owner_id,domain,check_name,status,message,metrics_json,created_at) '
            'VALUES(1,?,?,?,?,?,?)',
            (('example.com', 'http_basic', 'OK', 'PRIVATE', '{"final_code":200}',
              (now - timedelta(minutes=i)).isoformat(sep=' ')) for i in range(20000)),
        )
    result = overview_report(1, days=30, timezone='UTC')
    assert result['totals']['sample_count'] == 20000
    assert len(result['buckets']) <= 120
    assert len(result['domains']) == 2
    assert all(len(domain['buckets']) <= 120 for domain in result['domains'])
    assert len(json.dumps(result)) < 150000


@pytest.mark.parametrize('error', [httpx.ConnectError, httpx.ReadTimeout])
def test_new_request_errors_have_structured_unavailability_without_response_latency(error, monkeypatch):
    async def request(*args, **kwargs):
        raise error('sensitive remote message')
    monkeypatch.setattr('sitewatcher.checks.http_basic.get_with_retries', request)
    result = asyncio.run(HttpBasicCheck('example.com', None).run())
    assert result.status is Status.CRIT
    assert result.metrics['availability'] == 'unavailable'
    assert 'response_latency_ms' not in result.metrics


def test_new_http_success_has_structured_successful_response_latency():
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(
            lambda request: httpx.Response(200),
        )) as client:
            return await HttpBasicCheck('example.com', client).run()
    result = asyncio.run(run())
    assert result.metrics['availability'] == 'available'
    assert isinstance(result.metrics['response_latency_ms'], int)


@pytest.mark.parametrize('latency', [True, '10', -1, float('nan'), float('inf'),
                                    float('-inf'), 10 ** 400])
def test_malformed_numeric_latency_is_not_exposed(database, latency):
    observation({'final_code': 200, 'latency_ms_total': latency})
    result = report()
    assert result['totals']['latency_ms'] is None
    json.dumps(result, allow_nan=False)


def test_extreme_finite_latencies_cannot_overflow_the_average(database):
    for _ in range(3):
        observation({'final_code': 200, 'latency_ms_total': 1e308})
    result = report()
    assert result['totals']['latency_ms'] == 1e308
    json.dumps(result, allow_nan=False)


@pytest.mark.parametrize('final_code', [200, 503])
def test_new_redirects_record_final_availability_and_only_success_latency(final_code):
    def response(request):
        if request.url.path == '/':
            return httpx.Response(302, headers={'location': '/landing'})
        return httpx.Response(final_code)

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(response)) as client:
            return await HttpBasicCheck('example.com', client).run()
    result = asyncio.run(run())
    assert result.metrics['final_code'] == final_code
    assert result.metrics['availability'] == ('available' if final_code == 200 else 'unavailable')
    assert ('response_latency_ms' in result.metrics) == (final_code == 200)


def test_latest_observation_breaks_same_second_ties_by_history_id(database, monkeypatch):
    observation({'final_code': 200}, at='2026-10-22 11:00:00')
    observation({'final_code': 503}, at='2026-10-22 11:00:00')
    from sitewatcher.webapp import analytics
    # Current wall clock cannot affect this fixed fixture's inclusion.
    monkeypatch.setattr(analytics, '_now',
                        lambda: datetime(2026, 10, 22, 12, tzinfo=timezone.utc))
    assert report()['latest_availability'] == 'unavailable'


@pytest.mark.parametrize('module', ['sitewatcher.web', 'sitewatcher.webapp.domains'])
def test_web_manual_measurements_stamp_manual_provenance(database, monkeypatch, module):
    from importlib import import_module
    from sitewatcher.config import AppConfig

    web = import_module(module)

    class Dispatcher:
        def __init__(self, cfg):
            pass
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            pass
        async def run_for(self, owner, domain, **kwargs):
            return [CheckOutcome('http_basic', Status.OK, 'synthetic', {'final_code': 200})]

    monkeypatch.setattr(web, 'Dispatcher', Dispatcher)
    asyncio.run(web._check_domains(AppConfig(), 1, ['example.com']))
    assert storage.last_results(1, 'example.com')[0]['source'] == 'manual'


def test_report_cache_is_detached_and_invalidates_on_history_and_domain_changes(database, monkeypatch):
    from sitewatcher.webapp import analytics
    observation({'final_code': 200})
    first = report()
    original = analytics._aggregate
    calls = []

    def measured(*args):
        calls.append(True)
        return original(*args)

    monkeypatch.setattr(analytics, '_aggregate', measured)
    first['totals']['successful'] = -100
    assert report()['totals']['successful'] == 1
    assert calls == []
    # Auth/session/other-owner writes must not evict the owner's analytics.
    storage.ensure_user(55, username='synthetic')
    assert report()['totals']['successful'] == 1
    assert calls == []
    observation({'final_code': 503})
    assert report()['totals']['failed'] == 1
    assert len(calls) == 1
    with storage._connect() as conn:
        conn.execute('DELETE FROM history WHERE id=(SELECT MIN(id) FROM history)')
    assert report()['totals']['sample_count'] == 1
    assert len(calls) == 2
    storage.remove_domain(1, 'example.com')
    with pytest.raises(ValueError):
        report()


def test_report_cache_expires_and_remains_bounded(database, monkeypatch):
    from sitewatcher.webapp import analytics
    analytics._CACHE.clear()
    clock = [10.0]
    monkeypatch.setattr(analytics, 'monotonic', lambda: clock[0])
    observation({'final_code': 200})
    assert report()['totals']['successful'] == 1
    with storage._connect() as conn:
        conn.execute("UPDATE history SET metrics_json='{\"final_code\":503}'")
    # Historical in-place edits are not append-only revisions; TTL bounds their staleness.
    assert report()['totals']['successful'] == 1
    clock[0] += 61
    assert report()['totals']['failed'] == 1
    for owner in range(20):
        storage.add_domain(owner, 'other.example')
        analytics.overview_report(owner, days=1, timezone='UTC')
    assert len(analytics._CACHE) <= 8
    assert sum(item[1] for item in analytics._CACHE.values()) <= 4 * 1024 * 1024
