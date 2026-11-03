"""Activity is bounded, shared across processes, and isolated by workspace."""
import asyncio
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from django.contrib.auth import get_user_model
from django.test import RequestFactory

from sitewatcher import storage
from sitewatcher.checks.base import CheckOutcome, Status
from sitewatcher.config import AppConfig
from sitewatcher.dispatcher import Dispatcher


def seed():
    storage.add_domain(31, 'shared.example')
    storage.add_domain(99, 'shared.example')


def test_persistence_owner_cap_and_cascade():
    from sitewatcher.check_activity import finish, recent, start
    seed()
    other = start(99, 'shared.example', 'tls_cert')
    for _ in range(1002):
        event = start(31, 'shared.example', 'http_basic')
    finish(event, 'WARN', 25)
    rows = recent(31, limit=1000)
    assert len(rows) == 1000
    assert rows[-1]['status'] == 'WARN' and rows[-1]['elapsed_ms'] == 25
    assert len(recent(99)) == 1 and recent(99)[0]['id'] == other
    assert storage.last_results(31, 'shared.example') == []
    assert start(42, 'shared.example', 'http_basic') is None
    storage.remove_domain(31, 'shared.example')
    assert recent(31) == [] and len(recent(99)) == 1


def test_missing_storage_is_never_created(tmp_path, monkeypatch):
    from sitewatcher.check_activity import finish, recent, start
    monkeypatch.setattr(storage, 'DEFAULT_DB', tmp_path / 'absent.db')
    assert start(1, 'example.com', 'http_basic') is None
    finish(1, 'OK', 1)
    with pytest.raises(sqlite3.Error):
        recent(1)
    assert not storage.DEFAULT_DB.exists()


def dispatcher(monkeypatch, probes, *, concurrency=1):
    cfg = AppConfig()
    cfg.scheduler.per_domain_concurrency = concurrency
    cfg.scheduler.domain_timeout_s = 120
    instance = Dispatcher(cfg)
    instance._client = object()
    monkeypatch.setattr(instance, '_build_checks', lambda settings, **kwargs: probes)
    return instance


def test_dispatcher_actual_start_finish_and_waiting_cancellation(monkeypatch):
    from sitewatcher.check_activity import recent
    seed()

    async def scenario():
        entered, release = asyncio.Event(), asyncio.Event()

        class Probe:
            name = 'http_basic'

            async def run(self):
                entered.set()
                await release.wait()
                return CheckOutcome(self.name, Status.WARN, 'private diagnostic')

        instance = dispatcher(monkeypatch, [Probe(), Probe()])
        task = asyncio.create_task(instance.run_for(31, 'shared.example'))
        await entered.wait()
        rows = recent(31)
        assert len(rows) == 1 and rows[0]['finished_at'] is None
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        rows = recent(31)
        assert len(rows) == 1 and rows[0]['status'] == 'UNKNOWN'
        assert rows[0]['finished_at'] is not None

        release.set()
        results = await instance.run_for(31, 'shared.example')
        assert [item.status for item in results] == [Status.WARN, Status.WARN]
        assert [row['status'] for row in recent(31)][-2:] == ['WARN', 'WARN']

    asyncio.run(scenario())


def test_dispatcher_skip_cached_ephemeral_and_preserve_exceptions(monkeypatch):
    from sitewatcher.check_activity import recent
    seed()

    class Probe:
        name = 'http_basic'

        async def run(self):
            raise RuntimeError('synthetic')

    instance = dispatcher(monkeypatch, [Probe()])
    cached = CheckOutcome('http_basic', Status.OK, 'cached', cached=True)
    monkeypatch.setattr(instance, '_maybe_cached_result', lambda *args: cached)
    assert asyncio.run(instance.run_for(31, 'shared.example', use_cache=True)) == [cached]
    assert recent(31) == []
    result = asyncio.run(instance.run_for(31, 'shared.example', ephemeral=True))
    assert result[0].status == Status.UNKNOWN and recent(31) == []
    result = asyncio.run(instance.run_for(31, 'shared.example'))
    assert result[0].status == Status.UNKNOWN
    assert recent(31)[0]['status'] == 'UNKNOWN'
    assert recent(31)[0]['finished_at'] is not None


@pytest.fixture
def owner(web_database):
    from sitewatcher.webapp.models import Workspace
    seed()
    user = get_user_model().objects.create_user(username='activity-owner')
    return Workspace.objects.create(user=user, owner_id=31)


def call_api(owner, method='get', query=''):
    from sitewatcher.webapp.activity import activity
    request = getattr(RequestFactory(), method)('/api/activity' + query)
    request.user = owner.user
    return activity(request)


def test_api_owner_dto_stale_and_read_only(owner, monkeypatch):
    from django.conf import settings
    from sitewatcher.check_activity import recent, start
    monkeypatch.setattr(settings.SITEWATCHER_CONFIG.scheduler, 'domain_timeout_s', 120)
    first = start(31, 'shared.example', 'http_basic')
    start(99, 'shared.example', 'private_check')
    old = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    with storage._write_connection() as conn:
        conn.execute('UPDATE check_activity SET started_at=? WHERE id=?', (old, first))
    before = recent(31)
    response = call_api(owner)
    assert response.status_code == 200 and 'no-store' in response['Cache-Control']
    event, = json.loads(response.content)['events']
    assert event['id'] == first and event['phase'] == 'interrupted'
    assert event['status'] == 'UNKNOWN' and event['finished_at'] is None
    assert event['label'] and event['status_label']
    assert set(event) == {'id', 'domain', 'check_name', 'label', 'status', 'status_label',
                          'started_at', 'finished_at', 'elapsed_ms', 'phase'}
    assert recent(31) == before
    assert call_api(owner, 'post').status_code == 405
    for query in ('?owner_id=99', '?limit=100000', '?x=1&x=2'):
        assert call_api(owner, query=query).status_code == 400


def test_api_authentication_and_unavailable(owner, monkeypatch, tmp_path):
    from sitewatcher.webapp.activity import activity
    request = RequestFactory().get('/api/activity')
    request.user = SimpleNamespace(is_authenticated=False)
    assert activity(request).status_code == 401
    with monkeypatch.context() as patch:
        patch.setattr(storage, 'DEFAULT_DB', tmp_path / 'missing.db')
        response = call_api(owner)
        assert response.status_code == 503 and 'no-store' in response['Cache-Control']
        assert not storage.DEFAULT_DB.exists()


def test_shared_activity_is_visible_from_another_process():
    import subprocess
    import sys
    from sitewatcher.check_activity import recent
    seed()
    subprocess.run([
        sys.executable, '-c',
        'import sys; from pathlib import Path; from sitewatcher import storage; '
        'from sitewatcher.check_activity import start, finish; '
        'storage.DEFAULT_DB = Path(sys.argv[1]); '
        'finish(start(31, "shared.example", "tls_cert"), "CRIT", 12)',
        str(storage.DEFAULT_DB),
    ], check=True)
    event, = recent(31)
    assert event['check_name'] == 'tls_cert' and event['status'] == 'CRIT'
    assert event['elapsed_ms'] == 12


def test_dispatcher_activity_write_failure_preserves_check(monkeypatch):
    seed()

    class Probe:
        name = 'http_basic'

        async def run(self):
            return CheckOutcome(self.name, Status.OK, 'healthy')

    instance = dispatcher(monkeypatch, [Probe()])
    # Simulate an old database during an upgrade: telemetry is optional.
    with storage._write_connection() as conn:
        conn.execute('DROP TABLE check_activity')
    result, = asyncio.run(instance.run_for(31, 'shared.example'))
    assert result.status == Status.OK
    with storage._connect() as conn:
        assert not conn.execute(
            "SELECT name FROM sqlite_master WHERE name='check_activity'",
        ).fetchall()


def test_dispatcher_timeout_closes_only_started_checks(monkeypatch):
    from sitewatcher.check_activity import recent
    seed()

    class Probe:
        name = 'http_basic'

        async def run(self):
            await asyncio.Event().wait()

    instance = dispatcher(monkeypatch, [Probe(), Probe()])
    instance.cfg.scheduler.domain_timeout_s = 0.05
    results = asyncio.run(instance.run_for(31, 'shared.example'))
    assert len(results) == 2 and all(row.status == Status.UNKNOWN for row in results)
    row, = recent(31)
    assert row['finished_at'] is not None and row['status'] == 'UNKNOWN'


def test_api_bounded_running_and_finished_labels(owner):
    from sitewatcher.check_activity import finish, start
    first = start(31, 'shared.example', 'http_basic')
    for _ in range(99):
        start(31, 'shared.example', 'tls_cert')
    last = start(31, 'shared.example', 'whois')
    finish(last, 'OK', 42)
    response = call_api(owner)
    events = json.loads(response.content)['events']
    assert len(events) == 100 and events[0]['id'] > first
    assert [item['id'] for item in events] == sorted(item['id'] for item in events)
    assert events[0]['phase'] == 'running' and events[0]['finished_at'] is None
    assert events[-1]['phase'] == 'finished' and events[-1]['status'] == 'OK'
    assert events[-1]['elapsed_ms'] == 42


@pytest.mark.parametrize('timeout', [None, 0])
def test_api_unfinished_activity_without_deadline_stays_running(owner, timeout, monkeypatch):
    from django.conf import settings
    from sitewatcher.check_activity import recent, start
    event_id = start(31, 'shared.example', 'http_basic')
    old = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    with storage._write_connection() as conn:
        conn.execute('UPDATE check_activity SET started_at=? WHERE id=?', (old, event_id))
    monkeypatch.setattr(settings.SITEWATCHER_CONFIG.scheduler, 'domain_timeout_s', timeout)
    before = recent(31)
    response = call_api(owner)
    event, = json.loads(response.content)['events']
    assert response.status_code == 200
    assert event['phase'] == 'running' and event['status_label'] == 'Running'
    assert event['finished_at'] is None and event['status'] == 'UNKNOWN'
    assert recent(31) == before


def test_recent_includes_completion_of_an_older_long_running_check():
    from sitewatcher.check_activity import finish, recent, start
    seed()
    slow = start(31, 'shared.example', 'http_basic')
    for _ in range(110):
        start(31, 'shared.example', 'tls_cert')
    finish(slow, 'OK', 4000)
    assert recent(31)[-1]['id'] == slow
