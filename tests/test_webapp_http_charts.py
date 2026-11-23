"""Only configured HTTP monitoring with actual response-time points gets a chart."""
import re
from datetime import datetime, timedelta, timezone

import pytest
from django.contrib.auth import get_user_model
from django.test import Client

from sitewatcher import storage
from sitewatcher.config import ChecksModel


@pytest.mark.parametrize('page', ['overview', 'history', 'public'])
@pytest.mark.parametrize('http_enabled,observation,days,visible', [
    (False, 'successful', 1, False),
    (True, None, 1, False),
    (True, 'old', 1, False),
    (True, 'old', 7, True),
    (True, 'successful', 1, True),
    (True, 'failed', 1, False),
    (True, 'unknown', 1, False),
    (True, 'successful_without_latency', 1, False),
    (True, 'failed_with_latency', 1, False),
    (True, 'zero_latency', 1, True),
])
def test_domain_chart_requires_enabled_http_and_response_time_points(
        web_database, client, page, http_enabled, observation, days, visible):
    from sitewatcher.webapp.models import Workspace

    user = get_user_model().objects.create_user(username='chart-owner')
    Workspace.objects.create(user=user, owner_id=628)
    storage.ensure_user(628)
    storage.add_domain(628, 'chart.example')
    storage.set_domain_override(628, 'chart.example', {'checks': {
        name: (http_enabled if name == 'http_basic' else name == 'tls_cert')
        for name in ChecksModel.model_fields}})
    storage.save_history(628, 'chart.example', 'tls_cert', 'OK', 'Certificate valid', {})
    if observation:
        metrics = ({'availability': 'unavailable', 'final_code': 503}
                   if observation in {'failed', 'failed_with_latency'} else {'availability': 'unknown'}
                   if observation == 'unknown' else {'final_code': 200, 'latency_ms_total': 120})
        if observation == 'successful_without_latency':
            metrics.pop('latency_ms_total')
        elif observation == 'zero_latency':
            metrics['latency_ms_total'] = 0
        elif observation == 'failed_with_latency':
            metrics['latency_ms_total'] = 200
        storage.save_history(628, 'chart.example', 'http_basic',
                             'CRIT' if observation in {'failed', 'failed_with_latency'} else 'OK', 'saved', metrics)
        if observation == 'old':
            with storage._write_connection() as connection:
                connection.execute('UPDATE history SET created_at=? WHERE check_name=?',
                                   ((datetime.now(timezone.utc) - timedelta(days=2)).isoformat(),
                                    'http_basic'))
    client.force_login(user)
    path = '/domains/history?domain=chart.example&' if page == 'history' else '/?'
    if page == 'public':
        response = client.post('/settings/public', {'action': 'enable', 'domains': 'chart.example'},
                               HTTP_HOST='localhost')
        assert response.status_code == 200
        path = re.search(r'http://localhost(/status/[A-Za-z0-9_-]+/)',
                         response.content.decode()).group(1) + '?'
        client = Client()
    response = client.get(path + 'days=' + str(days), HTTP_HOST='localhost')
    assert response.status_code == 200
    body = response.content.decode()
    if page != 'history':
        assert 'class="response-chart"' not in body
        fragment = ('/domains/details?domain=chart.example&' if page == 'overview'
                    else path + 'domain=chart.example&fragment=1&')
        response = client.get(fragment + 'days=' + str(days), HTTP_HOST='localhost')
        assert response.status_code == 200
        body = response.content.decode()
    assert ('class="response-chart"' in body) is visible
    assert ('class="panel chart-panel"' in body) is (visible and page == 'history')
    assert ('class="domain-detail-chart"' in body) is (visible and page != 'history')
    assert 'Latest monitoring checks' in body
    assert 'TLS certificate' in body


def test_http_history_shows_latency_confirmation_without_exposing_internal_state(
    web_database, client,
):
    from sitewatcher.webapp.models import Workspace

    user = get_user_model().objects.create_user(username='confirmation-owner')
    Workspace.objects.create(user=user, owner_id=628, language='ru')
    storage.save_history(628, 'chart.example', 'http_basic', 'CRIT', 'HTTP 200', {
        'availability': 'available', 'final_code': 200, 'response_latency_ms': 8607,
        'chart_response_latency_ms': 1100,
        'latency_recheck': {'state': 'confirmed', 'initial_ms': 8607, 'median_ms': 1100,
                            'token': 'confirmation-token-for-test',
                            'samples': [{'latency_ms': ms} for ms in (900, 1100, 5000)]},
    }, source='scheduled')
    client.force_login(user)
    response = client.get('/domains/history?domain=chart.example', HTTP_HOST='localhost')
    assert response.status_code == 200
    body = response.content.decode()
    assert 'Первый ответ занял 8607 мс.' in body
    assert '900 мс, 1100 мс, 5000 мс' in body
    assert 'Подтверждённое время ответа 1100 мс' in body
    assert 'confirmation-token-for-test' not in body


@pytest.mark.parametrize('page', ['overview', 'history', 'public'])
@pytest.mark.parametrize('interval,edited_minutes,observations,segments,gaps', [
    pytest.param(60, 1440, [(age, 'scheduled') for age in (240, 180, 120, 60, 0)], 1, 0,
                 id='regular-hourly'),
    pytest.param(60, 1440, [(age, 'scheduled') for age in (240, 180, 60, 0)], 2, 1,
                 id='missed-hour'),
    pytest.param(60, 1440, [(240, 'scheduled'), (180, 'scheduled'), (130, 'manual'),
                 (70, 'scheduled'), (10, 'scheduled')], 1, 0, id='manual-resets-deadline'),
    pytest.param(60, 1440, [(240, 'scheduled'), (180, 'scheduled'), (120, 'failed'),
                 (60, 'scheduled'), (0, 'scheduled')], 1, 0, id='failed-result-was-saved'),
    pytest.param(60, 1440, [(age, 'scheduled') for age in (242, 182, 122, 62)], 1, 1,
                 id='overdue-at-right-edge'),
    pytest.param(60, 1440, [(age, 'scheduled') for age in (241, 181, 121, 61)], 1, 0,
                 id='within-scheduler-tick'),
    pytest.param(60, 2880, [(age, 'scheduled') for age in (1500, *range(1380, -1, -60))], 1, 1,
                 id='overdue-from-previous-window'),
    pytest.param(0, 1440, [(age, 'scheduled') for age in (240, 180, 60)], 1, 0,
                 id='paused'),
    pytest.param(60, 90, [(age, 'scheduled') for age in (240, 180, 60, 0)], 1, 0,
                 id='older-than-current-schedule'),
])
def test_hourly_chart_marks_only_overdue_http_checks(
    web_database, client, monkeypatch, page, interval, edited_minutes, observations, segments, gaps,
):
    from sitewatcher.webapp import analytics
    from sitewatcher.webapp.models import StatusPage, Workspace

    now = analytics._now().replace(second=0, microsecond=0)
    monkeypatch.setattr(analytics, '_now', lambda: now)
    owner_id, domain = 628, 'hourly.example'
    user = get_user_model().objects.create_user(username='hourly-chart-owner')
    workspace = Workspace.objects.create(user=user, owner_id=owner_id)
    storage.add_domain(owner_id, domain)
    storage.set_domain_override(owner_id, domain, {'interval_minutes': interval})
    with storage._write_connection() as conn:
        effective_since = (now - timedelta(minutes=edited_minutes)).replace(tzinfo=None).isoformat(sep=' ')
        conn.execute('UPDATE domain_overrides SET updated_at=? WHERE owner_id=? AND domain=?',
                     (effective_since, owner_id, domain))
    for age, source in observations:
        failed = source == 'failed'
        storage.save_history(owner_id, domain, 'http_basic', 'CRIT' if failed else 'OK',
                             'saved', {'final_code': 503 if failed else 200,
                                       'response_latency_ms': 120},
                             source='scheduled' if failed else source)
        with storage._write_connection() as conn:
            stamp = (now - timedelta(minutes=age)).replace(tzinfo=None).isoformat(sep=' ')
            conn.execute('UPDATE history SET created_at=? WHERE id=('
                         'SELECT MAX(id) FROM history WHERE owner_id=? AND domain=?)',
                         (stamp, owner_id, domain))
    if page == 'public':
        StatusPage.objects.create(workspace=workspace, public_slug='hourly',
                                  public_domains=[domain])
        path = f'/hourly?domain={domain}&fragment=1'
    else:
        client.force_login(user)
        endpoint = 'details' if page == 'overview' else 'history'
        path = f'/domains/{endpoint}?domain={domain}'
    response = client.get(path, HTTP_HOST='localhost')
    assert response.status_code == 200
    assert response.content.count(b'class="chart-line"') == segments
    assert response.content.count(b'class="chart-gap"') == gaps
    if gaps and edited_minutes == 2880:
        assert b'class="chart-gap" x="0.0"' in response.content
