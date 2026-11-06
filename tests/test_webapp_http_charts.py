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
    assert ('class="response-chart"' in body) is visible
    assert ('class="panel chart-panel"' in body) is (visible and page == 'history')
    assert ('class="domain-detail-chart"' in body) is (visible and page != 'history')
    assert 'Latest monitoring checks' in body
    assert 'TLS certificate' in body
