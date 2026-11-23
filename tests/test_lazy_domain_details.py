from django.contrib.auth import get_user_model
from django.test import Client

from sitewatcher import storage


def test_owner_overview_loads_charts_from_a_scoped_fragment(web_database, client):
    from sitewatcher.webapp.models import Workspace

    owner = get_user_model().objects.create_user(username='lazy-owner')
    Workspace.objects.create(user=owner, owner_id=15)
    storage.save_history(15, 'visible.example', 'http_basic', 'OK', 'Available',
                         {'final_code': 200, 'response_latency_ms': 123})
    storage.save_history(16, 'other.example', 'http_basic', 'OK', 'Other owner',
                         {'final_code': 200, 'response_latency_ms': 999})
    storage.add_domain(15, 'empty.example')
    client.force_login(owner)
    body = client.get('/?days=7', HTTP_HOST='localhost').content.decode()
    assert 'class="response-chart"' not in body
    assert body.count('class="response-chart chart-placeholder"') == 1
    assert 'data-details-message role="status"' in body
    assert '/domains/details?domain=visible.example&amp;days=7' in body
    path = '/domains/details?domain=visible.example&days=7'
    response = client.get(path, HTTP_HOST='localhost')
    assert response.status_code == 200
    assert b'class="response-chart"' in response.content
    assert b'class="chart-series"' in response.content
    assert b'chart-placeholder' not in response.content
    empty = client.get('/domains/details?domain=empty.example&days=7', HTTP_HOST='localhost')
    assert empty.status_code == 200
    assert b'class="response-chart"' not in empty.content
    assert 'no-store' in response.headers['Cache-Control']
    assert client.get('/domains/details?domain=other.example',
                      HTTP_HOST='localhost').status_code == 404
    assert Client().get(path, HTTP_HOST='localhost').status_code in (302, 401)
